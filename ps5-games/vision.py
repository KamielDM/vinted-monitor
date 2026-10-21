"""Zero-shot fotoherkenning met CLIP (ONNX, lokaal, gratis). Productonafhankelijk: wat herkend moet worden
staat als Engelse zinnen in config.toml ([vision.labels]).

Model: openai/clip-vit-base-patch32, ONNX-versie van Xenova op Hugging Face (±155 MB, eenmalig gedownload
naar ../models/, gedeeld door alle monitors in deze projectmap).
"""
import io
import logging
from pathlib import Path

import numpy as np
import requests

log = logging.getLogger("ps5")
MODEL_DIR = Path(__file__).resolve().parent.parent / "models" / "clip-vit-base-patch32"
REPO = "https://huggingface.co/Xenova/clip-vit-base-patch32/resolve/main/"
FILES = ["onnx/vision_model_quantized.onnx", "onnx/text_model_quantized.onnx", "tokenizer.json"]
MEAN = np.array([0.48145466, 0.4578275, 0.40821073], dtype=np.float32)
STD = np.array([0.26862954, 0.26130258, 0.27577711], dtype=np.float32)


def download():
    for f in FILES:
        dest = MODEL_DIR / f
        if dest.exists():
            continue
        dest.parent.mkdir(parents=True, exist_ok=True)
        log.info("CLIP-model downloaden: %s (eenmalig)", f)
        with requests.get(REPO + f, stream=True, timeout=60) as r:
            r.raise_for_status()
            tmp = dest.with_suffix(".part")
            with open(tmp, "wb") as out:
                for chunk in r.iter_content(1 << 20):
                    out.write(chunk)
            tmp.replace(dest)


def preprocess(data: bytes) -> np.ndarray:
    """CLIP-voorbewerking: kortste zijde 224, midden uitsnijden, normaliseren. -> (3, 224, 224)"""
    from PIL import Image
    im = Image.open(io.BytesIO(data)).convert("RGB")
    s = 224 / min(im.size)
    im = im.resize((max(224, round(im.width * s)), max(224, round(im.height * s))), Image.BICUBIC)
    left, top = (im.width - 224) // 2, (im.height - 224) // 2
    x = np.asarray(im.crop((left, top, left + 224, top + 224)), dtype=np.float32) / 255
    return ((x - MEAN) / STD).transpose(2, 0, 1)


class Clip:
    def __init__(self, labels: dict[str, str]):
        """labels = {"stock": "an official product photo on a white background", ...}"""
        import onnxruntime as ort
        from tokenizers import Tokenizer
        download()
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 2  # laptop niet volledig belasten
        self.names = list(labels)
        tok = Tokenizer.from_file(str(MODEL_DIR / "tokenizer.json"))
        text = ort.InferenceSession(str(MODEL_DIR / FILES[1]), opts)
        emb = []
        for sentence in labels.values():  # één per keer: geen padding nodig
            ids = np.array([tok.encode(sentence).ids], dtype=np.int64)
            emb.append(text.run(["text_embeds"], {"input_ids": ids})[0][0])
        self.text = np.array(emb) / np.linalg.norm(emb, axis=1, keepdims=True)
        del text  # tekstmodel is alleen bij het opstarten nodig
        self.vision = ort.InferenceSession(str(MODEL_DIR / FILES[0]), opts)

    def classify(self, images: list[bytes]) -> list[dict[str, float]]:
        """Per foto de kans per label (som = 1)."""
        x = np.stack([preprocess(b) for b in images])
        img = self.vision.run(["image_embeds"], {"pixel_values": x})[0]
        img /= np.linalg.norm(img, axis=1, keepdims=True)
        logits = 100 * img @ self.text.T  # CLIP's vaste logit-schaal
        p = np.exp(logits - logits.max(axis=1, keepdims=True))
        p /= p.sum(axis=1, keepdims=True)
        return [dict(zip(self.names, map(float, row))) for row in p]
