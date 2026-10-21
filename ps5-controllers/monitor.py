"""Vinted PS5 Controller Monitor - pollt Vinted (PS5-controllers), filtert scams, stuurt Telegram-meldingen.

Gebruik:  python monitor.py [--dry-run] [--notify-existing] [--once]
          python monitor.py --setup-telegram | --test-telegram | --log [N]
"""
import argparse
import datetime as dt
import html
import io
import json
import logging
import logging.handlers
import os
import re
import socket
import sqlite3
import statistics
import threading
import sys
import time
import tomllib
import unicodedata
import zlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit

import requests

ROOT = Path(__file__).resolve().parent
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
log = logging.getLogger("ps5")

# ---------------------------------------------------------------- tekst & regels

LEET = str.maketrans("0134578@$", "oieastbas")
PS5_RE = re.compile(r"\bp\W*s\W*5|play\W*station\W*5", re.I)


def norm(text: str, leet=True) -> str:
    """lowercase, accenten weg, optioneel leetspeak -> letters (p4ypal -> paypal)."""
    t = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode().lower()
    return t.translate(LEET) if leet else t


def compile_rule(word: str) -> re.Pattern:
    """'pay pal' -> regex die ook 'P.a.y-P.a.l', 'paypal' en 'p4ypal' vangt, op woordgrenzen."""
    if word.startswith("re:"):
        return re.compile(word[3:], re.I)
    chars = [c for c in norm(word) if not c.isspace()]
    return re.compile(r"(?<![a-z])" + r"[\W_]*".join(map(re.escape, chars)) + r"(?![a-z])")


FUZZY_MIN = 10  # lange losse woorden mogen 1 typfout hebben ("trasferencia"); korter niet ("vivement" ≠ "virement")


def one_edit(a: str, b: str) -> bool:
    """True als a en b hoogstens 1 letter verschillen (vervangen, toevoegen of weglaten)."""
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) > len(b):
        a, b = b, a
    i = 0
    while i < len(a) and a[i] == b[i]:
        i += 1
    return a[i + (len(a) == len(b)):] == b[i + 1:]


NEGATIONS = {"no", "non", "not", "never", "don", "geen", "niet", "nooit", "zonder", "pas", "jamais", "ni", "sans", "aucun",
             "aucune", "kein", "keine", "keinen", "keiner", "nicht", "niemals", "ohne", "sin", "nunca", "nada", "niente",
             "mai", "nessun", "nessuna", "nao", "rien", "nothing", "niets", "nulla", "nichts", "zero", "anti"}


def negated(n, start):
    """Ontkenning in de 3 woorden vóór positie start? "geen PayPal", "pas de virement", "jamais hors Vinted".
    Niet: "n'accepte que PayPal" (ne ... que = alleen), "pas de souci pour PayPal" (4 woorden ervoor) en
    "not on Vinted, PayPal" (de ontkenning slaat op Vinted, niet op PayPal) en "No PayPal, solo bonifico" (komma of punt
    beëindigt de ontkenning)."""
    words = re.findall(r"[a-z]+", re.split(r"[,.;:!?\n]", n[max(0, start - 40):start])[-1])[-3:]
    return bool(NEGATIONS & set(words)) and "vinted" not in words


def first_hit(rules, text, negatable=False):
    """Geeft (regel, gevonden tekst) terug voor de eerste regel die matcht; daarna nog typfouttolerant.
    negatable: treffers met een ontkenning ervoor tellen niet ("geen PayPal, alleen via Vinted" = eerlijke verkoper)."""
    n = norm(text)
    # "PayPaI" met hoofdletter i ziet eruit als PayPal: ook een variant met I -> l proberen
    ns = [n] + ([norm(text.replace("I", "l"))] if "I" in (text or "") else [])
    for word, rx in rules:
        # ponytail: regex-regels (e-mail/telefoon) op de originele tekst, want leet-normalisatie verandert cijfers
        m = rx.search(text) if word.startswith("re:") else \
            next((m for v in ns for m in rx.finditer(v) if not (negatable and negated(v, m.start()))), None)
        if m:
            return word, m.group(0).strip()
    tokens = [(m.group(0), m.start()) for m in re.finditer(r"[a-z]+", n)]
    for word, _ in rules:
        w = norm(word)
        if word.startswith("re:") or " " in w.strip() or len(w) < FUZZY_MIN:
            continue
        if tok := next((t for t, i in tokens if one_edit(t, w) and not (negatable and negated(n, i))), None):
            return word, tok
    return None


# (?<!...): de 5 van "PlayStation 5 game" / "PS5 games" is geen aantal
DRIFT = [(w, compile_rule(w)) for w in ("drift", "stickdrift", "drifting", "driftet", "deriva", "derive",
                                       "drifta", "strickstift")]  # "Strickstift" = verschreven Stickdrift (21/10)
NO_DRIFT = [(w, compile_rule(w)) for w in ("drift free", "driftfree", "driftfrei", "zero drift", "0 drift", "drift 0")]


def drift_status(text):
    """'drift' (vermeld), 'geen' ('sans drift', 'no drift', 'drift free') of None (niet vermeld)."""
    if first_hit(NO_DRIFT, text):
        return "geen"
    if first_hit(DRIFT, text, True):
        return "drift"
    return "geen" if first_hit(DRIFT, text) else None


# en ook niet de 27 van "FC27 jeux" of de 22 van "Fifa 22 - jeu" (21/10)
BULK_RE = re.compile(r"(?<!station )(?<!station)(?<!ps )(?<!ps)(?<![a-z\d])(?<!fifa )(?<!fc )(?<!2k)(?<!f1 )(?<!pes )(?<!nhl )(?<!gta )(?<!ops )(?<!mw )(?<!nba )(\d+)\s*(?:x\s*)?(?:jeux|jeu|games?|giochi|videogiochi|spiele|spielen|juegos|jogos|spellen|titres|titoli)\b"
                     r"|\b(?:lot|lotto|lote|set|pack|paquet|pakket|konvolut)\s+(?:de|di|van|of|mit|con|met|da)?\s*(\d+)\b")
LOT_RE = re.compile(r"\b(lot|lots|lotto|lote|pack de|set van|pakket|konvolut|sammlung|stock de jeux)\b")
PS4_RE = re.compile(r"\bp\W*s\W*[1-4]\b|play\W*station\W*[1-4]\b|\bps\W*vita\b|\bpsp\b|\bps\W*one\b")  # oude platformen


def bulk_count(t):
    """Aantal games in een bulkadvertentie ('lot de 5 jeux', '10 giochi', 'lotto di 4'); 0 = geen aantal gevonden."""
    return max((int(a or b) for a, b in BULK_RE.findall(t) if 1 < int(a or b) < 100), default=0)


def platform(t):
    """'ps5' als alleen PS5 vermeld, 'ps4' als alleen PS4/PS3 vermeld, anders None (niets of allebei: jij beslist)."""
    p5, p4 = bool(PS5_RE.search(t)), bool(PS4_RE.search(t))
    return "ps5" if p5 and not p4 else "ps4" if p4 and not p5 else None

# ---------------------------------------------------------------- vertrouwensscore


# Vinted-gebruikers-ID's lopen op. IJkpunten (id, datum) gemeten op 14/10/2026 via verificatiedatums van nieuwe accounts.
ID_ANCHORS = [(3152485505, "2026-04-29"), (3164593514, "2026-06-24"), (3180118664, "2026-08-27"),
              (3191802363, "2026-09-28"), (3198690329, "2026-10-14")]
OLDEST_ANCHOR = "eind april 2026"
IDS_PER_DAY = 275_000  # ponytail: extrapolatie na laatste ijkpunt; ijkpunten bijwerken als schattingen gaan afwijken


def account_age_days(user_id):
    """Geschatte accountleeftijd in dagen, of None als het account ouder is dan het oudste ijkpunt."""
    pts = [(i, dt.date.fromisoformat(d)) for i, d in ID_ANCHORS]
    if user_id < pts[0][0]:
        return None
    for (i0, d0), (i1, d1) in zip(pts, pts[1:]):
        if user_id <= i1:
            created = d0 + (d1 - d0) * ((user_id - i0) / (i1 - i0))
            break
    else:
        created = pts[-1][1] + dt.timedelta(days=(user_id - pts[-1][0]) / IDS_PER_DAY)
    return max(0, (dt.date.today() - created).days)


def trust_score(user, price, gen, cfg, extra=()):
    """Transparante score 0-100. Start op 50; elke regel is (delta, uitleg). Geen data = onbekend, geen straf.
    extra = bijkomende (delta, uitleg)-regels, bv. van de fotocontrole."""
    reasons = list(extra)
    if user is None:
        reasons.append((0, "verkopersprofiel niet opgehaald (onbekend)"))
    else:
        fc = user.get("feedback_count") or 0
        stars = (user.get("feedback_reputation") or 0) * 5
        neg = user.get("negative_feedback_count") or 0
        if fc == 0:
            reasons.append((-10, "nog geen reviews (onbekend, niet per se verdacht)"))
        else:
            if stars >= 4.0:  # veel reviews telt alleen als ze goed zijn
                reasons.append((5 if fc < 5 else 15 if fc < 20 else 25, f"{fc} review{'s' if fc != 1 else ''}"))
            if stars >= 4.7: reasons.append((10, f"hoge rating {stars:.1f}★".replace(".", ",")))
            elif stars < 4.0: reasons.append((-30 if stars < 3.0 else -20, f"lage rating {stars:.1f}★ ({fc} reviews)".replace(".", ",")))
            if neg >= 2 and neg / fc > 0.1: reasons.append((-10, f"{neg} negatieve reviews"))
        ver = [{"email": "e-mail"}.get(k, k.capitalize()) for k, v in (user.get("verification") or {}).items()
               if isinstance(v, dict) and v.get("valid")]
        if ver: reasons.append((3 * len(ver), "geverifieerd: " + ", ".join(ver)))
        if fc == 0 and (user.get("item_count") or 0) <= 1:
            reasons.append((-5, "enkel deze ene advertentie online"))
        age = account_age_days(user["id"]) if user.get("id") else None
        if age is None:
            reasons.append((5, f"account bestaat al van vóór {OLDEST_ANCHOR}"))
        elif age < 7:
            reasons.append((-10, f"gloednieuw account (~{age} dagen, geschat)"))
        elif age < 30:
            reasons.append((-5, f"jong account (~{age} dagen, geschat)"))
        else:
            reasons.append((0, f"account ~{age // 30} maanden oud (geschat)"))
        if user.get("is_on_holiday"): reasons.append((-5, "vakantiemodus aan"))
        if user.get("business"): reasons.append((0, "zakelijke verkoper"))
    limit = cfg["suspicious_price"].get(gen or "default", cfg["suspicious_price"]["default"])
    if price < limit:
        reasons.append((-25, f"prijs €{price:.0f} verdacht laag (< €{limit})"))
    score = max(0, min(100, 50 + sum(d for d, _ in reasons)))
    return score, reasons


PROOF_RE = re.compile(r"factu|factuur|ticket de caisse|kassabon|kassaticket|bon d.achat|receipt|invoice|fattura|"
                      r"scontrino|rechnung|kaufbeleg|garantie|garanzia|garantia|warranty")
DEFECT_RE = re.compile(r"rayure|krassen|\bkras\b|scratch|graffi|kratzer|bruit|lawaai|rumore|gerausch|ruido|surchauffe|"
                       r"oververhit|surriscald|uberhitz|\bdrift|ne s.allume pas|ne fonctionne pas|werkt niet|"
                       r"\bprobleme?|probleem|problema|defaut|defekt|difetto|defecto|\bstuk\b")


def read_description(desc):
    """Signalen uit de beschrijving: aankoopbewijs (+) en vermelde gebreken (info, kan ook 'geen krassen' zijn)."""
    d = norm(desc or "", leet=False)
    reasons, defects = [], sorted({m.group(0).strip() for m in DEFECT_RE.finditer(d)})
    if PROOF_RE.search(d):
        reasons.append((5, "factuur of garantie vermeld"))
    if defects:
        reasons.append((0, f"beschrijving vermeldt: {', '.join(defects[:3])} (lees na)"))
    return reasons


def review_check(feedbacks, warn_rules, scam_rules, now=None):
    """Reviews van de verkoper lezen. Geeft (reden om over te slaan of None, [(delta, uitleg), ...]).
    Alleen reviews met 3★ of minder tellen: '5★, geen arnaque!' mag geen vals alarm geven."""
    now = now or dt.datetime.now(dt.timezone.utc)
    reasons, recent_neg, auto = [], 0, 0
    for f in feedbacks:
        try:
            age = (now - dt.datetime.fromisoformat(f["created_at_ts"])).days
        except (KeyError, TypeError, ValueError):
            continue
        rating, text = f.get("rating") or 5, (f.get("feedback") or "").strip()
        if rating > 3:
            continue
        if hit := first_hit(warn_rules, text, True) or first_hit(scam_rules, text, True):  # "pas une arnaque" telt niet
            quote = f"{rating}★ review ({age} d geleden): “{text[:90]}”"
            if age <= 90:
                return f"waarschuwing in {quote}", reasons
            if not any("oude waarschuwing" in t for _, t in reasons):
                reasons.append((-30, f"oude waarschuwing in {quote}"))
        if rating <= 2 and age <= 30:
            recent_neg += 1
            auto += "automati" in norm(text, leet=False)  # "Recensione automatica: Vendita non completata" e.d.
    if recent_neg:
        reasons.append((-10 * min(3, recent_neg), f"{recent_neg} negatieve review{'s' if recent_neg > 1 else ''} "
                        f"afgelopen maand" + (f", waarvan {auto} automatisch (verkoop niet afgerond)" if auto else "")))
    return None, reasons


BELGIUM_RE = re.compile(r"\bbelg(ie|ique|ium|ien|ica|io|a)\b")  # na norm(): "België" -> "belgie"


def risk_label(score):
    return "🟢 laag risico" if score >= 70 else "🟡 gemiddeld risico" if score >= 40 else "🔴 hoog risico"


CONDITION_NL = {"Neuf avec étiquette": "Nieuw met label", "Neuf sans étiquette": "Nieuw zonder label",
                "Très bon état": "Zeer goede staat", "Bon état": "Goede staat", "Satisfaisant": "Redelijke staat"}


def spread(prices):
    """(laag, midden, hoog, n): 25%, mediaan en 75% van de prijzen; None bij minder dan 5."""
    if len(prices) < 5:
        return None
    q = statistics.quantiles(prices, n=4)
    return q[0], statistics.median(prices), q[2], len(prices)


def price_block(price, market, fast, ship=None, retail=None):
    """Prijsoordeel voor de melding: label, verschil met het midden, schaalbalk en hoe snel vergelijkbare weg waren.
    market = [(vraagprijs, ...)], fast = [(vraagprijs, minuten)]. Lege lijst bij te weinig data.
    ship gegeven: alles als eindprijs. price is dan de eindprijs van deze advertentie; de andere krijgen €0,70 + 5%
    bescherming en ship (gemiddelde verzending, hun echte is niet gekend). retail = winkelprijs nieuw, rechts op de balk."""
    if ship is not None:
        tot = lambda p: p * 1.05 + 0.70 + ship  # noqa: E731
        market, fast = [(tot(p),) for p, *_ in market], [(tot(p), m) for p, m in fast]
    if not (s := spread([p for p, *_ in market])):
        return []
    lo, mid, hi, n = s
    label = "🔥 <b>Scherpe prijs</b>" if price <= lo and price < mid else "🟢 <b>Onder marktprijs</b>" if price < mid else \
        "🟡 <b>Rond marktprijs</b>" if price <= hi else "🔴 <b>Duur</b>"
    diff = "= het midden" if round(price) == round(mid) else \
        f"{eur(round(abs(price - mid)))} {'onder' if price < mid else 'boven'} het midden ({eur(round(mid))})"
    # balk van de goedkoopste advertentie tot de grens van "duur" (75e percentiel; daarboven zitten vooral
    # gelimiteerde edities die de balk anders uitrekken), ● = deze prijs
    # van de goedkoopste advertentie tot de winkelprijs nieuw (of de grens van "duur"); ● = deze prijs, ┊ = midden
    a, b = min(p for p, *_ in market), (retail if retail and retail > mid else hi)
    at = lambda x: round(max(0, min(1, (x - a) / ((b - a) or 1))) * 14)  # noqa: E731
    bar = ["─"] * 15
    pm, pp = at(mid), at(price)
    if pm == pp:  # zelfde plek: streepje er net naast, anders tekent het bolletje erover
        pm = pp + 1 if pp < 14 else pp - 1
    bar[pm], bar[pp] = "┊", "●"
    out = [f"📊 {label}: {diff}", f"<code>{eur(round(a))} {''.join(bar)} {eur(round(b))}</code>"]
    if len(quick := [m for p, m in fast if abs(p - price) <= price * 0.1]) >= 2:
        out.append(f"⚡ Vergelijkbare rond {eur(round(price))} waren na ±{statistics.median(quick):.0f} min weg")
    return out


def eur(amount):
    """'311.00' -> '€311', '327.25' -> '€327,25'"""
    x = float(amount)
    return f"€{x:.0f}" if x == int(x) else f"€{x:.2f}".replace(".", ",")


def nl_age(text):
    """Vinted's Franse 'Il y a 5 heures' -> '5 uur geleden'. Onbekend formaat -> ongewijzigd."""
    if not text:
        return None
    t = norm(text, leet=False)
    if "instant" in t:
        return "zojuist"
    m = re.search(r"(\d+|une?) (minute|heure|jour|semaine|mois)", t)
    if not m:
        return text
    n = 1 if m.group(1) in ("un", "une") else int(m.group(1))
    unit = {"minute": "min", "heure": "uur", "jour": "dag" if n == 1 else "dagen",
            "semaine": "week" if n == 1 else "weken", "mois": "maand" if n == 1 else "maanden"}[m.group(2)]
    return f"{n} {unit} geleden"


# ---------------------------------------------------------------- gedeelde verkeersregeling
# Alle monitors in deze projectmap delen één IP-adres. Ze spreken via een bestand af: minstens GAP seconden tussen
# twee Vinted-verzoeken (over alle monitors samen), en krijgt één monitor fouten, dan pauzeren ze allemaal.
SHARED = ROOT.parent / "vinted_verkeer.json"
GAP = 1.5


def shared(update=None):
    """Gedeelde staat lezen (en eventueel aanpassen) onder een bestandslock."""
    import msvcrt  # ponytail: Windows-bestandslock; de monitors draaien op Windows
    with open(SHARED.with_suffix(".lock"), "a+") as lf:
        lf.seek(0)
        msvcrt.locking(lf.fileno(), msvcrt.LK_LOCK, 1)  # wacht tot een andere monitor klaar is
        try:
            try:
                st = json.loads(SHARED.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                st = {"next": 0, "pause": 0}
            if update:
                update(st)
                SHARED.write_text(json.dumps(st), encoding="utf-8")
            return st
        finally:
            lf.seek(0)
            msvcrt.locking(lf.fileno(), msvcrt.LK_UNLCK, 1)


def throttle():
    """Wacht op je beurt: min. GAP s na het vorige verzoek van gelijk welke monitor, en niet tijdens een pauze."""
    slot = {}

    def take(st):
        slot["t"] = max(time.time(), st["next"], st["pause"])
        st["next"] = slot["t"] + GAP
    shared(take)
    time.sleep(max(0.0, slot["t"] - time.time()))


def pause_all(seconds):
    """Alle monitors pauzeren (bv. na time-outs of 429/403 bij één monitor)."""
    shared(lambda st: st.update(pause=max(st["pause"], time.time() + seconds)))


def heartbeat(name):
    """Meld in het gedeelde bestand dat deze monitor draait. Geeft het aantal monitors dat de laatste 60 s actief was."""
    now, count = time.time(), {}

    def upd(st):
        act = st.setdefault("active", {})
        act[name] = now
        for k in [k for k, t in act.items() if now - t > 60]:
            del act[k]
        count["n"] = len(act)
    shared(upd)
    return count["n"]

# ---------------------------------------------------------------- Vinted


class Vinted:
    MARK = 'items\\":{\\"items\\":['
    OPEN = "self.__next_f.push([1,"

    def __init__(self, base):
        self.base = base
        self.s = None
        self.reset()

    def reset(self):
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept-Language": "nl-BE,nl;q=0.9,fr;q=0.8,en;q=0.7"})
        try:  # zet de anonieme sessiecookie die de profiel-API nodig heeft
            throttle()
            self.s.get(self.base + "/", timeout=15)
        except requests.RequestException as e:
            log.warning("sessie starten mislukt: %s", e)

    def catalog(self, url):
        """Nieuwste items uit de publieke catalogus-HTML (Next.js payload)."""
        throttle()
        r = self.s.get(url, timeout=20)
        r.raise_for_status()
        h = r.text
        i = h.find(self.MARK)
        if i < 0:
            raise ValueError("geen items in catalogus-HTML (paginastructuur gewijzigd?)")
        a = h.rfind(self.OPEN, 0, i) + len(self.OPEN)
        chunk = json.loads(h[a:h.find("])</script>", i)])
        j = chunk.find('"items":{"items":[') + len('"items":{"items":')
        return [x["productItem"] for x in json.JSONDecoder().raw_decode(chunk, j)[0]]

    def get(self, url, **kw):
        """GET die bij 429 (te veel requests) kort wacht en opnieuw probeert."""
        for wait in (2, 5, 0):
            throttle()
            r = self.s.get(url, timeout=15, **kw)
            if r.status_code != 429 or not wait:
                return r
            time.sleep(wait)

    def item_details(self, item_id):
        """Beschrijving, gereserveerd-status en 'toegevoegd'-tekst van de itempagina."""
        r = self.get(f"{self.base}/items/{item_id}")
        if r.status_code == 404:
            return {"gone": True}
        r.raise_for_status()
        h = r.text
        m = re.search(r'<script type="application/ld\+json"[^>]*>(.*?)</script>', h, re.S)
        desc = json.loads(m.group(1)).get("description", "") if m else None
        flat = h.replace('\\"', '"')
        up = re.search(r'"upload_date","data":\{"title":"[^"]*","value":"([^"]*)"', flat)
        # goedkoopste verzendoptie ("vanaf"); thuislevering berekent Vinted pas bij afrekenen
        ship = re.search(r'"shipping":\{"type":"shipping".*?"finalPrice":\{"amount":"([\d.]+)"', flat)
        # normale prijs: Vinted toont soms 100% korting ("Envoi gratuit", gezien 20/10 bij verkopers uit FR en BE)
        ship0 = re.search(r'"shipping":\{"type":"shipping","originalPrice":\{"amount":"([\d.]+)"', flat)
        price = re.search(r'"price":\{"amount":"([\d.]+)","currency_code":"EUR"\},"seller_id"', flat)
        i = flat.find('"photos":[')  # eerste fotolijst = die van deze advertentie (daarna volgen 'vergelijkbare')
        try:
            photos = [p["url"] for p in json.JSONDecoder().raw_decode(flat, i + 9)[0] if p.get("url")] if i >= 0 else []
        except ValueError:
            photos = []
        fee = re.search(r'"buyerProtection":\{"originalPrice":\{[^}]*\},"finalPrice":\{"amount":"([\d.]+)"', flat)
        return {"description": desc, "reserved": '"is_reserved":true' in flat, "sold": '"can_buy":false' in flat,
                "pickup_only": '"isPickUpOnly":true' in flat, "photos": photos[:20],
                "uploaded": json.loads(f'"{up.group(1)}"') if up else None,
                "shipping": float(ship.group(1)) if ship else None,
                "shipping_orig": float(ship0.group(1)) if ship0 else None,
                "price": float(price.group(1)) if price else None, "fee": float(fee.group(1)) if fee else None}

    def photo_hash(self, url):
        r = requests.get(url, timeout=10)
        r.raise_for_status()
        return dhash(r.content)

    def feedbacks(self, user_id):
        """De 20 recentste reviews van een verkoper (nieuwste eerst)."""
        r = self.get(f"{self.base}/api/v2/user_feedbacks?user_id={user_id}&page=1&per_page=20",
                     headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json().get("user_feedbacks") or []

    def user(self, user_id):
        r = self.get(f"{self.base}/api/v2/users/{user_id}", headers={"Accept": "application/json"})
        r.raise_for_status()
        return r.json()["user"]

# ---------------------------------------------------------------- Telegram


class Telegram:
    def __init__(self, token, chat_id, dry_run=False):
        self.url = f"https://api.telegram.org/bot{token}/"
        self.chat_id, self.dry_run = chat_id, dry_run

    def call(self, method, **params):
        for attempt in range(3):
            try:
                r = requests.post(self.url + method, json=params, timeout=20)
                d = r.json()
                if d.get("ok"):
                    return d["result"]
                if r.status_code == 429:
                    time.sleep(d.get("parameters", {}).get("retry_after", 3))
                    continue
                raise RuntimeError(d.get("description"))
            except requests.RequestException as e:
                log.warning("Telegram %s poging %d mislukt: %s", method, attempt + 1,
                            str(e).replace(self.url.split("/bot")[1].strip("/"), "<token>"))  # token niet in het log
                time.sleep(2 ** attempt)
        raise RuntimeError(f"Telegram {method} faalde na 3 pogingen")

    def send(self, text, photo=None, buttons=(), silent=False):
        """Foto + bijschrift; valt terug op tekstbericht als Telegram de foto weigert. Geeft message_id.
        buttons = [(label, url), ...]; silent = melding zonder geluid."""
        if self.dry_run:
            print("\n----- [DRY-RUN, niet verstuurd]" + (" (stil)" if silent else "") + " -----\n"
                  + html.unescape(re.sub(r"<[^>]+>", "", text)) + "\n")
            return None
        extra = {"parse_mode": "HTML", "disable_notification": silent}
        if buttons:
            extra["reply_markup"] = {"inline_keyboard": [[{"text": t, "url": u} for t, u in buttons]]}
        if photo and len(text) <= 1024:  # bijschrift max 1024 tekens
            try:
                return self.call("sendPhoto", chat_id=self.chat_id, photo=photo, caption=text, **extra)["message_id"]
            except RuntimeError as e:
                log.info("foto niet geaccepteerd (%s), stuur tekst", e)
        if buttons:
            extra["link_preview_options"] = {"url": buttons[0][1], "prefer_large_media": True}
        return self.call("sendMessage", chat_id=self.chat_id, text=text, **extra)["message_id"]

    def edit(self, msg_id, text, buttons=()):
        """Bestaande melding aanpassen (bijschrift bij foto, anders tekst)."""
        if self.dry_run:
            print(f"\n----- [DRY-RUN] melding {msg_id} aangepast -----\n" + html.unescape(re.sub(r"<[^>]+>", "", text)))
            return
        extra = {"parse_mode": "HTML"}
        if buttons:
            extra["reply_markup"] = {"inline_keyboard": [[{"text": t, "url": u} for t, u in buttons]]}
        try:
            self.call("editMessageCaption", chat_id=self.chat_id, message_id=msg_id, caption=text, **extra)
        except RuntimeError:
            self.call("editMessageText", chat_id=self.chat_id, message_id=msg_id, text=text, **extra)

# ---------------------------------------------------------------- opslag


def open_db():
    db = sqlite3.connect(ROOT / "seen.db")
    db.execute("""CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY, seen_at REAL, title TEXT,
                  price REAL, status TEXT, reason TEXT, trust INTEGER, tg_msg_id INTEGER)""")
    cols = {r[1] for r in db.execute("PRAGMA table_info(items)")}
    for col in ("user_id INTEGER", "phash TEXT", "tg_text TEXT", "checked_at REAL", "raw TEXT",  # migratie
                "description TEXT", "bio TEXT"):
        if col.split()[0] not in cols:
            db.execute(f"ALTER TABLE items ADD COLUMN {col}")
    return db


def remember(db, it, status, reason="", trust=None, msg_id=None):
    db.execute("""INSERT INTO items (id, seen_at, title, price, status, reason, trust, tg_msg_id, user_id, description, bio)
                  VALUES (?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status, price=excluded.price,
                  reason=excluded.reason, trust=excluded.trust, tg_msg_id=excluded.tg_msg_id,
                  description=COALESCE(excluded.description, description), bio=COALESCE(excluded.bio, bio)""",
               (it["id"], time.time(), it["title"], price_of(it), status, reason, trust, msg_id,
                (it.get("user") or {}).get("id"), it.get("_desc"), it.get("_bio")))
    db.commit()


def dhash(data: bytes) -> int:
    """64-bit dHash: (bijna) gelijk bij dezelfde foto, ook herschaald, gecomprimeerd of licht bewerkt."""
    from PIL import Image  # ponytail: alleen nodig voor fotovergelijking
    px = list(Image.open(io.BytesIO(data)).convert("L").resize((9, 8), Image.LANCZOS).getdata())
    return sum(1 << i for i, k in enumerate(k for k in range(72) if k % 9 != 8) if px[k] > px[k + 1])


def hamming(a, b):
    return bin(int(a, 16) ^ int(b, 16)).count("1")


def price_of(it):
    return float(it["price"]["amount"])

# ---------------------------------------------------------------- beslissingslogica


class Monitor:
    def __init__(self, cfg, tg):
        self.cfg, self.tg = cfg, tg
        f, r = cfg["filters"], cfg["rules"]
        self.f = f
        self.scam = [(w, compile_rule(w)) for w in r["scam"]]
        self.title_rules = [(w, compile_rule(w)) for w in r["title"]]
        self.platforms = [(w, compile_rule(w)) for w in r["other_platforms"]]
        self.pickup_only = [(w, compile_rule(w)) for w in r.get("pickup_only", [])]
        self.pickup = [(w, compile_rule(w)) for w in r.get("pickup", [])]
        self.review_warn = [(w, compile_rule(w)) for w in r.get("review_warnings", [])]
        self.domestic = [(w, compile_rule(w)) for w in r.get("domestic_only", [])]
        self.unavailable = [(w, compile_rule(w)) for w in r.get("unavailable", [])]
        self.pressure = [(w, compile_rule(w)) for w in r.get("pressure", [])]
        self.damaged = [(w, compile_rule(w)) for w in r.get("damaged", [])]  # beschadigd (titel of beschrijving)
        self.not_original = [(w, compile_rule(w)) for w in r.get("not_original", [])]
        # [games.<sleutel>]: name, pattern (regex op genormaliseerde tekst), max (maximumprijs)
        self.games = {k: (g["name"], re.compile(g["pattern"]), g["max"]) for k, g in cfg["games"].items()}
        self.retail = {k: g.get("retail") for k, g in cfg["games"].items()}  # winkelprijs nieuw (rechts op de prijsbalk)
        self.hint = re.compile(cfg["search"]["hints"])  # titel noemt de reeks maar niet welk deel -> beschrijving lezen
        self.urls = [self.search_url(u) for u in cfg["search"]["urls"]]
        self.vinted = Vinted("{0.scheme}://{0.netloc}".format(urlsplit(self.urls[0])))
        self.db = open_db()
        self.pool = ThreadPoolExecutor(4)  # itempagina, verkoper, reviews en fotohash tegelijk
        self.pending = []  # (item_id, future) van fotohashes die nog weggeschreven moeten worden
        self.tried = set()  # item-id's waarvoor deze sessie al een fotohash gestart is
        self.next_check = 0
        self.started, self.last_ok = time.time(), None
        self.base_f = json.loads(json.dumps(f))  # config.toml-waarden, voor /reset
        self.paused = False
        self.load_overrides()
        self.clip, self.vision_pool = None, ThreadPoolExecutor(1)  # 1 thread: fotochecks na elkaar
        self.vision_on = cfg.get("vision", {}).get("enabled", False)
        if self.vision_on:
            self.vision_pool.submit(self.load_clip)  # model laden zonder de start op te houden

    # ------------------------------------------------ bediening via Telegram

    SETTINGS = {"/min": ("min_price", "Min. prijs"), "/score": ("min_trust_score", "Min. vertrouwensscore")}
    HELP = ("🎮 <b>PS5 Controller Monitor: commando's</b>\n/status: stand van zaken\n/pauze: tijdelijk stoppen\n"
            "/hervat: weer zoeken\n/min 3: min. prijs\n/score 40: min. vertrouwensscore\n/reset: terug naar config.toml\n"
            "/prijzen: marktprijzen per game\n/gemiddelde: gemiddelde prijs (score 40+)\n"
            "Maximumprijzen per game staan in config.toml ([games]).")

    def load_overrides(self):
        try:
            o = json.loads((ROOT / "overrides.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        self.paused = o.pop("paused", False)
        for key, val in o.items():
            self.set_filter(key, val)

    def set_filter(self, key, val):
        if key in ("min_price", "min_trust_score"):
            self.f[key] = val

    def save_overrides(self):
        o = {k: self.f[k] for k in ("min_price", "min_trust_score") if self.f[k] != self.base_f[k]}
        if self.paused:
            o["paused"] = True
        (ROOT / "overrides.json").write_text(json.dumps(o, indent=1), encoding="utf-8")

    def command(self, text, db):
        """Eén Telegram-commando afhandelen. Geeft het antwoord terug."""
        parts = text.split()
        cmd = parts[0].lower().split("@")[0] if parts else ""
        if cmd == "/pauze":
            self.paused = True
            self.save_overrides()
            return "⏸ <b>Gepauzeerd.</b> Geen nieuwe meldingen tot /hervat."
        if cmd == "/hervat":
            self.paused = False
            self.save_overrides()
            return "▶️ <b>Hervat.</b> Ik zoek weer."
        if cmd == "/reset":
            self.f.update(json.loads(json.dumps(self.base_f)))
            self.save_overrides()
            db.execute("UPDATE items SET checked_at=0 WHERE status='te_duur'")
            db.commit()
            return "↩️ Instellingen terug naar config.toml.\n\n" + self.status(db)
        if cmd in self.SETTINGS:
            key, label = self.SETTINGS[cmd]
            if len(parts) < 2 or not parts[1].isdigit():
                return f"Gebruik bv.: <code>{cmd} 400</code>"
            self.set_filter(key, int(parts[1]))
            self.save_overrides()
            return f"✅ {label} is nu <b>{parts[1]}</b>.\n\n" + self.status(db)
        if cmd == "/status":
            return self.status(db)
        if cmd == "/gemiddelde":
            return self.average(db)
        if cmd == "/prijzen":
            return self.price_guide(db)
        return self.HELP

    def status(self, db):
        midnight = time.mktime(time.localtime()[:3] + (0, 0, 0, 0, 0, -1))
        n = dict(db.execute("SELECT status, COUNT(*) FROM items WHERE seen_at > ? GROUP BY status", (midnight,)))
        ago = f"{time.time() - self.last_ok:.0f} s geleden" if self.last_ok else "nog niet"
        f = self.f
        return "\n".join([
            "⏸ <b>GEPAUZEERD</b>" if self.paused else f"▶️ <b>Actief</b> sinds {time.strftime('%H:%M', time.localtime(self.started))}",
            f"🔄 Laatste geslaagde controle: {ago}" + (" ⚠️" if not self.last_ok or time.time() - self.last_ok > 120 else ""),
            f"📊 Vandaag: {n.get('notified', 0) + n.get('sold', 0)} gemeld, {n.get('excluded', 0)} scam/onbetrouwbaar, "
            f"{n.get('te_duur', 0)} te duur, {n.get('filtered', 0)} gefilterd",
            "💶 Max: " + ", ".join(f"{n.split(': ')[-1]} €{m}" for n, _, m in self.games.values())
            + f", met drift €{f['drift_max']}",
            f"🛡 Min. score {f['min_trust_score']}, stil onder {f.get('silent_below', 0)}, "
            f"min. {f.get('min_reviews', 0)} review(s)",
            f"⏱ Elke {self.interval()} s" + (" (nachtstand)" if self.is_night() else "")])

    def commands(self):
        """Achtergrondthread: luistert naar Telegram-commando's, alleen uit jouw eigen chat."""
        db = open_db()  # sqlite-verbinding per thread
        try:
            self.tg.call("setMyCommands", commands=[{"command": c.strip("/"), "description": d} for c, d in [
                ("/status", "Stand van zaken"), ("/pauze", "Tijdelijk stoppen"), ("/hervat", "Weer zoeken"),
                ("/min", "Min. prijs"), ("/score", "Min. vertrouwensscore"), ("/reset", "Terug naar config.toml"),
                ("/prijzen", "Marktprijzen per game"), ("/gemiddelde", "Gemiddelde prijs (score 40+)")]])
            old = self.tg.call("getUpdates", offset=-1, timeout=0)  # oude commando's niet opnieuw uitvoeren
            offset = old[-1]["update_id"] + 1 if old else None
        except Exception as e:
            log.warning("Telegram-commando's niet beschikbaar: %s", e)
            offset = None
        while True:
            try:
                r = requests.post(self.tg.url + "getUpdates", json={"offset": offset, "timeout": 50}, timeout=60).json()
                if not r.get("ok"):
                    raise RuntimeError(r.get("description"))
                for u in r["result"]:
                    offset = u["update_id"] + 1
                    msg = u.get("message") or {}
                    if str(msg.get("chat", {}).get("id")) != str(self.tg.chat_id):
                        continue  # vreemden negeren
                    log.info("commando: %s", msg.get("text"))
                    self.tg.send(self.command((msg.get("text") or "").strip(), db))
            except Exception as e:
                log.debug("commando-lus: %s", e)
                time.sleep(5)

    @staticmethod
    def search_url(u):
        p = urlsplit(u)
        q = [(k, v) for k, v in parse_qsl(p.query) if k not in ("order", "page", "time")] + [("order", "newest_first")]
        return f"{p.scheme}://{p.netloc}{p.path}?{urlencode(q)}"

    def quick_filter(self, it):
        """Goedkope check zonder netwerk. Geeft reden van afwijzing of None."""
        title, price = it["title"], price_of(it)
        if hit := first_hit(self.title_rules, title):
            return f"titel: '{hit[1]}'"
        if not PS5_RE.search(title) and (hit := first_hit(self.platforms, title)):
            return f"ander platform: '{hit[1]}'"
        if hit := first_hit(self.damaged, title, True):
            return f"beschadigd: '{hit[1]}'"
        game, plat, n = self.detect(title)
        if plat == "ps4":
            return "PS4/PS3-versie"
        if not game and not self.hint.search(norm(title, leet=False)):
            return "geen gezochte game"
        if hit := first_hit(self.pickup_only, title):
            return f"alleen afhalen: '{hit[1]}'"
        if price < self.f["min_price"]:
            return f"prijs €{price:.0f} < min €{self.f['min_price']}"
        if game and price > (maxp := self.max_for(game, n)):
            return f"te duur: €{price:.0f} > max €{maxp} ({self.game_name(game, n)})"
        if hit := first_hit(self.scam, title, True):
            return f"scamwoord in titel: '{hit[1]}' (regel '{hit[0]}')"
        return None

    def domestic_only(self, text, user):
        """Verzendt de verkoper enkel binnen zijn eigen land (en dat is niet België)? Geeft reden of None."""
        cc = (user or {}).get("country_code")
        if cc == "BE" or not (hit := first_hit(self.domestic, text)) or BELGIUM_RE.search(norm(text, leet=False)):
            return None
        return f"verzendt alleen binnen eigen land{f' ({cc})' if cc else ''}: '{hit[1]}'"

    def detect(self, title, desc=""):
        """(game, platform, aantal). game = sleutel uit [games], 'bulk' (lot van minstens bulk_min games, of 'lot'
        zonder aantal) of None. Titel eerst; de beschrijving pas als de titel geen game noemt."""
        t, d = norm(title, leet=False), norm(desc or "", leet=False)
        n = bulk_count(t) or (bulk_count(d) if LOT_RE.search(t) else 0)
        if self.f.get("bulk", True) and (n >= self.f["bulk_min"] or (LOT_RE.search(t) and not n)):
            return "bulk", platform(t + " " + d), n
        game = next((k for k, (_, rx, _) in self.games.items() if rx.search(t)), None) or \
            next((k for k, (_, rx, _) in self.games.items() if rx.search(d)), None)
        return game, platform(t + " " + d), 1

    def game_name(self, game, n=0):
        if game == "bulk":
            return f"Bulk: {n} games" if n else "Bulk (aantal niet vermeld)"
        return self.games[game][0] if game in self.games else "onbekende game"

    def max_for(self, game, n=0):
        """Maximumprijs: per game uit [games]; bulk = aantal x bulk_max_per_game (zonder aantal: bulk_min x),
        hoogstens bulk_max_total."""
        if game == "bulk":
            return min(self.f["bulk_max_total"], self.f["bulk_max_per_game"] * (n or self.f["bulk_min"]))
        return self.games[game][2] if game in self.games else 0

    def too_expensive(self, it, reason):
        """Te duur: bewaren met de volledige itemdata, zodat check_items een prijsdaling kan oppikken."""
        remember(self.db, it, "te_duur", reason)
        self.db.execute("UPDATE items SET raw=?, checked_at=? WHERE id=?", (json.dumps(it), time.time(), it["id"]))
        self.db.commit()

    def seller_blocked(self, uid):
        """Geblokkeerde verkoper? Handmatig (blocked_sellers in config.toml) of automatisch: de laatste 30 dagen al eens
        als scammer uitgesloten (scamwoord, scam-review, herplaatsen, te lage prijs). Geeft reden of None."""
        if uid in self.f.get("blocked_sellers", []):
            return "geblokkeerde verkoper (config.toml)"
        row = self.db.execute("""SELECT reason FROM items WHERE user_id=? AND seen_at>? AND
                                 (reason LIKE 'scamwoord%' OR reason LIKE 'waarschuwing%' OR reason LIKE 'herplaatst%'
                                  OR reason LIKE 'prijs % te laag%' OR reason LIKE 'verkopersaccount%'
                                  OR reason LIKE 'verkoper eerder%') LIMIT 1""",  # blijft gelden zolang hij blijft posten
                              (uid, time.time() - 30 * 86400)).fetchone()
        return f"verkoper eerder uitgesloten: {row[0][:60]}" if row else None

    def process(self, it, t_detect):
        if reason := self.seller_blocked((it.get("user") or {}).get("id")):
            log.info("skip  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason)
        if reason := self.quick_filter(it):
            log.info("skip  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], reason)
            if reason.startswith("te duur"):
                self.too_expensive(it, reason)
            else:
                remember(self.db, it, "filtered", reason)
            if fh := self.hash_item(it):  # ook gefilterde foto's bewaren: scammers kopiëren foto's van anderen
                self.pending.append((it["id"], fh))
            return

        uid = it["user"]["id"]
        fd = self.pool.submit(self.vinted.item_details, it["id"])
        fu = self.pool.submit(self.vinted.user, uid)
        ff = self.pool.submit(self.vinted.feedbacks, uid)
        fh = self.hash_item(it)
        if fh:
            self.pending.append((it["id"], fh))  # ook bewaren als het item straks als scam wordt uitgesloten
        try:
            det = fd.result()
        except Exception as e:
            log.warning("details %s mislukt: %s", it["id"], e)
            det = {"description": None}
        try:
            user = fu.result()
        except Exception as e:
            log.warning("verkoper %s mislukt: %s", uid, e)
            user = None
        it["_desc"], it["_bio"] = det.get("description"), (user or {}).get("about")  # bewaard voor --export

        if det.get("gone"):
            return remember(self.db, it, "gone", "advertentie al verdwenen")
        if det.get("reserved") or det.get("sold"):
            return remember(self.db, it, "filtered", "al gereserveerd of verkocht")
        desc = det.get("description")
        if desc and (hit := first_hit(self.scam, desc, True)):
            reason = f"scamwoord in beschrijving: '{hit[1]}' (regel '{hit[0]}')"
            log.info("SCAM  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason)
        if hit := first_hit(self.unavailable, it["title"] + "\n" + (desc or "")):
            reason = f"niet te koop: '{hit[1]}'"
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        txt = it["title"] + "\n" + (desc or "")
        if hit := first_hit(self.damaged, txt, True):
            reason = f"beschadigd: '{hit[1]}'"
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        if hit := first_hit(self.not_original, txt, True):
            reason = f"geen originele Sony-controller: '{hit[1]}'"
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        det["drift"] = drift_status(txt)
        if det["drift"] == "drift" and self.detect(it["title"], desc or "")[0] == "dualsense" \
                and price_of(it) > self.f["drift_max"]:
            return self.too_expensive(it, f"te duur met drift: €{price_of(it):.0f} > max €{self.f['drift_max']}")
        if user and (user.get("is_account_banned") or user.get("is_deleted")):
            return remember(self.db, it, "excluded", "verkopersaccount geblokkeerd/verwijderd")
        if user and (hit := first_hit(self.scam, user.get("about") or "", True)):
            reason = f"scamwoord in verkopersbio: '{hit[1]}' (regel '{hit[0]}')"
            log.info("SCAM  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason)
        try:
            bad, review_reasons = review_check(ff.result(), self.review_warn, self.scam)
        except Exception as e:
            log.warning("reviews %s mislukt: %s", uid, e)
            bad, review_reasons = None, [(0, "reviews niet gecontroleerd")]
        if bad:
            log.info("SCAM  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], bad)
            return remember(self.db, it, "excluded", bad)
        if (fc := (user or {}).get("feedback_count") or 0) < self.f.get("min_reviews", 0):
            reason = f"verkoper heeft {fc} reviews (min. {self.f['min_reviews']})" if user else \
                "verkopersprofiel niet opgehaald (reviews onbekend)"
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        if det.get("pickup_only") or (desc and (hit := first_hit(self.pickup_only, desc))):
            reason = "alleen afhalen" + (f": '{hit[1]}'" if not det.get("pickup_only") else " (Vinted-instelling)")
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        if reason := self.domestic_only(it["title"] + "\n" + (desc or ""), user):
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "filtered", reason)
        if hit := first_hit(self.pickup, it["title"] + "\n" + (desc or "")):
            det["pickup"] = hit[1]  # niet overslaan, wel markeren in de melding
        gen, ed, n = self.detect(it["title"], desc or "")  # gen = game, ed = platform (namen van de console-monitor)
        if ed == "ps4":
            return remember(self.db, it, "filtered", "PS4/PS3-versie (volgens beschrijving)")
        if not gen:
            return remember(self.db, it, "filtered", "geen gezochte game (ook niet in de beschrijving)")
        det["n"] = n
        if price_of(it) > (maxp := self.max_for(gen, n)):
            return self.too_expensive(it, f"te duur: €{price_of(it):.0f} > max €{maxp} ({self.game_name(gen, n)})")

        if (n := self.reposts(it, fh)) >= self.f.get("max_reposts", 99):
            reason = f"herplaatst: {n + 1}e keer dezelfde advertentie van deze verkoper (7 dagen)"
            log.info("skip  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason)

        desc_reasons = read_description(desc)
        if hit := first_hit(self.pressure, it["title"] + "\n" + (desc or "")):
            desc_reasons.append((-20, f"haast of geldnood: “{hit[1]}”"))
        prices, fast = self.market_prices(self.db)
        price = price_of(it)
        # bulk: geen prijsoordeel (elk lot is anders); games: vergelijken met dezelfde game
        if gen == "bulk":  # bulk: prijs per game, vergeleken met andere lots (zonder aantal: geen oordeel)
            b = price_block(price / n, prices.get((gen, None), []), fast.get((gen, None), [])) if n else []
            det["price_block"] = [b[0] + " (per game)"] + b[1:] if b else []
        else:
            fee, ship, *_ = self.costs(it, det, user)  # balk op eindprijs, net als 💶 bovenaan
            det["price_block"] = price_block(price + fee + (ship or 0), prices.get((gen, None), []), fast.get((gen, None), []),
                                             self.cfg.get("shipping_avg", {}).get("default", 0), self.retail.get(gen))
        susp = self.f["suspicious_price"].get(gen or "default", self.f["suspicious_price"]["default"])
        if price < susp:  # te mooi om waar te zijn: alle meldingen onder deze grens waren scams (19/10)
            reason = f"prijs {eur(price)} te laag voor {self.game_name(gen, n)} (< {eur(susp)})"
            log.info("SCAM  %s €%s %s  [%s]", it["id"], it["price"]["amount"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason)
        # ponytail: geen aftrek voor "ver onder de marktprijs": bij games zijn dat juist de deals
        score, reasons = trust_score(user, price, gen, self.f, self.photo_reasons(it, fh) + desc_reasons + review_reasons)
        if score < self.f["min_trust_score"]:
            reason = f"vertrouwensscore {score} < {self.f['min_trust_score']}: " + "; ".join(t for d, t in reasons if d < 0)
            log.info("LAAG  %s %s  [%s]", it["id"], it["title"][:50], reason)
            return remember(self.db, it, "excluded", reason, score)

        text = self.message(it, user, det, gen, ed, score, reasons, desc is None)
        buttons = [("🛒 Open advertentie op Vinted", f"{self.vinted.base}/items/{it['id']}")]
        photo = (it.get("photos") or [{}])[0].get("url") or it.get("thumbnailUrl")
        # eerst vastleggen, dan versturen: een crash/Ctrl+C na het versturen mag nooit tot een dubbele melding leiden
        remember(self.db, it, "sending", "", score)
        try:
            msg_id = self.tg.send(text, photo, buttons, silent=score < self.f.get("silent_below", 0))
        except Exception as e:
            log.error("Telegram-melding mislukt voor %s: %s", it["id"], e)
            self.db.execute("DELETE FROM items WHERE id=?", (it["id"],))  # volgende poll opnieuw proberen
            self.db.commit()
            return
        log.info("MELD  %s €%s %s  score %d  (detectie->melding %.1fs)", it["id"], it["price"]["amount"],
                 it["title"][:50], score, time.time() - t_detect)
        remember(self.db, it, "notified", "", score, msg_id)
        self.db.execute("UPDATE items SET tg_text=?, checked_at=? WHERE id=?", (text, time.time(), it["id"]))
        self.db.commit()
        if self.vision_on and det.get("photos"):  # trage fotocheck pas ná de melding
            self.vision_pool.submit(self.photo_check, it, user, det, gen, ed, reasons, desc is None, msg_id, buttons)

    def load_clip(self):
        try:
            from vision import Clip
            t = time.time()
            self.clip = Clip(self.cfg["vision"]["labels"])
            log.info("fotoherkenning (CLIP) klaar in %.1fs", time.time() - t)
        except Exception as e:
            log.warning("fotoherkenning uitgeschakeld: %s", e)

    def photo_check(self, it, user, det, gen, ed, reasons, desc_missing, msg_id, buttons):
        """Achtergrond: alle foto's door CLIP. Officiële productfoto's (stockfoto's) -> score en melding bijwerken."""
        if not self.clip:
            return
        try:
            res = self.clip.classify([requests.get(u, timeout=10).content for u in det["photos"]])
        except Exception as e:
            log.warning("fotocheck %s mislukt: %s", it["id"], e)
            return
        n, thr = len(res), self.cfg["vision"].get("stock_threshold", 0.5)
        stock = [k + 1 for k, r in enumerate(res) if r["stock"] >= thr]
        if stock and len(stock) == n:
            extra = [(-25, f"alle {n} foto's lijken officiële productfoto's" if n > 1 else
                           "de enige foto lijkt een officiële productfoto")]
            det["stock_all"] = True
        elif stock:
            extra = [(-5, f"foto {', '.join(map(str, stock))} van {n} lijkt een officiële productfoto")]
        else:
            extra = [(5, f"{n} eigen foto{'s' if n > 1 else ''}, geen stockfoto's")]
        reasons = reasons + extra
        score = max(0, min(100, 50 + sum(d for d, _ in reasons)))  # zelfde formule als trust_score
        text = self.message(it, user, det, gen, ed, score, reasons, desc_missing)
        try:
            self.tg.edit(msg_id, text, buttons)
        except Exception as e:
            log.warning("melding %s bijwerken na fotocheck mislukt: %s", it["id"], e)
            return
        db = open_db()  # eigen verbinding: deze thread is niet de hoofdthread
        db.execute("UPDATE items SET tg_text=?, trust=? WHERE id=? AND status='notified'", (text, score, it["id"]))
        db.commit()
        db.close()
        log.info("FOTO  %s %d foto's, %d stock -> score %d", it["id"], n, len(stock), score)

    def hash_item(self, it):
        """Start fotohash op de achtergrond. Geeft een future terug.
        Volledige foto (f800), niet de thumbnail: die is bijgesneden en geeft dan een andere hash."""
        url = (it.get("photos") or [{}])[0].get("url") or it.get("thumbnailUrl")
        self.tried.add(it["id"])
        return self.pool.submit(lambda: f"{self.vinted.photo_hash(url):016x}") if url else None

    def save_hashes(self):
        """Fotohashes van gefilterde/baseline-items wegschrijven zodra ze klaar zijn (vergelijkingsbasis)."""
        for iid, fut in self.pending[:]:
            if fut.done():
                self.pending.remove((iid, fut))
                try:
                    self.db.execute("UPDATE items SET phash=? WHERE id=?", (fut.result(), iid))
                except Exception as e:
                    log.debug("fotohash %s mislukt: %s", iid, e)
        self.db.commit()

    def market_prices(self, db, days=30):
        """Vraagprijzen van PS5's die de monitor de laatste 30 dagen zag (ook te dure), per (model, editie).
        Zonder scams, lage scores (het "€305-netwerk" van 15/10 scoorde 31-38), accounts zonder reviews, herplaatsingen
        en nepaccounts (beschrijving = titel).
        Geeft ({(gen, ed): [(prijs, controller?, doos?)]}, {(gen, ed): [(prijs, minuten tot verkocht)]})."""
        prices, fast, seen = defaultdict(list), defaultdict(list), set()
        rows = db.execute("""SELECT title, description, price, status, reason, user_id FROM items
                             WHERE seen_at > ? AND price BETWEEN ? AND 1500 AND status != 'excluded'
                             AND COALESCE(reason, '') NOT LIKE 'verkoper heeft%' AND COALESCE(reason, '') NOT LIKE 'herplaatst%'
                             AND (trust IS NULL OR trust >= ?) ORDER BY seen_at DESC""",
                          (time.time() - days * 86400, self.f["min_price"], self.f["min_trust_score"]))
        for t, d, p, status, reason, uid in rows:
            key = re.sub(r"\W", "", norm(t, leet=False))
            if (uid, key) in seen or first_hit(self.title_rules, t) \
                    or (d and re.sub(r"\W", "", norm(d, leet=False)) == key):
                continue
            seen.add((uid, key))
            game, plat, n = self.detect(t, d or "")
            if plat == "ps4" or not (game in self.games or (game == "bulk" and n)):
                continue
            k = (game, None)
            p = p / n if game == "bulk" else p  # bulk: prijs per game
            prices[k].append((p,))
            if status == "sold" and (m := re.search(r"±(\d+) min", reason or "")):  # gemeld en daarna verkocht
                fast[k].append((p, int(m.group(1))))
        return prices, fast

    def average(self, db):
        """/gemiddelde: gemiddelde prijs van advertenties met score >= 40 (laatste 30 dagen), per game."""
        groups = defaultdict(list)
        for t, d, p in db.execute("SELECT title, description, price FROM items WHERE trust >= 40 AND seen_at > ?",
                                  (time.time() - 30 * 86400,)):
            game, _, n = self.detect(t, d or "")
            if game:
                groups[self.game_name(game) if game != "bulk" else "Bulk"].append(p)
        if not groups:
            return "Nog geen advertenties met score 40 of meer."
        lines = ["💶 <b>Gemiddelde prijs, score 40+</b> (laatste 30 dagen)", ""]
        for name, v in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            lines.append(f"🎮 {html.escape(name)}: <b>{eur(round(statistics.mean(v), 2))}</b> ({len(v)})")
        return "\n".join(lines + ["", "<i>Score 40+ zijn vooral gemelde advertenties, dus tot je maximumprijs. "
                                      "/prijzen toont de hele markt.</i>"])

    def price_guide(self, db):
        """/prijzen: marktprijzen per game en wat snel verkocht werd."""
        prices, fast = self.market_prices(db)
        lines = ["📊 <b>Marktprijzen</b>", "<i>vraagprijzen van de laatste 30 dagen, zonder scams</i>", "",
                 "🔥 scherp, meteen kopen   🟢 redelijk   🔴 duur", ""]
        for k, (name, _, mx) in self.games.items():
            if not (s := spread([p for p, *_ in prices.get((k, None), [])])):
                lines += [f"🎮 <b>{html.escape(name)}</b>: nog te weinig data (jouw max {eur(mx)})", ""]
                continue
            lo, mid, hi, cnt = s
            lines += [f"🎮 <b>{html.escape(name)}</b>  <i>({cnt} adv., jouw max {eur(mx)})</i>",
                      f"🔥 tot {eur(round(lo, 2))}  ·  🟢 tot {eur(round(mid, 2))}  ·  🔴 boven {eur(round(hi, 2))}"]
            if len(f := fast.get((k, None), [])) >= 2:
                lines.append(f"⚡ snel weg: ±{eur(round(statistics.median(p for p, _ in f), 2))}, "
                             f"na ±{statistics.median(m for _, m in f):.0f} min ({len(f)}x)")
            lines.append("")
        f = self.f
        if f.get("bulk", True) and (s := spread([p for p, *_ in prices.get(("bulk", None), [])])):
            lines += [f"📦 <b>Bulk, per game</b>  <i>({s[3]} lots)</i>",
                      f"🔥 tot {eur(round(s[0], 2))}  ·  🟢 tot {eur(round(s[1], 2))}  ·  🔴 boven {eur(round(s[2], 2))}", ""]
        return "\n".join(lines + [
            f"🕹️ Met drift: max {eur(f['drift_max'])}",
            "💡 🔥 = goedkoopste kwart van de markt. 🟢 = onder het midden. 🔴 = duurste kwart."])

    def reposts(self, it, fh):
        """Hoe vaak plaatste deze verkoper de laatste 7 dagen al dezelfde advertentie: zelfde titel, zelfde foto of
        hetzelfde model (20/10: één verkoper "verkocht" dezelfde Slim 4x in 3 dagen, telkens met een iets andere titel)."""
        try:
            h = fh.result(timeout=5) if fh else None
        except Exception:
            h = None
        key = re.sub(r"\W", "", norm(it["title"], leet=False))
        gen = self.detect(it["title"])[0]
        rows = self.db.execute("SELECT title, phash FROM items WHERE user_id=? AND id!=? AND seen_at>?",
                               (it["user"]["id"], it["id"], time.time() - 7 * 86400))
        return sum(1 for t, oh in rows if re.sub(r"\W", "", norm(t, leet=False)) == key
                   or (h and oh and hamming(h, oh) <= 5) or (gen and self.detect(t)[0] == gen))

    def photo_reasons(self, it, fh):
        """Zelfde foto eerder gezien? Bij een andere verkoper = gestolen of stockfoto."""
        try:
            h = fh.result(timeout=5) if fh else None
        except Exception as e:
            log.debug("fotohash %s mislukt: %s", it["id"], e)
            return [(0, "fotocontrole niet gelukt")]
        if not h:
            return []
        uid = it["user"]["id"]
        for oid, ouid, oh, seen in self.db.execute(
                "SELECT id, user_id, phash, seen_at FROM items WHERE phash IS NOT NULL AND id != ?", (it["id"],)):
            if hamming(h, oh) <= 5:
                when = time.strftime("%d/%m", time.localtime(seen))
                if ouid == uid:
                    return [(0, f"foto al eens gebruikt door deze verkoper ({when}, herplaatst)")]
                # games: veel eerlijke verkopers gebruiken dezelfde hoesfoto van internet -> lichtere straf (config)
                return [(-self.f.get("duplicate_photo_penalty", 25),
                         f"zelfde foto als advertentie van een andere verkoper ({when}): gestolen of stockfoto")]
        return [(0, "foto nog niet eerder gezien")]

    def costs(self, it, det, user):
        """(bescherming, verzending, geschat?, gratis-actie?, land): wat er bovenop de vraagprijs komt."""
        price = price_of(it)
        fee = float((it.get("totalItemPrice") or {}).get("amount") or price) - price
        if fee <= 0:
            fee = round(0.70 + 0.05 * price, 2)  # Vinted-kopersbescherming: €0,70 + 5% (klopte op alle meldingen)
        ship, cc = det.get("shipping"), (user or {}).get("country_code")
        # "gratis" (actie) -> met de normale prijs rekenen: of de actie voor jou geldt, staat pas bij het afrekenen
        if free := (ship == 0 and det.get("shipping_orig")):
            ship = det["shipping_orig"]
        avg = self.cfg.get("shipping_avg", {})
        est = not ship and bool(ship := avg.get(cc, avg.get("default")))  # geen prijs op de pagina: gemiddelde per land
        return fee, ship, est, free, cc

    def message(self, it, user, det, gen, ed, score, reasons, desc_missing):
        """Volgorde: totaalprijs + berekening, scorebalk, product, staat (+ prijsdaling), verkoper, uitleg."""
        e = html.escape
        price = float(it["price"]["amount"])
        fee, ship, est, free, cc = self.costs(it, det, user)
        filled = round(score / 10)
        bar = ("🟩" if score >= 70 else "🟨" if score >= 40 else "🟥") * filled + "⬜" * (10 - filled)
        lines = [f"💶 <b>{eur(price + fee + (ship or 0))}</b>" + ("" if ship else " + verzending"),
                 *det.get("price_block", []),
                 f"{bar} <b>{score}</b>/100", "",
                 f"🎮 <b>{e(self.game_name(gen, det.get('n', 1)))}</b>",
                 *([{"drift": "🕹️ ⚠️ <b>Drift vermeld</b>", "geen": "🕹️ ✅ Geen drift (vermeld)"}.get(
                     det.get("drift"), "🕹️ ❔ Drift niet vermeld")] if gen == "dualsense" else [])]
        if gen == "bulk":
            lines.append(f"<i>{e(it['title'])}</i>")
            if det.get("n"):
                lines.append(f"📦 {eur(round(price / det['n'], 2))} per game")
        cond = it.get("itemBox", {}).get("secondLine")
        age = nl_age(det.get("uploaded"))
        lines.append(f"✨ {e(CONDITION_NL.get(cond, cond or 'staat onbekend'))}" + (f"   🕒 {e(age)}" if age else ""))
        if det.get("pickup"):
            lines.append(f"📍 <b>Afhalen vermeld</b> (“{e(det['pickup'])}”), lees de beschrijving na")
        if it.get("_was"):
            lines.append(f"📉 <b>Prijs verlaagd</b> van {eur(it['_was'])} naar {eur(price)}")
        if det.get("stock_all"):
            lines.append("⚠️ <b>Alleen officiële productfoto's</b>, geen eigen foto: vraag een echte foto")
        lines += ["", f"🧾 {eur(price)} + {eur(fee)} bescherming + "
                      + (f"±{eur(ship)} verzending (gemiddeld vanuit {cc or '?'})" if est else
                         f"{eur(ship)} verzending (Vinted toont nu gratis: actie)" if free else
                         f"{eur(ship)} verzending" if ship else "verzending (onbekend)"), "", ""]
        if user:
            cc = user.get("country_code") or ""
            flag = "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper()) if len(cc) == 2 else ""
            fc = user.get("feedback_count") or 0
            stars = (user.get("feedback_reputation") or 0) * 5
            n = max(1, user.get("item_count") or 0)  # deze advertentie telt mee; Vinted's teller loopt soms achter
            lines += [f"👤 <b>{e(user.get('login', '?'))}</b> {flag}",
                      f"{'⭐' * max(1, round(stars))} {stars:.1f} ({fc})".replace(".", ",") if fc else "☆ nog geen reviews",
                      f"📦 {n} advertentie{'s' if n != 1 else ''}"]
        else:
            lines.append("👤 verkoper onbekend (profiel niet opgehaald)")
        why = [f"{'🟢 +' if d > 0 else '🔴 −'} {e(t)}" for d, t in reasons if d] + [f"⚪ {e(t)}" for d, t in reasons if not d]
        lines.append(f"<blockquote expandable><b>Waarom {score}/100?</b>\n" + "\n".join(why) + "</blockquote>")
        if desc_missing:
            lines.append("⚠️ Beschrijving niet gecontroleerd: check zelf op betaalwoorden")
        return "\n".join(lines)

    def is_night(self, hour=None):
        night = self.cfg["search"].get("night_hours") or []
        hour = time.localtime().tm_hour if hour is None else hour
        return len(night) == 2 and (night[0] <= hour < night[1] if night[0] < night[1]  # bv. [1, 7]
                                    else hour >= night[0] or hour < night[1])       # bv. [23, 6] over middernacht

    def interval(self):
        s = self.cfg["search"]
        if self.is_night():
            return s.get("night_interval_seconds", s["interval_seconds"])
        # één monitor: interval_seconds; meerdere op deze computer (zelfde IP): shared_interval_seconds
        return s["interval_seconds"] if heartbeat(str(ROOT)) <= 1 else s.get("shared_interval_seconds", 15)

    def alert(self, text):
        try:
            self.tg.send(text)
        except Exception as e:
            log.error("Telegram-waarschuwing mislukt: %s", e)

    def check_items(self):
        """Max. 1 extra itempagina per 30 s: eerst gemelde advertenties (verkocht?), anders te dure (prijsdaling?)."""
        if time.time() < self.next_check:
            return
        self.next_check = time.time() + 30
        self.check_sold() or self.check_price()

    def check_price(self):
        """Te dure advertentie (< 3 dagen, max. 1,3x je maximum, elke ±30 min) opnieuw bekijken.
        Nu binnen budget -> alsnog verwerken. Werkt ook als je je maximum verhoogt (/max).
        Aantal verzoeken ligt vast via check_items (1 per 30 s); zijn er veel, dan eerst de goedkoopste."""
        cap = max([self.f["bulk_max_total"], *(m for _, _, m in self.games.values())]) * 1.3
        row = self.db.execute("""SELECT id, raw FROM items WHERE status='te_duur' AND raw IS NOT NULL AND seen_at > ?
                                 AND checked_at < ? AND price <= ? ORDER BY price LIMIT 1""",
                              (time.time() - 3 * 86400, time.time() - 1800, cap)).fetchone()
        if not row:
            return False
        iid, raw = row
        self.db.execute("UPDATE items SET checked_at=? WHERE id=?", (time.time(), iid))
        self.db.commit()
        try:
            det = self.vinted.item_details(iid)
        except Exception as e:
            log.debug("prijscheck %s mislukt: %s", iid, e)
            return True
        if det.get("gone") or det.get("sold"):
            self.db.execute("UPDATE items SET status='gone' WHERE id=?", (iid,))
            self.db.commit()
            return True
        it, new = json.loads(raw), det.get("price")
        old = price_of(it)
        game, _, n = self.detect(it["title"])
        if new is None or (new == old and old > self.max_for(game, n)):
            return True  # niets veranderd
        it["price"]["amount"] = f"{new:.2f}"
        if det.get("fee") is not None:
            it["totalItemPrice"] = {"amount": f"{new + det['fee']:.2f}"}
        if new < old:
            it["_was"] = old
            log.info("PRIJS %s %s: €%.0f -> €%.0f", iid, it["title"][:40], old, new)
        self.process(it, time.time())
        return True

    def check_sold(self):
        """Eerder gemelde advertentie (< 12 u oud, elke ±3 min) nakijken: verkocht, of nieuwe scam-review?
        -> melding aanpassen."""
        row = self.db.execute("""SELECT id, tg_msg_id, tg_text, seen_at, user_id FROM items WHERE status='notified'
                                 AND tg_msg_id IS NOT NULL AND tg_text IS NOT NULL AND seen_at > ? AND checked_at < ?
                                 ORDER BY checked_at LIMIT 1""", (time.time() - 12 * 3600, time.time() - 180)).fetchone()
        if not row:
            return False
        iid, msg_id, text, seen, uid = row
        self.db.execute("UPDATE items SET checked_at=? WHERE id=?", (time.time(), iid))
        self.db.commit()
        button = [("🛒 Open advertentie op Vinted", f"{self.vinted.base}/items/{iid}")]
        try:
            det = self.vinted.item_details(iid)
            bad = review_check(self.vinted.feedbacks(uid), self.review_warn, self.scam)[0] if uid else None
        except Exception as e:
            log.debug("verkocht-check %s mislukt: %s", iid, e)
            return True
        if bad and not (det.get("gone") or det.get("sold")):
            try:
                self.tg.edit(msg_id, f"⚠️ <b>NIET KOPEN: scam-waarschuwing</b> in een nieuwe {html.escape(bad[16:])}\n"
                             + text, button)
            except Exception as e:
                log.warning("melding %s bijwerken mislukt: %s", iid, e)
            self.db.execute("UPDATE items SET status='excluded', reason=? WHERE id=?", (bad, iid))
            self.db.commit()
            log.info("SCAM  %s achteraf: %s", iid, bad)
            return True
        if not (det.get("gone") or det.get("sold")):
            return True
        mins = (time.time() - seen) / 60
        took = f"{mins:.0f} min" if mins < 90 else f"{mins / 60:.1f} uur".replace(".", ",")
        try:
            self.tg.edit(msg_id, f"❌ <b>VERKOCHT of verwijderd</b> (na ±{took})\n" + text, button)
        except Exception as e:
            log.warning("melding %s bijwerken mislukt: %s", iid, e)
        self.db.execute("UPDATE items SET status='sold', reason=? WHERE id=?", (f"weg na ±{took}", iid))
        self.db.commit()
        log.info("WEG   %s na ±%s, melding bijgewerkt", iid, took)
        return True

    def run(self, once=False, notify_existing=False):
        fails, i = 0, 0
        baseline = not notify_existing and self.db.execute("SELECT COUNT(*) FROM items").fetchone()[0] == 0
        log.info("monitor gestart: %d zoek-URL('s), elke %ss", len(self.urls), self.cfg["search"]["interval_seconds"])
        if not self.tg.dry_run and not once:
            threading.Thread(target=self.commands, daemon=True).start()
        while True:
            if self.paused:
                time.sleep(2)
                continue
            url = self.urls[i % len(self.urls)]
            i += 1
            t0 = time.time()
            try:
                items = list({x["id"]: x for x in self.vinted.catalog(url)}.values())  # zelfde item 2x (gepromoot)
                t_detect = self.last_ok = time.time()
                if fails >= 3:
                    self.alert("✅ <b>PS5 Controller Monitor werkt weer</b>: Vinted is opnieuw bereikbaar.")
                fails = 0
            except Exception as e:
                fails += 1
                status = getattr(getattr(e, "response", None), "status_code", None)
                log.warning("catalogus ophalen mislukt (%s keer): %s", fails, e)
                if fails == 3:  # ±5 min zonder resultaat
                    self.alert(f"⚠️ <b>PS5 Controller Monitor ligt plat</b>: Vinted ophalen mislukt sinds enkele minuten.\n"
                               f"<code>{html.escape(str(e))[:200]}</code>\nIk blijf het automatisch proberen.")
                if status in (401, 403, 429) or fails % 3 == 0:
                    self.vinted.reset()
                if once:
                    raise
                pause_all(min(self.interval() * 2 ** fails, 600))  # ook de andere monitors wachten
                time.sleep(min(self.interval() * 2 ** fails, 600))
                continue
            if not items:
                log.warning("catalogus gaf 0 items terug")
            known = {r[0] for r in self.db.execute(
                f"SELECT id FROM items WHERE id IN ({','.join('?' * len(items)) or 'NULL'})", [x["id"] for x in items])}
            new = [x for x in items if x["id"] not in known]
            if baseline:
                for x in items:
                    remember(self.db, x, "baseline")
                log.info("eerste run: %d bestaande advertenties als gezien gemarkeerd (geen meldingen)", len(items))
                baseline = False
            else:
                for x in reversed(new):  # oudste eerst
                    try:
                        self.process(x, t_detect)
                    except Exception:
                        log.exception("fout bij item %s", x.get("id"))
            # foto's van al geziene items zonder hash (baseline, oudere seen.db) alsnog hashen
            ids = [x["id"] for x in items if x["id"] not in self.tried]
            missing = {r[0] for r in self.db.execute(
                f"SELECT id FROM items WHERE phash IS NULL AND id IN ({','.join('?' * len(ids)) or 'NULL'})", ids)}
            for x in items:
                if x["id"] in missing and (fh := self.hash_item(x)):
                    self.pending.append((x["id"], fh))
            self.save_hashes()
            self.check_items()
            log.debug("poll %.1fs, %d items, %d nieuw", time.time() - t0, len(items), len(new))
            if once:
                return
            time.sleep(max(0, self.interval() - (time.time() - t0)))

# ---------------------------------------------------------------- CLI


def load_env():
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.strip().startswith("#"):
                os.environ.setdefault(k.strip(), v.strip().strip('"'))


def export(cfg):
    """Alle bewaarde beschrijvingen + bio's met de uitkomst (gemeld, verkocht, scam, ...) naar beschrijvingen.md,
    om met Claude Code door te lezen en de filters aan te scherpen."""
    base = "{0.scheme}://{0.netloc}".format(urlsplit(cfg["search"]["urls"][0]))
    rows = open_db().execute("""SELECT id, datetime(seen_at,'unixepoch','localtime'), status, price, trust, title, reason,
                                description, bio FROM items WHERE description IS NOT NULL OR bio IS NOT NULL
                                ORDER BY seen_at DESC""").fetchall()

    def quote(t):
        return "\n".join("> " + line for line in t.strip().splitlines()) if t and t.strip() else "> (leeg)"

    out = [f"# Beschrijvingen en verkopersbio's ({len(rows)} advertenties, nieuwste eerst)", ""]
    for iid, when, status, price, trust, title, reason, desc, bio in rows:
        out += [f"## {title}", f"`{status}` · €{price:.0f}" + (f" · score {trust}" if trust is not None else "")
                + f" · {when} · {base}/items/{iid}"]
        out += [f"Reden: {reason}"] if reason else []
        out += ["", "**Beschrijving**", quote(desc), "", "**Bio verkoper**", quote(bio), ""]
    (ROOT / "beschrijvingen.md").write_text("\n".join(out), encoding="utf-8")
    print(f"{len(rows)} advertenties geschreven naar {ROOT / 'beschrijvingen.md'}")


def setup_logging():
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", "%H:%M:%S")
    sys.stdout.reconfigure(encoding="utf-8")
    h1 = logging.StreamHandler(sys.stdout)
    h2 = logging.handlers.RotatingFileHandler(ROOT / "monitor.log", maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    for h in (h1, h2):
        h.setFormatter(fmt)
        log.addHandler(h)
    log.setLevel(logging.INFO)


def main():
    ap = argparse.ArgumentParser(description="Vinted PS5 Controller Monitor")
    ap.add_argument("--dry-run", action="store_true", help="niets naar Telegram sturen, meldingen printen")
    ap.add_argument("--once", action="store_true", help="één poll en stoppen")
    ap.add_argument("--notify-existing", action="store_true", help="ook huidige advertenties beoordelen bij eerste start")
    ap.add_argument("--setup-telegram", action="store_true", help="toon je chat-id (stuur eerst een bericht naar je bot)")
    ap.add_argument("--test-telegram", action="store_true", help="stuur een testmelding")
    ap.add_argument("--log", nargs="?", const=20, type=int, metavar="N", help="toon laatste N beslissingen met reden")
    ap.add_argument("--export", action="store_true", help="beschrijvingen en verkopersbio's naar beschrijvingen.md")
    a = ap.parse_args()
    setup_logging()
    load_env()
    cfg = tomllib.loads((ROOT / "config.toml").read_text(encoding="utf-8"))

    if a.log:
        for row in open_db().execute("SELECT datetime(seen_at,'unixepoch','localtime'),status,price,title,reason,trust "
                                     "FROM items WHERE status!='baseline' ORDER BY seen_at DESC LIMIT ?", (a.log,)):
            print(" | ".join("" if c is None else str(c) for c in row))
        return
    if a.export:
        export(cfg)
        return

    token, chat = os.environ.get("TELEGRAM_BOT_TOKEN", ""), os.environ.get("TELEGRAM_CHAT_ID", "")
    if a.setup_telegram:
        if not token:
            sys.exit("Zet eerst TELEGRAM_BOT_TOKEN in .env (zie README).")
        ups = requests.get(f"https://api.telegram.org/bot{token}/getUpdates", timeout=20).json()
        chats = {u["message"]["chat"]["id"]: u["message"]["chat"].get("first_name") or u["message"]["chat"].get("title")
                 for u in ups.get("result", []) if "message" in u}
        if not chats:
            sys.exit("Geen berichten gevonden. Stuur je bot eerst een bericht (bv. /start) in Telegram en probeer opnieuw.")
        for cid, name in chats.items():
            print(f"chat '{name}': TELEGRAM_CHAT_ID={cid}")
        return
    if not a.dry_run and not (token and chat):
        sys.exit("TELEGRAM_BOT_TOKEN en TELEGRAM_CHAT_ID ontbreken in .env. Zie README, of gebruik --dry-run.")

    tg = Telegram(token, chat, a.dry_run)
    if a.test_telegram:
        tg.send("🧪 <b>TESTMELDING</b> — Vinted PS5 Controller Monitor werkt. (Dit is geen echte advertentie.)", None,
                [("Open Vinted", "https://www.vinted.be/catalog?catalog[]=3025&video_game_platform_ids[]=1281")])
        print("Testmelding verstuurd.")
        return
    lock = socket.socket()  # ponytail: poort als vergrendeling, Windows geeft hem vrij als het proces stopt
    try:  # poort per map: monitors in andere mappen (andere producten) mogen wel tegelijk draaien
        lock.bind(("127.0.0.1", 47000 + zlib.crc32(str(ROOT).lower().encode()) % 1000))
    except OSError:
        sys.exit("Er draait al een monitor (bv. in een ander venster). Stop die eerst; twee tegelijk geeft dubbele meldingen.")
    try:
        Monitor(cfg, tg).run(once=a.once, notify_existing=a.notify_existing)
    except KeyboardInterrupt:
        log.info("gestopt")


if __name__ == "__main__":
    main()
