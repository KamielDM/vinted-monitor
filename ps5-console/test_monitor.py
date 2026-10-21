"""Zelftest van de filters (geen netwerk). Run: python test_monitor.py"""
import tomllib
from pathlib import Path

from monitor import Monitor, detect_model, first_hit, compile_rule, trust_score, eur, nl_age

cfg = tomllib.loads((Path(__file__).parent / "config.toml").read_text(encoding="utf-8"))
scam = [(w, compile_rule(w)) for w in cfg["rules"]["scam"]]
m = Monitor.__new__(Monitor)
m.f = cfg["filters"]
m.scam, m.title_rules, m.platforms = scam, [(w, compile_rule(w)) for w in cfg["rules"]["title"]], \
    [(w, compile_rule(w)) for w in cfg["rules"]["other_platforms"]]
m.pickup_only = [(w, compile_rule(w)) for w in cfg["rules"]["pickup_only"]]
pickup = [(w, compile_rule(w)) for w in cfg["rules"]["pickup"]]


def item(title, price):
    return {"id": 1, "title": title, "price": {"amount": str(price)}}


# scamwoorden: varianten moeten vallen
for t in ["Pagamento solo PayPal con beni e Servizi", "betaling via PAY-PAL", "p4ypal ok", "IBAN: BE12...",
          "virement bancaire", "Bankoverschrijving graag", "contact me on WhatsApp", "Überweisung möglich",
          "mail me naam@example.com", "bel 0470 00 00 00", "+32 470 00 00 00", "betalen buiten Vinted",
          "en perfecto estado pago solo por trasferencia envio por vinted",  # typfout, advertentie <advertentie>
          "betaling uitsluitend via bankoverschrijving", "pago por transferencias"]:
    assert first_hit(scam, t), t
# lekken gevonden in de opgeslagen beschrijvingen (18/10)
for t in ["Accetto solo PayPaI", "scrivetemi su wz 351 234 5678 non perdite di tempo", "Contattare 3512345678 qui",
          "Très bon état ✅ 👻 voorbeeld.123", "prima di acquistare contattatemi su istangram voorbeeldnaam",
          "no vinted, e solo per vetrina per pagamenti DM", "vorher Zahlung Bank Echtzeit",
          "Al comprar esto recibirá la imagen de la portada impresa en papel", "SPEDISCO PRIVATAMENTE CON SPEDIZIONE ASSICURATA"]:
    assert first_hit(scam, t), t
for t in ["Acquistata il 03.10.2025, 825 GB, firmware 12.40", "Prezzo 1 300 €", "PS5 CFI-2016 1TB", "IBAN nee, enkel Vinted"[5:]]:
    assert not first_hit(scam, t), (t, first_hit(scam, t))
# weigert betaling via Vinted (19/10, advertentie <advertentie>)
for t in ["❗Ich akzeptiere keine Zahlungen über das System❗", "ik accepteer geen betaling via dit systeem",
          "PAS DE PAIEMENT VIA VINTED", "no acepto el pago por vinted", "No pagamenti tramite wallet Vinted",
          "I don't accept payment through the app", "Leggi bio per info"]:
    assert first_hit(scam, t), t
for t in ["Paiement uniquement via Vinted", "Pagamento solo tramite Vinted", "No problem, pay through Vinted only",
          "Pas de souci. Paiement via Vinted", "Envoi rapide, paiement sécurisé par Vinted"]:
    assert not first_hit(scam, t), (t, first_hit(scam, t))
# varianten uit de opgeslagen advertenties (20/10)
for t in ["WICHTIG KEIN VERKAUF ÜBER DAS SYSTEM", "Kein Verkauf über Vinted", "Bitte kein Kauf über das System",
          "(kein systemverkauf)", "NON effettuiamo vendite tramite wallet Vinted", "mon porte-monnaie Vinted est bloqué",
          "Merci de ne pas effectuer de paiement directement via le site", "scrivere al 351--23--45--678 per info",
          "Bitte kontaktieren Sie mich vor der Zahlung", "⚠️ me contacter avant achat svp ⚠️", "NE PAS ACHETEZ PASSER PRIVE",
          "Non leggiamo i messaggi qui", "I'll put the play at one euro so that the shipment", "klickt diesen link https://tidd.ly/4zC"]:
    assert first_hit(scam, t), t
for t in ["Pas d'arnaque, achat protégé par Vinted", "Kein Umtausch. Kauf über Vinted mit Käuferschutz",
          "Rechnung vom 11.05.26 - 14.06.26", "12.05.2025 - 14.06.2025"]:
    assert not first_hit(scam, t), (t, first_hit(scam, t))
for t in ["Ps5 portale", "Procuro ps5", "Concours PS5 PlayStation tirage au sort"]:
    assert m.quick_filter(item(t, 350)), t
pressure = [(w, compile_rule(w)) for w in cfg["rules"]["pressure"]]
assert first_hit(pressure, "nuova mai aperta urgente, a causa di un incidente") and not first_hit(pressure, "Envoi rapide")
unavailable = [(w, compile_rule(w)) for w in cfg["rules"]["unavailable"]]
assert first_hit(unavailable, "⚠️ NE PAS ACHETER ⚠️") and first_hit(unavailable, "Reserve a lucianno")
assert not first_hit(unavailable, "Vendu en lot avec 2 jeux, verkauft wird alles")
for t in ["Compro PS5", "cerco PS5 qualsiasi funzionante", "Ps5 usata (bio)", "Ps5 banni temporairement", "Ps5 vendu"]:
    assert m.quick_filter(item(t, 350)), t
assert m.quick_filter(item("PS5 slim vendu avec 2 manettes", 350)) is None
# typfouttolerantie alleen voor lange woorden: "vivement" mag niet als "virement" tellen
for t in ["Je recommande vivement", "transferir los datos al disco"]:
    assert not first_hit(scam, t), (t, first_hit(scam, t))
# ... maar normale tekst niet
for t in ["PS5 slim 1TB met 2 controllers, werkt perfect", "Console en très bon état, lui bandé",
          "Ibanez gitaar", "825GB, CFI-1216A, pas de rayures", "Prix ferme 350 euros", "Envoi rapide"]:
    assert not first_hit(scam, t), (t, first_hit(scam, t))

# snelle titel/prijsfilter
assert m.quick_filter(item("Ps5 slim", 370)) is None
assert m.quick_filter(item("Playstation 5 con 2 Joypad", 380)) is None
assert m.quick_filter(item("PS5 + jeux PS4", 350)) is None                 # PS4 mag als PS5 vermeld is
assert m.quick_filter(item("PS5 in originele doos", 400)) is None
assert m.quick_filter(item("Sony PlayStation 5 Pro Solo PayPal", 299))       # scam in titel
assert m.quick_filter(item("PlayStation Portal", 200))
assert m.quick_filter(item("PlayStation VR2", 300)) and m.quick_filter(item("PS5 remote player", 160))  # VR-regel stond per ongeluk in commentaar (19-20/10)
assert m.quick_filter(item("Pack Sony PS4 + 2 Manettes", 300))
assert m.quick_filter(item("Consola Nintendo 3ds XL", 165))
assert m.quick_filter(item("Basetta per ps5 slim", 23))
assert m.quick_filter(item("PS5 boîte vide", 160))
assert m.quick_filter(item("PS5 HS ne s'allume plus", 160))
assert m.quick_filter(item("Ps5 pro", 750))                                 # boven max pro (650)
assert m.quick_filter(item("Ps5 pro", 600)) is None
assert m.quick_filter(item("PS5 Slim Digital Edition", 350))                # alleen Disc gewenst
assert m.quick_filter(item("PS5 Pro Digital 2TB", 600)) is None          # Pro: elke editie (any_edition)
assert m.quick_filter(item("PS5 Digital", 350))                             # model onbekend + digital
assert m.quick_filter(item("PS5 Slim disc edition", 380)) is None
assert m.quick_filter(item("PS5 Slim met lezer", 380)) is None

# fat/origineel overslaan; "original" = echt, niet het model (echte titels)
assert m.quick_filter(item("PS5 fat digital 850go avec manette", 300))
assert m.quick_filter(item("Sony PlayStation 5 Disc Edition + 2 Controller – CFI-1116A", 399))
assert m.quick_filter(item("Ps5 classique", 230))
assert detect_model("PlayStation 5 Konsole 4 Original Sony DualSense", "")[0] is None
assert detect_model("PlayStation 5", "scatola originale, come nuova")[0] is None
assert detect_model("PlayStation 5", "C'est la version fat, CFI-1216A") == ("original", None)
assert detect_model("PS5 CFI-2016") == ("slim", None) and detect_model("PS5 CFI-7016")[0] == "pro"

# afhalen: "alleen afhalen" overslaan, "afhalen" markeren
assert m.quick_filter(item("PS5 slim alleen afhalen Gent", 350))
for t in ["Uniquement en main propre sur Lyon", "Solo ritiro a mano, Milano", "Nur Abholung in Berlin", "Geen verzending"]:
    assert first_hit(m.pickup_only, t), t
for t in ["Afhalen in Gent of verzenden", "Envoi ou remise en main propre", "Possibile ritiro a Roma"]:
    assert not first_hit(m.pickup_only, t) and first_hit(pickup, t), t
assert not first_hit(pickup, "PS5 slim met 2 controllers, verzending via Vinted")

# modeldetectie
assert detect_model("Ps5 Slim Disco 1TB + Dualsense") == ("slim", "disc")
assert detect_model("PS5 Slim Digital Edition") == ("slim", "digital")
# fat-signalen (18/10): "Standard/Normal" in de titel en 825 GB; Slim in de titel gaat voor
assert detect_model("Ps5 standard + controller", "PlayStation 5 Standard con lettore disco, venduta per passaggio al "
                    "modello Slim.") == (None, "disc")   # <advertentie>: onbekend (jij kijkt), niet Slim
assert detect_model("Ps5 normal")[0] is None and detect_model("PlayStation 5 - 825gb")[0] == "original"  # standard/normal = onbekend
assert detect_model("PlayStation 5 Standard – 1 To – Neuve, jamais ouverte")[0] == "slim"   # winkelnaam van de Slim
assert detect_model("Playstation 5 Standard", "- stockage : 1 To")[0] == "slim"
assert detect_model("PS5 Standard 825GB con lettore disco", "1TB")[0] == "original"           # 825 GB gaat voor
assert detect_model("Playstation 5", "Console 825 GB, perfetta")[0] == "original"
assert detect_model("PS5 Slim édition standard")[0] == detect_model("PS5 Slim Digital 825 GB")[0] == "slim"
assert detect_model("Playstation 5", "Ich verkaufe eine PlayStation 5, Modell Slim, mit Disc-Laufwerk")[0] == "slim"
assert detect_model("PS5 slim avec CD") == ("slim", "disc")
assert detect_model("Ps5 classique") == ("original", None)
assert detect_model("Playstation 5", "versie zonder disc, geen Pro") == (None, "digital")
assert detect_model("PS5 sans lecteur") == (None, "digital")

# vertrouwensscore
import datetime as dt
from monitor import account_age_days, ID_ANCHORS
newest_id = int(ID_ANCHORS[-1][0] + (dt.date.today() - dt.date.fromisoformat(ID_ANCHORS[-1][1])).days * 275_000)
assert account_age_days(77116367) is None                        # oud account (2021)
assert account_age_days(newest_id) == 0
assert 40 <= account_age_days(3180118664) <= 60 or dt.date.today() > dt.date(2026, 11, 1)

ms, slo = m.f["min_trust_score"], m.f["silent_below"]
good = {"id": 40071393, "feedback_count": 40, "feedback_reputation": 0.98, "negative_feedback_count": 0,
        "item_count": 12, "verification": {"email": {"valid": True}, "google": {"valid": True}}}
fresh = {"id": newest_id, "feedback_count": 0, "feedback_reputation": 0, "item_count": 1,
         "verification": {"email": {"valid": True}}}
assert trust_score(good, 380, "slim", m.f)[0] >= 70
assert trust_score(fresh, 380, "slim", m.f)[0] < min(ms, slo)   # gloednieuw account: geen (of hooguit stille) melding
assert trust_score(fresh, 299, "pro", m.f)[0] < ms               # nieuw + Pro te goedkoop -> geblokkeerd
assert trust_score(None, 380, None, m.f)[0] == 50                # onbekend = neutraal
bad = {"id": 60326801, "feedback_count": 3, "feedback_reputation": 0.2, "negative_feedback_count": 3, "item_count": 1,
       "verification": {"email": {"valid": True}, "google": {"valid": True}}}
assert trust_score(bad, 250, "slim", m.f)[0] < ms                # 1★ met 3 negatieve reviews (echt geval)

# Game Boy met platform-tag "PS5" (echt geval) en andere consoles
assert m.quick_filter(item("Game boy advance nuovo fondo mag.", 450))
assert m.quick_filter(item("Nintendo Wii + 4 manettes", 160))

# fotohash: zelfde foto herschaald/gecomprimeerd = match, andere foto = geen match
import io
from PIL import Image, ImageDraw
from monitor import dhash, hamming, product_name, extras
def img(seed, size=(310, 430), fmt="WEBP"):
    im = Image.new("RGB", (310, 430), "white")
    d = ImageDraw.Draw(im)
    for k in range(12):
        d.ellipse([(seed * 37 + k * 53) % 280, (seed * 91 + k * 29) % 400, (seed * 37 + k * 53) % 280 + 40,
                   (seed * 91 + k * 29) % 400 + 60], fill=((k * 40) % 255, (seed * 70) % 255, 120))
    b = io.BytesIO(); im.resize(size).save(b, fmt, quality=60); return b.getvalue()
h1, h2, h3 = (f"{dhash(x):016x}" for x in (img(1), img(1, (150, 210), "JPEG"), img(2)))
assert hamming(h1, h2) <= 5, hamming(h1, h2)
assert hamming(h1, h3) > 10, hamming(h1, h3)

assert m.quick_filter(item("PlayStation portable édition limitée 30th anniversary", 300))   # = Portal (echt geval)
assert m.quick_filter(item("Ps5 portable", 200))                          # = Portal (<advertentie>)
assert m.quick_filter(item("PS5 portatile come nuova", 190))

# beschrijving
from monitor import read_description
r = read_description("Vendue avec facture, petite rayure sur le côté, aucun bruit")
assert r == [(5, "factuur of garantie vermeld"), (0, "beschrijving vermeldt: bruit, rayure (lees na)")]
assert read_description("Console parfaite") == []

# alleen binnenlands verzenden: overslaan, behalve vanuit/naar België
m.domestic = [(w, compile_rule(w)) for w in cfg["rules"]["domestic_only"]]
for t, cc in [("Envoi en France uniquement, pas d'envoi à l'étranger", "FR"), ("Spedisco solo in Italia", "IT"),
              ("Versand nur innerhalb Deutschlands!", "DE"), ("Solo envíos a España", "ES"),
              ("Alleen binnen Nederland verzenden", "NL"), ("No international shipping", "IE"), ("Só Portugal", "PT")]:
    assert m.domestic_only(t, {"country_code": cc}), t
assert m.domestic_only("Alleen binnen België", {"country_code": "BE"}) is None          # Belgische verkoper
assert m.domestic_only("Envoi uniquement en France et Belgique", {"country_code": "FR"}) is None
assert m.domestic_only("Envoi rapide partout en Europe", {"country_code": "FR"}) is None
assert m.domestic_only("Garanzia Italia, spedizione veloce", {"country_code": "IT"}) is None

# reviews van de verkoper (echte teksten van een verkoper, 14/10/2026)
from monitor import review_check
warn = [(w, compile_rule(w)) for w in cfg["rules"]["review_warnings"]]
NOW = dt.datetime(2026, 10, 14, 17, 15, tzinfo=dt.timezone.utc)
def fb(rating, text, when): return {"rating": rating, "feedback": text, "created_at_ts": when}
leo = [fb(1, "Scammer bitte nicht kaufen. Er will Zahlung per Banküberweisung!!!!", "2026-10-14T17:11:35+02:00"),
       fb(1, "Recensione automatica: Vendita non completata", "2026-10-13T21:53:10+02:00"),
       fb(5, "Au top merci 🙏", "2026-09-29T13:12:00+02:00")]
bad_reason, _ = review_check(leo, warn, scam, NOW)
assert bad_reason and "Scammer" in bad_reason
assert first_hit(scam, "Er will Zahlung per Banküberweisung")             # één woord, toch gevangen
_, r = review_check(leo[1:], warn, scam, NOW)
assert r == [(-10, "1 negatieve review afgelopen maand, waarvan 1 automatisch (verkoop niet afgerond)")]
assert review_check([fb(5, "Top, pas une arnaque du tout !", "2026-10-10T10:00:00+02:00")], warn, scam, NOW) == (None, [])
_, r = review_check([fb(1, "Arnaque, il voulait un virement", "2025-01-10T10:00:00+02:00")], warn, scam, NOW)
assert r[0][0] == -30                                                    # oude waarschuwing: straf, geen blokkade

# telefooncommando's (in-memory database, overrides.json in tijdelijke map)
import sqlite3, tempfile, json as _json, monitor as M
M.ROOT = Path(tempfile.mkdtemp())
c = Monitor.__new__(Monitor)
c.f, c.cfg = _json.loads(_json.dumps(cfg["filters"])), cfg
c.base_f, c.paused, c.started, c.last_ok = _json.loads(_json.dumps(cfg["filters"])), False, 0, None
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE items (id, seen_at, status, checked_at)")
assert "Max. prijs is nu <b>400</b>" in c.command("/max 400", db) and c.f["max_price"] == 400
assert "Gebruik" in c.command("/max veel", db)
c.command("/maxpro 700", db)
c.command("/pauze", db)
assert c.paused and _json.loads((M.ROOT / "overrides.json").read_text()) == {"max_price": 400, "pro": 700, "paused": True}
c2 = Monitor.__new__(Monitor)
c2.f, c2.base_f = _json.loads(_json.dumps(cfg["filters"])), cfg["filters"]
c2.load_overrides()  # overleeft een herstart
assert c2.paused and c2.f["max_price"] == 400 and c2.f["max_price_per_model"]["pro"] == 700
assert [c.is_night(h) for h in (0, 1, 6, 7, 23)] == [False, True, True, False, False]   # [1, 7]
c.cfg = {"search": {"night_hours": [23, 6]}}
assert [c.is_night(h) for h in (22, 23, 0, 5, 6)] == [False, True, True, True, False]  # over middernacht
c.cfg = cfg
c.command("/reset", db)
assert c.f["max_price"] == cfg["filters"]["max_price"] and c.paused  # reset = filters, pauze blijft
assert "commando" in c.command("/start", db)

# herplaatsingen: zelfde verkoper, zelfde titel (andere schrijfwijze) of zelfde foto
import time as _time
c.db = sqlite3.connect(":memory:")
c.db.execute("CREATE TABLE items (id, user_id, title, phash, seen_at)")
c.db.executemany("INSERT INTO items VALUES (?,?,?,?,?)", [
    (1, 7, "Ps5 slim", "c3173afae8e9f8fc", _time.time() - 3600), (2, 7, "PS5 SLIM", None, _time.time()),
    (3, 7, "Andere titel", "c2173afae8e9f8fc", _time.time()),    # foto 1 bit anders
    (4, 7, "Ps5 slim", None, _time.time() - 8 * 86400),          # ouder dan 7 dagen
    (5, 8, "Ps5 slim", None, _time.time())])                     # andere verkoper
class _F:
    def result(self, timeout=None): return "c2173afae8e9f8fc"
assert c.reposts({"id": 9, "title": "Ps5  slim!", "user": {"id": 7}}, _F()) == 3
assert c.reposts({"id": 9, "title": "PS5 Pro", "user": {"id": 7}}, None) == 0
assert c.reposts({"id": 9, "title": "Slim met lezer, nieuwe titel", "user": {"id": 7}}, None) == 2  # zelfde model, 2 Slims

# opmaak
assert product_name("slim", "disc") == "PS5 Slim Disc"
assert product_name(None, "digital") == "PS5 Digital"
assert product_name("original", None) == "PS5 (origineel model)"
assert product_name(None, None) == "PS5 (model onbekend)"
assert extras("PS5 avec 3 manettes") == ["3 controllers"]
assert extras("Ps5 Slim 825GB + Joystick") == ["+ controller"]
assert extras("PS5 1 To Fortnite – 2 manettes + 5 jeux") == ["2 controllers", "5 games"]
assert extras("Ps5 slim") == []
assert eur("311.00") == "€311" and eur("327.25") == "€327,25"
assert nl_age("Il y a 5 heures") == "5 uur geleden" and nl_age("Il y a une minute") == "1 min geleden"
assert nl_age("À l'instant") == "zojuist" and nl_age("Il y a 2 jours") == "2 dagen geleden"
# prijsoordeel en "pro" dat geen Pro is
from monitor import price_block, spread
assert detect_model("Ps5 et manette pro")[0] is None and detect_model("Play Station 5 1Terra No Pro")[0] is None
assert detect_model("Ps5 slim + pro controller")[0] == "slim" and detect_model("PS5 Pro 2TB")[0] == "pro"
mk = [(p,) for p in (300, 350, 400, 450, 500, 550, 600)]
assert spread([300, 400]) is None and spread([p for p, in mk])[1] == 450
assert price_block(400, mk[:3], []) == []                                   # te weinig data: niets tonen
b = price_block(320, mk, [(330, 4), (310, 6), (450, 30)])
assert "Scherpe prijs" in b[0] and b[1].startswith("<code>€") and "±5 min" in b[2]
assert "Duur" in price_block(590, mk, [])[0] and len(price_block(590, mk, [(300, 3), (310, 4)])) == 2
# geblokkeerde verkopers: handmatig en automatisch (eerder als scammer uitgesloten)
c.db = sqlite3.connect(":memory:")
c.db.execute("CREATE TABLE items (id, user_id, status, reason, seen_at)")
c.db.executemany("INSERT INTO items VALUES (?,?,?,?,?)", [
    (1, 11, "excluded", "scamwoord in beschrijving: 'paypal'", _time.time()),
    (2, 12, "excluded", "vertrouwensscore 30 < 40: nog geen reviews", _time.time()),   # lage score = geen blokkade
    (3, 13, "excluded", "herplaatst: 3e keer dezelfde advertentie", _time.time() - 40 * 86400)])  # te lang geleden
assert c.seller_blocked(11)
assert not c.seller_blocked(12) and not c.seller_blocked(13) and not c.seller_blocked(99)
# eerlijke verkopers: scamwoord met ontkenning ervoor telt niet (wel in dezelfde zin, niet na een komma)
for t in ["Geen PayPal, alleen via Vinted", "pas de virement, paiement uniquement via Vinted", "Kein PayPal!",
          "no acepto bizum ni transferencias", "Je ne vends jamais hors Vinted", "niet via whatsapp aub"]:
    assert not first_hit(scam, t, True), (t, first_hit(scam, t, True))
    assert first_hit(scam, t)                                              # zonder negatable wel (oude gedrag)
for t in ["Paiement PayPal ou virement", "No PayPal, solo bonifico", "Je n'accepte que PayPal", "not on Vinted, PayPal",
          "pas de souci pour paypal", "Contact WhatsApp, no PayPal"]:
    assert first_hit(scam, t, True), t
print("alle tests geslaagd")
