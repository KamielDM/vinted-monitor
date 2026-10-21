"""Zelftest van de gamesfilters (geen netwerk). Run: python test_monitor.py"""
import sqlite3
import time
import tomllib
from pathlib import Path

from monitor import Monitor, bulk_count, compile_rule, first_hit, platform

cfg = tomllib.loads((Path(__file__).parent / "config.toml").read_text(encoding="utf-8"))
m = Monitor.__new__(Monitor)
m.f, m.cfg = cfg["filters"], cfg
r = cfg["rules"]
m.scam, m.title_rules, m.platforms, m.pickup_only = ([(w, compile_rule(w)) for w in r[k]]
                                                     for k in ("scam", "title", "other_platforms", "pickup_only"))
m.games = {k: (g["name"], __import__("re").compile(g["pattern"]), g["max"]) for k, g in cfg["games"].items()}
m.hint = __import__("re").compile(cfg["search"]["hints"])


def item(title, price):
    return {"id": 1, "title": title, "price": {"amount": str(price)}}


# welke game?
for t, want in [("Call of Duty Black Ops 7 PS5", "bo7"), ("COD BO6 ps5", "bo6"), ("Black Ops VI - PS5", "bo6"),
                ("Modern Warfare III PS5", "mw3"), ("cod mw3", "mw3"), ("ARK Survival Ascended PS5", "ark"),
                ("GTA V PS5", None), ("FIFA 23 PS5", None),
                ("Ark survival evolved", None)]:
    assert m.detect(t)[0] == want, (t, m.detect(t))
assert m.detect("Call of Duty PS5", "Il s'agit de Black Ops 6, disque en parfait état")[0] == "bo6"  # uit beschrijving

# platform: alleen PS4/PS3 vermeld = weg; niets of allebei = jij beslist
assert platform("black ops 6 ps5") == "ps5" and platform("gta 5 ps4") == "ps4" and platform("gta 5 ps3") == "ps4"
assert platform("black ops 6") is None and platform("spider-man ps4/ps5") is None and platform("ps45") is None

# bulk
assert bulk_count("lot de 5 jeux ps5") == 5 and bulk_count("10 giochi ps5") == 10 and bulk_count("lotto di 4") == 4
assert bulk_count("black ops 6 + 2 jeux") == 2 and bulk_count("ps5 1 tb") == 0
assert bulk_count("playstation 5 game") == 0 and bulk_count("ps5 games x3") == 0 and bulk_count("lot 6 jeux ps5") == 6
assert m.detect("Lot de 5 jeux PS5")[0] == "bulk" and m.detect("Lot jeux PS5")[:3:2] == ("bulk", 0)
assert m.detect("Black Ops 6 + 2 jeux")[0] == "bo6"                       # 2 games is geen bulk
assert m.max_for("bulk", 5) == 30 and m.max_for("bulk", 20) == 60 and m.max_for("bulk", 0) == 18
assert m.max_for("bo6") == 12 and m.max_for(None) == 0

# snelle filter
assert m.quick_filter(item("Call of Duty Black Ops 6 PS5", 10)) is None
assert m.quick_filter(item("Call of Duty Black Ops 6 PS5", 15))            # boven max €12
assert m.quick_filter(item("GTA 5 PS4", 8))                                # PS4
assert m.quick_filter(item("FIFA 23 PS5", 5))                              # niet gezocht
assert m.quick_filter(item("Call of Duty PS5", 10)) is None                # reeks zonder deel: beschrijving lezen
assert m.quick_filter(item("Lot de 6 jeux PS5", 30)) is None and m.quick_filter(item("Lot de 6 jeux PS5", 40))
for t in ["Black Ops 6 code DLC", "Black Ops 6 steelbook seul", "Black Ops 6 boitier vide", "Black Ops 7 digital",
          "Bundle Cobalt Star Bundle ps5", "Cherche Black Ops 7", "Black Ops 6 vendu", "Black Ops 6 PS5 1€"]:
    assert m.quick_filter(item(t, 10 if "1€" not in t else 1)), t
assert m.detect("Black Ops Cold War Cross-Gen Bundle PS5")[0] is None  # Cold War: niet gezocht (valt na de beschrijving weg)
assert m.quick_filter(item("Black Ops 6 Cross-Gen Bundle PS5", 10)) is None  # schijf: mag
for t in ["Lot 3 steelbook cod", "Steelbooks Call of Duty", "3x steelbook black ops"]:   # lege verzameldozen (20/10)
    assert m.quick_filter(item(t, 15)), t
assert m.quick_filter(item("Black Ops 6 Steelbook Edition PS5", 12)) is None   # game in steelbook-editie: mag

# scamfilter en eerlijke verkopers (zelfde regels als de console-monitor)
assert first_hit(m.scam, "Paiement PayPal ou virement") and first_hit(m.scam, "Contact WhatsApp +39 351 234 5678")
assert not first_hit(m.scam, "Geen PayPal, alleen via Vinted", True)

# geblokkeerde verkopers
m.db = sqlite3.connect(":memory:")
m.db.execute("CREATE TABLE items (id, user_id, status, reason, seen_at)")
m.db.execute("INSERT INTO items VALUES (1, 11, 'excluded', 'scamwoord in beschrijving: ''paypal''', ?)", (time.time(),))
assert m.seller_blocked(11) and m.seller_blocked(267624708) and not m.seller_blocked(99)
# 21/10: getal in een gamenaam is geen bulk, tijdschrift is geen game, PS2/PSP = oud platform
assert bulk_count("fc27 jeux") == 0 and bulk_count("fifa 22 jeu ps5") == 0 and bulk_count("lot de 4 jeux") == 4
assert m.quick_filter(item("Magazine Vintage Gamestop GTA 5 2013", 10))
assert platform("lot jeux playstation japonais 5 jeux ps2 1 jeu psp") == "ps4"
# 21/10: Gran Turismo 7 en stuur + pedalen (PS4-stuur mag, Xbox-stuur, losse pedalen en zonder pedalen niet)
assert m.detect("GT7 PS5")[0] == "gt7" and m.quick_filter(item("Gran Turismo 7 PS5", 18)) is None
for t, p in [("Volant Logitech G29 PS4 PS5 + pédalier", 100), ("Volant Thrustmaster T150 PS4", 70), ("Lenkrad PS5 Logitech", 80)]:
    assert m.detect(t)[0] == "stuur" and m.quick_filter(item(t, p)) is None, (t, m.quick_filter(item(t, p)))
for t, p in [("Pédalier seul G29", 30), ("Volant Logitech G920 Xbox", 90), ("Volante G923 PS5", 150), ("Wheel stand Playseat", 40)]:
    assert m.quick_filter(item(t, p)), t
un = [(w, compile_rule(w)) for w in cfg["rules"]["unavailable"]]
assert first_hit(un, "Volant G29 vendu sans pédalier", True) and first_hit(un, "Lenkrad ohne Pedale", True)
for t in ["Mini volante mando ps5", "Volant manette pour PS5", "Corona Volante T300 Thrustmaster",
          "Volante Mod F1 per thrustmaster t300", "Volante de formula 1 para Logitech G29/G923", "Volante PS3 Logitech Driving Force"]:
    assert m.quick_filter(item(t, 20)) or m.detect(t)[1] == "ps4", t
assert m.quick_filter(item("Volante Thrustmaster T80 PS 4/5 PC", 49)) is None
print("alle tests geslaagd")
