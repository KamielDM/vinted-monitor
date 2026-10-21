"""Zelftest van de controllerfilters (geen netwerk). Run: python test_monitor.py"""
import re
import sqlite3
import time
import tomllib
from pathlib import Path

from monitor import Monitor, compile_rule, drift_status, first_hit

cfg = tomllib.loads((Path(__file__).parent / "config.toml").read_text(encoding="utf-8"))
m = Monitor.__new__(Monitor)
m.f, m.cfg = cfg["filters"], cfg
r = cfg["rules"]
m.scam, m.title_rules, m.platforms, m.pickup_only, m.damaged = ([(w, compile_rule(w)) for w in r[k]] for k in
                                                                ("scam", "title", "other_platforms", "pickup_only", "damaged"))
m.games = {k: (g["name"], re.compile(g["pattern"]), g["max"]) for k, g in cfg["games"].items()}
m.hint = re.compile(cfg["search"]["hints"])


def item(title, price):
    return {"id": 1, "title": title, "price": {"amount": str(price)}}


# doorlaten
for t in ["Manette PS5", "DualSense PS5 Nero TMR", "Mando ps5 blanco", "Controller PS5 white", "Joystick PS5",
          "Manette PS5 + support de charge", "Dualsense Midnight Black"]:
    assert m.quick_filter(item(t, 20)) is None, (t, m.quick_filter(item(t, 20)))
assert m.quick_filter(item("Manette PS5", 25)) is None and m.quick_filter(item("Manette PS5", 26))  # max €25

# geen controller, PS4, beschadigd
for t in ["Support manette PS5", "Coque manette ps5", "Chargeur manette PS5", "Station de charge DualSense",
          "Thumb grips PS5", "Manette PS4", "Dualshock 4", "PS VR2 Sense controller", "Manette PS5 HS",
          "Manette PS5 cassée", "Mando PS5 roto", "Controller PS5 defekt", "Xbox controller", "Cherche manette ps5",
          "Manette filaire ps4 officiel PlayStation compatible", "Cache manette Ps5", 
          "Boîte de rangement manette scuf", "Charm Focus Remap Kit voor PS5 Controller",
          "PS5 Controller BDM-060M Platine mit KSilver", "PS5 Controller-Halterung", "GTA 6 PS5-controllerbehuizing"]:
    assert m.quick_filter(item(t, 20)), t

# schade met ontkenning telt niet; drift is geen schade
for t in ["Aucun bouton cassé, fonctionne parfaitement", "Rien de cassé", "non rotto, perfetto", "Petit drift à gauche"]:
    assert not first_hit(m.damaged, t, True), (t, first_hit(m.damaged, t, True))
assert first_hit(m.damaged, "Le bouton R2 est bloqué", True) and first_hit(m.damaged, "Ne charge plus", True)
# schade uit gemelde advertenties (20/10)
for t in ["juste une touche un peu casser", "il y a seulement un choc", "a perdu l'elastique interne, il se balade",
          "Gâchettes et touches modifiées", "Piccolo difetto sul tasto L1, a volte si incastra", "Funktioniert, jedoch fehlt oben der R1 Knopf",
          "parzialmente funzionante, ogni tanto si blocca", "Analogico destro difettoso da sostituire", "faut légèrement forcer", "ha dei buchi"]:
    assert first_hit(m.damaged, t, True), t
for t in ["Nessun difetto, perfetto", "Originalverpackung fehlt", "sans choc ni rayure", "manette PS5 fonctionne parfaitement"]:
    assert not first_hit(m.damaged, t, True), (t, first_hit(m.damaged, t, True))
# andere merken / Xbox / merkloos "compatible"; een Scuf of "DualSense compatible PC" mag wel
for t in ["Mando Inalámbrico Subsonic para PS5 y PC", "Manette Nacon Revolution 5 Pro", "Manette Xbox Series", "Manette sans fil compatible PS5"]:
    assert m.quick_filter(item(t, 30)), t
for t in ["Manette PS5 Dualsense compatible PC", "Scuf Reflex PS5", "Manette PS5 Sony officielle"]:
    assert m.quick_filter(item(t, 20)) is None, (t, m.quick_filter(item(t, 20)))

# drift
assert drift_status("Manette PS5 avec léger drift") == "drift" and drift_status("stick drift gauche") == "drift"
assert drift_status("Manette PS5 sans drift") == "geen" and drift_status("No drift, perfect") == "geen"
assert drift_status("Kein Drift") == "geen" and drift_status("drift free") == "geen" and drift_status("Zero drift") == "geen"
assert drift_status("Comme neuve") is None
assert m.f["drift_max"] == 20

# bulk staat uit: "lot" is geen bulk
assert m.detect("Lot manette PS5")[0] == "dualsense"
# losse TMR/Hall-sticks: eigen categorie; een controller met TMR-sticks blijft een controller
for t in ["4x Joystick TMR K-Silver", "Joystick TMR PS5 x2", "Hall Effect joysticks PS5", "GuliKit TMR NS51", "Ginfull hall sticks"]:
    assert m.detect(t)[0] == "tmr" and m.quick_filter(item(t, 15)) is None, (t, m.detect(t), m.quick_filter(item(t, 15)))
assert m.detect("DualSense PS5 Nero TMR")[0] == "dualsense" and m.detect("Manette ps5 TMR Anti drift")[0] == "dualsense"
assert m.quick_filter(item("Joystick TMR PS5 x2", 30))                          # boven max €25
assert drift_status("TMR anti drift") == "geen"

# scamfilter en eerlijke verkopers
assert first_hit(m.scam, "Paiement PayPal ou virement") and not first_hit(m.scam, "Geen PayPal, alleen via Vinted", True)

# geblokkeerde verkopers
m.db = sqlite3.connect(":memory:")
m.db.execute("CREATE TABLE items (id, user_id, status, reason, seen_at)")
m.db.execute("INSERT INTO items VALUES (1, 11, 'excluded', 'scamwoord in beschrijving: ''paypal''', ?)", (time.time(),))
assert m.seller_blocked(11) and not m.seller_blocked(99)
# 21/10: niet-origineel (ook in de beschrijving), meer schade, drift-spellingen
no = [(w, compile_rule(w)) for w in cfg["rules"]["not_original"]]
for t in ["Manette ps5 non officiel", "Manette ps5\nManette compatible ps5", "Mando replica PS5"]:
    assert first_hit(no, t, True), t
assert not first_hit(no, "Manette PS5 DualSense compatible PC\nofficielle Sony", True)
for t in ["il touchpad è un po difettato", "non del tutto funzionante", "problemi al microfono", "da cambiare i cuscinetti",
          "Le revêtement en caoutchouc s'est usé à force de jouer", "voll funktionsfähig mit kleinem Mangel", "manca la plastica rotonda"]:
    assert first_hit(m.damaged, t, True), t
assert drift_status("das einzigste was der Controller hat ist Strickstift") == "drift" and drift_status("drifta un po") == "drift"
assert m.quick_filter(item("Dragon shock wireless gaming controller", 21))
print("alle tests geslaagd")
