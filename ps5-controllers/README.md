# PS5 Controller Monitor

Zoekt PS5-controllers (DualSense) en losse TMR/Hall-sticks in de categorie Controllers op vinted.be. Installatie en Telegram-instellingen: zie de [hoofd-README](../README.md).

## Snel starten

1. `.env.example` kopiëren naar `.env`, token en chat-id van een **eigen** bot invullen.
2. `python monitor.py --test-telegram`
3. Dubbelklik `start.bat`

## Filters (`config.toml`)

- Controller max **€25** (`[games.dualsense] max`), met drift max **€20** (`drift_max`), losse sticks max **€25**.
- Elke melding zegt of er drift vermeld is (⚠️), geen drift (✅) of niets (❔).
- Beschadigd (lijst `damaged`), niet-origineel (`not_original`), andere merken, PS4-controllers en accessoires worden overgeslagen.
- Scamfilter: betalen of contact buiten Vinted (PayPal, overschrijving, WhatsApp, telefoonnummers, "geen betaling via het systeem", …) in titel, beschrijving en bio. Met een ontkenning ervoor telt het niet ("geen PayPal, alleen via Vinted").
- Verkopers zonder reviews, met een recente scam-review of die dezelfde advertentie steeds herplaatsen, worden overgeslagen. Wie als scammer werd uitgesloten, wordt 30 dagen geblokkeerd (`blocked_sellers` voor een vaste lijst).
- Vertrouwensscore onder `min_trust_score` = geen melding.

Na een wijziging: het venster sluiten en `start.bat` opnieuw starten. Zelftest: `python test_monitor.py`.
