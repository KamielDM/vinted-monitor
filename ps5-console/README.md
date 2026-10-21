# PS5 Console Monitor

Zoekt PS5-consoles in de categorie Consoles (platform PS5) op vinted.be. Installatie en Telegram-instellingen: zie de [hoofd-README](../README.md).

## Snel starten

1. `.env.example` kopiëren naar `.env`, token en chat-id van een **eigen** bot invullen.
2. `python monitor.py --test-telegram`
3. Dubbelklik `start.bat`

## Filters (`config.toml`)

- Alleen **Slim met schijflezer** of **Pro** (`models`, `editions`, `any_edition`). Staat het model er niet bij, dan komt de advertentie door en beslis jij.
- Max **€500**, Pro **€650** (`max_price`, `max_price_per_model`). Onder €200 / €400 = te mooi om waar te zijn: overgeslagen.
- 825 GB, fat, Digital en PS4/VR/Portal worden overgeslagen.
- Scamfilter: betalen of contact buiten Vinted (PayPal, overschrijving, WhatsApp, telefoonnummers, "geen betaling via het systeem", …) in titel, beschrijving en bio. Met een ontkenning ervoor telt het niet ("geen PayPal, alleen via Vinted").
- Verkopers zonder reviews, met een recente scam-review of die dezelfde advertentie steeds herplaatsen, worden overgeslagen. Wie als scammer werd uitgesloten, wordt 30 dagen geblokkeerd (`blocked_sellers` voor een vaste lijst).
- Vertrouwensscore onder `min_trust_score` = geen melding.

Na een wijziging: het venster sluiten en `start.bat` opnieuw starten. Zelftest: `python test_monitor.py`.
