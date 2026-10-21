# PS5 Games Monitor

Zoekt PS5-games (categorie Games) en stuur + pedalen (categorie Controllers) op vinted.be. Installatie en Telegram-instellingen: zie de [hoofd-README](../README.md).

## Snel starten

1. `.env.example` kopiëren naar `.env`, token en chat-id van een **eigen** bot invullen.
2. `python monitor.py --test-telegram`
3. Dubbelklik `start.bat`

## Filters (`config.toml`)

- Gezochte games staan als blokken `[games.…]` in `config.toml`: naam, regex op de titel, `max` (maximumprijs) en `retail` (nieuwprijs, rechts op de prijsbalk). Een game toevoegen = een blok kopiëren.
- **Bulk**: minstens 3 PS5-games in één advertentie, max €6 per game (`bulk_min`, `bulk_max_per_game`, `bulk_max_total`).
- Codes, digitale versies, lege hoesjes/steelbooks, PS4/PS3-versies en mini-stuurtjes/rims worden overgeslagen. PS4-sturen mogen (die werken op PS5).
- Scamfilter: betalen of contact buiten Vinted (PayPal, overschrijving, WhatsApp, telefoonnummers, "geen betaling via het systeem", …) in titel, beschrijving en bio. Met een ontkenning ervoor telt het niet ("geen PayPal, alleen via Vinted").
- Verkopers zonder reviews, met een recente scam-review of die dezelfde advertentie steeds herplaatsen, worden overgeslagen. Wie als scammer werd uitgesloten, wordt 30 dagen geblokkeerd (`blocked_sellers` voor een vaste lijst).
- Vertrouwensscore onder `min_trust_score` = geen melding.

Na een wijziging: het venster sluiten en `start.bat` opnieuw starten. Zelftest: `python test_monitor.py`.
