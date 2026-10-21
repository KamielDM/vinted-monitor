# Vinted Monitor

Houdt Vinted in de gaten en stuurt een Telegrammelding zodra er een goede deal verschijnt. Scams worden eruit gefilterd. Kopen doe je zelf, in de Vinted-app.

Drie monitors, elk in een eigen map en met een eigen Telegrambot:

| Map | Zoekt | Standaardfilter |
|---|---|---|
| [`ps5-console`](ps5-console) | PS5-consoles | Slim met schijflezer of Pro, max €500 (Pro €650) |
| [`ps5-games`](ps5-games) | PS5-games, bulklots, stuur + pedalen | Black Ops 6/7, MW III, ARK, Gran Turismo 7, elk met een eigen max |
| [`ps5-controllers`](ps5-controllers) | DualSense-controllers en losse TMR/Hall-sticks | max €25, met drift max €20 |

Alles is aan te passen in `config.toml` van elke monitor.

## Wat elke melding toont

- **Eindprijs**: vraagprijs + kopersbescherming (€0,70 + 5%) + verzending naar België
- **Prijsoordeel** met een balk van goedkoop naar duur (● = deze advertentie, ┊ = midden van de markt)
- **Vertrouwensscore** van de verkoper (reviews, rating, accountleeftijd, gestolen foto's, …) met uitleg
- Een knop om de advertentie in Vinted te openen

Wordt een gemelde advertentie verkocht of krijgt de verkoper een scam-review, dan past de melding zich aan.

## Installeren (eenmalig)

1. Installeer [Python 3.11 of nieuwer](https://www.python.org/downloads/). Vink **"Add Python to PATH"** aan.
2. Download deze repository (groene knop **Code → Download ZIP**) en pak hem uit. Of: `git clone`.
3. Open een terminal in de uitgepakte map en installeer de libraries:
   ```
   pip install -r requirements.txt
   ```

## Een monitor instellen (per monitor, ±5 minuten)

1. **Telegrambot maken**: open Telegram, zoek **@BotFather**, stuur `/newbot` en volg de stappen. Je krijgt een token. Elke monitor heeft een **eigen** bot nodig.
2. Ga naar de map van de monitor (bv. `ps5-games`), kopieer `.env.example` naar **`.env`** en zet je token achter `TELEGRAM_BOT_TOKEN=`.
3. Stuur je nieuwe bot een bericht in Telegram (bv. `/start`).
4. Haal je chat-id op en zet het getal achter `TELEGRAM_CHAT_ID=` in `.env`:
   ```
   python monitor.py --setup-telegram
   ```
5. Test: `python monitor.py --test-telegram`. Je krijgt een testbericht.
6. **Starten**: dubbelklik `start.bat`. Laat het venster open; sluiten = stoppen.

Bij de eerste start worden de huidige advertenties als "gezien" gemarkeerd, zodat je niet tientallen meldingen tegelijk krijgt.

## Updaten

Download de nieuwste versie (of `git pull`) en zet je eigen `.env`, `seen.db` en eventuele aanpassingen in `config.toml` terug. Die bestanden worden nooit overschreven door git.

## Bediening vanaf je telefoon

Stuur deze commando's naar je bot (typ `/` voor het menu): `/status`, `/pauze`, `/hervat`, `/prijzen`, `/gemiddelde`, `/min`, `/score`, `/reset`. De console-monitor heeft ook `/max` en `/maxpro`.

## Handig

| Commando | Wat |
|---|---|
| `python monitor.py --dry-run` | Draaien zonder Telegram, meldingen in het venster |
| `python monitor.py --log 30` | Laatste 30 beslissingen met de reden |
| `python monitor.py --export` | Opgeslagen beschrijvingen en bio's naar `beschrijvingen.md` |
| `python test_monitor.py` | Zelftest van de filters |

- **Regio**: standaard vinted.be. Andere regio = het domein in `urls` (`config.toml`) aanpassen.
- **Tempo**: draait er één monitor, dan kijkt hij elke **10 s**. Draaien er meerdere op dezelfde computer, dan merken ze dat van elkaar en gaan ze elk naar **15 s**, met minstens 1,5 s tussen alle verzoeken samen. Krijgt één monitor fouten, dan pauzeren ze allemaal. Zo raakt je IP-adres niet geblokkeerd (`interval_seconds`, `shared_interval_seconds`).
- **Automatisch starten**: Win+R → `shell:startup` → maak daar een snelkoppeling naar `start.bat`.
- De console-monitor gebruikt een klein AI-model (CLIP, ±155 MB) om stockfoto's te herkennen. Het wordt bij de eerste start automatisch gedownload naar `models/`.

## Eerlijk

Vinted heeft geen openbare API. De monitors lezen de openbare webpagina's, zonder captcha- of botbeveiliging te omzeilen, en rustig gedoseerd. Dat is niet door Vinted goedgekeurd: gebruik het voor eigen, beperkt gebruik. Verandert Vinted zijn website, dan kan het stoppen met werken.
