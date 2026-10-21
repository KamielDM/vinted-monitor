@echo off
title Vinted PS5 Games Monitor  (sluit dit venster om te stoppen)
cd /d "%~dp0"
:loop
python monitor.py
echo.
echo Monitor gestopt. Automatische herstart over 30 seconden. Sluit dit venster om echt te stoppen.
timeout /t 30 /nobreak >nul
goto loop
