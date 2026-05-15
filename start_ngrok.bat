@echo off
title EthiHack v4.0 Launcher
color 0A

echo.
echo  ███████╗████████╗██╗  ██╗██╗██╗  ██╗ █████╗  ██████╗██╗  ██╗
echo  ██╔════╝╚══██╔══╝██║  ██║██║██║  ██║██╔══██╗██╔════╝██║ ██╔╝
echo  █████╗     ██║   ███████║██║███████║███████║██║     █████╔╝ 
echo  ██╔══╝     ██║   ██╔══██║██║██╔══██║██╔══██║██║     ██╔═██╗ 
echo  ███████╗   ██║   ██║  ██║██║██║  ██║██║  ██║╚██████╗██║  ██╗
echo  ╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
echo.
echo  v4.0 — OWASP LLM Top 10 + MITRE ATLAS + Adaptive Chains
echo  ──────────────────────────────────────────────────────────
echo.

:: Install dependencies
echo [1/3] Installing dependencies...
pip install -r requirements.txt -q
echo       Done.

:: Start EthiHack in background
echo [2/3] Starting EthiHack server...
start "EthiHack Server" cmd /k "cd /d %~dp0 && python app.py"
timeout /t 3 /nobreak > nul
echo       Running at http://localhost:8000

:: Start ngrok tunnel
echo [3/3] Opening ngrok tunnel...
echo.
echo  ┌─────────────────────────────────────────────┐
echo  │  ngrok will show your PUBLIC URL below.     │
echo  │  Share that URL with anyone in the world.   │
echo  │  Press Ctrl+C to stop the tunnel.           │
echo  └─────────────────────────────────────────────┘
echo.
ngrok http 8000

pause
