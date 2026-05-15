@echo off
echo.
echo  EthiHack v5.0 - Competition Edition
echo.

REM Load API key from .env file if it exists
if exist .env (
  for /f "tokens=1,2 delims==" %%a in (.env) do (
    if "%%a"=="ANTHROPIC_API_KEY" set ANTHROPIC_API_KEY=%%b
  )
)

REM If still not set, ask the user
if "%ANTHROPIC_API_KEY%"=="" (
  echo  No API key found in .env file.
  set /p ANTHROPIC_API_KEY= Enter your Anthropic API key:
)

pip install -r requirements.txt -q
echo  Starting server...
python app.py
pause
