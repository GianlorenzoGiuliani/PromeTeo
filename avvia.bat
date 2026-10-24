@echo off
REM ==========================================================================
REM  Avvio di PromeTeus per Windows.
REM  La prima volta prepara tutto da solo; le volte dopo avvia e basta.
REM  Usarlo: doppio clic su "avvia.bat".
REM ==========================================================================
cd /d "%~dp0"

REM Controlliamo che Python ci sia.
where python >nul 2>&1
if errorlevel 1 (
  echo Python non trovato. Installa Python 3.10+ da https://www.python.org/downloads/
  echo Durante l'installazione spunta "Add Python to PATH".
  pause
  exit /b 1
)

REM Creiamo l'ambiente virtuale la prima volta.
if not exist ".venv" (
  echo Primo avvio: creo l'ambiente virtuale...
  python -m venv .venv
)

call .venv\Scripts\activate.bat

REM Installiamo le librerie se mancano.
if not exist ".venv\Scripts\uvicorn.exe" (
  echo Installo le librerie necessarie ^(solo questa volta^)...
  python -m pip install --upgrade pip >nul
  pip install -r requirements.txt
)

echo.
echo PromeTeus e' in avvio su http://127.0.0.1:8000
echo Per fermarlo: premi Ctrl+C in questa finestra.
echo.

REM Apriamo il browser (se dice "impossibile connettersi", aspetta un attimo e ricarica).
start "" http://127.0.0.1:8000

REM Avviamo il server (resta in esecuzione finche' non premi Ctrl+C).
uvicorn app.main:app

pause
