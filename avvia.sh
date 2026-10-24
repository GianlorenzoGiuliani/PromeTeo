#!/usr/bin/env bash
# =============================================================================
# Avvio di PromeTeus per macOS e Linux.
# La prima volta prepara tutto da solo; le volte dopo avvia e basta.
# Usarlo:  da terminale  ->  ./avvia.sh
#          (su macOS il doppio clic potrebbe aprirlo in un editor: in quel
#           caso rinominalo "avvia.command" oppure lancialo da Terminale.)
# =============================================================================
set -e

# Spostiamoci nella cartella dello script, cosi' funziona da qualunque posto.
cd "$(dirname "$0")"

# Troviamo l'interprete Python.
if command -v python3 >/dev/null 2>&1; then
  PY=python3
elif command -v python >/dev/null 2>&1; then
  PY=python
else
  echo "Python non trovato. Installa Python 3.10+ da https://www.python.org/downloads/"
  exit 1
fi

# Creiamo l'ambiente virtuale la prima volta.
if [ ! -d ".venv" ]; then
  echo "Primo avvio: creo l'ambiente virtuale..."
  "$PY" -m venv .venv
fi

# Installiamo le librerie se mancano (es. primo avvio o nuove dipendenze).
if [ ! -x "./.venv/bin/uvicorn" ]; then
  echo "Installo le librerie necessarie (solo questa volta)..."
  ./.venv/bin/python -m pip install --upgrade pip >/dev/null
  ./.venv/bin/pip install -r requirements.txt
fi

echo ""
echo "PromeTeus e' in avvio su http://127.0.0.1:8000"
echo "Per fermarlo: premi Ctrl+C in questa finestra."
echo ""

# Proviamo ad aprire il browser dopo un paio di secondi (senza bloccare).
(
  sleep 2
  if command -v open >/dev/null 2>&1; then open http://127.0.0.1:8000
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open http://127.0.0.1:8000
  fi
) >/dev/null 2>&1 &

# Avviamo il server (resta in esecuzione finche' non premi Ctrl+C).
exec ./.venv/bin/uvicorn app.main:app
