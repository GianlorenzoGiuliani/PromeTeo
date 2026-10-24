"""
Infrastruttura web condivisa fra i vari gruppi di pagine (i "router").

Qui mettiamo le cose che servono a piu' file e che vogliamo definire UNA sola
volta, cosi' da avere un unico posto da modificare:
  - il motore dei template Jinja2 (tutte le pagine leggono dalla stessa cartella);
  - le etichette leggibili (tipo di voce, gravita', stato) usate dai template;
  - una piccola utility per leggere numeri dai form.

Perche' separarle? Se queste definizioni restassero dentro main.py, ogni router
dovrebbe importarle da li' e main.py tornerebbe a essere il "file che sa tutto".
Mettendole in un modulo neutro, i router dipendono da app.web (semplice) e non
da app.main (che invece dipende dai router): niente dipendenze circolari.
"""
from pathlib import Path

from fastapi.templating import Jinja2Templates

from app.models import (
    KIND_AD,
    KIND_PORT,
    KIND_TECH,
    KIND_TECHNIQUE,
    KIND_WEB,
    SEVERITIES,
)

# Cartella "app" (dove si trova questo file): i template sono in app/templates.
BASE_DIR = Path(__file__).resolve().parent

# Motore dei template: definito qui una volta e importato da tutti i router.
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# Etichette leggibili per i tipi di voce (le usano i template).
KIND_LABELS = {
    KIND_PORT: "Porte",
    KIND_TECH: "Tecnologie",
    KIND_TECHNIQUE: "Tecniche",
    KIND_AD: "Active Directory",
    KIND_WEB: "Web App",
}

# Etichette in italiano per gravita' e stato dei findings.
SEVERITY_LABELS = {
    "critical": "Critica",
    "high": "Alta",
    "medium": "Media",
    "low": "Bassa",
    "info": "Info",
}
STATUS_LABELS = {
    "open": "Aperto",
    "confirmed": "Confermato",
    "false_positive": "Falso positivo",
    "resolved": "Risolto",
}
# Ordine di gravita' (0 = piu' grave): serve per ordinare i findings.
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def int_or_none(value):
    """Converte in intero, oppure None se vuoto/non valido (usato per i form)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
