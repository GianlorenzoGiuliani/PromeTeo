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
import secrets
from pathlib import Path

from fastapi import HTTPException, Request
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
# Etichette per la probabilita' (valutazione del rischio).
LIKELIHOOD_LABELS = {"high": "Alta", "medium": "Media", "low": "Bassa"}
# Ordine di gravita' (0 = piu' grave): serve per ordinare i findings.
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def int_or_none(value):
    """Converte in intero, oppure None se vuoto/non valido (usato per i form)."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


# ===========================================================================
# Protezione CSRF (Cross-Site Request Forgery).
#
# Il rischio: un sito malevolo che apri in un'altra scheda puo' far partire di
# nascosto una richiesta POST verso http://127.0.0.1:8000 (es. "elimina
# progetto"). Senza difese, il browser la eseguirebbe.
#
# La difesa (schema "double-submit cookie"): a ogni visitatore assegniamo un
# token casuale, salvato in un cookie. Ogni form che modifica dati porta lo
# stesso token in un campo nascosto. Al POST confrontiamo cookie e campo: se
# combaciano, la richiesta viene davvero dalle nostre pagine. Un sito esterno
# non puo' leggere il cookie (regole di same-origin del browser) ne' indovinare
# il token, quindi non riesce a forgiare una richiesta valida.
# ===========================================================================
CSRF_COOKIE = "csrftoken"   # nome del cookie
CSRF_FIELD = "csrf_token"   # nome del campo nascosto nei form


def new_csrf_token() -> str:
    """Genera un token casuale e imprevedibile."""
    return secrets.token_urlsafe(32)


async def csrf_protect(request: Request):
    """Dipendenza applicata a tutte le rotte: sulle richieste che MODIFICANO
    dati (POST/PUT/PATCH/DELETE) pretende che il token del form combaci con
    quello del cookie. Sulle richieste di sola lettura (GET) non fa nulla."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        cookie = request.cookies.get(CSRF_COOKIE)
        form = await request.form()
        sent = form.get(CSRF_FIELD)
        # secrets.compare_digest confronta senza fughe di informazioni sui tempi.
        if not cookie or not sent or not secrets.compare_digest(str(cookie), str(sent)):
            raise HTTPException(status_code=403, detail="Token CSRF mancante o non valido")
