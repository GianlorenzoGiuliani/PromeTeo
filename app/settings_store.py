"""
Impostazioni a RUNTIME, tenute solo in memoria (non su disco).

La chiave API di Claude che inserisci dalla webapp vive SOLO qui, nella memoria
del processo del server. NON viene scritta su file, ne' nel database, ne' nei
log: appena fermi e riavvii Prometeo sparisce e va reinserita. E' una scelta di
sicurezza voluta (una chiave e' come una password).

Ordine di precedenza per la chiave e il modello:
  1) quello inserito dalla webapp (qui in memoria);
  2) le variabili d'ambiente (ANTHROPIC_API_KEY / PROMETEO_AI_MODEL), per chi
     preferisce impostarle dal terminale.
"""
import os

# Modello di default. Si puo' cambiare dalla webapp o con PROMETEO_AI_MODEL.
# (es. "claude-haiku-5-5" per spendere molto meno quando fai delle prove.)
DEFAULT_MODEL = "claude-opus-5-5"

# Contenitore in memoria. Parte vuoto a ogni avvio del server.
_store = {"api_key": None, "model": None}


def set_api_key(value) -> None:
    """Salva la chiave in memoria (stringa vuota -> nessuna chiave)."""
    _store["api_key"] = (value or "").strip() or None


def set_model(value) -> None:
    """Salva il modello scelto in memoria (vuoto -> si usa il default)."""
    _store["model"] = (value or "").strip() or None


def clear_api_key() -> None:
    """Dimentica la chiave inserita dalla webapp."""
    _store["api_key"] = None


def explicit_api_key():
    """La chiave da passare ESPLICITAMENTE al client Claude: quella in memoria
    oppure ANTHROPIC_API_KEY. Non include ANTHROPIC_AUTH_TOKEN, che l'SDK legge
    da solo dall'ambiente."""
    return _store["api_key"] or os.environ.get("ANTHROPIC_API_KEY")


def is_configured() -> bool:
    """True se c'e' una chiave utilizzabile (in memoria o nell'ambiente)."""
    return bool(
        _store["api_key"]
        or os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("ANTHROPIC_AUTH_TOKEN")
    )


def effective_model() -> str:
    """Il modello che verra' effettivamente usato."""
    return _store["model"] or os.environ.get("PROMETEO_AI_MODEL", DEFAULT_MODEL)


def status() -> dict:
    """Stato leggibile per la pagina Impostazioni, SENZA rivelare la chiave.

    Ritorna: set (c'e' una chiave?), source ('memoria'/'ambiente'), tail (le
    ultime 4 cifre, solo per la chiave inserita dalla webapp, per riconoscerla)."""
    k = _store["api_key"]
    if k:
        return {"set": True, "source": "memoria", "tail": k[-4:] if len(k) >= 4 else None}
    if os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"):
        return {"set": True, "source": "ambiente", "tail": None}
    return {"set": False, "source": None, "tail": None}
