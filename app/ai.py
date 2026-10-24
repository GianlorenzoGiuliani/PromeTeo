"""
Assistente AI dei findings.

Da una descrizione APPROSSIMATIVA, chiede a Claude di compilare tutti i campi
di un finding (titolo, gravita', CVSS, impatto, passi, rimedio...). Usa l'SDK
ufficiale `anthropic` e gli "structured outputs" (output JSON garantito dallo
schema), cosi' la risposta e' sempre interpretabile.

Degradazione elegante: se manca la chiave API o la libreria, il resto dell'app
funziona lo stesso. La funzione solleva AIError con un messaggio pensato per
l'utente, e la rotta lo mostra senza far crashare nulla.

Configurazione (variabili d'ambiente):
  - ANTHROPIC_API_KEY  -> la tua chiave API di Claude (obbligatoria).
  - PROMETEO_AI_MODEL -> modello da usare (facoltativa; default qui sotto).
"""
import json
import os

from app.models import LIKELIHOODS, SEVERITIES

# Modello di default. Si puo' cambiare con la variabile PROMETEO_AI_MODEL
# (es. "claude-haiku-5-5" per spendere molto meno, "claude-sonnet-5-5" via di mezzo).
DEFAULT_MODEL = "claude-opus-5-5"

# Schema dei campi che l'AI deve restituire. Con gli structured outputs la
# risposta rispetta questo schema: niente testo libero da "ripulire a mano".
_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "severity": {"type": "string", "enum": SEVERITIES},
        "likelihood": {"type": "string", "enum": LIKELIHOODS + [""]},
        "cvss_score": {"type": ["number", "null"]},
        "cvss_vector": {"type": "string"},
        "cve": {"type": "string"},
        "cwe": {"type": "string"},
        "description": {"type": "string"},
        "impact": {"type": "string"},
        "reproduction": {"type": "string"},
        "remediation": {"type": "string"},
        "references": {"type": "string"},
    },
    "required": [
        "title", "severity", "likelihood", "cvss_score", "cvss_vector",
        "cve", "cwe", "description", "impact", "reproduction",
        "remediation", "references",
    ],
    "additionalProperties": False,
}

_SYSTEM = """Sei un assistente esperto di penetration test. L'utente ti da' una
descrizione APPROSSIMATIVA di una vulnerabilita' trovata durante un test
AUTORIZZATO. Produci un finding completo e professionale, in italiano, pronto
per un report.

Regole:
- Scrivi in italiano, con tono tecnico e sintetico.
- severity: scegli tra critical/high/medium/low/info in base alla gravita' reale.
- likelihood: alta=high, media=medium, bassa=low; "" se non valutabile.
- cvss_score: punteggio CVSS 3.1 coerente con la gravita' (0-10), null se non applicabile.
- cvss_vector: vettore CVSS 3.1 se puoi stimarlo con ragionevolezza, altrimenti "".
- cve/cwe: inseriscili SOLO se davvero pertinenti e noti (es. CWE-89); altrimenti "".
- reproduction: passi concreti, con comandi reali dove ha senso.
- Non inventare dettagli specifici del bersaglio (IP, hostname, credenziali): usa segnaposto come <ip> o <url>.
- Se un campo non e' deducibile dalla descrizione, restituisci stringa vuota (null per cvss_score). Non inventare.
"""


class AIError(Exception):
    """Errore 'gestito': il messaggio e' pensato per essere mostrato all'utente."""


def suggest_finding(description: str) -> dict:
    """Chiede a Claude di compilare i campi del finding. Ritorna un dict con i
    valori gia' normalizzati. Solleva AIError (con messaggio leggibile) se la
    configurazione manca o la chiamata fallisce."""
    description = (description or "").strip()
    if not description:
        raise AIError("Scrivi prima una breve descrizione del finding.")

    if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
        raise AIError(
            "Assistente AI non configurato: imposta la variabile d'ambiente "
            "ANTHROPIC_API_KEY con la tua chiave di Claude."
        )
    try:
        import anthropic
    except ImportError:
        raise AIError(
            "Libreria 'anthropic' non installata. Esegui: pip install -r requirements.txt"
        )

    model = os.environ.get("PROMETEO_AI_MODEL", DEFAULT_MODEL)
    client = anthropic.Anthropic()
    try:
        response = client.messages.create(
            model=model,
            max_tokens=2000,
            system=_SYSTEM,
            messages=[{"role": "user", "content": description}],
            output_config={"format": {"type": "json_schema", "schema": _SCHEMA}},
        )
    except anthropic.AuthenticationError:
        raise AIError("Chiave API non valida: controlla ANTHROPIC_API_KEY.")
    except anthropic.APIConnectionError:
        raise AIError("Impossibile raggiungere l'API di Claude (connessione di rete?).")
    except anthropic.APIStatusError as e:
        raise AIError(f"L'API di Claude ha risposto con un errore ({e.status_code}). Riprova piu' tardi.")

    text = next((b.text for b in response.content if b.type == "text"), "")
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        raise AIError("La risposta dell'AI non e' interpretabile. Riprova.")
    return _normalize(data)


def _normalize(data: dict) -> dict:
    """Vincola i valori ai range ammessi, cosi' il form riceve dati sensati
    (anche se il modello sbagliasse qualcosa)."""
    out = {"title": str(data.get("title") or "").strip()}

    sev = str(data.get("severity") or "").strip().lower()
    out["severity"] = sev if sev in SEVERITIES else "medium"

    lk = str(data.get("likelihood") or "").strip().lower()
    out["likelihood"] = lk if lk in LIKELIHOODS else ""

    score = data.get("cvss_score")
    try:
        out["cvss_score"] = max(0.0, min(10.0, float(score)))
    except (TypeError, ValueError):
        out["cvss_score"] = ""

    for key in ("cvss_vector", "cve", "cwe", "description", "impact",
                "reproduction", "remediation", "references"):
        out[key] = str(data.get(key) or "").strip()
    return out
