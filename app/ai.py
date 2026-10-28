"""
Assistente AI dei findings.

Da una descrizione APPROSSIMATIVA, chiede a Claude di compilare i campi di un
finding (titolo, descrizione, CVSS score+vector, CVE/CWE, PoC, rimedio). Usa l'SDK
ufficiale `anthropic` e gli "structured outputs" (output JSON garantito dallo
schema), cosi' la risposta e' sempre interpretabile.

Degradazione elegante: se manca la chiave API o la libreria, il resto dell'app
funziona lo stesso. La funzione solleva AIError con un messaggio pensato per
l'utente, e la rotta lo mostra senza far crashare nulla.

Configurazione (vedi app/settings_store.py): la chiave e il modello si possono
impostare dalla pagina Impostazioni della webapp (restano solo in memoria)
oppure con le variabili d'ambiente ANTHROPIC_API_KEY / PROMETEO_AI_MODEL.
"""
import json

from app import settings_store

# Schema dei campi che l'AI deve restituire. Con gli structured outputs la
# risposta rispetta questo schema: niente testo libero da "ripulire a mano".
_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "description": {"type": "string"},
        "cvss_score": {"type": ["number", "null"]},
        "cvss_vector": {"type": "string"},
        "cve": {"type": "string"},
        "cwe": {"type": "string"},
        "poc": {"type": "string"},
        "remediation": {"type": "string"},
    },
    "required": [
        "title", "description", "cvss_score", "cvss_vector",
        "cve", "cwe", "poc", "remediation",
    ],
    "additionalProperties": False,
}

_SYSTEM = """Sei un assistente esperto di penetration test. L'utente ti da' una
descrizione APPROSSIMATIVA di una vulnerabilita' trovata durante un test
AUTORIZZATO. Produci un finding completo e professionale, in italiano, pronto
per un report.

Regole:
- Scrivi in italiano, con tono tecnico e sintetico.
- title: titolo chiaro e specifico della vulnerabilita'.
- description: descrizione BREVE (2-4 frasi): cos'e' la vulnerabilita' e che impatto ha.
- cvss_score: punteggio CVSS 3.1 (0-10) coerente con la gravita' reale; null se non applicabile.
- cvss_vector: vettore CVSS 3.1 se puoi stimarlo con ragionevolezza, altrimenti "".
- cve/cwe: inseriscili SOLO se davvero pertinenti e noti (es. CVE-2019-0708, CWE-89); altrimenti "".
- poc: proof of concept, ovvero i passi concreti per riprodurre/dimostrare la vulnerabilita', con comandi o payload reali dove ha senso.
- remediation: come correggere la vulnerabilita'.
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

    if not settings_store.is_configured():
        raise AIError(
            "Assistente AI non configurato: apri le Impostazioni (icona ⚙ in alto "
            "a destra) e incolla la tua chiave API di Claude."
        )
    try:
        import anthropic
    except ImportError:
        raise AIError(
            "Libreria 'anthropic' non installata. Esegui: pip install -r requirements.txt"
        )

    model = settings_store.effective_model()
    # Se abbiamo una chiave esplicita (inserita dalla webapp o in ANTHROPIC_API_KEY)
    # la passiamo al client; altrimenti lasciamo che l'SDK la legga dall'ambiente.
    key = settings_store.explicit_api_key()
    client = anthropic.Anthropic(api_key=key) if key else anthropic.Anthropic()
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

    score = data.get("cvss_score")
    try:
        out["cvss_score"] = max(0.0, min(10.0, float(score)))
    except (TypeError, ValueError):
        out["cvss_score"] = ""

    for key in ("description", "cvss_vector", "cve", "cwe", "poc", "remediation"):
        out[key] = str(data.get(key) or "").strip()
    return out
