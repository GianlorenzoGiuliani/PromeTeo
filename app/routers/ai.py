"""Rotta dell'assistente AI: riceve una descrizione e restituisce (in JSON) i
campi del finding da precompilare nel form. Non scrive nel database: suggerisce
e basta, poi l'utente controlla e salva."""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from app.ai import AIError, suggest_finding

router = APIRouter()


@router.post("/ai/suggerisci-finding")
async def ai_suggerisci(request: Request):
    """Chiede all'assistente di compilare i campi a partire dalla descrizione.

    Risponde sempre in JSON: {ok: true, fields: {...}} oppure
    {ok: false, error: "..."} con un messaggio leggibile. Cosi' il JavaScript
    del form puo' riempire i campi o mostrare l'errore senza rompere nulla."""
    form = await request.form()
    description = (form.get("description") or "").strip()
    try:
        fields = suggest_finding(description)
    except AIError as e:
        # Problema atteso (chiave mancante, rete, descrizione vuota...).
        return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
    except Exception:
        # Qualsiasi altro imprevisto: non mostriamo i dettagli interni.
        return JSONResponse(
            {"ok": False, "error": "Errore imprevisto dell'assistente AI."},
            status_code=502,
        )
    return JSONResponse({"ok": True, "fields": fields})
