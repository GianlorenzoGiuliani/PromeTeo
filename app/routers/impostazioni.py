"""
Impostazioni dell'app (per ora: l'assistente AI).

La chiave API inserita qui viene tenuta SOLO in memoria (vedi settings_store):
al riavvio del server va reinserita. E' una scelta di sicurezza.
"""
from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse

from app import settings_store
from app.web import templates

router = APIRouter()

# Modelli che proponiamo nel menu a tendina (dal piu' capace al piu' economico).
MODELLI = [
    ("claude-opus-5-5", "Opus 5.5 — il piu' capace (costa di piu')"),
    ("claude-sonnet-5-5", "Sonnet 5.5 — equilibrato"),
    ("claude-haiku-5-5", "Haiku 5.5 — il piu' economico (ideale per le prove)"),
]


@router.get("/impostazioni", response_class=HTMLResponse)
def impostazioni(request: Request, salvato: int = 0, rimosso: int = 0):
    """Pagina delle impostazioni: stato della chiave AI e scelta del modello."""
    return templates.TemplateResponse(
        request=request,
        name="impostazioni.html",
        context={
            "stato": settings_store.status(),
            "modello_attuale": settings_store.effective_model(),
            "modelli": MODELLI,
            "salvato": bool(salvato),
            "rimosso": bool(rimosso),
        },
    )


@router.post("/impostazioni")
def salva_impostazioni(api_key: str = Form(""), model: str = Form("")):
    """Salva (in memoria) la chiave e il modello. Campo chiave vuoto = lascia
    invariata quella eventualmente gia' presente."""
    if api_key.strip():
        settings_store.set_api_key(api_key)
    settings_store.set_model(model)
    return RedirectResponse(url="/impostazioni?salvato=1", status_code=303)


@router.post("/impostazioni/rimuovi")
def rimuovi_chiave():
    """Dimentica subito la chiave tenuta in memoria."""
    settings_store.clear_api_key()
    return RedirectResponse(url="/impostazioni?rimosso=1", status_code=303)
