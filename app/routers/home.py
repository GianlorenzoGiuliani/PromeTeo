"""Pagina iniziale: presenta PromeTeus e conta le voci di ogni sezione."""
from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse
from sqlmodel import Session, func, select

from app.database import get_session
from app.models import (
    KIND_AD,
    KIND_PORT,
    KIND_TECH,
    KIND_TECHNIQUE,
    KIND_WEB,
    Project,
    Topic,
)
from app.web import templates

# APIRouter e' come una "mini-app": raccoglie delle rotte che poi main.py
# collega all'app vera e propria con app.include_router(router).
router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    """Pagina iniziale: presenta PromeTeus e mostra quante voci ha ogni sezione.

    'session: Session = Depends(get_session)' chiede a FastAPI di aprire una
    sessione sul database e passarcela; a fine richiesta la chiude da sola.
    """
    counts = {
        kind: session.exec(
            select(func.count()).select_from(Topic).where(Topic.kind == kind)
        ).one()
        for kind in (KIND_PORT, KIND_TECH, KIND_TECHNIQUE, KIND_AD, KIND_WEB)
    }
    n_progetti = session.exec(select(func.count()).select_from(Project)).one()
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"counts": counts, "n_progetti": n_progetti},
    )
