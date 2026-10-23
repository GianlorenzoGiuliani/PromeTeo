"""
PromeTeus - punto di ingresso dell'applicazione.

Qui facciamo tre cose:
  1) creiamo l'app FastAPI (l'oggetto "app" che il server esegue);
  2) colleghiamo i file statici (CSS) e il motore dei template (Jinja2);
  3) definiamo le "rotte" (route): ogni rotta e' un indirizzo del sito
     (es. "/") a cui corrisponde una funzione Python che decide cosa mostrare.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import or_
from sqlmodel import Session, func, select

from app.database import create_db_and_tables, get_session
from app.models import KIND_PORT, KIND_TECH, KIND_TECHNIQUE, Check, Topic
from app.seed import seed_if_empty, seed_payloads_if_absent

# BASE_DIR = la cartella "app" dove si trova questo file.
# La calcoliamo in automatico cosi' l'app funziona ovunque venga copiata,
# senza dover scrivere a mano percorsi fissi tipo "C:\Users\...".
BASE_DIR = Path(__file__).resolve().parent

# Cosa deve succedere all'avvio e allo spegnimento dell'app.
@asynccontextmanager
async def lifespan(app: FastAPI):
    # All'avvio: creiamo il database (se non esiste) e, se il catalogo e' vuoto,
    # carichiamo la base pronta di porte e tecnologie.
    create_db_and_tables()
    base = seed_if_empty()
    tecniche = seed_payloads_if_absent()
    if base:
        print(f"[PromeTeus] Base del catalogo caricata: {base} voci.")
    if tecniche:
        print(f"[PromeTeus] Tecniche (PayloadsAllTheThings) caricate: {tecniche} categorie.")
    yield
    # (allo spegnimento non c'e' nulla di speciale da fare)


# L'applicazione. "title" compare nella documentazione automatica di FastAPI
# (la trovi su http://127.0.0.1:8000/docs quando il server e' avviato).
app = FastAPI(title="PromeTeus", lifespan=lifespan)

# File statici = file che il browser scarica cosi' come sono (CSS, immagini...).
# Li mettiamo in app/static e saranno raggiungibili sotto l'indirizzo /static/...
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Motore dei template: legge i file HTML dentro app/templates e li "riempie"
# con i dati che gli passiamo dalla funzione della rotta.
templates = Jinja2Templates(directory=BASE_DIR / "templates")


# Etichette leggibili per i tipi di voce (le usano i template).
KIND_LABELS = {
    KIND_PORT: "Porte",
    KIND_TECH: "Tecnologie",
    KIND_TECHNIQUE: "Tecniche",
}


@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    """Pagina iniziale: presenta PromeTeus e mostra quante voci ha ogni sezione.

    'session: Session = Depends(get_session)' chiede a FastAPI di aprire una
    sessione sul database e passarcela; a fine richiesta la chiude da sola.
    """
    counts = {
        kind: session.exec(
            select(func.count()).select_from(Topic).where(Topic.kind == kind)
        ).one()
        for kind in (KIND_PORT, KIND_TECH, KIND_TECHNIQUE)
    }
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"counts": counts},
    )


@app.get("/catalogo", response_class=HTMLResponse)
def catalogo(
    request: Request,
    kind: str | None = None,
    q: str | None = None,
    session: Session = Depends(get_session),
):
    """Elenco del catalogo, con filtro per tipo ('kind') e ricerca testuale ('q').

    'kind' e 'q' arrivano dall'URL (es. /catalogo?kind=port&q=rdp): FastAPI li
    legge in automatico perche' sono parametri della funzione con un valore di
    default.
    """
    statement = select(Topic)
    if kind in (KIND_PORT, KIND_TECH, KIND_TECHNIQUE):
        statement = statement.where(Topic.kind == kind)
    if q:
        like = f"%{q}%"
        statement = statement.where(
            or_(Topic.name.ilike(like), Topic.description.ilike(like))
        )
    statement = statement.order_by(Topic.kind, Topic.name)
    topics = session.exec(statement).all()

    # Quanti test ha ogni voce: UNA sola query con GROUP BY (invece di una per voce).
    counts = dict(
        session.exec(select(Check.topic_id, func.count()).group_by(Check.topic_id)).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="catalogo.html",
        context={
            "topics": topics,
            "counts": counts,
            "kind": kind,
            "q": q or "",
            "kind_labels": KIND_LABELS,
        },
    )


@app.get("/topic/{topic_id}", response_class=HTMLResponse)
def topic_detail(
    topic_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Dettaglio di una voce: la voce e tutti i suoi test.

    '{topic_id}' nell'indirizzo e' una parte variabile: /topic/1, /topic/2...
    """
    topic = session.get(Topic, topic_id)
    if topic is None:
        # Se l'id non esiste, rispondiamo con un errore 404 (pagina non trovata).
        raise HTTPException(status_code=404, detail="Voce non trovata")
    checks = session.exec(select(Check).where(Check.topic_id == topic_id)).all()
    return templates.TemplateResponse(
        request=request,
        name="topic.html",
        context={"topic": topic, "checks": checks, "kind_labels": KIND_LABELS},
    )
