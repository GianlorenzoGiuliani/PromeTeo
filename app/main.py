"""
PromeTeus - punto di ingresso dell'applicazione.

Questo file fa solo da "regia": e' corto di proposito.
  1) crea l'app FastAPI (l'oggetto "app" che il server esegue);
  2) all'avvio prepara il database e, se il catalogo e' vuoto, lo riempie;
  3) collega i file statici (CSS/JS);
  4) "monta" i router, cioe' i gruppi di pagine definiti in app/routers/.

Le pagine vere e proprie NON stanno piu' qui: ognuna vive nel suo router
(home, catalogo, progetti, findings, target, report), cosi' ogni file resta
corto e si trova subito dove mettere mano.
"""
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.database import create_db_and_tables
from app.routers import ai, catalogo, findings, home, progetti, report, target
from app.seed import (
    seed_ad_if_absent,
    seed_payloads_if_absent,
    seed_ports_if_absent,
    seed_tech_if_absent,
    seed_web_if_absent,
)
from app.web import CSRF_COOKIE, csrf_protect, new_csrf_token

# BASE_DIR = la cartella "app" dove si trova questo file. La calcoliamo in
# automatico cosi' l'app funziona ovunque venga copiata.
BASE_DIR = Path(__file__).resolve().parent


# Cosa deve succedere all'avvio e allo spegnimento dell'app.
@asynccontextmanager
async def lifespan(app: FastAPI):
    # All'avvio: creiamo il database (se non esiste) e, se il catalogo e' vuoto,
    # carichiamo la base pronta di porte, tecnologie, tecniche, AD e Web App.
    create_db_and_tables()
    porte = seed_ports_if_absent()
    tecno = seed_tech_if_absent()
    tecniche = seed_payloads_if_absent()
    ad = seed_ad_if_absent()
    web = seed_web_if_absent()
    for etichetta, n in [("Porte", porte), ("Tecnologie", tecno),
                         ("Tecniche", tecniche), ("Active Directory", ad), ("Web App", web)]:
        if n:
            print(f"[PromeTeus] {etichetta} caricate: {n}.")
    yield
    # (allo spegnimento non c'e' nulla di speciale da fare)


# L'applicazione. "title" compare nella documentazione automatica di FastAPI
# (la trovi su http://127.0.0.1:8000/docs quando il server e' avviato).
app = FastAPI(title="PromeTeus", lifespan=lifespan)


# A ogni richiesta assicuriamo un token CSRF: lo mettiamo in request.state (lo
# leggono i template per il campo nascosto dei form) e, se il cookie non c'e'
# ancora, lo impostiamo nella risposta. Questo middleware NON legge il corpo
# della richiesta, quindi non interferisce con l'invio dei form.
@app.middleware("http")
async def csrf_cookie(request: Request, call_next):
    token = request.cookies.get(CSRF_COOKIE)
    da_impostare = token is None
    if da_impostare:
        token = new_csrf_token()
    request.state.csrf_token = token
    response = await call_next(request)
    if da_impostare:
        response.set_cookie(
            CSRF_COOKIE, token, httponly=True, samesite="strict", path="/"
        )
    return response


# File statici = file che il browser scarica cosi' come sono (CSS, JS, immagini).
# Stanno in app/static e sono raggiungibili sotto l'indirizzo /static/...
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# "Montiamo" i gruppi di pagine. Ogni router porta con se' le proprie rotte;
# l'ordine non conta perche' gli indirizzi non si sovrappongono. La dipendenza
# csrf_protect vale per tutte le rotte: lascia passare le GET e blocca le POST
# prive di un token CSRF valido.
protette = [Depends(csrf_protect)]
app.include_router(home.router, dependencies=protette)
app.include_router(catalogo.router, dependencies=protette)
app.include_router(progetti.router, dependencies=protette)
app.include_router(findings.router, dependencies=protette)
app.include_router(target.router, dependencies=protette)
app.include_router(report.router, dependencies=protette)
app.include_router(ai.router, dependencies=protette)
