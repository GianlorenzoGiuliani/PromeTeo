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

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app.database import create_db_and_tables
from app.routers import catalogo, findings, home, progetti, report, target
from app.seed import (
    seed_ad_if_absent,
    seed_payloads_if_absent,
    seed_ports_if_absent,
    seed_tech_if_absent,
    seed_web_if_absent,
)

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

# File statici = file che il browser scarica cosi' come sono (CSS, JS, immagini).
# Stanno in app/static e sono raggiungibili sotto l'indirizzo /static/...
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# "Montiamo" i gruppi di pagine. Ogni router porta con se' le proprie rotte;
# l'ordine non conta perche' gli indirizzi non si sovrappongono.
app.include_router(home.router)
app.include_router(catalogo.router)
app.include_router(progetti.router)
app.include_router(findings.router)
app.include_router(target.router)
app.include_router(report.router)
