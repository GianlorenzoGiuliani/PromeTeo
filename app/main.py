"""
PromeTeus - punto di ingresso dell'applicazione.

Qui facciamo tre cose:
  1) creiamo l'app FastAPI (l'oggetto "app" che il server esegue);
  2) colleghiamo i file statici (CSS) e il motore dei template (Jinja2);
  3) definiamo le "rotte" (route): ogni rotta e' un indirizzo del sito
     (es. "/") a cui corrisponde una funzione Python che decide cosa mostrare.
"""
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# BASE_DIR = la cartella "app" dove si trova questo file.
# La calcoliamo in automatico cosi' l'app funziona ovunque venga copiata,
# senza dover scrivere a mano percorsi fissi tipo "C:\Users\...".
BASE_DIR = Path(__file__).resolve().parent

# L'applicazione. "title" compare nella documentazione automatica di FastAPI
# (la trovi su http://127.0.0.1:8000/docs quando il server e' avviato).
app = FastAPI(title="PromeTeus")

# File statici = file che il browser scarica cosi' come sono (CSS, immagini...).
# Li mettiamo in app/static e saranno raggiungibili sotto l'indirizzo /static/...
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")

# Motore dei template: legge i file HTML dentro app/templates e li "riempie"
# con i dati che gli passiamo dalla funzione della rotta.
templates = Jinja2Templates(directory=BASE_DIR / "templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    """Pagina iniziale: presenta PromeTeus e le sue sezioni principali.

    Il decoratore '@app.get("/")' qui sopra significa:
    "quando qualcuno apre l'indirizzo '/', esegui questa funzione".
    """
    # Prendiamo il template home.html e lo mostriamo.
    # 'request' serve sempre a Jinja2; dentro 'context' mettiamo i dati
    # che vogliamo usare nella pagina (qui, per ora, solo un titolo).
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"titolo": "PromeTeus"},
    )
