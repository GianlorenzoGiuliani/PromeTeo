# PromeTeus

Assistente per penetration test **autorizzati**. Ti aiuta a ricordare:

- **cosa testare** quando trovi una porta aperta o riconosci una tecnologia;
- **quali strumenti e comandi** usare;
- **come interpretare i risultati** ("se nell'output vedi X, c'e' la vulnerabilita' Y");
- a **tenere traccia dei findings** per generare il **report** finale.

> ⚠️ Usa PromeTeus solo su sistemi per cui hai un'autorizzazione esplicita
> (ingaggio di pentest, programma di bug bounty in scope, laboratori o CTF).

## Com'e' fatto (in breve)

- **Python + FastAPI**: un piccolo server web che gira sul tuo computer.
- **Jinja2**: i template delle pagine HTML.
- **SQLite** (dal prossimo step): i dati, salvati in un file **in locale**.

## Requisiti

- [Python 3.10+](https://www.python.org/downloads/)

## Come avviarlo

Dal terminale, dentro la cartella del progetto:

```bash
# 1) Crea un "ambiente virtuale": una sandbox per le librerie di questo progetto
python -m venv .venv

# 2) Attivalo
#    Linux / macOS:
source .venv/bin/activate
#    Windows (PowerShell):
#    .venv\Scripts\Activate.ps1

# 3) Installa le librerie elencate in requirements.txt
pip install -r requirements.txt

# 4) Avvia l'app
uvicorn app.main:app --reload
```

Apri il browser su **http://127.0.0.1:8000**
(la documentazione automatica delle API e' su **/docs**).
Per fermare il server: `Ctrl + C`.

## Struttura del progetto

```
PromeTeus/
├─ app/
│  ├─ __init__.py        # rende "app" un pacchetto Python
│  ├─ main.py            # il cuore: crea l'app e definisce le pagine (route)
│  ├─ database.py        # configurazione del database SQLite
│  ├─ models.py          # le "tabelle": Topic, Check, Project, Finding
│  ├─ seed.py            # carica i contenuti iniziali nel database
│  ├─ templates/         # le pagine HTML
│  │  ├─ base.html       # struttura comune a tutte le pagine
│  │  └─ home.html       # la home
│  └─ static/
│     └─ style.css       # lo stile grafico
├─ data/
│  └─ payloads_seed.json # tecniche importate da PayloadsAllTheThings
├─ tools/
│  └─ import_payloads.py # trasforma PayloadsAllTheThings nel formato di PromeTeus
├─ requirements.txt      # elenco delle librerie da installare
├─ .gitignore            # file che git deve ignorare
├─ prometeus.db          # il database (creato in automatico; NON su git)
├─ THIRD_PARTY_NOTICES.md # licenze/attribuzioni dei contenuti di terze parti
└─ README.md             # questo file
```

## Il database

Al primo avvio PromeTeus crea da solo il file `prometeus.db` e, se il catalogo
e' vuoto, lo riempie con una base di porte e tecnologie comuni.
Il file resta sul tuo computer e non viene salvato su git (contiene dati, non codice).

Per (ri)caricare a mano i contenuti del catalogo:

```bash
python -m app.seed
```

## Il catalogo

Al primo avvio il catalogo si riempie con:

- una **base** di porte e tecnologie comuni, scritta a mano in `app/seed.py`;
- un'ampia raccolta di **tecniche e payload** importata da
  [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
  (licenza MIT — vedi `THIRD_PARTY_NOTICES.md` per l'attribuzione).

Ogni voce ha anche un **link di approfondimento** (campo `references`): le voci
di base rimandano alla pagina [HackTricks](https://book.hacktricks.xyz)
corrispondente, le tecniche alla loro pagina su PayloadsAllTheThings.
HackTricks **non** viene copiato nel database: la sua licenza è CC BY-NC
(non commerciale), quindi lo **colleghiamo** soltanto.

Le tecniche sono già pronte nel file `data/payloads_seed.json`. Per
**rigenerarle** dalla fonte (serve una copia clonata del repository):

```bash
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git /tmp/patt
python tools/import_payloads.py --source /tmp/patt --out data/payloads_seed.json
```

## Stato dei lavori

- [x] **M0** - Scheletro: il server parte e mostra la home
- [x] **M1** - Database, modelli e riempimento del catalogo (base + import da PayloadsAllTheThings)
- [x] **M2** - Catalogo navigabile: sezioni (porte/tecnologie/tecniche), ricerca e dettaglio voce
- [ ] **M3** - Progetti e findings
- [ ] **M4** - Report ed esportazione
- [ ] **M5** - Rifiniture (ricerca, modifica del catalogo, grafica)
