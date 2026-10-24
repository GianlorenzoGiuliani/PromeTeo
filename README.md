# PromeTeus

Assistente per penetration test **autorizzati**. Ti aiuta a ricordare:

- **cosa testare** quando trovi una porta aperta o riconosci una tecnologia;
- **quali strumenti e comandi** usare;
- **come interpretare i risultati** ("se nell'output vedi X, c'e' la vulnerabilita' Y");
- a **tenere traccia dei findings** per generare il **report** finale.

> ⚠️ Usa PromeTeus solo su sistemi per cui hai un'autorizzazione esplicita
> (ingaggio di pentest, programma di bug bounty in scope, laboratori o CTF).

📖 **Nuovo qui?** Parti dalla [guida passo-passo con screenshot](GUIDA.md).

## Com'e' fatto (in breve)

- **Python + FastAPI**: un piccolo server web che gira sul tuo computer.
- **Jinja2**: i template delle pagine HTML.
- **SQLite** (dal prossimo step): i dati, salvati in un file **in locale**.

## Requisiti

- [Python 3.10+](https://www.python.org/downloads/)

## Avvio rapido (con un doppio clic)

Se hai gia' [Python 3.10+](https://www.python.org/downloads/) installato, non serve il terminale:

- **Windows:** doppio clic su **`avvia.bat`**
- **macOS / Linux:** esegui **`./avvia.sh`** (su macOS, se il doppio clic apre un
  editor, lancialo da Terminale oppure rinominalo in `avvia.command`)

La prima volta lo script prepara l'ambiente e installa le librerie da solo; poi
avvia PromeTeus e apre il browser su http://127.0.0.1:8000. Per fermarlo: `Ctrl + C`.

## Come avviarlo (manuale)

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

# 4) Avvia l'app (--host 127.0.0.1 = ascolta solo sul tuo computer)
uvicorn app.main:app --host 127.0.0.1 --reload
```

> 🔒 **Nota di sicurezza:** PromeTeus ascolta di proposito solo su
> `127.0.0.1` (il tuo computer), quindi non e' raggiungibile da altri in rete.
> I form che modificano dati sono protetti da un token anti-CSRF.

Apri il browser su **http://127.0.0.1:8000**
(la documentazione automatica delle API e' su **/docs**).
Per fermare il server: `Ctrl + C`.

## Struttura del progetto

```
PromeTeus/
├─ app/
│  ├─ __init__.py        # rende "app" un pacchetto Python
│  ├─ main.py            # regia: crea l'app, prepara il DB, monta i router
│  ├─ web.py             # pezzi condivisi: template, etichette, utility, CSRF
│  ├─ ai.py              # assistente AI (API di Claude): compila i findings
│  ├─ database.py        # configurazione del database SQLite
│  ├─ models.py          # le "tabelle": Topic, Check, Project, Target, Finding
│  ├─ reporting.py       # costruisce il report in Markdown
│  ├─ seed.py            # carica i contenuti iniziali nel database
│  ├─ routers/           # le pagine, divise per area
│  │  ├─ home.py         # la home
│  │  ├─ catalogo.py     # catalogo + gestione voci/test
│  │  ├─ progetti.py     # progetti
│  │  ├─ findings.py     # findings
│  │  ├─ target.py       # target (bersagli di un progetto)
│  │  ├─ report.py       # report (HTML e Markdown)
│  │  └─ ai.py           # endpoint dell'assistente AI
│  ├─ templates/         # le pagine HTML
│  │  ├─ base.html       # struttura comune a tutte le pagine
│  │  └─ home.html       # la home
│  └─ static/
│     ├─ style.css       # lo stile grafico
│     └─ app.js          # il poco JavaScript lato browser (tasto Copia)
├─ data/
│  ├─ ports_seed.json    # catalogo delle porte/servizi comuni
│  ├─ ad_seed.json       # metodologia Active Directory
│  ├─ web_seed.json      # metodologia Web App
│  └─ payloads_seed.json # tecniche importate da PayloadsAllTheThings
├─ tools/
│  ├─ build_ports.py     # genera data/ports_seed.json
│  ├─ build_ad.py        # genera data/ad_seed.json
│  ├─ build_web.py       # genera data/web_seed.json
│  └─ import_payloads.py # trasforma PayloadsAllTheThings nel formato di PromeTeus
├─ requirements.txt      # elenco delle librerie da installare
├─ avvia.sh / avvia.bat  # avvio rapido (macOS-Linux / Windows)
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

- un catalogo di **porte/servizi comuni** (`data/ports_seed.json`, con tool e
  comandi noti) e di **tecnologie** (`app/seed.py`);
- sezioni di metodologia per **Active Directory** (`data/ad_seed.json`) e
  **Web App** (`data/web_seed.json`);
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

## Assistente AI (facoltativo)

Nel form di un finding c'e' un riquadro **Assistente AI**: scrivi la
vulnerabilita' a grandi linee e lui compila tutti i campi (titolo, gravita',
CVSS, impatto, passi per riprodurre, rimedio, riferimenti...). Poi **controlli
e correggi** prima di salvare: l'AI assiste, non decide al posto tuo.

Per attivarlo serve una chiave API di Claude:

```bash
export ANTHROPIC_API_KEY="la-tua-chiave"      # macOS / Linux
#  setx ANTHROPIC_API_KEY "la-tua-chiave"      # Windows (poi riapri il terminale)
```

Poi avvia PromeTeus normalmente. **Senza chiave il riquadro mostra un avviso e
tutto il resto dell'app funziona lo stesso.**

Il modello di default e' `claude-opus-5-5`. Per spendere molto meno puoi
cambiarlo con una variabile d'ambiente:

```bash
export PROMETEUS_AI_MODEL="claude-haiku-5-5"   # piu' economico
```

> ⚠️ La descrizione che scrivi viene inviata all'API di Claude. Usa solo dati
> di test autorizzati ed evita di incollare segreti reali (credenziali, chiavi).

## Stato dei lavori

- [x] **M0** - Scheletro: il server parte e mostra la home
- [x] **M1** - Database, modelli e riempimento del catalogo (base + import da PayloadsAllTheThings)
- [x] **M2** - Catalogo navigabile: sezioni (porte/tecnologie/tecniche), ricerca e dettaglio voce
- [x] **M3** - Progetti e findings (anche partendo da un test del catalogo)
- [x] **M4** - Report del progetto (pagina stampabile/PDF + export Markdown)
- [x] **M5** - Modifica ed eliminazione di progetti e findings (CRUD completo)
- [x] **M6** - Gestione del catalogo dall'app, comodità (copia comando, filtri, ricerca) e report più ricco
