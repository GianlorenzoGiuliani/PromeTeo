# Guida rapida a PromeTeus

Questa guida ti accompagna nell'uso di PromeTeus passo per passo, con le
immagini di ogni schermata. È pensata per chi parte da zero.

> ⚠️ **Promemoria:** usa PromeTeus solo su sistemi per cui hai
> un'autorizzazione esplicita (ingaggio di pentest, bug bounty in scope,
> laboratori o CTF).

---

## 1. Avvio

- **Windows:** doppio clic su `avvia.bat`
- **macOS / Linux:** esegui `./avvia.sh` da terminale

La prima volta lo script prepara tutto da solo, poi apre il browser su
**http://127.0.0.1:8000**. Per fermarlo: `Ctrl + C`.
(I dettagli e l'avvio manuale sono nel [README](README.md).)

---

## 2. La home

Appena apri PromeTeus trovi le quattro aree principali: le tre sezioni del
**catalogo** (Porte, Tecnologie, Tecniche) e l'area **Progetti & findings**.
Ogni card mostra quante voci contiene.

![La home di PromeTeus](docs/img/01-home.png)

---

## 3. Il catalogo — *cosa testare*

Il catalogo risponde alla domanda "ho trovato questa cosa, cosa ci faccio?".
È diviso in tre sezioni:

- **Porte** (es. RDP, SMB, FTP) — quando trovi una porta aperta
- **Tecnologie** (es. WordPress) — quando riconosci una tecnologia
- **Tecniche** (SQLi, XSS, SSRF…) — classi di vulnerabilità e payload

In alto hai una **ricerca** per nome e i **filtri** per sezione.

![Il catalogo con ricerca e filtri](docs/img/02-catalogo.png)

---

## 4. Una voce e i suoi test

Cliccando una voce (qui **RDP**) vedi, per ogni test:

- l'**obiettivo** (cosa stai verificando);
- il **comando / payload** da lanciare — con il tasto **Copia**;
- **come leggere il risultato** ("se vedi X, c'è la vulnerabilità");
- il link **Fonte** per approfondire.

Da qui puoi anche **gestire il catalogo** (`+ Aggiungi test`, `Modifica voce`,
`Elimina voce`) e, soprattutto, trasformare un test in un finding con
**`+ Aggiungi come finding`**: apre il modulo già pre-compilato.

![Dettaglio della voce RDP con i suoi test](docs/img/03-voce-rdp.png)

---

## 5. Creare un progetto

Un **progetto** è un'attività di pentest: raccoglie i tuoi findings per poi
generare il report. Vai su **Progetti → Nuovo progetto** e compila:

- **Nome** dell'attività e **Cliente**;
- **La tua azienda** e **Autore** (compaiono nell'intestazione del report);
- **Scope / note** (utile annotare qui l'autorizzazione).

---

## 6. Segnare un finding

Quando un test conferma una vulnerabilità, la registri come **finding**.
Il modulo ti fa indicare: progetto, titolo, **gravità** e **stato**, il
**bersaglio** (host+porta *e/o* URL), **CVE/CWE**, descrizione, la **prova**
(l'output che la dimostra) e il **rimedio**.

![Il modulo per aggiungere un finding](docs/img/04-nuovo-finding.png)

---

## 7. Il progetto e i suoi findings

Nella pagina del progetto vedi tutti i findings, ordinati per gravità e con un
bordo colorato (rosso = critica, arancione = alta…). Puoi **filtrarli** per
gravità/stato, **modificarli** o **eliminarli**, e in alto trovi i pulsanti per
il **report**.

![La pagina di un progetto con i findings](docs/img/05-progetto.png)

---

## 8. Generare il report

Il pulsante **Vedi report** produce il documento finale: intestazione con la
tua azienda e l'autore, un **riepilogo** per gravità, e i findings
**raggruppati e numerati**. Da lì puoi:

- **Stampa / PDF** (il tasto apre la stampa del browser → "Salva come PDF");
- **Scarica .md** per avere il report come file di testo (Markdown), comodo da
  convertire o incollare altrove.

![Il report del progetto](docs/img/06-report.png)

---

## 9. Personalizzare il catalogo

PromeTeus parte con un catalogo già pieno (porte e tecnologie comuni + tecniche
da PayloadsAllTheThings), ma è **tutto tuo**: dal **Catalogo → `+ Nuova voce`**
aggiungi le tue porte/tecnologie/tecniche, e dentro ogni voce aggiungi i tuoi
test con i comandi che usi davvero. Col tempo diventa il *tuo* metodo di lavoro.

---

## Il flusso tipico, in breve

1. Trovi una porta aperta o una tecnologia → la cerchi nel **Catalogo**
2. Apri la voce → leggi **test, comando e come interpretare il risultato**
3. Il test conferma la vulnerabilità → **`+ Aggiungi come finding`**
4. A fine attività → **Report** (schermo, PDF o Markdown) da consegnare

Buon lavoro — e ricorda: solo su bersagli **autorizzati**.
