"""
I "modelli" di Prometeo: descrivono QUALI dati salviamo e COME si collegano.
Ogni classe con `table=True` diventa una tabella nel database.

Due gruppi:
  - CATALOGO (consultazione):   Topic, Check
  - LAVORO (i tuoi progetti):   Project, Finding
"""
from datetime import datetime, timezone
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel

# --- Valori ammessi, scritti in un punto solo per non sbagliare a digitarli ---

KIND_PORT = "port"            # una voce del catalogo che rappresenta una porta
KIND_TECH = "tech"            # una voce del catalogo che rappresenta una tecnologia
KIND_TECHNIQUE = "technique"  # una tecnica / classe di vulnerabilita' (es. SQL Injection)
KIND_AD = "ad"               # metodologia su Active Directory
KIND_WEB = "web"             # metodologia su applicazioni web

# Gravita' di un finding, dalla piu' grave alla meno grave.
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Stato di un finding nel tempo.
STATUSES = ["open", "confirmed", "false_positive", "resolved"]

# Stati "chiusi": entrando in uno di questi registriamo la data di chiusura.
CLOSED_STATUSES = {"resolved", "false_positive"}

# Probabilita' che la vulnerabilita' venga sfruttata (valutazione del rischio).
LIKELIHOODS = ["high", "medium", "low"]


# ==============================  CATALOGO  ==============================

class Topic(SQLModel, table=True):
    """Una voce del catalogo: una PORTA (es. RDP/3389) o una TECNOLOGIA (es. WordPress)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(index=True)            # KIND_PORT oppure KIND_TECH
    name: str = Field(index=True)            # es. "RDP", "WordPress"
    port: Optional[int] = None               # es. 3389 (solo per le porte)
    protocol: Optional[str] = None           # es. "tcp" (solo per le porte)
    description: str = ""                     # cos'e' / a cosa serve (riga breve)
    intro: Optional[str] = None              # spiegazione piu' approfondita del servizio
    detection: Optional[str] = None          # come riconoscerlo durante il test
    references: Optional[str] = None         # link di approfondimento (es. HackTricks)

    # Una voce ha molti test. `back_populates` collega i due lati della relazione:
    # da un Topic arrivo ai suoi Check, e da un Check torno al suo Topic.
    checks: list["Check"] = Relationship(back_populates="topic")


class Check(SQLModel, table=True):
    """Un test da fare su una voce del catalogo: scopo, comando, come leggere il risultato."""

    id: Optional[int] = Field(default=None, primary_key=True)
    # `foreign_key` dice: questo numero e' l'id di una riga della tabella 'topic'.
    # E' cosi' che un test "appartiene" a una voce del catalogo.
    topic_id: int = Field(foreign_key="topic.id", index=True)

    title: str                               # es. "Login anonimo RDP"
    goal: Optional[str] = None               # cosa stai verificando
    tool: Optional[str] = None               # es. "nmap", "wpscan"
    command: Optional[str] = None            # il comando da lanciare
    interpretation: Optional[str] = None     # "se nell'output vedi X -> vulnerabile"
    references: Optional[str] = None         # link o note

    topic: Optional[Topic] = Relationship(back_populates="checks")


# ======================  LAVORO (progetti e findings)  ======================

class Project(SQLModel, table=True):
    """Un'attivita' di pentest: raccoglie i findings per poi generare il report."""

    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    client: Optional[str] = None             # il cliente dell'attivita'
    company: Optional[str] = None            # la tua azienda (intestazione del report)
    author: Optional[str] = None             # chi ha eseguito il test
    scope: Optional[str] = None              # note sullo scope / autorizzazione
    info: Optional[str] = None               # note operative: VPN, credenziali, accessi...
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # Un progetto ha molti bersagli (target), tecnologie e findings.
    targets: list["Target"] = Relationship(back_populates="project")
    technologies: list["Technology"] = Relationship(back_populates="project")
    findings: list["Finding"] = Relationship(back_populates="project")


class Target(SQLModel, table=True):
    """Un bersaglio dentro un progetto: un host/IP e/o un URL, riusabile dai findings."""

    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    name: Optional[str] = None               # etichetta, es. "DC01" o "Web app login"
    host: Optional[str] = None               # IP o hostname
    port: Optional[int] = None               # porta
    url: Optional[str] = None                # URL / endpoint
    notes: Optional[str] = None              # note sul singolo bersaglio

    project: Optional[Project] = Relationship(back_populates="targets")


class Technology(SQLModel, table=True):
    """Una tecnologia individuata in un progetto (es. 'nginx 1.18.0'), con il
    suo CPE. Dal CPE si interroga l'NVD per sapere quali CVE la riguardano."""

    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    # La tecnologia appartiene a un TARGET del progetto (si aggiunge entrando
    # nel target). project_id resta per comodita' di aggregazione per progetto.
    target_id: Optional[int] = Field(default=None, foreign_key="target.id", index=True)
    name: Optional[str] = None            # es. "nginx", "Apache httpd"
    version: Optional[str] = None         # es. "1.18.0"
    cpe: Optional[str] = None             # es. "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    project: Optional[Project] = Relationship(back_populates="technologies")


class Finding(SQLModel, table=True):
    """Una vulnerabilita' trovata durante un progetto."""

    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)
    # Il bersaglio ora si SELEZIONA tra i target del progetto (facoltativo).
    target_id: Optional[int] = Field(default=None, foreign_key="target.id")

    title: str                               # es. "RDP: login anonimo possibile"
    description: Optional[str] = None
    severity: str = "medium"                 # uno tra SEVERITIES
    status: str = "open"                     # uno tra STATUSES
    evidence: Optional[str] = None           # la prova: output del comando, screenshot...
    remediation: Optional[str] = None        # come correggerla (va nel report)
    cve: Optional[str] = None                # es. "CVE-2019-0708"
    cwe: Optional[str] = None                # es. "CWE-89"
    port: Optional[int] = None               # la porta dove e' stato trovato (es. 3389)

    # --- Valutazione del rischio e ciclo di vita ---
    impact: Optional[str] = None             # impatto se la vulnerabilita' e' sfruttata
    likelihood: Optional[str] = None         # probabilita': uno tra LIKELIHOODS
    reproduction: Optional[str] = None       # passi per riprodurre
    references: Optional[str] = None         # riferimenti / link di approfondimento
    cvss_vector: Optional[str] = None        # es. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/..."
    cvss_score: Optional[float] = None       # punteggio CVSS 0.0-10.0
    assignee: Optional[str] = None           # a chi e' assegnata la verifica/correzione
    retest: Optional[str] = None             # esito della verifica della correzione (retest)
    closed_at: Optional[datetime] = None     # quando il finding e' stato chiuso

    # Campi "bersaglio" storici: restano per i findings creati prima dei target.
    # I nuovi findings usano 'target_id' qui sopra (si seleziona un target).
    target_host: Optional[str] = None        # (storico) IP o hostname
    target_port: Optional[int] = None        # (storico) porta
    target_url: Optional[str] = None         # (storico) URL / endpoint

    # Collegamento FACOLTATIVO al catalogo, se il finding nasce da un test.
    topic_id: Optional[int] = Field(default=None, foreign_key="topic.id")
    check_id: Optional[int] = Field(default=None, foreign_key="check.id")

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    project: Optional[Project] = Relationship(back_populates="findings")


class FindingEvent(SQLModel, table=True):
    """Una riga dello storico di un finding: cosa e' cambiato e quando.

    Ogni volta che un finding viene creato o modificato, aggiungiamo qui una
    riga leggibile (es. "Stato: aperto -> risolto"). Cosi' resta traccia del
    ciclo di vita senza toccare il finding stesso."""

    id: Optional[int] = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="finding.id", index=True)
    at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    message: str                             # descrizione leggibile del cambiamento
