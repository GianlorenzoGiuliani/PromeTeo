"""
I "modelli" di PromeTeus: descrivono QUALI dati salviamo e COME si collegano.
Ogni classe con `table=True` diventa una tabella nel database.

Due gruppi:
  - CATALOGO (consultazione):   Topic, Check
  - LAVORO (i tuoi progetti):   Project, Finding
"""
from datetime import datetime
from typing import Optional

from sqlmodel import Field, Relationship, SQLModel

# --- Valori ammessi, scritti in un punto solo per non sbagliare a digitarli ---

KIND_PORT = "port"            # una voce del catalogo che rappresenta una porta
KIND_TECH = "tech"            # una voce del catalogo che rappresenta una tecnologia
KIND_TECHNIQUE = "technique"  # una tecnica / classe di vulnerabilita' (es. SQL Injection)

# Gravita' di un finding, dalla piu' grave alla meno grave.
SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Stato di un finding nel tempo.
STATUSES = ["open", "confirmed", "false_positive", "resolved"]


# ==============================  CATALOGO  ==============================

class Topic(SQLModel, table=True):
    """Una voce del catalogo: una PORTA (es. RDP/3389) o una TECNOLOGIA (es. WordPress)."""

    id: Optional[int] = Field(default=None, primary_key=True)
    kind: str = Field(index=True)            # KIND_PORT oppure KIND_TECH
    name: str = Field(index=True)            # es. "RDP", "WordPress"
    port: Optional[int] = None               # es. 3389 (solo per le porte)
    protocol: Optional[str] = None           # es. "tcp" (solo per le porte)
    description: str = ""                     # cos'e' / a cosa serve
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
    scope: Optional[str] = None              # note sullo scope / autorizzazione
    created_at: datetime = Field(default_factory=datetime.now)

    findings: list["Finding"] = Relationship(back_populates="project")


class Finding(SQLModel, table=True):
    """Una vulnerabilita' trovata durante un progetto."""

    id: Optional[int] = Field(default=None, primary_key=True)
    project_id: int = Field(foreign_key="project.id", index=True)

    title: str                               # es. "RDP: login anonimo possibile"
    description: Optional[str] = None
    severity: str = "medium"                 # uno tra SEVERITIES
    status: str = "open"                     # uno tra STATUSES
    evidence: Optional[str] = None           # la prova: output del comando, screenshot...
    remediation: Optional[str] = None        # come correggerla (va nel report)
    cve: Optional[str] = None                # es. "CVE-2019-0708"
    cwe: Optional[str] = None                # es. "CWE-89"

    # Il bersaglio: puo' essere host+porta (rete) e/o un URL (web app).
    # Sono tutti facoltativi, cosi' copriamo entrambi i casi senza obbligare nulla.
    target_host: Optional[str] = None        # IP o hostname
    target_port: Optional[int] = None        # porta
    target_url: Optional[str] = None         # URL / endpoint

    # Collegamento FACOLTATIVO al catalogo, se il finding nasce da un test.
    topic_id: Optional[int] = Field(default=None, foreign_key="topic.id")
    check_id: Optional[int] = Field(default=None, foreign_key="check.id")

    created_at: datetime = Field(default_factory=datetime.now)

    project: Optional[Project] = Relationship(back_populates="findings")
