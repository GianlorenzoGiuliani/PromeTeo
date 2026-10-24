"""
Configurazione del database di PromeTeus.

Usiamo SQLite: salva TUTTO in un unico file (prometeus.db) nella cartella del
progetto. Nessun server da installare e i dati restano sul tuo computer.
"""
from pathlib import Path

from sqlmodel import Session, SQLModel, create_engine

# Il file del database sta nella cartella radice del progetto (una sopra "app").
BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "prometeus.db"

# L'"engine" e' l'oggetto che sa come parlare col database.
#   - echo=True stamperebbe ogni query SQL: utile per imparare o per il debug.
#   - check_same_thread=False serve a SQLite per lavorare bene con un server web
#     (che gestisce piu' richieste contemporaneamente).
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    echo=False,
    connect_args={"check_same_thread": False},
)


def create_db_and_tables() -> None:
    """Crea il file del database e tutte le tabelle, se non esistono gia'."""
    # Importiamo i modelli in modo che SQLModel "sappia" quali tabelle creare.
    from app import models  # noqa: F401  (import necessario per registrare le tabelle)

    SQLModel.metadata.create_all(engine)
    _run_light_migrations()


def _run_light_migrations() -> None:
    """Migrazione leggera: aggiunge le colonne nuove alle tabelle gia' esistenti.

    'create_all' crea le tabelle che mancano, ma NON aggiunge colonne a una
    tabella che esiste gia'. Quando aggiungiamo un campo a un modello, qui
    controlliamo se la colonna c'e' e, se manca, la creiamo con ALTER TABLE.
    Cosi' aggiorniamo lo schema senza cancellare i dati gia' salvati.
    (Per progetti grandi si usano strumenti dedicati, es. Alembic; qui basta questo.)
    """
    # Per ogni tabella: le colonne che il modello si aspetta, con il tipo SQL.
    # (La tabella 'target', essendo nuova, la crea gia' create_all.)
    attese = {
        "project": [("company", "VARCHAR"), ("author", "VARCHAR"), ("info", "TEXT")],
        "finding": [("target_id", "INTEGER")],
        "topic": [("intro", "TEXT")],
    }
    with engine.connect() as conn:
        for tabella, colonne in attese.items():
            presenti = {row[1] for row in conn.exec_driver_sql(f"PRAGMA table_info({tabella})")}
            for nome, tipo in colonne:
                if nome not in presenti:
                    conn.exec_driver_sql(f"ALTER TABLE {tabella} ADD COLUMN {nome} {tipo}")
        conn.commit()


def get_session():
    """Fornisce una 'sessione' per leggere/scrivere nel database.

    Una sessione e' come una conversazione col database: la apri, fai quel che
    serve, e la chiudi. Il costrutto 'with ... yield' la chiude automaticamente.
    La useremo nelle pagine a partire dal prossimo step (Milestone 2).
    """
    with Session(engine) as session:
        yield session
