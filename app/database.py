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


def get_session():
    """Fornisce una 'sessione' per leggere/scrivere nel database.

    Una sessione e' come una conversazione col database: la apri, fai quel che
    serve, e la chiudi. Il costrutto 'with ... yield' la chiude automaticamente.
    La useremo nelle pagine a partire dal prossimo step (Milestone 2).
    """
    with Session(engine) as session:
        yield session
