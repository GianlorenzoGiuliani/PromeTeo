"""
Contenuti iniziali del catalogo ("base pronta").

Sono riferimenti STANDARD e pubblici: il tipo di metodologia che si trova nei
corsi di sicurezza e nella documentazione ufficiale dei tool. Nei comandi,
<ip> e <url> sono segnaposto da sostituire con il bersaglio reale.

    ⚠️ Usa questi test solo su sistemi per cui hai un'autorizzazione esplicita.

Il catalogo si popola da tre fonti, ognuna con il suo controllo anti-doppioni:
  - PORTE: da data/ports_seed.json (generato da tools/build_ports.py);
  - TECNOLOGIE: scritte a mano qui sotto;
  - TECNICHE: da data/payloads_seed.json (PayloadsAllTheThings).

Due modi per popolare: automatico al primo avvio, oppure  python -m app.seed
"""
import json

from sqlmodel import Session, select

from app.database import BASE_DIR, create_db_and_tables, engine
from app.models import KIND_PORT, KIND_TECH, KIND_TECHNIQUE, Check, Topic

PORTS_SEED_PATH = BASE_DIR / "data" / "ports_seed.json"
PAYLOADS_SEED_PATH = BASE_DIR / "data" / "payloads_seed.json"


def load_topics_json(path, default_kind: str) -> list[Topic]:
    """Legge un file JSON e costruisce i Topic + Check (in memoria).

    Funziona sia per le porte sia per le tecniche: il riferimento della voce
    si prende da 'references' oppure da 'source_url', a seconda del file.
    """
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    topics: list[Topic] = []
    for t in data.get("topics", []):
        topic = Topic(
            kind=t.get("kind", default_kind),
            name=t["name"],
            port=t.get("port"),
            protocol=t.get("protocol"),
            description=t.get("description", ""),
            detection=t.get("detection"),
            references=t.get("references") or t.get("source_url"),
        )
        topic.checks = [
            Check(
                title=c["title"],
                goal=c.get("goal"),
                tool=c.get("tool"),
                command=c.get("command"),
                interpretation=c.get("interpretation"),
                references=c.get("references"),
            )
            for c in t.get("checks", [])
        ]
        topics.append(topic)
    return topics


def build_tech_topics() -> list[Topic]:
    """Le voci "tecnologia" di base, scritte a mano (WordPress, campo web)."""
    topics: list[Topic] = []

    wp = Topic(
        kind=KIND_TECH, name="WordPress",
        description="CMS molto diffuso per siti e blog.",
        detection="Presenza di /wp-login.php, /wp-admin/, meta generator 'WordPress', cartella /wp-content/.",
        references="https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/wordpress",
    )
    wp.checks = [
        Check(
            title="Scansione con WPScan",
            goal="Rilevare versione, utenti, plugin e temi vulnerabili.",
            tool="wpscan",
            command="wpscan --url <url> --enumerate u,vp,vt",
            interpretation="Plugin/temi segnalati come vulnerabili e relativi CVE diventano findings. (Serve un API token gratuito di WPScan per i dati sulle vulnerabilita'.)",
            references="https://github.com/wpscanteam/wpscan",
        ),
        Check(
            title="Enumerazione utenti",
            goal="Scoprire nomi utente validi.",
            tool="wpscan",
            command="wpscan --url <url> --enumerate u    #   indizio manuale: <url>/?author=1",
            interpretation="Gli username trovati sono utili per i test di autenticazione (sempre e solo in scope).",
            references="https://github.com/wpscanteam/wpscan",
        ),
    ]
    topics.append(wp)

    webinput = Topic(
        kind=KIND_TECH, name="Campo di input / login (web)",
        description="Qualsiasi campo di una web app dove l'utente inserisce dati (login, ricerca, filtri...).",
        detection="Form HTML, parametri nell'URL (?id=1), campi user/password.",
        references="https://book.hacktricks.xyz/pentesting-web/sql-injection",
    )
    webinput.checks = [
        Check(
            title="Test di SQL injection",
            goal="Verificare se un parametro finisce in una query SQL senza controlli.",
            tool="sqlmap",
            command='sqlmap -u "<url>?id=1" --batch',
            interpretation="Se sqlmap indica il parametro come 'injectable' c'e' una SQL injection: finding (CWE-89). Testa solo i parametri in scope.",
            references="https://github.com/sqlmapproject/sqlmap/wiki",
        ),
        Check(
            title="Prova manuale con caratteri speciali",
            goal="Primo indizio rapido di comportamenti anomali.",
            tool="browser / curl",
            command="Inserisci nel campo caratteri come  '  \"  )  e osserva la risposta.",
            interpretation="Errori SQL in pagina, risposte diverse o tempi anomali suggeriscono un punto da approfondire con sqlmap.",
            references="https://owasp.org/www-community/attacks/SQL_Injection",
        ),
    ]
    topics.append(webinput)

    return topics


def _seed_if_absent(kind: str, topics: list[Topic]) -> int:
    """Inserisce 'topics' solo se non esistono gia' voci di quel 'kind'."""
    if not topics:
        return 0
    with Session(engine) as session:
        gia_presenti = session.exec(select(Topic).where(Topic.kind == kind)).first()
        if gia_presenti is not None:
            return 0
        session.add_all(topics)
        session.commit()
        return len(topics)


def seed_ports_if_absent() -> int:
    """Carica le porte da data/ports_seed.json, se non ancora presenti."""
    return _seed_if_absent(KIND_PORT, load_topics_json(PORTS_SEED_PATH, KIND_PORT))


def seed_tech_if_absent() -> int:
    """Carica le tecnologie di base, se non ancora presenti."""
    return _seed_if_absent(KIND_TECH, build_tech_topics())


def seed_payloads_if_absent() -> int:
    """Carica le tecniche (PayloadsAllTheThings), se non ancora presenti."""
    return _seed_if_absent(KIND_TECHNIQUE, load_topics_json(PAYLOADS_SEED_PATH, KIND_TECHNIQUE))


if __name__ == "__main__":
    # Eseguito con:  python -m app.seed
    create_db_and_tables()
    porte = seed_ports_if_absent()
    tecno = seed_tech_if_absent()
    tecniche = seed_payloads_if_absent()
    print(f"Porte: {porte} inserite." if porte else "Porte gia' presenti.")
    print(f"Tecnologie: {tecno} inserite." if tecno else "Tecnologie gia' presenti.")
    print(f"Tecniche (PayloadsAllTheThings): {tecniche} inserite." if tecniche else "Tecniche gia' presenti.")
