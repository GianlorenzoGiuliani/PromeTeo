"""
Contenuti iniziali del catalogo ("base pronta").

Sono riferimenti STANDARD e pubblici: il tipo di metodologia che si trova nei
corsi di sicurezza e nella documentazione ufficiale dei tool. Nei comandi,
<ip> e <url> sono segnaposto da sostituire con il bersaglio reale.

    ⚠️ Usa questi test solo su sistemi per cui hai un'autorizzazione esplicita.

Due modi per popolare il catalogo:
  - automatico: al primo avvio dell'app, se il catalogo e' vuoto;
  - manuale:    python -m app.seed
"""
import json

from sqlmodel import Session, select

from app.database import BASE_DIR, create_db_and_tables, engine
from app.models import KIND_PORT, KIND_TECH, KIND_TECHNIQUE, Check, Topic

# JSON con le tecniche importate da PayloadsAllTheThings (prodotto da
# tools/import_payloads.py). Lo teniamo versionato: cosi' chiunque cloni il
# progetto ottiene lo stesso catalogo, senza dover riscaricare la fonte.
PAYLOADS_SEED_PATH = BASE_DIR / "data" / "payloads_seed.json"


def build_starter_topics() -> list[Topic]:
    """Costruisce (in memoria) le voci di partenza con i loro test."""
    topics: list[Topic] = []

    # ---------------------------- PORTE ----------------------------

    rdp = Topic(
        kind=KIND_PORT, name="RDP", port=3389, protocol="tcp",
        description="Remote Desktop Protocol: il desktop remoto di Windows.",
        detection="Porta 3389/tcp aperta; nmap la riconosce come 'ms-wbt-server'.",
        references="https://book.hacktricks.xyz/network-services-pentesting/pentesting-rdp",
    )
    rdp.checks = [
        Check(
            title="Ricognizione del servizio (cifratura e NLA)",
            goal="Capire versione, cifratura e se e' richiesta la Network Level Authentication.",
            tool="nmap",
            command="nmap -p 3389 --script rdp-enum-encryption,rdp-ntlm-info <ip>",
            interpretation="Se la NLA risulta disabilitata, il servizio e' piu' esposto: annota il dettaglio.",
            references="https://nmap.org/nsedoc/scripts/rdp-ntlm-info.html",
        ),
        Check(
            title="BlueKeep (CVE-2019-0708)",
            goal="Verificare la presenza della vulnerabilita' pre-autenticazione BlueKeep.",
            tool="nmap",
            command="nmap -p 3389 --script rdp-vuln-ms12-020 <ip>",
            interpretation="Un esito 'VULNERABLE' = sistema non aggiornato: finding critico (CVE-2019-0708).",
            references="https://msrc.microsoft.com/update-guide/vulnerability/CVE-2019-0708",
        ),
    ]
    topics.append(rdp)

    smb = Topic(
        kind=KIND_PORT, name="SMB", port=445, protocol="tcp",
        description="Server Message Block: condivisione file e stampanti su rete Windows.",
        detection="Porte 445/tcp (e 139/tcp) aperte; nmap mostra 'microsoft-ds'.",
        references="https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb",
    )
    smb.checks = [
        Check(
            title="Enumerazione senza credenziali (null session)",
            goal="Verificare se si possono elencare share/utenti senza autenticazione.",
            tool="smbclient / enum4linux",
            command="smbclient -L //<ip>/ -N    #   oppure:   enum4linux -a <ip>",
            interpretation="Se ottieni l'elenco delle share senza password, la 'null session' e' abilitata: da segnalare.",
            references="https://www.samba.org/samba/docs/current/man-html/smbclient.1.html",
        ),
        Check(
            title="EternalBlue (MS17-010)",
            goal="Verificare la vulnerabilita' SMBv1 MS17-010.",
            tool="nmap",
            command="nmap -p 445 --script smb-vuln-ms17-010 <ip>",
            interpretation="Esito 'VULNERABLE' = finding critico (CVE-2017-0144). Spesso indica anche SMBv1 attivo.",
            references="https://nmap.org/nsedoc/scripts/smb-vuln-ms17-010.html",
        ),
    ]
    topics.append(smb)

    ftp = Topic(
        kind=KIND_PORT, name="FTP", port=21, protocol="tcp",
        description="File Transfer Protocol: trasferimento file (spesso in chiaro).",
        detection="Porta 21/tcp aperta; il banner mostra il software del server FTP.",
        references="https://book.hacktricks.xyz/network-services-pentesting/pentesting-ftp",
    )
    ftp.checks = [
        Check(
            title="Login anonimo",
            goal="Verificare se e' permesso l'accesso anonimo.",
            tool="nmap",
            command="nmap -p 21 --script ftp-anon <ip>    #   o a mano: ftp <ip>  (utente: anonymous)",
            interpretation="Se compare 'Anonymous login allowed' puoi entrare senza credenziali: da segnalare.",
            references="https://nmap.org/nsedoc/scripts/ftp-anon.html",
        ),
    ]
    topics.append(ftp)

    # -------------------------- TECNOLOGIE --------------------------

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
            interpretation="Plugin/temi segnalati come vulnerabili e relativi CVE diventano findings. (Per i dati sulle vulnerabilita' serve un API token gratuito di WPScan.)",
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


def seed_if_empty() -> int:
    """Inserisce i contenuti di partenza SOLO se il catalogo e' ancora vuoto.

    Restituisce il numero di voci inserite (0 se il catalogo era gia' popolato).
    Questo controllo evita di creare doppioni a ogni avvio.
    """
    with Session(engine) as session:
        # Controlliamo solo le voci "di base" (porte e tecnologie): le tecniche
        # importate hanno un loro controllo separato, piu' sotto.
        gia_presenti = session.exec(
            select(Topic).where(Topic.kind.in_([KIND_PORT, KIND_TECH]))
        ).first()
        if gia_presenti is not None:
            return 0

        topics = build_starter_topics()
        session.add_all(topics)
        session.commit()
        return len(topics)


def load_payload_topics() -> list[Topic]:
    """Legge il JSON di PayloadsAllTheThings e costruisce Topic + Check (in memoria)."""
    if not PAYLOADS_SEED_PATH.exists():
        return []

    data = json.loads(PAYLOADS_SEED_PATH.read_text(encoding="utf-8"))
    topics: list[Topic] = []
    for t in data.get("topics", []):
        topic = Topic(
            kind=t.get("kind", KIND_TECHNIQUE),
            name=t["name"],
            description=t.get("description", ""),
            detection=t.get("detection"),
            references=t.get("source_url"),
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


def seed_payloads_if_absent() -> int:
    """Carica le tecniche (PayloadsAllTheThings) solo se non gia' presenti.

    Restituisce il numero di categorie inserite (0 se erano gia' nel database).
    """
    with Session(engine) as session:
        gia_presenti = session.exec(
            select(Topic).where(Topic.kind == KIND_TECHNIQUE)
        ).first()
        if gia_presenti is not None:
            return 0

        topics = load_payload_topics()
        if not topics:
            return 0

        session.add_all(topics)
        session.commit()
        return len(topics)


if __name__ == "__main__":
    # Eseguito con:  python -m app.seed
    create_db_and_tables()
    base = seed_if_empty()
    tecniche = seed_payloads_if_absent()
    print(f"Base del catalogo (porte/tecnologie): {base} voci inserite."
          if base else "Base del catalogo gia' presente.")
    print(f"Tecniche (PayloadsAllTheThings): {tecniche} categorie inserite."
          if tecniche else "Tecniche gia' presenti.")
