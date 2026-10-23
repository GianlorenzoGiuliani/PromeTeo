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
from sqlmodel import Session, select

from app.database import create_db_and_tables, engine
from app.models import KIND_PORT, KIND_TECH, Check, Topic


def build_starter_topics() -> list[Topic]:
    """Costruisce (in memoria) le voci di partenza con i loro test."""
    topics: list[Topic] = []

    # ---------------------------- PORTE ----------------------------

    rdp = Topic(
        kind=KIND_PORT, name="RDP", port=3389, protocol="tcp",
        description="Remote Desktop Protocol: il desktop remoto di Windows.",
        detection="Porta 3389/tcp aperta; nmap la riconosce come 'ms-wbt-server'.",
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
        gia_presenti = session.exec(select(Topic)).first()
        if gia_presenti is not None:
            return 0

        topics = build_starter_topics()
        session.add_all(topics)
        session.commit()
        return len(topics)


if __name__ == "__main__":
    # Eseguito con:  python -m app.seed
    create_db_and_tables()
    inserite = seed_if_empty()
    if inserite:
        print(f"Catalogo popolato: {inserite} voci inserite.")
    else:
        print("Catalogo gia' presente: non ho inserito nulla (nessun doppione).")
