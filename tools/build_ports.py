#!/usr/bin/env python3
"""
Genera data/ports_seed.json: il catalogo delle PORTE/servizi comuni, curato a
mano. Sono riferimenti STANDARD e noti (il tipo di metodologia che si trova nei
corsi e nella documentazione dei tool). Nei comandi, <ip>/<dominio> sono
segnaposto da sostituire col bersaglio reale e AUTORIZZATO.

Uso:  python tools/build_ports.py
(poi il seed dell'app carica il JSON prodotto)
"""
import json
from pathlib import Path

HT = "https://book.hacktricks.xyz/network-services-pentesting/"


def t(name, port, protocol, description, detection, slug, checks):
    return {
        "kind": "port", "name": name, "port": port, "protocol": protocol,
        "description": description, "detection": detection,
        "references": HT + slug, "checks": checks,
    }


def c(title, goal, tool, command, interpretation):
    return {"title": title, "goal": goal, "tool": tool,
            "command": command, "interpretation": interpretation, "references": None}


# Introduzione approfondita per ogni servizio (cos'e', come funziona, perche'
# conta in un pentest). Agganciata a ogni porta in main() tramite il nome.
INTROS = {
    "FTP": (
        "Il File Transfer Protocol trasferisce file tra client e server. Nasce senza "
        "cifratura: credenziali e dati viaggiano in chiaro e sono intercettabili sulla "
        "rete (a meno di FTPS). Usa due canali separati: uno di controllo (porta 21) e "
        "uno per i dati.\n"
        "Per il pentester e' interessante soprattutto per il login anonimo (spesso "
        "abilitato per sbaglio), le credenziali deboli e i file sensibili lasciati sulle "
        "cartelle condivise."
    ),
    "SSH": (
        "Secure Shell fornisce accesso remoto a riga di comando in modo cifrato, ed e' il "
        "sostituto sicuro di Telnet. L'autenticazione puo' avvenire a password o, meglio, "
        "con chiave pubblica.\n"
        "E' generalmente robusto: i punti deboli reali sono credenziali deboli o "
        "riutilizzate, chiavi private rubate, versioni vecchie con CVE note e algoritmi di "
        "cifratura obsoleti. Un accesso SSH valido e' spesso gia' un piede dentro il sistema."
    ),
    "Telnet": (
        "Telnet e' un vecchio protocollo di accesso remoto testuale, completamente NON "
        "cifrato: nome utente, password e comandi viaggiano in chiaro. E' considerato "
        "insicuro e andrebbe sostituito da SSH.\n"
        "Si trova ancora su apparati di rete, stampanti e sistemi legacy, spesso con "
        "credenziali di default. Chi si trova sulla stessa rete puo' intercettare l'intera "
        "sessione."
    ),
    "SMTP": (
        "Il Simple Mail Transfer Protocol gestisce l'invio della posta tra i server.\n"
        "Per il pentester conta per tre motivi: l'enumerazione utenti (i comandi VRFY, EXPN "
        "e RCPT confermano se un account esiste), l'open relay (un server mal configurato "
        "che inoltra posta per chiunque, sfruttabile per spam e phishing) e le informazioni "
        "rivelate dai banner."
    ),
    "DNS": (
        "Il Domain Name System traduce i nomi (es. acme.it) negli indirizzi IP.\n"
        "In un pentest e' una miniera di informazioni: il trasferimento di zona (AXFR), se "
        "mal configurato, rivela l'intera mappa dei nomi interni; la ricorsione aperta puo' "
        "essere abusata; l'enumerazione di sottodomini amplia la superficie d'attacco. "
        "Spesso e' il primo passo della ricognizione."
    ),
    "HTTP/HTTPS": (
        "Sono i protocolli del web: HTTP in chiaro (porta 80) e HTTPS cifrato con TLS (443).\n"
        "Dietro una porta web puo' esserci qualunque cosa: un sito, un pannello di "
        "amministrazione, un'API, un'applicazione complessa. E' la superficie d'attacco piu' "
        "ricca e variegata: prima si identificano le tecnologie, poi si cercano contenuti "
        "nascosti e vulnerabilita'. Vedi anche le sezioni Web App e Tecniche."
    ),
    "POP3 / IMAP": (
        "Sono i protocolli per leggere la posta: POP3 (scarica e in genere rimuove i "
        "messaggi) e IMAP (li sincronizza mantenendoli sul server). Esistono in versione in "
        "chiaro (110/143) e cifrata (995/993).\n"
        "Per il pentester contano per le credenziali deboli: una casella compromessa spesso "
        "contiene dati sensibili e permette di resettare le password di altri servizi."
    ),
    "SMB": (
        "Server Message Block e' il protocollo Windows per condividere file e stampanti e "
        "per far comunicare le macchine; e' anche un pilastro di Active Directory.\n"
        "E' uno dei servizi piu' preziosi in un pentest: consente l'enumerazione di utenti, "
        "share e policy, a volte l'accesso anonimo (null session), ed e' stato bersaglio di "
        "falle gravi come EternalBlue (MS17-010). La versione SMBv1 e' obsoleta e pericolosa."
    ),
    "SNMP": (
        "Il Simple Network Management Protocol serve a monitorare e gestire dispositivi di "
        "rete (router, switch, stampanti, server). L'accesso e' protetto da una 'community "
        "string', spesso lasciata al valore di default (public/private). Viaggia su UDP.\n"
        "Con una community valida si leggono moltissime informazioni: processi, software "
        "installato, interfacce di rete e a volte credenziali in chiaro nelle configurazioni."
    ),
    "LDAP": (
        "Il Lightweight Directory Access Protocol interroga una directory di utenti, gruppi "
        "e risorse; su Windows e' il protocollo con cui si parla ad Active Directory.\n"
        "Se il bind anonimo e' permesso si enumerano utenti e gruppi senza credenziali; anche "
        "con un account qualsiasi, LDAP e' lo strumento principale per mappare il dominio. "
        "Porta 389 (in chiaro) e 636 (LDAPS)."
    ),
    "MSSQL": (
        "Microsoft SQL Server e' il database di Microsoft, molto diffuso in ambienti Windows.\n"
        "Oltre ai dati, e' interessante perche' un account con privilegi puo' eseguire comandi "
        "sul sistema operativo (xp_cmdshell) e perche' si integra con l'autenticazione di "
        "Windows e Active Directory. Password vuote o deboli per l'utente 'sa' sono un classico "
        "punto d'ingresso."
    ),
    "MySQL": (
        "MySQL (e il fork MariaDB) e' un database relazionale diffusissimo, spesso dietro le "
        "applicazioni web.\n"
        "Per il pentester conta per le credenziali deboli o di default (root senza password e' "
        "comune nelle installazioni di sviluppo), per i dati che contiene, e perche' con il "
        "privilegio FILE si possono leggere o scrivere file sul server."
    ),
    "RDP": (
        "Remote Desktop Protocol fornisce il desktop grafico remoto di Windows. E' un bersaglio "
        "ad alto valore: un accesso RDP valido equivale a sedersi davanti alla macchina.\n"
        "I punti d'attenzione sono le credenziali deboli (occhio ai blocchi account), l'assenza "
        "di NLA, le vulnerabilita' pre-autenticazione come BlueKeep (CVE-2019-0708) e il riuso "
        "di hash (Pass-the-Hash)."
    ),
    "PostgreSQL": (
        "PostgreSQL e' un potente database relazionale open source.\n"
        "Come gli altri database interessa per le credenziali deboli o di default "
        "(postgres/postgres), per i dati, e perche' con i giusti privilegi permette "
        "l'esecuzione di comandi sul server (COPY ... FROM PROGRAM). Spesso e' esposto dietro "
        "un'applicazione."
    ),
    "WinRM": (
        "Windows Remote Management e' il servizio con cui si amministrano da remoto le macchine "
        "Windows (e' il trasporto di PowerShell Remoting).\n"
        "Non e' una vulnerabilita' di per se', ma con credenziali valide (o un hash) e i giusti "
        "privilegi offre una shell PowerShell remota: e' una via di movimento laterale molto "
        "usata in Active Directory."
    ),
    "Redis": (
        "Redis e' un database in memoria di tipo chiave-valore, usato per cache, code e "
        "sessioni.\n"
        "Il problema classico e' l'esposizione senza autenticazione: in molte installazioni di "
        "default chi raggiunge la porta puo' leggere e scrivere dati. In certe configurazioni "
        "si arriva all'esecuzione di codice o alla scrittura di file (chiavi SSH, webshell)."
    ),
    "MongoDB": (
        "MongoDB e' un database NoSQL orientato ai documenti, comune dietro le applicazioni "
        "moderne.\n"
        "Il rischio tipico e' l'esposizione in rete con l'autenticazione disabilitata: chi "
        "raggiunge la porta puo' elencare e leggere interi database senza credenziali. Molte "
        "fughe di dati sono nate da istanze MongoDB aperte su Internet."
    ),
    "NFS": (
        "Il Network File System condivide cartelle tra sistemi Unix/Linux sulla rete.\n"
        "Le condivisioni (export) possono essere mal configurate e accessibili a chiunque; "
        "l'opzione 'no_root_squash' e' particolarmente pericolosa perche' permette a chi ha "
        "accesso di agire come root sui file, aprendo la strada a un'escalation di privilegi."
    ),
}


PORTS = [
    t("FTP", 21, "tcp", "File Transfer Protocol: trasferimento file, spesso in chiaro.",
      "Porta 21/tcp aperta; il banner mostra il software del server FTP.", "pentesting-ftp", [
        c("Ricognizione e login anonimo", "Versione del server e accesso anonimo.", "nmap",
          "nmap -sV -p21 --script ftp-anon,ftp-syst <ip>",
          "'Anonymous login allowed' = accesso senza credenziali. Il banner rivela software e versione (cerca exploit noti)."),
        c("Connessione manuale", "Provare l'accesso anonimo e sfogliare i file.", "ftp",
          "ftp <ip>    # utente: anonymous  -  password: qualsiasi",
          "Se entri, scarica (get) ed eventualmente carica (put) file. Spesso ci sono dati sensibili."),
        c("Brute force credenziali", "Trovare credenziali valide (occhio al lockout).", "hydra",
          "hydra -L users.txt -P pass.txt ftp://<ip>",
          "Una riga 'login: ... password: ...' indica credenziali valide."),
      ]),
    t("SSH", 22, "tcp", "Secure Shell: accesso remoto cifrato.",
      "Porta 22/tcp aperta; il banner mostra versione (es. OpenSSH 8.9).", "pentesting-ssh", [
        c("Ricognizione", "Versione, algoritmi e metodi di autenticazione.", "nmap",
          "nmap -sV -p22 --script ssh2-enum-algos,ssh-auth-methods --script-args ssh.user=root <ip>",
          "Mostra i metodi auth (password/publickey) e algoritmi deboli. Versioni vecchie = possibili CVE."),
        c("Audit di sicurezza", "Trovare algoritmi/cifrari deboli o obsoleti.", "ssh-audit",
          "ssh-audit <ip>",
          "Evidenzia in rosso cifrari/chiavi deboli e CVE note per quella versione."),
        c("Brute force / login", "Provare credenziali deboli o default.", "hydra",
          "hydra -l <user> -P pass.txt ssh://<ip>    # poi:  ssh <user>@<ip>",
          "Credenziali valide se hydra le riporta. Attenzione a fail2ban/blocchi."),
      ]),
    t("Telnet", 23, "tcp", "Accesso remoto NON cifrato (tutto in chiaro).",
      "Porta 23/tcp aperta; prompt di login testuale.", "pentesting-telnet", [
        c("Ricognizione", "Banner e informazioni di sistema.", "nmap",
          "nmap -sV -p23 --script telnet-ntlm-info,telnet-encryption <ip>",
          "Il banner rivela device/OS. 'encryption: no' = credenziali trasmesse in chiaro (sniffabili)."),
        c("Login e credenziali default", "Provare accessi deboli/default.", "telnet",
          "telnet <ip>",
          "Molti dispositivi hanno credenziali di default (admin/admin). Traffico intercettabile sulla rete."),
      ]),
    t("SMTP", 25, "tcp", "Simple Mail Transfer Protocol: invio email.",
      "Porte 25/465/587 aperte; il banner mostra il server di posta.", "pentesting-smtp", [
        c("Ricognizione", "Comandi supportati, open relay, utenti.", "nmap",
          "nmap -sV -p25 --script smtp-commands,smtp-open-relay,smtp-enum-users <ip>",
          "'smtp-open-relay' positivo = relay aperto (abuso per spam). Comandi VRFY/EXPN abilitati = enum utenti."),
        c("Enumerazione utenti", "Scoprire account validi.", "smtp-user-enum",
          "smtp-user-enum -M VRFY -U users.txt -t <ip>",
          "Gli utenti riconosciuti dal server sono validi: utili per attacchi di autenticazione altrove."),
      ]),
    t("DNS", 53, "tcp/udp", "Domain Name System: risoluzione dei nomi.",
      "Porta 53 aperta (udp e/o tcp).", "pentesting-dns", [
        c("Trasferimento di zona (AXFR)", "Scaricare tutti i record di un dominio.", "dig",
          "dig axfr @<ip> <dominio>",
          "Se ricevi l'elenco completo dei record, l'AXFR e' aperto (configurazione errata, grave): mappa tutta l'infrastruttura."),
        c("Ricognizione server", "Ricorsione e informazioni del resolver.", "nmap",
          "nmap -sSU -p53 --script dns-recursion,dns-nsid <ip>",
          "Ricorsione aperta verso l'esterno = possibile abuso (amplification). NSID rivela info sul server."),
        c("Enumerazione sottodomini", "Scoprire host del dominio.", "dnsrecon",
          "dnsrecon -d <dominio>    # oppure: dnsenum <dominio>",
          "Nuovi sottodomini/record ampliano la superficie d'attacco."),
      ]),
    t("HTTP/HTTPS", 80, "tcp", "Server web (HTTP su 80, HTTPS su 443).",
      "Porte 80/443 aperte; risponde una pagina o un'API.", "pentesting-web", [
        c("Fingerprint tecnologie", "Capire server, framework, CMS, metodi.", "whatweb / nmap",
          "whatweb http://<ip>    # e:  nmap -p80,443 --script http-headers,http-methods,http-title <ip>",
          "Identifica tecnologie (poi cercale nel catalogo, es. WordPress). Metodi PUT/DELETE abilitati sono pericolosi."),
        c("Scanner di vulnerabilita' note", "Misconfig, file noti, header mancanti.", "nikto / nuclei",
          "nikto -h http://<ip>    # e:  nuclei -u http://<ip>",
          "Segnala file/pannelli esposti, header di sicurezza mancanti e CVE note dei componenti."),
        c("Brute force di directory e file", "Scoprire contenuti nascosti.", "feroxbuster",
          "feroxbuster -u http://<ip> -w /usr/share/wordlists/dirb/common.txt    # o gobuster/ffuf",
          "Pagine/cartelle non linkate (admin, backup, .git) spesso rivelano vulnerabilita' o dati."),
        c("Analisi TLS (HTTPS)", "Cifrari deboli, certificati, protocolli vecchi.", "testssl.sh / sslscan",
          "testssl.sh <ip>:443    # o:  sslscan <ip>:443",
          "Protocolli obsoleti (SSLv3/TLS1.0), cifrari deboli o certificati scaduti/non validi."),
      ]),
    t("POP3 / IMAP", 110, "tcp", "Lettura della posta (POP3 110/995, IMAP 143/993).",
      "Porte 110/143/993/995 aperte.", "pentesting-pop", [
        c("Ricognizione", "Capacita' del server e STARTTLS.", "nmap",
          "nmap -sV -p110,143,993,995 --script pop3-capabilities,imap-capabilities <ip>",
          "Mostra i meccanismi di autenticazione e se la cifratura (STARTTLS) e' disponibile."),
        c("Brute force", "Provare credenziali deboli.", "hydra",
          "hydra -l <user> -P pass.txt pop3://<ip>",
          "Credenziali valide = accesso alla casella (spesso info sensibili e reset password)."),
      ]),
    t("SMB", 445, "tcp", "Server Message Block: condivisione file/stampanti su Windows.",
      "Porte 445/tcp (e 139/tcp) aperte; nmap mostra 'microsoft-ds'.", "pentesting-smb", [
        c("Ricognizione e vulnerabilita'", "OS, versione del protocollo, falle note.", "nmap",
          "nmap -p139,445 --script smb-os-discovery,smb-protocols,smb-vuln-ms17-010 <ip>",
          "SMBv1 attivo = rischio. 'smb-vuln-ms17-010: VULNERABLE' = EternalBlue (CVE-2017-0144), critico."),
        c("Enumerazione completa", "Utenti, gruppi, share, policy password.", "enum4linux-ng",
          "enum4linux-ng -A <ip>",
          "Elenca utenti e share: base per attacchi mirati. Policy password utile per il brute force."),
        c("Accesso senza credenziali (null session)", "Elencare/accedere alle share anonimamente.", "netexec / smbclient",
          "netexec smb <ip> -u '' -p '' --shares    # o:  smbclient -L //<ip>/ -N",
          "Share leggibili/scrivibili senza password = esposizione di dati (da segnalare)."),
        c("Accesso con credenziali", "Verificare share ed eventuale esecuzione.", "netexec",
          "netexec smb <ip> -u <user> -p <pass> --shares",
          "'(Pwn3d!)' indica privilegi amministrativi (possibile esecuzione comandi)."),
      ]),
    t("SNMP", 161, "udp", "Simple Network Management Protocol: gestione dispositivi.",
      "Porta 161/udp aperta (spesso su router, stampanti, server).", "pentesting-snmp", [
        c("Community di default", "Trovare community string valide.", "onesixtyone",
          "onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <ip>",
          "Una community valida (spesso 'public') da' accesso in lettura a molte info del dispositivo."),
        c("Estrazione informazioni", "Leggere sistema, processi, utenti, rete.", "snmpwalk",
          "snmpwalk -v2c -c public <ip>    # riepilogo:  snmp-check <ip> -c public",
          "Rivela processi, software, interfacce e a volte credenziali in chiaro nelle configurazioni."),
      ]),
    t("LDAP", 389, "tcp", "Directory service (Active Directory su Windows).",
      "Porte 389/636 aperte; tipico dei Domain Controller.", "pentesting-ldap", [
        c("Base DN e bind anonimo", "Capire il dominio e tentare lettura senza credenziali.", "ldapsearch",
          "ldapsearch -x -H ldap://<ip> -s base namingcontexts",
          "Rivela il base DN (es. DC=acme,DC=local). Se poi -b '<baseDN>' restituisce oggetti senza login, il bind anonimo e' abilitato."),
        c("Enumerazione directory", "Elencare utenti e gruppi.", "ldapsearch / nmap",
          "ldapsearch -x -H ldap://<ip> -b \"DC=acme,DC=local\"    # e:  nmap -p389 --script ldap-rootdse <ip>",
          "Utenti, gruppi e attributi del dominio: base per attacchi su Active Directory."),
      ]),
    t("MSSQL", 1433, "tcp", "Microsoft SQL Server.",
      "Porta 1433/tcp aperta; tipico su server Windows.", "pentesting-mssql-microsoft-sql-server", [
        c("Ricognizione", "Versione, istanza, password vuota per 'sa'.", "nmap",
          "nmap -p1433 --script ms-sql-info,ms-sql-ntlm-info,ms-sql-empty-password <ip>",
          "'sa' con password vuota = accesso totale. NTLM-info rivela hostname e dominio."),
        c("Accesso ed esecuzione comandi", "Connettersi ed eventualmente eseguire comandi.", "impacket-mssqlclient",
          "impacket-mssqlclient <user>:<pass>@<ip>    # o:  -windows-auth",
          "Con privilegi adeguati, 'enable_xp_cmdshell' permette l'esecuzione di comandi sul sistema."),
      ]),
    t("MySQL", 3306, "tcp", "Database MySQL/MariaDB.",
      "Porta 3306/tcp aperta.", "pentesting-mysql", [
        c("Ricognizione", "Versione, utenti, password vuota per root.", "nmap",
          "nmap -p3306 --script mysql-info,mysql-empty-password,mysql-users <ip>",
          "'root' con password vuota = accesso completo al database."),
        c("Accesso", "Connettersi con credenziali deboli/default.", "mysql",
          "mysql -h <ip> -u root -p",
          "Se entri, leggi i dati; con privilegi FILE puoi leggere/scrivere file sul server."),
      ]),
    t("RDP", 3389, "tcp", "Remote Desktop Protocol: desktop remoto di Windows.",
      "Porta 3389/tcp aperta; nmap la riconosce come 'ms-wbt-server'.", "pentesting-rdp", [
        c("Ricognizione (cifratura e NLA)", "Capire versione, cifratura e Network Level Authentication.", "nmap",
          "nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info <ip>",
          "NLA disabilitata = servizio piu' esposto. NTLM-info rivela hostname e dominio."),
        c("BlueKeep (CVE-2019-0708)", "Verificare la falla pre-autenticazione.", "nmap",
          "nmap -p3389 --script rdp-vuln-ms12-020 <ip>",
          "'VULNERABLE' = sistema non aggiornato: finding critico, RCE pre-auth."),
        c("Accesso (anche Pass-the-Hash)", "Verificare credenziali o hash.", "xfreerdp",
          "xfreerdp /u:<user> /p:<pass> /v:<ip>    # con hash:  /pth:<NTLM-hash>",
          "Se ottieni il desktop, le credenziali/hash sono validi."),
      ]),
    t("PostgreSQL", 5432, "tcp", "Database PostgreSQL.",
      "Porta 5432/tcp aperta.", "pentesting-postgresql", [
        c("Credenziali deboli", "Trovare login validi.", "nmap / psql",
          "nmap -p5432 --script pgsql-brute <ip>    # o:  psql -h <ip> -U postgres",
          "Coppia default 'postgres/postgres' molto comune. Con privilegi, COPY ... FROM PROGRAM esegue comandi."),
      ]),
    t("WinRM", 5985, "tcp", "Windows Remote Management (shell remota Windows).",
      "Porte 5985 (http) / 5986 (https) aperte.", "5985-5986-pentesting-winrm", [
        c("Verifica accesso", "Controllare se le credenziali danno accesso.", "netexec",
          "netexec winrm <ip> -u <user> -p <pass>",
          "'(Pwn3d!)' = accesso valido (di solito amministrativo)."),
        c("Shell interattiva", "Ottenere una shell se le credenziali sono valide.", "evil-winrm",
          "evil-winrm -i <ip> -u <user> -p <pass>",
          "Shell PowerShell remota: utile anche con hash (-H) per Pass-the-Hash."),
      ]),
    t("Redis", 6379, "tcp", "Database in memoria chiave-valore.",
      "Porta 6379/tcp aperta.", "6379-pentesting-redis", [
        c("Accesso non autenticato", "Verificare se risponde senza password.", "redis-cli",
          "redis-cli -h <ip>    # poi:  INFO   e   CONFIG GET *",
          "Se risponde senza auth, e' esposto: possibile lettura dati e, in certi casi, scrittura file/RCE."),
      ]),
    t("MongoDB", 27017, "tcp", "Database NoSQL orientato ai documenti.",
      "Porta 27017/tcp aperta.", "27017-27018-mongodb", [
        c("Accesso non autenticato", "Verificare se i database sono leggibili senza credenziali.", "mongosh",
          "mongosh \"mongodb://<ip>:27017\"    # poi:  show dbs",
          "Se elenca i database senza login, l'autenticazione e' disabilitata (esposizione dati)."),
      ]),
    t("NFS", 2049, "tcp", "Network File System: condivisione file su rete Unix.",
      "Porta 2049/tcp aperta (spesso con 111 rpcbind).", "nfs-service-pentesting", [
        c("Export disponibili", "Vedere quali cartelle sono condivise e a chi.", "showmount",
          "showmount -e <ip>",
          "Un export verso '*' (tutti) e' una misconfigurazione. Annota i percorsi condivisi."),
        c("Montaggio", "Accedere ai file condivisi.", "mount",
          "mount -t nfs <ip>:/percorso/share /mnt",
          "Se monti e leggi/scrivi, i dati sono esposti. Con no_root_squash si puo' arrivare a privilegi elevati."),
      ]),
]


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "ports_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    for port in PORTS:
        port["intro"] = INTROS.get(port["name"])
    data = {"source": "curato a mano (metodologia standard)", "topics": PORTS}
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    n_checks = sum(len(t["checks"]) for t in PORTS)
    print(f"Scritte {len(PORTS)} porte e {n_checks} test in {out}")


if __name__ == "__main__":
    main()
