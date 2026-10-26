#!/usr/bin/env python3
"""
Genera data/ports_commands_seed.json: i comandi per-porta dagli appunti
personali. Il seed li aggiunge in modo ADDITIVO alle voci PORTA del catalogo
(per numero di porta): arricchisce le porte gia' presenti e crea quelle nuove.

Nei comandi, IP/DOMINIO/UTENTE/PASSWORD sono segnaposto da sostituire col
bersaglio reale e AUTORIZZATO.

Uso:  python tools/build_ports_commands.py
"""
import json
from pathlib import Path


def c(title, command, goal=None, interp=None, tool=None):
    return {"title": title, "goal": goal, "tool": tool,
            "command": command, "interpretation": interp}


def p(port, name, checks, protocol=None, description=None, intro=None):
    return {"port": port, "name": name, "protocol": protocol,
            "description": description, "intro": intro, "checks": checks}


PORTS = [
    p(None, "Scansione delle porte", [
        c("Nmap completo (tutte le porte + versioni)",
          "sudo nmap -p- -T4 -sV -sC -Pn -n -vv -oN nmapcompleto.txt IP",
          "Scansione completa con rilevamento versioni e script di default."),
        c("Nmap veloce (top 1000 porte)",
          "sudo nmap -sV -Pn -n -vv -oN nmapveloce.txt IP",
          "Prima occhiata rapida sulle porte piu' comuni."),
        c("RustScan (tutte le porte)",
          "sudo docker run -it --rm --name rustscan rustscan/rustscan:latest -a IP -r 1-65535 -b 1500",
          "Scansione molto veloce di tutte le porte. Abbassa -b a 500 se instabile."),
        c("Masscan (tutte le porte)",
          "sudo masscan IP -p1-65535 --rate 500",
          "Scansione ad alta velocita' con rate controllato."),
        c("Service detection sulle porte trovate",
          "sudo nmap -sV -sC -p porta1,porta2,porta3 IP",
          "Approfondisci versioni e script solo sulle porte scoperte."),
    ], description="Da dove partire: trovare le porte aperte e i servizi."),

    p(21, "FTP", [
        c("Banner grabbing", "nc -vn IP 21", "Leggi il banner del servizio."),
        c("Script nmap FTP (safe)",
          'nmap -p21 -sV --script "ftp-* and safe" IP',
          "Enumerazione e controlli sicuri (anche nmap --script ftp-* -p 21 IP)."),
        c("Verifica supporto TLS",
          'echo -e "AUTH TLS\\r" | nc -vn IP 21', None,
          "Risposta 530 = niente crittografia (credenziali in chiaro → finding)."),
        c("Brute force",
          "hydra [-L users.txt | -l utente] [-P pass.txt | -p password] -f ftp://IP\n"
          "nmap -p 21 --script ftp-brute IP", None,
          "Credenziali deboli = accesso."),
        c("Accesso / login anonimo",
          "ftp IP", None,
          "Muoviti con ls, cd, get. Se 'anonymous' e' accettato = finding (login anonimo)."),
    ]),

    p(22, "SSH", [
        c("Banner grabbing", "nc -vn IP 22", "Leggi il banner (versione OpenSSH)."),
        c("Algoritmi e metodi di autenticazione",
          'nmap -p22 --script "ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" -sV IP',
          "Algoritmi deboli o auth via password abilitata."),
        c("Audit completo", "ssh-audit IP", "Segnala cifrature/algoritmi deboli o obsoleti."),
        c("Enumerazione utenti (Metasploit)",
          "msfconsole -q\nuse scanner/ssh/ssh_enumusers",
          "Scopre nomi utente validi."),
        c("Brute force",
          "hydra -l UTENTE -P /usr/share/wordlists/rockyou.txt -t 4 ssh://IP", None,
          "Password deboli = accesso."),
        c("Connessione", "ssh UTENTE@IP", "Accesso con credenziali valide."),
    ]),

    p(23, "Telnet", [
        c("Banner grabbing", "nc -vn IP 23", "Leggi il banner."),
        c("Enumerazione nmap (safe)",
          'nmap -n -sV -Pn --script "*telnet* and safe" -p 23 IP',
          "Controlli sicuri sul servizio."),
        c("Comunicazione", "telnet IP", None, "Puo' dare information disclosure."),
        c("Brute force",
          "hydra -l admin -P /usr/share/wordlists/rockyou.txt -t 4 -f telnet://IP", None,
          "Credenziali deboli = accesso."),
    ], description="Protocollo obsoleto: trasmette TUTTO in chiaro.",
       intro="Telnet invia credenziali e dati in chiaro: la sua sola presenza attiva e' gia' un finding. Preferire SSH."),

    p(53, "DNS", [
        c("Versione del server", "dig @IP version.bind chaos txt", "Fingerprint del resolver."),
        c("Zone transfer (AXFR)",
          "dig @IP DOMINIO AXFR", None,
          "Se il trasferimento riesce, ottieni TUTTI i record della zona = esposizione grave (finding)."),
        c("Test ricorsione", "dig @IP google.com", None,
          "Se risolve domini esterni, il resolver e' ricorsivo e aperto (possibile abuso/amplification)."),
        c("Verifica DNSSEC", "dig @IP ZONA DNSKEY", "Presenza/assenza di DNSSEC."),
        c("Script nmap",
          'nmap -p53 --script "dns-nsid,dns-recursion,dns-zone-transfer" --script-args dns-zone-transfer.domain=ZONA IP',
          "Ricorsione, NSID e zone transfer in un colpo solo."),
        c("Enumerazione (dnsrecon / dnsenum)",
          "dnsrecon -n IP -d ZONA\ndnsenum --dnsserver IP ZONA",
          "Enumerazione record e sottodomini (puo' puntare a un DNS diverso dall'IP)."),
    ]),

    p(80, "HTTP", [
        c("Comunicazione", "curl -sik http://IP/\nnc IP 80", "Leggi header e corpo della risposta."),
        c("Stack tecnologico", "whatweb http://IP/", None,
          "Riconosce server, framework e CMS (anche con l'estensione Wappalyzer). Cerca poi la tecnologia nel catalogo."),
        c("Ricerca vulnerabilita'",
          "nikto -h http://IP/\nnuclei -u http://IP/   # oppure: nuclei -u http://IP/ -t http/technologies/",
          "Misconfigurazioni, file esposti e CVE note. Visita anche manualmente con Burp."),
        c("Fuzzing di directory/file",
          "ffuf -u http://IP/FUZZ -w /usr/share/wordlists/dirb/common.txt\n"
          "feroxbuster -u http://IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
          "Pagine/cartelle non linkate (admin, backup, .git...)."),
        c("Se IIS: tilde enumeration", "(manuale su Burp Suite)", None,
          "Sui server IIS prova la tilde (8.3) enumeration per scoprire nomi file nascosti."),
    ]),

    p(443, "HTTPS", [
        c("Comunicazione", "curl -sik https://IP/\nnc IP 443", "Leggi header e corpo (ignora cert con -k)."),
        c("Stack tecnologico", "whatweb https://IP/", "Server, framework e CMS (anche Wappalyzer)."),
        c("Ricerca vulnerabilita'",
          "nikto -h https://IP/\nnuclei -u https://IP/   # oppure: nuclei -u https://IP/ -t http/technologies/",
          "Misconfigurazioni e CVE note. Visita anche con Burp."),
        c("Controlli sui certificati e cifrari",
          "sudo nmap -p443 --script ssl-enum-ciphers,ssl-cert IP\nsslscan IP:443\ntestssl IP:443", None,
          "Cifrari/protocolli deboli (SSLv3/TLS1.0), certificati scaduti o self-signed."),
        c("Header di sicurezza", "curl -sIk https://IP/", None,
          "Mancanza di HSTS, CSP, X-Frame-Options, cookie senza flag = debolezze da annotare."),
        c("Fuzzing di directory/file",
          "ffuf -u https://IP/FUZZ -w /usr/share/wordlists/dirb/common.txt\n"
          "feroxbuster -u https://IP/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
          "Contenuti non linkati."),
        c("Se WordPress: WPScan",
          "wpscan --url https://NOME/ --disable-tls-checks --enumerate vp,vt,u \\\n"
          "  --plugins-detection aggressive --api-token TUO_TOKEN",
          "Versione, utenti, plugin/temi vulnerabili."),
    ], description="HTTP su TLS: come la 80, piu' i controlli sui certificati."),

    p(111, "rpcbind / portmapper", [
        c("Interroga il portmapper", "rpcinfo -p IP", "Elenca i servizi RPC registrati e le loro porte."),
        c("Share NFS esposte", "showmount -e IP", None,
          "Mostra le cartelle NFS condivise: share esportate a tutti = possibile accesso/lettura dati."),
    ], description="Portmapper di Linux: mappa i servizi RPC (spesso NFS).",
       protocol="tcp/udp"),

    p(135, "MSRPC", [
        c("Elenca gli endpoint RPC", "impacket-rpcdump IP",
          "Tutti gli endpoint DCE/RPC registrati."),
        c("Filtra endpoint interessanti",
          'impacket-rpcdump IP | grep -iE "ncacn_ip_tcp|annotation|mssql|sql server|spool|atsvc|samr"',
          "Evidenzia spooler, SAMR, task scheduler, MSSQL..."),
        c("PrintNightmare (se Print Spooler attivo)",
          "msfconsole -q\nuse exploit/windows/dcerpc/cve_2021_1675_printnightmare\nset RHOSTS IP\ncheck", None,
          "Se lo spooler e' esposto, verifica CVE-2021-1675/34527 (RCE)."),
    ], description="Endpoint Mapper RPC di Windows: dice su quale porta dinamica (49xxx) gira un servizio.",
       intro="Le porte 49xxx sono dinamiche, assegnate da RPC: non si testano direttamente, si parte da qui (135)."),

    p(445, "SMB", [
        c("Controllo sicurezza (protocolli e signing)",
          'sudo nmap -p139,445 --script "smb-protocols,smb2-security-mode,smb-security-mode" IP\n'
          "nxc smb IP\nenum4linux-ng -A IP",
          "Versioni SMB, signing, info dominio/host."),
        c("EternalBlue MS17-010 (se SMBv1 attivo)",
          "sudo nmap -p445 --script smb-vuln-ms17-010 IP\n"
          "nxc smb IP -u '' -p '' -M ms17-010\n"
          "msfconsole -q\nuse auxiliary/scanner/smb/smb_ms17_010\nset RHOSTS IP\nrun", None,
          "Se SMBv1 e' attivo, verifica MS17-010 (solo con credenziali o login guest/null)."),
        c("Null session sulle share",
          "smbclient //IP/NOMESHARE -N", None,
          "Accesso senza credenziali: dentro muoviti con ls, cd e scarica con get."),
    ]),

    p(515, "LPD", [
        c("Stampa la coda di stampa",
          "printf '\\x03lp\\n' | nc -w3 IP 515",
          "Interroga il demone LPD (RFC 1179) di una stampante."),
    ], description="Line Printer Daemon: canale di stampa (oltre a FTP e 9100)."),

    p(631, "IPP / CUPS", [
        c("Script nmap CUPS", "nmap -sV -p631 --script=cups* IP",
          "Enumerazione del servizio di stampa IPP (gira sopra HTTP)."),
    ], description="Internet Printing Protocol: il protocollo di stampa moderno."),

    p(3389, "RDP", [
        c("Sicurezza, cifratura e NLA",
          "sudo nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info IP\n"
          "nxc rdp IP\ncd rdp-sec-check && ./rdp-sec-check.pl IP",
          "Livello di cifratura, NLA on/off, info NTLM (dominio/host)."),
        c("Login", "xfreerdp /v:IP /u:UTENTE /p:PASSWORD /cert:ignore", "Accesso con credenziali."),
        c("Brute force",
          "hydra -t 1 -V -f -l administrator -P /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt rdp://IP\n"
          "nxc rdp IP -u utenti.txt -p /usr/share/wordlists/seclists/Passwords/Common-Credentials/10k-most-common.txt", None,
          "Attenzione al lockout degli account."),
        c("BlueKeep (se NLA off)",
          "msfconsole -q\nuse auxiliary/scanner/rdp/cve_2019_0708_bluekeep\nset RHOSTS IP\nrun", None,
          "Con NLA disattivata, verifica CVE-2019-0708 (RCE)."),
    ]),

    p(5985, "WinRM", [
        c("Configurazione (senza credenziali)",
          "curl -sik http://IP:47001/wsman\n"
          "sudo nmap -p47001,5985,5986 --script http-winrm-info IP\nnxc winrm IP",
          "Verifica se WinRM (gestione remota) e' esposto. Porte 5985 (http), 5986 (https), 47001."),
        c("Con credenziali",
          "nxc winrm IP -u utente -p password\nevil-winrm -i IP -u utente -p password", None,
          "Con credenziali valide ottieni una shell PowerShell remota."),
    ]),

    p(5060, "SIP", [
        c("Enumerazione", "svmap IP\nsipsak -s sip:IP -vv",
          "Scoperta di dispositivi/estensioni VoIP."),
    ], description="Session Initiation Protocol (VoIP).", protocol="udp"),

    p(5357, "WSDAPI", [
        c("Nota", "(nessun test diretto)", None,
          "Servizio HTTP.SYS di Windows per scoprire e comunicare con dispositivi in rete. Raramente sfruttabile direttamente."),
    ], description="Web Services on Devices API di Windows."),

    p(5504, "RDWeb (possibile)", [
        c("Cerca il portale RDWeb", "(apri nel browser) https://IP/RDWeb   e   http://IP/RDWeb", None,
          "Possibile RPC di RemoteApp/RD: controlla se su 80/443 esiste il percorso /RDWeb (portale RemoteApp)."),
    ], description="Possibile gestione RemoteApp/RD Connection (Windows RDS)."),
]


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "ports_commands_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": "appunti comandi per porta", "ports": PORTS},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    ncheck = sum(len(e["checks"]) for e in PORTS)
    print(f"Scritti comandi per {len(PORTS)} porte, {ncheck} check in {out}")


if __name__ == "__main__":
    main()
