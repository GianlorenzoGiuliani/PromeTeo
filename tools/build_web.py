#!/usr/bin/env python3
"""
Genera data/web_seed.json: metodologia di pentest su applicazioni web, curata a
mano. E' il "come approcciare" un test web (ricognizione -> scoperta -> auth ->
controllo accessi -> injection -> upload...); per i payload dettagliati si rimanda
alla sezione Tecniche (PayloadsAllTheThings).

Uso:  python tools/build_web.py
"""
import json
from pathlib import Path

REF = "https://book.hacktricks.xyz/pentesting-web"


def T(name, description, intro, checks):
    return {"kind": "web", "name": name, "description": description,
            "intro": intro, "detection": None, "references": REF, "checks": checks}


def c(title, goal, tool, command, interpretation):
    return {"title": title, "goal": goal, "tool": tool,
            "command": command, "interpretation": interpretation, "references": None}


TOPICS = [
    T("Ricognizione e fingerprint",
      "Identificare server, framework, CMS e tecnologie prima di testare.",
      "Prima di attaccare conviene capire con cosa si ha a che fare: server web, "
      "linguaggio, framework, eventuale CMS, header di sicurezza. Questo orienta tutti i "
      "test successivi (es. se e' WordPress, vai alla voce WordPress nelle Tecnologie).", [
        c("Fingerprint tecnologie", "Riconoscere lo stack dell'applicazione.",
          "whatweb / nmap",
          "whatweb http://<url>    # e:  nmap -p80,443 --script http-headers,http-methods,http-title <ip>",
          "Rivela tecnologie e versioni (cercale poi nel catalogo). Metodi come PUT/DELETE abilitati sono pericolosi."),
        c("Header di sicurezza", "Verificare le protezioni lato browser.",
          "curl / browser",
          "curl -sI http://<url>",
          "Mancanza di CSP, HSTS, X-Frame-Options, cookie senza HttpOnly/Secure: debolezze da annotare."),
      ]),
    T("Scoperta dei contenuti",
      "Trovare pagine, cartelle e file non collegati.",
      "Gran parte della superficie d'attacco non e' linkata nelle pagine: pannelli di "
      "amministrazione, backup, file di configurazione, repository .git esposti. Si "
      "scoprono con il brute force di directory/file e controllando i file noti.", [
        c("Brute force di directory", "Enumerare percorsi nascosti.",
          "feroxbuster / ffuf",
          "feroxbuster -u http://<url> -w /usr/share/wordlists/dirb/common.txt",
          "Pagine come /admin, /backup, /.git, /api spesso rivelano funzioni o dati sensibili."),
        c("File noti e sensibili", "Controllare i file che espongono informazioni.",
          "browser / curl",
          "curl http://<url>/robots.txt    # poi: sitemap.xml, .git/, /backup.zip, /.env",
          "robots.txt e sitemap svelano percorsi; un .git/ o .env esposto e' una fuga grave."),
      ]),
    T("Scanner automatici",
      "Primo passaggio per misconfigurazioni e CVE note.",
      "Gli scanner automatici danno una fotografia rapida: componenti con CVE note, file "
      "esposti, misconfigurazioni comuni. Sono un punto di partenza, NON la fine: ogni "
      "segnalazione va verificata a mano per escludere i falsi positivi.", [
        c("Scansione con nuclei", "Cercare CVE note e misconfigurazioni con template.",
          "nuclei",
          "nuclei -u http://<url>",
          "Segnala vulnerabilita' note dei componenti e configurazioni errate. Verifica sempre manualmente."),
        c("Scansione con Nikto", "Controlli classici su file e header.",
          "nikto",
          "nikto -h http://<url>",
          "File/pannelli di default, metodi pericolosi, header mancanti."),
      ]),
    T("Autenticazione e sessione",
      "Come l'app gestisce login, sessioni e reset password.",
      "L'area di autenticazione e' critica: credenziali deboli o di default, gestione "
      "insicura della sessione, funzioni di 'password dimenticata' sfruttabili.\n"
      "Si verificano il login (forza bruta, default), i cookie di sessione e il flusso di "
      "reset.", [
        c("Credenziali deboli / default", "Provare accessi facili.",
          "hydra / manuale",
          "hydra -l admin -P pass.txt <ip> http-post-form \"/login:user=^USER^&pass=^PASS^:fallita\"",
          "Credenziali admin/admin o deboli = accesso. Occhio a eventuali blocchi e rate limiting."),
        c("Sicurezza della sessione", "Analizzare i cookie e il ciclo della sessione.",
          "browser (DevTools)",
          "Esamina il cookie di sessione: flag HttpOnly, Secure, SameSite.",
          "Il token cambia dopo il login? Il logout lo invalida davvero? Flag mancanti = sessione a rischio."),
      ]),
    T("Controllo degli accessi (IDOR)",
      "Verificare che un utente non acceda a dati o azioni non suoi.",
      "Molte app controllano chi sei al login ma non su ogni singola azione. Cosi' un "
      "utente puo' accedere ai dati di un altro cambiando un identificativo (IDOR) o "
      "usare funzioni da amministratore andando direttamente all'URL.\n"
      "E' una delle categorie piu' comuni e gravi.", [
        c("IDOR (accesso orizzontale)", "Accedere ai dati di altri utenti.",
          "browser / Burp",
          "Cambia un id nell'URL o nel parametro: es. /ordine/123 -> /ordine/124",
          "Se vedi dati di un altro utente senza autorizzazione, e' una IDOR (Insecure Direct Object Reference)."),
        c("Accesso verticale (privilege)", "Usare funzioni di livello superiore.",
          "browser",
          "Da utente normale, apri direttamente URL/funzioni da amministratore.",
          "Se la funzione si esegue, manca il controllo dei ruoli (broken access control)."),
      ]),
    T("Injection (SQLi, XSS, Command)",
      "I classici: input non validati che finiscono dove non dovrebbero.",
      "Quando l'input dell'utente finisce in una query, in una pagina o in un comando "
      "senza controlli, nascono le injection: SQL injection, Cross-Site Scripting (XSS), "
      "command injection e altre.\n"
      "Qui trovi l'approccio; per i payload completi vai alla sezione Tecniche.", [
        c("SQL injection", "Verificare se un parametro e' iniettabile.",
          "sqlmap",
          "sqlmap -u \"http://<url>?id=1\" --batch",
          "Parametro 'injectable' = SQL injection (CWE-89): accesso/lettura del database."),
        c("Cross-Site Scripting (XSS)", "Verificare l'esecuzione di codice nel browser.",
          "browser",
          "Inserisci nei campi riflessi/memorizzati:  <script>alert(1)</script>",
          "Se lo script viene eseguito, c'e' una XSS. Vedi la Tecnica 'Cross Site Scripting' per i payload."),
      ]),
    T("Upload di file",
      "Funzioni di upload mal validate che portano a webshell.",
      "Se un'app accetta l'upload di file senza validarli bene (tipo, estensione, "
      "contenuto), si puo' caricare una webshell ed eseguire codice sul server.\n"
      "Si prova a bypassare i controlli con estensioni doppie, content-type falsi, "
      "estensioni alternative.", [
        c("Test di upload", "Caricare un file eseguibile o bypassare i filtri.",
          "browser / Burp",
          "Carica una webshell (es. shell.php); se bloccato prova shell.php.jpg, shell.phtml, content-type image/jpeg",
          "Se riesci a far eseguire il file caricato, hai una RCE. Controlla dove finisce il file (path prevedibile)."),
      ]),
    T("SSRF e richieste lato server",
      "Far eseguire al server richieste verso risorse interne.",
      "Se l'app prende un URL dall'utente e il server lo 'visita' (anteprime, import, "
      "webhook), si puo' puntarlo verso risorse interne non raggiungibili dall'esterno: "
      "e' la Server-Side Request Forgery (SSRF).", [
        c("Test SSRF", "Verificare se il server raggiunge risorse interne.",
          "browser / Burp",
          "In un parametro che accetta URL, punta a:  http://169.254.169.254/  o a servizi interni",
          "Una risposta da un servizio interno (o dai metadata cloud) conferma la SSRF. Vedi la Tecnica dedicata."),
      ]),
    T("API",
      "Le API hanno la loro superficie: endpoint, metodi, autorizzazione.",
      "Le applicazioni moderne espongono API (REST/GraphQL). Spesso la sicurezza si "
      "concentra sull'interfaccia e le API restano meno protette: endpoint non "
      "documentati, metodi pericolosi, controlli di autorizzazione assenti.", [
        c("Enumerazione e metodi", "Scoprire endpoint e come rispondono.",
          "browser / ffuf",
          "Cerca /api, /swagger, /openapi.json; prova metodi diversi (GET/POST/PUT/DELETE) sugli endpoint",
          "Endpoint esposti, documentazione aperta o metodi che modificano dati senza autorizzazione = problemi."),
        c("Autorizzazione a livello di oggetto", "Verificare l'accesso ai dati altrui via API.",
          "Burp / curl",
          "Ripeti una chiamata cambiando l'id dell'oggetto (come una IDOR, ma sull'API)",
          "Se ottieni dati non tuoi, l'API non verifica la proprieta' dell'oggetto (BOLA/IDOR)."),
      ]),
]


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "web_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": "curato a mano", "topics": TOPICS}, ensure_ascii=False, indent=2), encoding="utf-8")
    n = sum(len(t["checks"]) for t in TOPICS)
    print(f"Scritte {len(TOPICS)} voci Web e {n} test in {out}")


if __name__ == "__main__":
    main()
