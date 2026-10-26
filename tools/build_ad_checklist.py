#!/usr/bin/env python3
"""
Genera data/ad_checklist_seed.json: la checklist di AUDIT Active Directory
(solo PowerShell, enumerazione in sola lettura) dagli appunti personali, nella
struttura macro -> microcategorie (sezioni A-G) -> check.

Ogni check porta il comando PowerShell e l'interpretazione (✅ sano · ❌ finding
· ⚠️ da valutare). Sono comandi di SOLA LETTURA: usali su domini AUTORIZZATI.

Uso:  python tools/build_ad_checklist.py
(poi il seed dell'app carica il JSON prodotto, in modo additivo)
"""
import json
from pathlib import Path


def t(title, command, goal, interp, tool="PowerShell (modulo ActiveDirectory)", references=None):
    return {"title": title, "goal": goal, "tool": tool,
            "command": command, "interpretation": interp, "references": references}


def micro(name, description, checks):
    return {"name": name, "description": description, "checks": checks}


MACRO = {
    "name": "Checklist Audit Active Directory",
    "description": "Audit di un dominio Windows in sola lettura (PowerShell): policy, account, privilegi, delega, crittografia, GPO, infrastruttura.",
    "references": "https://www.pingcastle.com/",
    "intro": (
        "Checklist di audit di un dominio Active Directory. Tutti i comandi sono di SOLA "
        "LETTURA/enumerazione: fotografano lo stato del dominio senza modificarlo.\n\n"
        "Prerequisiti: sessione PowerShell con il modulo ActiveDirectory (cmdlet Get-AD*) e, "
        "per le GPO, il modulo GroupPolicy. Sostituisci 'egicon.local' col tuo dominio.\n\n"
        "Legenda interpretazione: ✅ = configurazione sana · ❌ = finding da segnalare · "
        "⚠️ = dipende dal contesto, da valutare.\n\n"
        "Nota: questi controlli sono enumerazione; le remediation (modifica policy, rotazione "
        "krbtgt, rimozione membri...) vanno testate fuori produzione. Per salvare un output: "
        "aggiungi | Export-Csv C:\\audit\\nome.csv -NoTypeInformation. Per una visione d'insieme "
        "affianca PingCastle prima di approfondire a mano."
    ),
    "children": [
        micro("A. Policy di dominio", "Password policy, PSO, reversible encryption.", [
            t("A1 — Password policy di dominio",
              "Get-ADDefaultDomainPasswordPolicy",
              "Legge la policy password autoritativa del dominio (vale per tutti gli account di dominio).",
              "✅ MinPasswordLength ≥ 14, ComplexityEnabled True, PasswordHistoryCount ≥ 24, LockoutThreshold tra 5 e 10, MaxPasswordAge > 0.\n"
              "❌ MinPasswordLength 0, ComplexityEnabled False, LockoutThreshold 0 (nessun blocco → brute force/password spraying liberi), MaxPasswordAge 0 senza strategia compensativa."),
            t("A2 — Fine-Grained Password Policies (PSO)",
              "Get-ADFineGrainedPasswordPolicy -Filter *",
              "Elenca policy password alternative applicate a gruppi/utenti specifici, che scavalcano quella di dominio.",
              "✅ Vuoto (vale la policy di dominio) oppure PSO piu' SEVERE per gli account privilegiati.\n"
              "❌ PSO esistenti ma piu' DEBOLI della policy di dominio, o applicate a soggetti inattesi."),
            t("A3 — Reversible encryption",
              "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption | Select Name,SamAccountName",
              "Trova account la cui password e' memorizzata in forma reversibile (quasi in chiaro).",
              "✅ Nessun risultato.\n❌ Qualsiasi account elencato: la password e' recuperabile in chiaro."),
        ]),
        micro("B. Account a rischio", "Password deboli/eterne, AS-REP/Kerberoast, SID history, account stale.", [
            t("B1 — Password che non scade mai (account attivi)",
              "Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires | Select Name,SamAccountName",
              "Account abilitati la cui password non scade mai.",
              "✅ Solo eccezioni giustificate e documentate (es. account di sync MSOL_*, alcuni service account gestiti).\n"
              "❌ Utenti normali o admin con password eterna. I service account andrebbero migrati a gMSA (rotazione automatica)."),
            t("B2 — Password non richiesta",
              "Get-ADUser -Filter {PasswordNotRequired -eq $true} -Properties PasswordNotRequired | Select Name,SamAccountName,Enabled",
              "Account che possono avere password VUOTA (flag PASSWD_NOTREQD).",
              "✅ Nessun account attivo.\n❌ Account abilitati: rischio di accesso senza password."),
            t("B3 — AS-REP roastable (pre-auth Kerberos disabilitata)",
              "Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth | Select Name,SamAccountName,Enabled",
              "Account da cui si puo' richiedere materiale Kerberos crackabile offline senza autenticarsi.",
              "✅ Vuoto.\n❌ Qualsiasi account (specie se attivo): esposto ad AS-REP Roasting."),
            t("B4 — Kerberoastable (SPN su account utente)",
              'Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName,PasswordLastSet,Enabled | Select Name,SamAccountName,PasswordLastSet,ServicePrincipalName',
              "Account UTENTE con SPN, da cui si possono estrarre ticket crackabili offline (Kerberoasting).",
              "✅ Solo krbtgt con kadmin/changepw (default, non sfruttabile nel modo classico).\n"
              "❌ Service account utente con SPN, soprattutto con PasswordLastSet vecchia → probabile password debole. Mitigazione: password lunghe/casuali o gMSA."),
            t("B5 — SID History",
              'Get-ADUser -Filter {SIDHistory -like "*"} -Properties SIDHistory | Select Name,SamAccountName,SIDHistory',
              "Account che portano SID storici (residui di migrazioni).",
              "✅ Vuoto, o solo migrazioni note in corso.\n❌ SID History inattesa, specie con SID di gruppi privilegiati → via di privilege escalation/persistenza."),
            t("B6 — Account stale (login vecchio > 90 giorni)",
              "$cutoff = (Get-Date).AddDays(-90)\n"
              "Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate |\n"
              "    Where-Object { $_.LastLogonDate -and $_.LastLogonDate -lt $cutoff } |\n"
              "    Select Name,SamAccountName,LastLogonDate | Sort LastLogonDate",
              "Account abilitati ma inutilizzati da oltre 90 giorni.",
              "✅ Lista corta/vuota.\n❌ Molti account abilitati e inattivi: superficie d'attacco inutile, da disabilitare/rimuovere."),
        ]),
        micro("C. Account e gruppi privilegiati", "Membri, residui, adminCount, Protected Users.", [
            t("C1 — Membri dei gruppi privilegiati (con annidamento)",
              'foreach ($g in "Domain Admins","Enterprise Admins","Schema Admins","Administrators","Account Operators","Backup Operators","Server Operators","Print Operators") {\n'
              '    "=== $g ==="\n'
              "    Get-ADGroupMember $g -Recursive -ErrorAction SilentlyContinue | Select Name,objectClass\n"
              "}",
              "Elenca tutti i membri (anche annidati) dei gruppi ad alto privilegio.",
              "✅ Domain Admins ridotto al minimo; Enterprise/Schema Admins vuoti in operativita' normale; nessun service account dentro.\n"
              "❌ Molti membri, account di servizio dentro gruppi admin, o gruppi che dovrebbero essere vuoti popolati stabilmente."),
            t("C2 — Account disabilitati ma ancora in gruppi privilegiati",
              'Get-ADGroupMember "Domain Admins" -Recursive |\n'
              "    Get-ADUser -Properties Enabled |\n"
              "    Where-Object { $_.Enabled -eq $false } |\n"
              "    Select Name,SamAccountName",
              "Trova membri disabilitati di Domain Admins (ripeti per gli altri gruppi).",
              "✅ Nessuno.\n❌ Account disabilitati ancora membri: se riabilitati ereditano subito i privilegi → vanno RIMOSSI dai gruppi, non solo disabilitati."),
            t("C3 — Account con adminCount=1",
              "Get-ADUser -Filter {adminCount -eq 1} -Properties adminCount,Enabled | Select Name,SamAccountName,Enabled",
              "Account marcati da AdminSDHolder come (ora o in passato) privilegiati.",
              "✅ Coincide con gli attuali admin.\n❌ Account che NON sono piu' admin ma hanno ancora adminCount=1: residui con ACL ereditate da ripulire (orphaned adminCount)."),
            t("C4 — Protected Users",
              'Get-ADGroupMember "Protected Users" | Select Name,objectClass',
              "Verifica chi e' protetto dalle difese aggiuntive del gruppo Protected Users.",
              "✅ Gli account amministrativi umani sono qui dentro.\n⚠️ Vuoto = protezione non sfruttata (buona pratica mancante). Non inserire service account con cifrature legacy: si rompono."),
        ]),
        micro("D. Delega Kerberos", "Unconstrained/constrained/RBCD e MachineAccountQuota.", [
            t("D1 — Unconstrained delegation",
              "Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name,DistinguishedName\n"
              "Get-ADUser     -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation | Select Name,SamAccountName",
              "Trova oggetti che possono impersonare qualsiasi utente che si autentica su di loro.",
              "✅ Solo i Domain Controller (per loro e' normale).\n❌ Server membri o account utente con unconstrained delegation: vettore classico di escalation."),
            t("D2 — Constrained delegation",
              "Get-ADObject -Filter {msDS-AllowedToDelegateTo -like \"*\"} -Properties msDS-AllowedToDelegateTo | Select Name,msDS-AllowedToDelegateTo",
              "Elenca chi puo' delegare verso servizi specifici.",
              "✅ Configurazioni note e giustificate.\n⚠️ Da rivedere caso per caso; attenzione alla delega verso servizi sensibili (es. host dei DC)."),
            t("D3 — Resource-Based Constrained Delegation (RBCD)",
              "Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity |\n"
              "    Where-Object { $_.'msDS-AllowedToActOnBehalfOfOtherIdentity' } |\n"
              "    Select Name",
              "Trova computer su cui altri oggetti possono agire per conto di terzi (RBCD).",
              "✅ Nessuno o configurazioni note.\n❌ RBCD inattesa: spesso lasciata da un attacco o da test → da investigare."),
            t("D4 — Machine Account Quota",
              '(Get-ADObject -Identity (Get-ADDomain).DistinguishedName -Properties "ms-DS-MachineAccountQuota")."ms-DS-MachineAccountQuota"',
              "Quanti computer un utente non privilegiato puo' aggiungere al dominio (default 10).",
              "✅ 0 (impedisce abusi tipo RBCD/noPac da parte di utenti standard).\n❌ 10 (default): un qualsiasi utente puo' creare account computer, utile a diverse tecniche di attacco."),
        ]),
        micro("E. Crittografia e protocolli", "Cifrature deboli e configurazione SMB.", [
            t("E1 — Cifrature deboli (DES / RC4)",
              "Get-ADUser -Filter {UseDESKeyOnly -eq $true} -Properties UseDESKeyOnly | Select Name,SamAccountName\n"
              "Get-ADObject -Filter 'msDS-SupportedEncryptionTypes -ne $null' -Properties msDS-SupportedEncryptionTypes |\n"
              "    Select Name,msDS-SupportedEncryptionTypes",
              "Trova account costretti a DES o che dichiarano cifrature deboli per Kerberos.",
              "✅ Nessun DES; valori che indicano solo AES.\n❌ DES abilitato, o RC4 ancora ammesso dove si puo' imporre AES."),
            t("E2 — Configurazione SMB",
              "Get-SmbServerConfiguration | Select EnableSMB1Protocol,EncryptData,RequireSecuritySignature,EnableSecuritySignature",
              "Stato di SMBv1, signing e cifratura SMB.",
              "✅ EnableSMB1Protocol False, RequireSecuritySignature True.\n❌ EnableSMB1Protocol True (protocollo obsoleto e vulnerabile). ⚠️ EncryptData False su file server sensibili e' da valutare.",
              tool="PowerShell"),
        ]),
        micro("F. GPO e SYSVOL", "cpassword nelle GPP, inventario e link delle GPO.", [
            t("F1 — Ricerca cpassword nelle GPP (MS14-025)",
              "Get-ChildItem \\\\egicon.local\\SYSVOL\\egicon.local\\Policies -Recurse -Include Groups.xml,Services.xml,ScheduledTasks.xml,Printers.xml,Drives.xml,DataSources.xml -ErrorAction SilentlyContinue |\n"
              '    Select-String "cpassword"',
              "Cerca password salvate nelle Group Policy Preferences, cifrate con chiave AES pubblicata da Microsoft (decifrabili da chiunque nel dominio).",
              "✅ Nessun risultato.\n❌ Righe con cpassword=\"...\": password recuperabile → finding grave. Documenta file e GPO (il path contiene il GUID)."),
            t("F2 — Inventario GPO e stato",
              "Get-GPO -All | Select DisplayName,GpoStatus,CreationTime,ModificationTime | Sort DisplayName",
              "Elenca tutte le GPO e il loro stato (AllSettingsEnabled, AllSettingsDisabled, ...).",
              "✅ Inventario pulito, nomi coerenti.\n⚠️ Molte GPO OLD_*/NOTUSED → verifica se ancora collegate (vedi F3) e rimuovi i residui.",
              tool="PowerShell (modulo GroupPolicy)"),
            t("F3 — GPO realmente collegate e abilitate (per OU)",
              "Get-ADOrganizationalUnit -Filter * | ForEach-Object {\n"
              "    $ou = $_.DistinguishedName\n"
              "    (Get-GPInheritance -Target $ou).GpoLinks |\n"
              "        Select-Object @{N='OU';E={$ou}}, DisplayName, Enabled, Enforced\n"
              "}",
              "Mostra, OU per OU, quali GPO sono collegate, se il link e' abilitato e se e' enforced.",
              "✅ Solo GPO attese e attive.\n❌ GPO che indeboliscono la sicurezza ancora collegate e con Enabled True (es. una 'Defender-Disable' attiva). Una GPO 'OLD' con link attivo va trattata come attiva.",
              tool="PowerShell (moduli ActiveDirectory + GroupPolicy)"),
        ]),
        micro("G. Infrastruttura e configurazioni generali",
              "LAPS, trust, DnsAdmins, OS obsoleti, functional level, krbtgt.", [
            t("G1 — LAPS (password admin locale gestite)",
              '# LAPS classico\n'
              'Get-ADComputer -Filter * -Properties "ms-Mcs-AdmPwdExpirationTime" |\n'
              '    Where-Object { $_."ms-Mcs-AdmPwdExpirationTime" } | Measure-Object | Select Count\n'
              '# Windows LAPS (piu\' recente)\n'
              'Get-ADComputer -Filter * -Properties "msLAPS-PasswordExpirationTime" -ErrorAction SilentlyContinue |\n'
              '    Where-Object { $_."msLAPS-PasswordExpirationTime" } | Measure-Object | Select Count',
              "Stima quante macchine hanno una password admin locale gestita da LAPS.",
              "✅ Count vicino al numero totale di workstation/server.\n❌ 0 o numero basso → admin locale probabilmente con password unica/condivisa = rischio di movimento laterale. Soluzione: implementare (Windows) LAPS."),
            t("G2 — Trust del dominio/foresta",
              "Get-ADTrust -Filter * | Select Name,Direction,TrustType,SelectiveAuthentication,SIDFilteringQuarantined",
              "Elenca i trust e le loro proprieta' di sicurezza.",
              "✅ Trust noti, con SID filtering attivo dove appropriato.\n❌ Trust dimenticati, bidirezionali senza necessita', o senza SID filtering verso domini non fidati."),
            t("G3 — DnsAdmins",
              'Get-ADGroupMember "DnsAdmins" -ErrorAction SilentlyContinue | Select Name,objectClass',
              "Chi e' in DnsAdmins (gruppo storicamente sfruttabile per eseguire codice sui DC).",
              "✅ Vuoto o solo admin attesi.\n❌ Membri non giustificati: privilegio potenzialmente escalabile."),
            t("G4 — Sistemi operativi obsoleti",
              "Get-ADComputer -Filter {Enabled -eq $true} -Properties OperatingSystem |\n"
              "    Group-Object OperatingSystem | Sort Count -Descending | Select Count,Name",
              "Distribuzione degli OS dei computer di dominio.",
              "✅ Solo OS supportati.\n❌ Windows 7/Server 2008/2012 ecc. non piu' supportati: privi di patch, da isolare/dismettere."),
            t("G5 — Livello funzionale di dominio e foresta",
              "Get-ADDomain | Select DomainMode\nGet-ADForest | Select ForestMode",
              "Mostra il functional level, che abilita/limita le funzioni di sicurezza moderne.",
              "✅ Livello recente (es. 2016+).\n⚠️ Livelli vecchi (2008/2012) limitano feature di sicurezza: valuta l'innalzamento dopo verifica dei DC."),
            t("G6 — krbtgt: eta' password",
              "Get-ADUser krbtgt -Properties PasswordLastSet | Select PasswordLastSet",
              "Data dell'ultimo cambio password dell'account che firma tutti i ticket Kerberos.",
              "✅ Rotazione recente (entro ~180 giorni) e periodica.\n❌ Data molto vecchia (anni): se l'hash e' mai stato compromesso, Golden Ticket con persistenza lunghissima. Rotazione con procedura a DOPPIO reset (due cambi distanziati, per non rompere i ticket in corso)."),
        ]),
        micro("Note operative e strumenti", "Come eseguire, salvare e approfondire.", [
            t("Esecuzione e salvataggio output",
              "# salva un output per il report:\n<comando> | Export-Csv C:\\audit\\nome.csv -NoTypeInformation\n<comando> | Out-File C:\\audit\\nome.txt",
              "Come eseguire i controlli e conservarne l'output.",
              "Esegui da una sessione con privilegi di lettura sul dominio (alcuni attributi richiedono privilegi maggiori). I controlli sono enumerazione: le remediation vanno testate fuori produzione.",
              tool="PowerShell"),
            t("GPO con interfaccia grafica",
              "gpmc.msc",
              "Rivedere le GPO con la Group Policy Management Console.",
              "Utile per ispezionare visivamente impostazioni e link delle GPO oltre ai comandi F2/F3.",
              tool="gpmc"),
            t("Certificati vulnerabili (AD CS / ESC)",
              "certipy-ad find -u UTENTE@DOMINIO -p 'PASSWORD' -dc-ip IP_DC -stdout -vulnerable",
              "Cerca template e configurazioni di Certificate Services sfruttabili (ESC1-ESC8...).",
              "Template segnalati come 'vulnerable' → possibili vie di escalation/persistenza tramite AD CS. Richiede credenziali di dominio valide.",
              tool="Certipy"),
        ]),
    ],
}


def main():
    out = Path(__file__).resolve().parent.parent / "data" / "ad_checklist_seed.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"source": "appunti checklist AD", "topics": [MACRO]},
                              ensure_ascii=False, indent=2), encoding="utf-8")
    nmicro = len(MACRO["children"])
    ncheck = sum(len(mi["checks"]) for mi in MACRO["children"])
    print(f"Scritta la checklist AD: 1 macro, {nmicro} sezioni, {ncheck} check in {out}")


if __name__ == "__main__":
    main()
