"""
Generazione del report di un progetto in formato Markdown.

Lo teniamo separato dalle rotte (main.py): cosi' la logica "come si scrive il
report" sta in un posto solo ed e' facile da leggere e da modificare.
Il Markdown e' comodo perche' e' testo semplice: lo apri ovunque, lo converti
in PDF o Word, lo incolli in un ticket.
"""
from datetime import datetime

from app.models import SEVERITIES, Finding, Project


def target_str(f: Finding) -> str:
    """Bersaglio leggibile di un finding: host[:porta] e/o URL."""
    parts = []
    if f.target_host:
        host = f.target_host
        if f.target_port:
            host += f":{f.target_port}"
        parts.append(host)
    if f.target_url:
        parts.append(f.target_url)
    return " | ".join(parts)


def build_markdown_report(
    project: Project,
    findings: list[Finding],
    severity_labels: dict[str, str],
    status_labels: dict[str, str],
) -> str:
    """Costruisce il testo Markdown del report a partire dai dati."""
    out: list[str] = []

    # Intestazione (con azienda e autore, se presenti).
    if project.company:
        out.append(f"**{project.company}**")
        out.append("")
    out.append(f"# Report di penetration test - {project.name}")
    out.append("")
    if project.client:
        out.append(f"**Cliente:** {project.client}  ")
    if project.author:
        out.append(f"**Autore:** {project.author}  ")
    out.append(f"**Data:** {datetime.now():%Y-%m-%d}  ")
    out.append(f"**Findings totali:** {len(findings)}")
    out.append("")

    if project.scope:
        out.append("## Scope")
        out.append("")
        out.append(project.scope)
        out.append("")

    # Riepilogo: quanti findings per ogni livello di gravita'.
    out.append("## Riepilogo")
    out.append("")
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    for s in SEVERITIES:
        out.append(f"- {severity_labels.get(s, s)}: {counts[s]}")
    out.append("")

    # Dettaglio dei findings, raggruppati per gravita' e numerati di seguito.
    out.append("## Findings")
    out.append("")
    if not findings:
        out.append("_Nessun finding registrato._")

    n = 0
    for s in SEVERITIES:
        group = [f for f in findings if f.severity == s]
        if not group:
            continue
        out.append(f"### {severity_labels.get(s, s)} ({len(group)})")
        out.append("")
        for f in group:
            n += 1
            out.append(f"#### {n}. {f.title}")
            out.append("")
            meta = [f"**Stato:** {status_labels.get(f.status, f.status)}"]
            target = target_str(f)
            if target:
                meta.append(f"**Bersaglio:** {target}")
            if f.cve:
                meta.append(f"**CVE:** {f.cve}")
            if f.cwe:
                meta.append(f"**CWE:** {f.cwe}")
            out.append("  \n".join(meta))
            out.append("")

            if f.description:
                out.append("**Descrizione**")
                out.append("")
                out.append(f.description)
                out.append("")
            if f.evidence:
                out.append("**Prova (evidence)**")
                out.append("")
                out.append("```")
                out.append(f.evidence)
                out.append("```")
                out.append("")
            if f.remediation:
                out.append("**Rimedio**")
                out.append("")
                out.append(f.remediation)
                out.append("")

    return "\n".join(out)
