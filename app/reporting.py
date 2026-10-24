"""
Generazione del report di un progetto in formato Markdown, piu' le funzioni
per descrivere il "bersaglio" di un finding.

Teniamo questa logica separata dalle rotte (main.py): cosi' sta in un posto solo.
NB: le note operative del progetto (project.info: VPN, credenziali...) NON
finiscono nel report: sono appunti interni, non roba da consegnare al cliente.
"""
from datetime import datetime

from app.models import SEVERITIES, Finding, Project, Target


def _target_from_obj(t: Target) -> str:
    """Testo leggibile di un target: 'Nome (host:porta | url)'."""
    bits = []
    if t.host:
        bits.append(t.host + (f":{t.port}" if t.port else ""))
    if t.url:
        bits.append(t.url)
    joined = " | ".join(bits)
    if t.name and joined:
        return f"{t.name} ({joined})"
    return t.name or joined


def finding_target_str(f: Finding, targets_by_id: dict[int, Target]) -> str:
    """Bersaglio di un finding: dal target collegato, o dai vecchi campi (storico)."""
    if f.target_id and f.target_id in targets_by_id:
        return _target_from_obj(targets_by_id[f.target_id])
    bits = []
    if f.target_host:
        bits.append(f.target_host + (f":{f.target_port}" if f.target_port else ""))
    if f.target_url:
        bits.append(f.target_url)
    return " | ".join(bits)


def build_markdown_report(
    project: Project,
    findings: list[Finding],
    severity_labels: dict[str, str],
    status_labels: dict[str, str],
    targets_by_id: dict[int, Target],
) -> str:
    """Costruisce il testo Markdown del report a partire dai dati."""
    out: list[str] = []

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

    out.append("## Riepilogo")
    out.append("")
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    for s in SEVERITIES:
        out.append(f"- {severity_labels.get(s, s)}: {counts[s]}")
    out.append("")

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
            target = finding_target_str(f, targets_by_id)
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
