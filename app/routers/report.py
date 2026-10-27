"""Report del progetto: pagina HTML (stampabile/PDF) ed export Markdown."""
from datetime import datetime

from fastapi import APIRouter, Depends, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import SEVERITIES, Finding, Project, Target
from app.reporting import build_markdown_report, finding_target_str
from app.web import (
    SEVERITY_LABELS,
    get_or_404,
    severity_from_cvss,
    templates,
)


def _sorted_by_severity(findings):
    """Ordina i findings dal piu' grave al meno grave: la gravita' deriva dal
    punteggio CVSS, quindi ordiniamo per CVSS decrescente (None in coda)."""
    return sorted(
        findings,
        key=lambda f: (-(f.cvss_score if f.cvss_score is not None else -1.0), f.id),
    )

router = APIRouter()


@router.get("/progetti/{project_id}/report", response_class=HTMLResponse)
def report_html(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Report del progetto, in una pagina pensata anche per la stampa / PDF."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    findings = session.exec(select(Finding).where(Finding.project_id == project_id)).all()
    findings = _sorted_by_severity(findings)
    targets = session.exec(select(Target).where(Target.project_id == project_id)).all()
    targets_by_id = {t.id: t for t in targets}
    target_strings = {f.id: finding_target_str(f, targets_by_id) for f in findings}
    sev_counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        sev_counts[severity_from_cvss(f.cvss_score)] += 1
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "project": project,
            "findings": findings,
            "target_strings": target_strings,
            "sev_counts": sev_counts,
            "severities": SEVERITIES,
            "severity_labels": SEVERITY_LABELS,
            "severity_from_cvss": severity_from_cvss,
            "now": datetime.now(),
        },
    )


@router.get("/progetti/{project_id}/report.md")
def report_md(project_id: int, session: Session = Depends(get_session)):
    """Scarica il report in formato Markdown (un file di testo)."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    findings = session.exec(select(Finding).where(Finding.project_id == project_id)).all()
    findings = _sorted_by_severity(findings)
    targets = session.exec(select(Target).where(Target.project_id == project_id)).all()
    targets_by_id = {t.id: t for t in targets}
    markdown = build_markdown_report(project, findings, SEVERITY_LABELS, targets_by_id)
    filename = f"report-progetto-{project.id}.md"
    return PlainTextResponse(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
