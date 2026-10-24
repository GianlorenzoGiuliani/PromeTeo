"""Progetti: elenco, creazione, dettaglio (con findings raggruppati per
target), modifica ed eliminazione."""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlmodel import Session, func, select

from app.database import get_session
from app.models import SEVERITIES, STATUSES, Finding, Project, Target
from app.reporting import target_label
from app.web import (
    LIKELIHOOD_LABELS,
    SEVERITY_LABELS,
    SEVERITY_RANK,
    STATUS_LABELS,
    templates,
)

router = APIRouter()


@router.get("/progetti", response_class=HTMLResponse)
def progetti(request: Request, session: Session = Depends(get_session), q: str | None = None):
    """Elenco dei progetti (ricercabili per nome/cliente) + form per crearne uno."""
    statement = select(Project).order_by(Project.created_at.desc())
    if q:
        like = f"%{q}%"
        statement = statement.where(or_(Project.name.ilike(like), Project.client.ilike(like)))
    projects = session.exec(statement).all()
    counts = dict(
        session.exec(select(Finding.project_id, func.count()).group_by(Finding.project_id)).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="progetti.html",
        context={"projects": projects, "counts": counts, "q": q or ""},
    )


@router.post("/progetti")
def crea_progetto(
    name: str = Form(...),
    client: str = Form(""),
    company: str = Form(""),
    author: str = Form(""),
    scope: str = Form(""),
    info: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un progetto e reindirizza alla sua pagina.

    Il reindirizzamento dopo un POST (codice 303) e' il pattern
    'Post/Redirect/Get': evita che ricaricando la pagina si reinvii il form.
    """
    project = Project(
        name=name.strip(),
        client=client.strip() or None,
        company=company.strip() or None,
        author=author.strip() or None,
        scope=scope.strip() or None,
        info=info.strip() or None,
    )
    session.add(project)
    session.commit()
    session.refresh(project)
    return RedirectResponse(url=f"/progetti/{project.id}", status_code=303)


@router.get("/progetti/{project_id}", response_class=HTMLResponse)
def progetto_detail(
    project_id: int,
    request: Request,
    session: Session = Depends(get_session),
    severity: str | None = None,
    status: str | None = None,
):
    """Dettaglio di un progetto: dati + findings, filtrabili per gravita' e stato."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    statement = select(Finding).where(Finding.project_id == project_id)
    if severity in SEVERITIES:
        statement = statement.where(Finding.severity == severity)
    if status in STATUSES:
        statement = statement.where(Finding.status == status)
    findings = sorted(
        session.exec(statement).all(),
        key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id),
    )
    targets = session.exec(
        select(Target).where(Target.project_id == project_id).order_by(Target.id)
    ).all()
    targets_by_id = {t.id: t for t in targets}
    # Raggruppiamo i findings per target (nell'ordine dei target), con un
    # gruppo finale "Senza target" per quelli non associati a un bersaglio.
    grouped = []
    for t in targets:
        fs = [f for f in findings if f.target_id == t.id]
        if fs:
            grouped.append({"label": target_label(t), "findings": fs})
    senza = [f for f in findings if not f.target_id or f.target_id not in targets_by_id]
    if senza:
        grouped.append({"label": "Senza target", "findings": senza})

    # Statistiche per la mini-dashboard in cima alla pagina. Le calcoliamo
    # sull'INTERO progetto (non sul filtro attivo) con due GROUP BY: una query
    # per la gravita' e una per lo stato, invece di contare in Python.
    sev_counts = {s: 0 for s in SEVERITIES}
    for sev, n in session.exec(
        select(Finding.severity, func.count())
        .where(Finding.project_id == project_id)
        .group_by(Finding.severity)
    ).all():
        if sev in sev_counts:
            sev_counts[sev] = n
    status_counts = {s: 0 for s in STATUSES}
    for st, n in session.exec(
        select(Finding.status, func.count())
        .where(Finding.project_id == project_id)
        .group_by(Finding.status)
    ).all():
        if st in status_counts:
            status_counts[st] = n
    stats = {
        "n_targets": len(targets),
        "n_findings": sum(sev_counts.values()),
        "da_verificare": status_counts["open"] + status_counts["confirmed"],
        "risolti": status_counts["resolved"],
        "sev_counts": sev_counts,
        "status_counts": status_counts,
    }

    return templates.TemplateResponse(
        request=request,
        name="progetto.html",
        context={
            "project": project,
            "findings": findings,
            "targets": targets,
            "grouped": grouped,
            "stats": stats,
            "severities": SEVERITIES,
            "statuses": STATUSES,
            "sel_severity": severity or "",
            "sel_status": status or "",
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
            "likelihood_labels": LIKELIHOOD_LABELS,
        },
    )


@router.get("/progetti/{project_id}/modifica", response_class=HTMLResponse)
def progetto_edit_form(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare i dati di un progetto."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    return templates.TemplateResponse(
        request=request,
        name="progetto_modifica.html",
        context={"project": project},
    )


@router.post("/progetti/{project_id}")
def progetto_update(
    project_id: int,
    name: str = Form(...),
    client: str = Form(""),
    company: str = Form(""),
    author: str = Form(""),
    scope: str = Form(""),
    info: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna i dati di un progetto."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    project.name = name.strip()
    project.client = client.strip() or None
    project.company = company.strip() or None
    project.author = author.strip() or None
    project.scope = scope.strip() or None
    project.info = info.strip() or None
    session.add(project)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@router.post("/progetti/{project_id}/elimina")
def progetto_delete(project_id: int, session: Session = Depends(get_session)):
    """Elimina un progetto e TUTTI i suoi findings (cascata manuale ed esplicita)."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    findings = session.exec(select(Finding).where(Finding.project_id == project_id)).all()
    for f in findings:
        session.delete(f)
    session.delete(project)
    session.commit()
    return RedirectResponse(url="/progetti", status_code=303)
