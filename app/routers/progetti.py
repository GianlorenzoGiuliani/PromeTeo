"""Progetti: elenco, creazione, dettaglio (dashboard + elenco dei target),
modifica ed eliminazione. I findings e le tecnologie stanno dentro i target."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, func, select

from app.database import get_session
from app.models import (
    SEVERITIES,
    STATUSES,
    Finding,
    FindingEvent,
    Project,
    Target,
    Technology,
)
from app.web import (
    SEVERITY_LABELS,
    get_or_404,
    templates,
)

router = APIRouter()


@router.get("/progetti", response_class=HTMLResponse)
def progetti(request: Request, session: Session = Depends(get_session), q: str | None = None):
    """Elenco dei progetti (ricercabili per nome) + form per crearne uno."""
    statement = select(Project).order_by(Project.created_at.desc())
    if q:
        statement = statement.where(Project.name.ilike(f"%{q}%"))
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
    info: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un progetto (nome + nota) e reindirizza alla sua pagina.

    Il reindirizzamento dopo un POST (codice 303) e' il pattern
    'Post/Redirect/Get': evita che ricaricando la pagina si reinvii il form.
    """
    project = Project(name=name.strip(), info=info.strip() or None)
    session.add(project)
    session.commit()
    session.refresh(project)
    return RedirectResponse(url=f"/progetti/{project.id}", status_code=303)


@router.get("/progetti/{project_id}", response_class=HTMLResponse)
def progetto_detail(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Dettaglio di un progetto: dashboard di riepilogo + elenco dei target.
    I findings e le tecnologie si vedono e si aggiungono entrando nel target."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    targets = session.exec(
        select(Target).where(Target.project_id == project_id).order_by(Target.id)
    ).all()
    # Quanti findings ha ciascun target: un solo GROUP BY, non una query per target.
    finding_counts = dict(
        session.exec(
            select(Finding.target_id, func.count())
            .where(Finding.project_id == project_id)
            .group_by(Finding.target_id)
        ).all()
    )

    # Statistiche per la mini-dashboard in cima alla pagina: due GROUP BY (una
    # per la gravita' e una per lo stato), invece di contare in Python.
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
            "targets": targets,
            "finding_counts": finding_counts,
            "stats": stats,
            "severities": SEVERITIES,
            "severity_labels": SEVERITY_LABELS,
        },
    )


@router.get("/progetti/{project_id}/modifica", response_class=HTMLResponse)
def progetto_edit_form(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare i dati di un progetto."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    return templates.TemplateResponse(
        request=request,
        name="progetto_modifica.html",
        context={"project": project},
    )


@router.post("/progetti/{project_id}")
def progetto_update(
    project_id: int,
    name: str = Form(...),
    info: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna nome e nota di un progetto."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    project.name = name.strip()
    project.info = info.strip() or None
    session.add(project)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@router.post("/progetti/{project_id}/elimina")
def progetto_delete(project_id: int, session: Session = Depends(get_session)):
    """Elimina un progetto e tutto cio' che contiene: findings (con il loro
    storico), target e tecnologie. Cascata manuale ed esplicita."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    for f in session.exec(select(Finding).where(Finding.project_id == project_id)).all():
        for ev in session.exec(select(FindingEvent).where(FindingEvent.finding_id == f.id)).all():
            session.delete(ev)
        session.delete(f)
    for t in session.exec(select(Target).where(Target.project_id == project_id)).all():
        session.delete(t)
    for tech in session.exec(select(Technology).where(Technology.project_id == project_id)).all():
        session.delete(tech)
    session.delete(project)
    session.commit()
    return RedirectResponse(url="/progetti", status_code=303)
