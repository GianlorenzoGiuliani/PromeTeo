"""Progetti: elenco, creazione, dettaglio (dashboard + elenco dei target),
modifica ed eliminazione. I findings e le tecnologie stanno dentro i target."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, func, select

from app.database import get_session
from app.models import (
    SEVERITIES,
    Finding,
    Project,
    Target,
    Technology,
)
from app.web import (
    SEVERITY_LABELS,
    get_or_404,
    severity_from_cvss,
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

    # Statistiche per la mini-dashboard in cima alla pagina. La gravita' non e'
    # piu' un campo salvato: la ricaviamo dal punteggio CVSS di ogni finding.
    # Leggiamo i soli punteggi (una query) e contiamo le bande in Python.
    scores = session.exec(
        select(Finding.cvss_score).where(Finding.project_id == project_id)
    ).all()
    sev_counts = {s: 0 for s in SEVERITIES}
    for score in scores:
        sev_counts[severity_from_cvss(score)] += 1
    n_findings = len(scores)
    stats = {
        "n_targets": len(targets),
        "n_findings": n_findings,
        # "Gravi" = findings Critici + Alti: quelli da affrontare per primi.
        "gravi": sev_counts["critical"] + sev_counts["high"],
        "sev_counts": sev_counts,
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
    """Elimina un progetto e tutto cio' che contiene: findings, target e
    tecnologie. Cascata manuale ed esplicita."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    for f in session.exec(select(Finding).where(Finding.project_id == project_id)).all():
        session.delete(f)
    for t in session.exec(select(Target).where(Target.project_id == project_id)).all():
        session.delete(t)
    for tech in session.exec(select(Technology).where(Technology.project_id == project_id)).all():
        session.delete(tech)
    session.delete(project)
    session.commit()
    return RedirectResponse(url="/progetti", status_code=303)
