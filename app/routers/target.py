"""Target di un progetto (nome + IP/URL) e la sua pagina di dettaglio: e' dentro
il target che si aggiungono i findings e le tecnologie di quel bersaglio."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import Finding, FindingEvent, Project, Target, Technology
from app.web import (
    LIKELIHOOD_LABELS,
    SEVERITY_LABELS,
    SEVERITY_RANK,
    STATUS_LABELS,
    get_or_404,
    templates,
)

router = APIRouter()


@router.get("/target/{target_id}", response_class=HTMLResponse)
def target_detail(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Pagina del target: i suoi findings e le sue tecnologie, con i pulsanti
    per aggiungerli (il target e' gia' fissato, niente menu da selezionare)."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    findings = sorted(
        session.exec(select(Finding).where(Finding.target_id == target_id)).all(),
        key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id),
    )
    technologies = session.exec(
        select(Technology).where(Technology.target_id == target_id).order_by(Technology.id)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="target.html",
        context={
            "target": target,
            "project": project,
            "findings": findings,
            "technologies": technologies,
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
            "likelihood_labels": LIKELIHOOD_LABELS,
        },
    )


@router.get("/progetti/{project_id}/target/nuovo", response_class=HTMLResponse)
def target_new_form(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per aggiungere un target a un progetto."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    values = {"name": "", "host": ""}
    return templates.TemplateResponse(
        request=request,
        name="target_form.html",
        context={
            "project": project,
            "values": values,
            "form_action": f"/progetti/{project_id}/target",
            "form_title": "Nuovo target",
            "submit_label": "Aggiungi target",
            "back_url": f"/progetti/{project_id}",
        },
    )


@router.post("/progetti/{project_id}/target")
def target_create(
    project_id: int,
    name: str = Form(""),
    host: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un target (nome + IP/URL) e porta dritti alla sua pagina."""
    get_or_404(session, Project, project_id, "Progetto non trovato")
    target = Target(
        project_id=project_id,
        name=name.strip() or None,
        host=host.strip() or None,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return RedirectResponse(url=f"/target/{target.id}", status_code=303)


@router.get("/target/{target_id}/modifica", response_class=HTMLResponse)
def target_edit_form(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare un target."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    values = {"name": target.name or "", "host": target.host or ""}
    return templates.TemplateResponse(
        request=request,
        name="target_form.html",
        context={
            "project": project,
            "values": values,
            "form_action": f"/target/{target.id}",
            "form_title": "Modifica target",
            "submit_label": "Salva modifiche",
            "back_url": f"/target/{target.id}",
        },
    )


@router.post("/target/{target_id}")
def target_update(
    target_id: int,
    name: str = Form(""),
    host: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna un target (nome + IP/URL)."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    target.name = name.strip() or None
    target.host = host.strip() or None
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/target/{target.id}", status_code=303)


@router.post("/target/{target_id}/elimina")
def target_delete(target_id: int, session: Session = Depends(get_session)):
    """Elimina un target e tutto cio' che contiene: i suoi findings (con lo
    storico) e le sue tecnologie."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project_id = target.project_id
    for f in session.exec(select(Finding).where(Finding.target_id == target_id)).all():
        for ev in session.exec(select(FindingEvent).where(FindingEvent.finding_id == f.id)).all():
            session.delete(ev)
        session.delete(f)
    for tech in session.exec(select(Technology).where(Technology.target_id == target_id)).all():
        session.delete(tech)
    session.delete(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
