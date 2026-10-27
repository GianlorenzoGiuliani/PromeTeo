"""Target di un progetto (nome + IP/URL) e la sua pagina di dettaglio: e' dentro
il target che si aggiungono i findings e le tecnologie di quel bersaglio."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import Finding, Project, Target, Technology
from app.web import (
    SEVERITY_LABELS,
    get_or_404,
    severity_from_cvss,
    templates,
)

router = APIRouter()


@router.get("/target/{target_id}", response_class=HTMLResponse)
def target_detail(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Pagina del target: i suoi findings e le sue tecnologie, con i pulsanti
    per aggiungerli (il target e' gia' fissato, niente menu da selezionare)."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    # Ordiniamo i findings dal piu' grave al meno grave: la gravita' si deriva
    # dal punteggio CVSS, quindi ordiniamo per CVSS decrescente (il None va in
    # coda) e, a parita', per id.
    findings = sorted(
        session.exec(select(Finding).where(Finding.target_id == target_id)).all(),
        key=lambda f: (-(f.cvss_score if f.cvss_score is not None else -1.0), f.id),
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
            # Funzione per ricavare la gravita' dal CVSS (la usa il template).
            "severity_from_cvss": severity_from_cvss,
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
    """Elimina un target e tutto cio' che contiene: i suoi findings e le sue
    tecnologie."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project_id = target.project_id
    for f in session.exec(select(Finding).where(Finding.target_id == target_id)).all():
        session.delete(f)
    for tech in session.exec(select(Technology).where(Technology.target_id == target_id)).all():
        session.delete(tech)
    session.delete(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
