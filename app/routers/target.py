"""Target: i bersagli di un progetto (host/IP o URL). Creazione, modifica
ed eliminazione."""
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import Finding, Project, Target
from app.web import get_or_404, int_or_none, templates

router = APIRouter()


@router.get("/progetti/{project_id}/target/nuovo", response_class=HTMLResponse)
def target_new_form(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per aggiungere un target a un progetto."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    values = {"name": "", "host": "", "port": "", "url": "", "notes": ""}
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
    port: str = Form(""),
    url: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un target dentro un progetto."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    target = Target(
        project_id=project_id,
        name=name.strip() or None,
        host=host.strip() or None,
        port=int_or_none(port),
        url=url.strip() or None,
        notes=notes.strip() or None,
    )
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@router.get("/target/{target_id}/modifica", response_class=HTMLResponse)
def target_edit_form(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare un target."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    values = {
        "name": target.name or "",
        "host": target.host or "",
        "port": target.port or "",
        "url": target.url or "",
        "notes": target.notes or "",
    }
    return templates.TemplateResponse(
        request=request,
        name="target_form.html",
        context={
            "project": project,
            "values": values,
            "form_action": f"/target/{target.id}",
            "form_title": "Modifica target",
            "submit_label": "Salva modifiche",
            "back_url": f"/progetti/{target.project_id}",
        },
    )


@router.post("/target/{target_id}")
def target_update(
    target_id: int,
    name: str = Form(""),
    host: str = Form(""),
    port: str = Form(""),
    url: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna un target."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    target.name = name.strip() or None
    target.host = host.strip() or None
    target.port = int_or_none(port)
    target.url = url.strip() or None
    target.notes = notes.strip() or None
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{target.project_id}", status_code=303)


@router.post("/target/{target_id}/elimina")
def target_delete(target_id: int, session: Session = Depends(get_session)):
    """Elimina un target. I findings che lo usavano perdono il collegamento."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project_id = target.project_id
    orfani = session.exec(select(Finding).where(Finding.target_id == target_id)).all()
    for f in orfani:
        f.target_id = None
        session.add(f)
    session.delete(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
