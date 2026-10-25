"""Tecnologie di un target: creazione, modifica, eliminazione e ricerca delle
CVE sull'NVD dal CPE. Una tecnologia si aggiunge entrando nel target."""
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session

from app import nvd
from app.database import get_session
from app.models import Project, Target, Technology
from app.web import get_or_404, templates

router = APIRouter()


def _back_url(tech: Technology) -> str:
    """Dove tornare dopo un'azione: la pagina del target (o il progetto, per le
    vecchie tecnologie senza target)."""
    return f"/target/{tech.target_id}" if tech.target_id else f"/progetti/{tech.project_id}"


@router.get("/target/{target_id}/tecnologie/nuovo", response_class=HTMLResponse)
def tech_new_form(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per aggiungere una tecnologia a un target."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    values = {"name": "", "version": "", "cpe": "", "notes": ""}
    return templates.TemplateResponse(
        request=request,
        name="tech_form.html",
        context={
            "project": project,
            "target": target,
            "values": values,
            "form_action": f"/target/{target_id}/tecnologie",
            "form_title": "Nuova tecnologia",
            "submit_label": "Aggiungi tecnologia",
            "back_url": f"/target/{target_id}",
        },
    )


@router.post("/target/{target_id}/tecnologie")
def tech_create(
    target_id: int,
    name: str = Form(""),
    version: str = Form(""),
    cpe: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea una tecnologia dentro un target."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    tech = Technology(
        project_id=target.project_id,
        target_id=target.id,
        name=name.strip() or None,
        version=version.strip() or None,
        cpe=cpe.strip() or None,
        notes=notes.strip() or None,
    )
    session.add(tech)
    session.commit()
    return RedirectResponse(url=f"/target/{target_id}", status_code=303)


@router.get("/tecnologia/{tech_id}/modifica", response_class=HTMLResponse)
def tech_edit_form(tech_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare una tecnologia."""
    tech = get_or_404(session, Technology, tech_id, "Tecnologia non trovata")
    project = session.get(Project, tech.project_id)
    target = session.get(Target, tech.target_id) if tech.target_id else None
    values = {
        "name": tech.name or "", "version": tech.version or "",
        "cpe": tech.cpe or "", "notes": tech.notes or "",
    }
    return templates.TemplateResponse(
        request=request,
        name="tech_form.html",
        context={
            "project": project,
            "target": target,
            "values": values,
            "form_action": f"/tecnologia/{tech.id}",
            "form_title": "Modifica tecnologia",
            "submit_label": "Salva modifiche",
            "back_url": _back_url(tech),
        },
    )


@router.post("/tecnologia/{tech_id}")
def tech_update(
    tech_id: int,
    name: str = Form(""),
    version: str = Form(""),
    cpe: str = Form(""),
    notes: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna una tecnologia."""
    tech = get_or_404(session, Technology, tech_id, "Tecnologia non trovata")
    tech.name = name.strip() or None
    tech.version = version.strip() or None
    tech.cpe = cpe.strip() or None
    tech.notes = notes.strip() or None
    session.add(tech)
    session.commit()
    return RedirectResponse(url=_back_url(tech), status_code=303)


@router.post("/tecnologia/{tech_id}/elimina")
def tech_delete(tech_id: int, session: Session = Depends(get_session)):
    """Elimina una tecnologia."""
    tech = get_or_404(session, Technology, tech_id, "Tecnologia non trovata")
    dest = _back_url(tech)
    session.delete(tech)
    session.commit()
    return RedirectResponse(url=dest, status_code=303)


@router.get("/tecnologia/{tech_id}/cve", response_class=HTMLResponse)
def tech_cve(tech_id: int, request: Request, session: Session = Depends(get_session)):
    """Interroga l'NVD dal CPE della tecnologia e mostra le CVE trovate."""
    tech = get_or_404(session, Technology, tech_id, "Tecnologia non trovata")
    cves = []
    error = None
    if not (tech.cpe or "").strip():
        error = "Questa tecnologia non ha un CPE: aggiungilo per cercare le CVE."
    else:
        try:
            cves = nvd.cerca_cve(tech.cpe)
        except nvd.NvdError as e:
            error = str(e)

    # Per ogni CVE, un link al form del finding gia' precompilato, sul target
    # della tecnologia (cosi' la CVE diventa un finding di quel bersaglio).
    label = " ".join(p for p in (tech.name, tech.version) if p)
    for c in cves:
        params = {"cve": c["id"], "title": (f"{label}: " if label else "") + c["id"]}
        if c["description"]:
            params["description"] = c["description"]
        if c["severity"]:
            params["severity"] = c["severity"].lower()
        if c["cvss_score"] is not None:
            params["cvss_score"] = c["cvss_score"]
        if tech.target_id:
            c["finding_url"] = f"/target/{tech.target_id}/findings/nuovo?" + urlencode(params)
        else:
            params["project_id"] = tech.project_id
            c["finding_url"] = "/findings/nuovo?" + urlencode(params)

    target = session.get(Target, tech.target_id) if tech.target_id else None
    return templates.TemplateResponse(
        request=request,
        name="cve_list.html",
        context={
            "tech": tech,
            "project": session.get(Project, tech.project_id),
            "target": target,
            "cves": cves,
            "error": error,
        },
    )
