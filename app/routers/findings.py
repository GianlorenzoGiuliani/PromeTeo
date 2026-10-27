"""
Findings: creazione (dentro un target, o scegliendo il progetto dal catalogo),
modifica ed eliminazione.

Campi essenziali: titolo, descrizione breve, CVSS (punteggio + vettore),
CVE/CWE, PoC (proof of concept) e rimedio. La GRAVITA' non e' un campo: si
deriva dal punteggio CVSS (web.severity_from_cvss).
"""
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import Check, Finding, Project, Target, Topic
from app.reporting import target_label
from app.web import get_or_404, int_or_none, templates

router = APIRouter()


# ===========================================================================
# Helpers: validazione e salvataggio. Tenere la logica qui (fuori dalle rotte)
# significa un solo posto da leggere e da correggere.
# ===========================================================================

def float_or_none(value):
    """Converte in numero con la virgola (accetta anche '7,5'), oppure None."""
    try:
        return float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return None


# Campi di testo del finding: li puliamo tutti allo stesso modo (strip -> None).
TEXT_FIELDS = ["description", "cvss_vector", "cve", "cwe", "poc", "remediation"]


def clean_finding_fields(form) -> dict:
    """Legge e normalizza i campi di un finding da un form: titolo obbligatorio,
    punteggio CVSS convertito in numero, testi vuoti -> None."""
    def s(key):
        return (form.get(key) or "").strip() or None

    fields = {
        "title": (form.get("title") or "").strip(),
        "cvss_score": float_or_none(form.get("cvss_score")),
        "target_id": int_or_none(form.get("target_id")),
        "topic_id": int_or_none(form.get("topic_id")),
        "check_id": int_or_none(form.get("check_id")),
    }
    for key in TEXT_FIELDS:
        fields[key] = s(key)
    return fields


def valid_target_id(session, project_id, target_id):
    """Un target vale solo se appartiene a QUESTO progetto, altrimenti None."""
    if target_id is None:
        return None
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        return None
    return target_id


def create_finding(session, project_id, fields) -> Finding:
    """Crea un finding dai campi gia' validati."""
    data = dict(fields)
    data["target_id"] = valid_target_id(session, project_id, data.get("target_id"))
    finding = Finding(project_id=project_id, **data)
    session.add(finding)
    session.commit()
    session.refresh(finding)
    return finding


def apply_finding_update(session, finding, fields):
    """Applica i campi validati a un finding esistente."""
    data = dict(fields)
    data["target_id"] = valid_target_id(session, finding.project_id, data.get("target_id"))
    for key, value in data.items():
        setattr(finding, key, value)
    session.add(finding)
    session.commit()


def empty_values() -> dict:
    """Valori di partenza di un form finding vuoto."""
    return {
        "title": "", "cvss_score": "", "cvss_vector": "", "cve": "", "cwe": "",
        "description": "", "poc": "", "remediation": "",
        "target_id": "", "topic_id": "", "check_id": "",
    }


def values_from_finding(f: Finding) -> dict:
    """Riempie i valori del form a partire da un finding esistente (modifica)."""
    return {
        "title": f.title,
        "cvss_score": f.cvss_score if f.cvss_score is not None else "",
        "cvss_vector": f.cvss_vector or "", "cve": f.cve or "", "cwe": f.cwe or "",
        "description": f.description or "", "poc": f.poc or "",
        "remediation": f.remediation or "",
        "target_id": f.target_id or "", "topic_id": f.topic_id or "", "check_id": f.check_id or "",
    }


def prefill_from_check(session, values, check_id):
    """Se il finding nasce da un test del catalogo, precompila titolo e descrizione."""
    check = session.get(Check, check_id)
    if check is not None:
        topic = session.get(Topic, check.topic_id)
        values["title"] = f"{topic.name}: {check.title}" if topic else check.title
        values["description"] = check.goal or ""
        values["topic_id"] = check.topic_id
        values["check_id"] = check.id
    return check


# ===========================================================================
# Rotte
# ===========================================================================

@router.get("/target/{target_id}/findings/nuovo", response_class=HTMLResponse)
def finding_new_form(
    target_id: int,
    request: Request,
    session: Session = Depends(get_session),
    check_id: int | None = None,
    cve: str | None = None,
    title: str | None = None,
    cvss_score: str | None = None,
    description: str | None = None,
):
    """Form per CREARE un finding DENTRO un target: il target e' gia' fissato."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    project = session.get(Project, target.project_id)
    values = empty_values()
    values["target_id"] = target.id
    check = prefill_from_check(session, values, check_id) if check_id is not None else None
    # Precompilazione da una CVE (arriva dalla pagina CVE di una tecnologia).
    if cve:
        values["cve"] = cve
    if title:
        values["title"] = title
    if cvss_score:
        values["cvss_score"] = cvss_score
    if description:
        values["description"] = description
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project": project,
            "fixed_target": target,
            "values": values,
            "check": check,
            "project_picker": False,
            "form_action": f"/target/{target_id}/findings",
            "form_title": "Nuovo finding",
            "submit_label": "Salva finding",
            "back_url": f"/target/{target_id}",
        },
    )


@router.post("/target/{target_id}/findings")
async def finding_create(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Crea un finding dentro un target (il target arriva dal percorso, non da un menu)."""
    target = get_or_404(session, Target, target_id, "Target non trovato")
    fields = clean_finding_fields(await request.form())
    if not fields["title"]:
        raise HTTPException(status_code=400, detail="Il titolo e' obbligatorio")
    fields["target_id"] = target.id
    create_finding(session, target.project_id, fields)
    return RedirectResponse(url=f"/target/{target_id}", status_code=303)


@router.get("/findings/nuovo", response_class=HTMLResponse)
def finding_new_global(
    request: Request,
    session: Session = Depends(get_session),
    project_id: int | None = None,
    check_id: int | None = None,
):
    """Form per creare un finding scegliendo il progetto (es. dal catalogo).
    Il menu dei target si aggiorna in base al progetto scelto, via JavaScript."""
    projects = session.exec(select(Project).order_by(Project.name)).all()
    # Tutti i target in UNA query, poi raggruppati per progetto (evita l'N+1).
    by_project = {}
    for t in session.exec(select(Target).order_by(Target.project_id, Target.id)).all():
        by_project.setdefault(t.project_id, []).append({"id": t.id, "label": target_label(t)})
    project_targets = [{"id": p.id, "name": p.name, "targets": by_project.get(p.id, [])} for p in projects]
    targets_by_project = {p.id: by_project.get(p.id, []) for p in projects}
    values = empty_values()
    values["project_id"] = project_id or ""
    check = prefill_from_check(session, values, check_id) if check_id is not None else None
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project_picker": True,
            "projects": projects,
            "project_targets": project_targets,
            "targets_by_project": targets_by_project,
            "values": values,
            "check": check,
            "form_action": "/findings",
            "form_title": "Nuovo finding",
            "submit_label": "Salva finding",
            "back_url": "/catalogo" if check else "/progetti",
        },
    )


@router.post("/findings")
async def finding_create_global(request: Request, session: Session = Depends(get_session)):
    """Crea un finding scegliendo il progetto nel form."""
    form = await request.form()
    project_id = int_or_none(form.get("project_id"))
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    fields = clean_finding_fields(form)
    if not fields["title"]:
        raise HTTPException(status_code=400, detail="Il titolo e' obbligatorio")
    finding = create_finding(session, project.id, fields)
    dest = f"/target/{finding.target_id}" if finding.target_id else f"/progetti/{project.id}"
    return RedirectResponse(url=dest, status_code=303)


@router.get("/findings/{finding_id}/modifica", response_class=HTMLResponse)
def finding_edit_form(finding_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per MODIFICARE un finding: riusa lo stesso template della creazione."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    project = session.get(Project, finding.project_id)
    targets = session.exec(
        select(Target).where(Target.project_id == finding.project_id).order_by(Target.id)
    ).all()
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project": project,
            "targets": targets,
            "values": values_from_finding(finding),
            "check": None,
            "project_picker": False,
            "form_action": f"/findings/{finding.id}",
            "form_title": "Modifica finding",
            "submit_label": "Salva modifiche",
            "back_url": (f"/target/{finding.target_id}" if finding.target_id
                         else f"/progetti/{finding.project_id}"),
        },
    )


@router.post("/findings/{finding_id}")
async def finding_update(finding_id: int, request: Request, session: Session = Depends(get_session)):
    """Aggiorna un finding esistente."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    fields = clean_finding_fields(await request.form())
    if not fields["title"]:
        raise HTTPException(status_code=400, detail="Il titolo e' obbligatorio")
    apply_finding_update(session, finding, fields)
    dest = f"/target/{finding.target_id}" if finding.target_id else f"/progetti/{finding.project_id}"
    return RedirectResponse(url=dest, status_code=303)


@router.post("/findings/{finding_id}/elimina")
def finding_delete(finding_id: int, session: Session = Depends(get_session)):
    """Elimina un finding e torna al suo target (o progetto)."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    project_id = finding.project_id
    target_id = finding.target_id
    session.delete(finding)
    session.commit()
    dest = f"/target/{target_id}" if target_id else f"/progetti/{project_id}"
    return RedirectResponse(url=dest, status_code=303)
