"""
Findings: creazione (dentro un progetto o scegliendo il progetto dal catalogo),
modifica ed eliminazione, con il loro ciclo di vita completo (campi di rischio,
CVSS, assegnatario, date, verifica della correzione e storico delle modifiche).
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import (
    CLOSED_STATUSES,
    LIKELIHOODS,
    SEVERITIES,
    STATUSES,
    Check,
    Finding,
    FindingEvent,
    Project,
    Target,
    Topic,
)
from app.reporting import target_label
from app.web import (
    LIKELIHOOD_LABELS,
    SEVERITY_LABELS,
    STATUS_LABELS,
    get_or_404,
    int_or_none,
    templates,
)

router = APIRouter()


# ===========================================================================
# Helpers: validazione, salvataggio e storico. Tenere qui la logica (fuori
# dalle rotte) significa un solo posto da leggere e da correggere.
# ===========================================================================

def float_or_none(value):
    """Converte in numero con la virgola (accetta anche '7,5'), oppure None."""
    try:
        return float(str(value).replace(",", "."))
    except (TypeError, ValueError):
        return None


# Campi di testo del finding: li puliamo tutti allo stesso modo (strip -> None).
TEXT_FIELDS = [
    "cve", "cwe", "cvss_vector", "assignee", "description", "impact",
    "reproduction", "evidence", "remediation", "references", "retest",
]


def clean_finding_fields(form) -> dict:
    """Legge e VALIDA i campi di un finding da un form. Unico punto di
    validazione: gravita'/stato/probabilita' devono stare nei valori ammessi,
    i testi vuoti diventano None, i numeri vengono convertiti."""
    def s(key):
        return (form.get(key) or "").strip() or None

    severity = form.get("severity") or "medium"
    if severity not in SEVERITIES:
        severity = "medium"
    status = form.get("status") or "open"
    if status not in STATUSES:
        status = "open"
    likelihood = (form.get("likelihood") or "").strip() or None
    if likelihood is not None and likelihood not in LIKELIHOODS:
        likelihood = None

    fields = {
        "title": (form.get("title") or "").strip(),
        "severity": severity,
        "status": status,
        "likelihood": likelihood,
        "cvss_score": float_or_none(form.get("cvss_score")),
        "target_id": int_or_none(form.get("target_id")),
        "topic_id": int_or_none(form.get("topic_id")),
        "check_id": int_or_none(form.get("check_id")),
    }
    for key in TEXT_FIELDS:
        fields[key] = s(key)
    return fields


def log_event(session, finding_id, message):
    """Aggiunge una riga allo storico del finding (senza commit: lo fa il chiamante)."""
    session.add(FindingEvent(finding_id=finding_id, message=message))


def valid_target_id(session, project_id, target_id):
    """Un target vale solo se appartiene a QUESTO progetto, altrimenti None."""
    if target_id is None:
        return None
    t = session.get(Target, target_id)
    if t is None or t.project_id != project_id:
        return None
    return target_id


def create_finding(session, project_id, fields) -> Finding:
    """Crea un finding dai campi gia' validati e ne registra la nascita."""
    data = dict(fields)
    data["target_id"] = valid_target_id(session, project_id, data.get("target_id"))
    finding = Finding(project_id=project_id, **data)
    if finding.status in CLOSED_STATUSES:
        finding.closed_at = datetime.now(timezone.utc)
    session.add(finding)
    session.commit()
    session.refresh(finding)
    log_event(session, finding.id, "Creato")
    session.commit()
    return finding


def apply_finding_update(session, finding, fields):
    """Applica i campi validati a un finding esistente: registra i cambiamenti
    piu' significativi nello storico e gestisce la data di chiusura."""
    old_status, old_sev = finding.status, finding.severity
    old_assignee = finding.assignee

    data = dict(fields)
    data["target_id"] = valid_target_id(session, finding.project_id, data.get("target_id"))
    for key, value in data.items():
        setattr(finding, key, value)

    changes = []
    if old_status != finding.status:
        changes.append(f"Stato: {STATUS_LABELS.get(old_status, old_status)}"
                       f" -> {STATUS_LABELS.get(finding.status, finding.status)}")
    if old_sev != finding.severity:
        changes.append(f"Gravita': {SEVERITY_LABELS.get(old_sev, old_sev)}"
                       f" -> {SEVERITY_LABELS.get(finding.severity, finding.severity)}")
    if (old_assignee or None) != (finding.assignee or None):
        changes.append(f"Assegnatario: {old_assignee or '—'} -> {finding.assignee or '—'}")

    # Data di chiusura: impostata entrando in uno stato chiuso, rimossa se riaperto.
    if finding.status in CLOSED_STATUSES and finding.closed_at is None:
        finding.closed_at = datetime.now(timezone.utc)
    elif finding.status not in CLOSED_STATUSES:
        finding.closed_at = None

    session.add(finding)
    session.commit()
    for msg in (changes or ["Modificato"]):
        log_event(session, finding.id, msg)
    session.commit()


def empty_values() -> dict:
    """Valori di partenza di un form finding vuoto."""
    return {
        "title": "", "severity": "medium", "status": "open", "likelihood": "",
        "target_id": "", "cve": "", "cwe": "", "cvss_vector": "", "cvss_score": "",
        "assignee": "", "description": "", "impact": "", "reproduction": "",
        "evidence": "", "remediation": "", "references": "", "retest": "",
        "topic_id": "", "check_id": "",
    }


def values_from_finding(f: Finding) -> dict:
    """Riempie i valori del form a partire da un finding esistente (per la modifica)."""
    return {
        "title": f.title, "severity": f.severity, "status": f.status,
        "likelihood": f.likelihood or "", "target_id": f.target_id or "",
        "cve": f.cve or "", "cwe": f.cwe or "", "cvss_vector": f.cvss_vector or "",
        "cvss_score": f.cvss_score if f.cvss_score is not None else "",
        "assignee": f.assignee or "", "description": f.description or "",
        "impact": f.impact or "", "reproduction": f.reproduction or "",
        "evidence": f.evidence or "", "remediation": f.remediation or "",
        "references": f.references or "", "retest": f.retest or "",
        "topic_id": f.topic_id or "", "check_id": f.check_id or "",
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


def _form_extras() -> dict:
    """Le liste/etichette comuni a tutti i form dei findings."""
    return {
        "severities": SEVERITIES,
        "statuses": STATUSES,
        "likelihoods": LIKELIHOODS,
        "severity_labels": SEVERITY_LABELS,
        "status_labels": STATUS_LABELS,
        "likelihood_labels": LIKELIHOOD_LABELS,
    }


# ===========================================================================
# Rotte
# ===========================================================================

@router.get("/progetti/{project_id}/findings/nuovo", response_class=HTMLResponse)
def finding_new_form(
    project_id: int,
    request: Request,
    session: Session = Depends(get_session),
    check_id: int | None = None,
    cve: str | None = None,
    title: str | None = None,
    severity: str | None = None,
    cvss_score: str | None = None,
    description: str | None = None,
):
    """Form per CREARE un finding dentro un progetto: si seleziona un target."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    targets = session.exec(
        select(Target).where(Target.project_id == project_id).order_by(Target.id)
    ).all()
    values = empty_values()
    check = prefill_from_check(session, values, check_id) if check_id is not None else None
    # Precompilazione da una CVE (arriva dalla pagina delle tecnologie di un progetto).
    if cve:
        values["cve"] = cve
    if title:
        values["title"] = title
    if severity in SEVERITIES:
        values["severity"] = severity
    if cvss_score:
        values["cvss_score"] = cvss_score
    if description:
        values["description"] = description
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project": project,
            "targets": targets,
            "values": values,
            "check": check,
            "project_picker": False,
            "events": [],
            "form_action": f"/progetti/{project_id}/findings",
            "form_title": "Nuovo finding",
            "submit_label": "Salva finding",
            "back_url": f"/progetti/{project_id}",
            **_form_extras(),
        },
    )


@router.post("/progetti/{project_id}/findings")
async def finding_create(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Crea un finding dentro un progetto (il target si seleziona)."""
    project = get_or_404(session, Project, project_id, "Progetto non trovato")
    fields = clean_finding_fields(await request.form())
    if not fields["title"]:
        raise HTTPException(status_code=400, detail="Il titolo e' obbligatorio")
    create_finding(session, project_id, fields)
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@router.get("/findings/nuovo", response_class=HTMLResponse)
def finding_new_global(
    request: Request,
    session: Session = Depends(get_session),
    project_id: int | None = None,
    check_id: int | None = None,
):
    """Form per creare un finding scegliendo il progetto (es. dal catalogo).

    Il menu dei target si aggiorna in base al progetto scelto, via JavaScript.
    """
    projects = session.exec(select(Project).order_by(Project.name)).all()
    # Tutti i target in UNA query, poi raggruppati per progetto. Prima si faceva
    # una query dei target PER OGNI progetto (problema "N+1").
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
            "events": [],
            "form_action": "/findings",
            "form_title": "Nuovo finding",
            "submit_label": "Salva finding",
            "back_url": "/catalogo" if check else "/progetti",
            **_form_extras(),
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
    create_finding(session, project.id, fields)
    return RedirectResponse(url=f"/progetti/{project.id}", status_code=303)


@router.get("/findings/{finding_id}/modifica", response_class=HTMLResponse)
def finding_edit_form(finding_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per MODIFICARE un finding: riusa lo stesso template della creazione
    e mostra in fondo lo storico delle modifiche."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    project = session.get(Project, finding.project_id)
    targets = session.exec(
        select(Target).where(Target.project_id == finding.project_id).order_by(Target.id)
    ).all()
    events = session.exec(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.at.desc())
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
            "events": events,
            "form_action": f"/findings/{finding.id}",
            "form_title": "Modifica finding",
            "submit_label": "Salva modifiche",
            "back_url": f"/progetti/{finding.project_id}",
            **_form_extras(),
        },
    )


@router.post("/findings/{finding_id}")
async def finding_update(finding_id: int, request: Request, session: Session = Depends(get_session)):
    """Aggiorna un finding esistente (resta nel suo progetto)."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    fields = clean_finding_fields(await request.form())
    if not fields["title"]:
        raise HTTPException(status_code=400, detail="Il titolo e' obbligatorio")
    apply_finding_update(session, finding, fields)
    return RedirectResponse(url=f"/progetti/{finding.project_id}", status_code=303)


@router.post("/findings/{finding_id}/elimina")
def finding_delete(finding_id: int, session: Session = Depends(get_session)):
    """Elimina un finding, il suo storico, e torna al suo progetto."""
    finding = get_or_404(session, Finding, finding_id, "Finding non trovato")
    project_id = finding.project_id
    for ev in session.exec(select(FindingEvent).where(FindingEvent.finding_id == finding_id)).all():
        session.delete(ev)
    session.delete(finding)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
