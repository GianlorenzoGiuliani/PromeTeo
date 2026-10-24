"""
Findings: creazione (sia dentro un progetto, sia scegliendo il progetto dal
catalogo), modifica ed eliminazione.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlmodel import Session, select

from app.database import get_session
from app.models import SEVERITIES, STATUSES, Check, Finding, Project, Target, Topic
from app.reporting import target_label
from app.web import SEVERITY_LABELS, STATUS_LABELS, int_or_none, templates

router = APIRouter()


def save_new_finding(session, project_id, title, target_id, severity, status,
                     cve, cwe, description, evidence, remediation, topic_id, check_id):
    """Crea e salva un finding. Usato sia dalla via 'dentro il progetto' sia da
    quella globale (dal catalogo): la logica sta in un posto solo."""
    if severity not in SEVERITIES:
        severity = "medium"
    if status not in STATUSES:
        status = "open"
    # Il target scelto deve appartenere a questo progetto, altrimenti lo ignoriamo.
    tid = int_or_none(target_id)
    if tid is not None:
        t = session.get(Target, tid)
        if t is None or t.project_id != project_id:
            tid = None
    finding = Finding(
        project_id=project_id,
        target_id=tid,
        title=title.strip(),
        severity=severity,
        status=status,
        cve=cve.strip() or None,
        cwe=cwe.strip() or None,
        description=description.strip() or None,
        evidence=evidence.strip() or None,
        remediation=remediation.strip() or None,
        topic_id=int_or_none(topic_id),
        check_id=int_or_none(check_id),
    )
    session.add(finding)
    session.commit()


@router.get("/progetti/{project_id}/findings/nuovo", response_class=HTMLResponse)
def finding_new_form(
    project_id: int,
    request: Request,
    session: Session = Depends(get_session),
    check_id: int | None = None,
):
    """Form per CREARE un finding dentro un progetto: si seleziona un target."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    targets = session.exec(
        select(Target).where(Target.project_id == project_id).order_by(Target.id)
    ).all()
    check = None
    values = {
        "title": "", "severity": "medium", "status": "open",
        "target_id": "", "cve": "", "cwe": "",
        "description": "", "evidence": "", "remediation": "",
        "topic_id": "", "check_id": "",
    }
    if check_id is not None:
        check = session.get(Check, check_id)
        if check is not None:
            topic = session.get(Topic, check.topic_id)
            values["title"] = f"{topic.name}: {check.title}" if topic else check.title
            values["description"] = check.goal or ""
            values["topic_id"] = check.topic_id
            values["check_id"] = check.id
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project": project,
            "targets": targets,
            "values": values,
            "check": check,
            "project_picker": False,
            "form_action": f"/progetti/{project_id}/findings",
            "form_title": "Nuovo finding",
            "submit_label": "Salva finding",
            "back_url": f"/progetti/{project_id}",
            "severities": SEVERITIES,
            "statuses": STATUSES,
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
        },
    )


@router.post("/progetti/{project_id}/findings")
def finding_create(
    project_id: int,
    title: str = Form(...),
    target_id: str = Form(""),
    severity: str = Form("medium"),
    status: str = Form("open"),
    cve: str = Form(""),
    cwe: str = Form(""),
    description: str = Form(""),
    evidence: str = Form(""),
    remediation: str = Form(""),
    topic_id: str = Form(""),
    check_id: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un finding dentro un progetto (il target si seleziona)."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    save_new_finding(session, project_id, title, target_id, severity, status,
                     cve, cwe, description, evidence, remediation, topic_id, check_id)
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
    project_targets = []
    targets_by_project = {}
    for p in projects:
        ts = session.exec(select(Target).where(Target.project_id == p.id).order_by(Target.id)).all()
        labeled = [{"id": t.id, "label": target_label(t)} for t in ts]
        project_targets.append({"id": p.id, "name": p.name, "targets": labeled})
        targets_by_project[p.id] = labeled
    check = None
    values = {
        "title": "", "severity": "medium", "status": "open",
        "target_id": "", "cve": "", "cwe": "",
        "description": "", "evidence": "", "remediation": "",
        "project_id": project_id or "", "topic_id": "", "check_id": "",
    }
    if check_id is not None:
        check = session.get(Check, check_id)
        if check is not None:
            topic = session.get(Topic, check.topic_id)
            values["title"] = f"{topic.name}: {check.title}" if topic else check.title
            values["description"] = check.goal or ""
            values["topic_id"] = check.topic_id
            values["check_id"] = check.id
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
            "severities": SEVERITIES,
            "statuses": STATUSES,
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
        },
    )


@router.post("/findings")
def finding_create_global(
    project_id: int = Form(...),
    title: str = Form(...),
    target_id: str = Form(""),
    severity: str = Form("medium"),
    status: str = Form("open"),
    cve: str = Form(""),
    cwe: str = Form(""),
    description: str = Form(""),
    evidence: str = Form(""),
    remediation: str = Form(""),
    topic_id: str = Form(""),
    check_id: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un finding scegliendo il progetto nel form."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    save_new_finding(session, project_id, title, target_id, severity, status,
                     cve, cwe, description, evidence, remediation, topic_id, check_id)
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@router.get("/findings/{finding_id}/modifica", response_class=HTMLResponse)
def finding_edit_form(finding_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per MODIFICARE un finding: riusa lo stesso template della creazione."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding non trovato")
    project = session.get(Project, finding.project_id)
    targets = session.exec(
        select(Target).where(Target.project_id == finding.project_id).order_by(Target.id)
    ).all()
    values = {
        "title": finding.title,
        "severity": finding.severity,
        "status": finding.status,
        "target_id": finding.target_id or "",
        "cve": finding.cve or "",
        "cwe": finding.cwe or "",
        "description": finding.description or "",
        "evidence": finding.evidence or "",
        "remediation": finding.remediation or "",
        "topic_id": finding.topic_id or "",
        "check_id": finding.check_id or "",
    }
    return templates.TemplateResponse(
        request=request,
        name="finding_form.html",
        context={
            "project": project,
            "targets": targets,
            "values": values,
            "check": None,
            "project_picker": False,
            "form_action": f"/findings/{finding.id}",
            "form_title": "Modifica finding",
            "submit_label": "Salva modifiche",
            "back_url": f"/progetti/{finding.project_id}",
            "severities": SEVERITIES,
            "statuses": STATUSES,
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
        },
    )


@router.post("/findings/{finding_id}")
def finding_update(
    finding_id: int,
    title: str = Form(...),
    target_id: str = Form(""),
    severity: str = Form("medium"),
    status: str = Form("open"),
    cve: str = Form(""),
    cwe: str = Form(""),
    description: str = Form(""),
    evidence: str = Form(""),
    remediation: str = Form(""),
    topic_id: str = Form(""),
    check_id: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna un finding esistente (resta nel suo progetto)."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding non trovato")
    if severity not in SEVERITIES:
        severity = "medium"
    if status not in STATUSES:
        status = "open"
    tid = int_or_none(target_id)
    if tid is not None:
        t = session.get(Target, tid)
        if t is None or t.project_id != finding.project_id:
            tid = None
    finding.target_id = tid
    finding.title = title.strip()
    finding.severity = severity
    finding.status = status
    finding.cve = cve.strip() or None
    finding.cwe = cwe.strip() or None
    finding.description = description.strip() or None
    finding.evidence = evidence.strip() or None
    finding.remediation = remediation.strip() or None
    finding.topic_id = int_or_none(topic_id)
    finding.check_id = int_or_none(check_id)
    session.add(finding)
    session.commit()
    return RedirectResponse(url=f"/progetti/{finding.project_id}", status_code=303)


@router.post("/findings/{finding_id}/elimina")
def finding_delete(finding_id: int, session: Session = Depends(get_session)):
    """Elimina un finding e torna al suo progetto."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding non trovato")
    project_id = finding.project_id
    session.delete(finding)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
