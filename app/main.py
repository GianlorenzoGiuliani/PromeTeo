"""
PromeTeus - punto di ingresso dell'applicazione.

Qui facciamo tre cose:
  1) creiamo l'app FastAPI (l'oggetto "app" che il server esegue);
  2) colleghiamo i file statici (CSS) e il motore dei template (Jinja2);
  3) definiamo le "rotte" (route): ogni rotta e' un indirizzo del sito
     (es. "/") a cui corrisponde una funzione Python che decide cosa mostrare.
"""
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import Depends, FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import or_
from sqlmodel import Session, func, select

from app.database import create_db_and_tables, get_session
from app.models import (
    KIND_AD,
    KIND_PORT,
    KIND_TECH,
    KIND_TECHNIQUE,
    KIND_WEB,
    SEVERITIES,
    STATUSES,
    Check,
    Finding,
    Project,
    Target,
    Topic,
)
from app.reporting import build_markdown_report, finding_target_str, target_label
from app.seed import (
    seed_ad_if_absent,
    seed_payloads_if_absent,
    seed_ports_if_absent,
    seed_tech_if_absent,
    seed_web_if_absent,
)
from app.web import (
    KIND_LABELS,
    SEVERITY_LABELS,
    SEVERITY_RANK,
    STATUS_LABELS,
    int_or_none,
    templates,
)

# BASE_DIR = la cartella "app" dove si trova questo file.
# La calcoliamo in automatico cosi' l'app funziona ovunque venga copiata,
# senza dover scrivere a mano percorsi fissi tipo "C:\Users\...".
BASE_DIR = Path(__file__).resolve().parent

# Cosa deve succedere all'avvio e allo spegnimento dell'app.
@asynccontextmanager
async def lifespan(app: FastAPI):
    # All'avvio: creiamo il database (se non esiste) e, se il catalogo e' vuoto,
    # carichiamo la base pronta di porte e tecnologie.
    create_db_and_tables()
    porte = seed_ports_if_absent()
    tecno = seed_tech_if_absent()
    tecniche = seed_payloads_if_absent()
    ad = seed_ad_if_absent()
    web = seed_web_if_absent()
    for etichetta, n in [("Porte", porte), ("Tecnologie", tecno),
                         ("Tecniche", tecniche), ("Active Directory", ad), ("Web App", web)]:
        if n:
            print(f"[PromeTeus] {etichetta} caricate: {n}.")
    yield
    # (allo spegnimento non c'e' nulla di speciale da fare)


# L'applicazione. "title" compare nella documentazione automatica di FastAPI
# (la trovi su http://127.0.0.1:8000/docs quando il server e' avviato).
app = FastAPI(title="PromeTeus", lifespan=lifespan)

# File statici = file che il browser scarica cosi' come sono (CSS, immagini...).
# Li mettiamo in app/static e saranno raggiungibili sotto l'indirizzo /static/...
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


def _save_new_finding(session, project_id, title, target_id, severity, status,
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


@app.get("/", response_class=HTMLResponse)
def home(request: Request, session: Session = Depends(get_session)):
    """Pagina iniziale: presenta PromeTeus e mostra quante voci ha ogni sezione.

    'session: Session = Depends(get_session)' chiede a FastAPI di aprire una
    sessione sul database e passarcela; a fine richiesta la chiude da sola.
    """
    counts = {
        kind: session.exec(
            select(func.count()).select_from(Topic).where(Topic.kind == kind)
        ).one()
        for kind in (KIND_PORT, KIND_TECH, KIND_TECHNIQUE, KIND_AD, KIND_WEB)
    }
    n_progetti = session.exec(select(func.count()).select_from(Project)).one()
    return templates.TemplateResponse(
        request=request,
        name="home.html",
        context={"counts": counts, "n_progetti": n_progetti},
    )


@app.get("/catalogo", response_class=HTMLResponse)
def catalogo(
    request: Request,
    kind: str | None = None,
    q: str | None = None,
    session: Session = Depends(get_session),
):
    """Elenco del catalogo, con filtro per tipo ('kind') e ricerca testuale ('q').

    'kind' e 'q' arrivano dall'URL (es. /catalogo?kind=port&q=rdp): FastAPI li
    legge in automatico perche' sono parametri della funzione con un valore di
    default.
    """
    statement = select(Topic)
    if kind in KIND_LABELS:
        statement = statement.where(Topic.kind == kind)
    if q:
        like = f"%{q}%"
        statement = statement.where(
            or_(Topic.name.ilike(like), Topic.description.ilike(like))
        )
    statement = statement.order_by(Topic.kind, Topic.name)
    topics = session.exec(statement).all()

    # Quanti test ha ogni voce: UNA sola query con GROUP BY (invece di una per voce).
    counts = dict(
        session.exec(select(Check.topic_id, func.count()).group_by(Check.topic_id)).all()
    )
    return templates.TemplateResponse(
        request=request,
        name="catalogo.html",
        context={
            "topics": topics,
            "counts": counts,
            "kind": kind,
            "q": q or "",
            "kind_labels": KIND_LABELS,
        },
    )


@app.get("/topic/{topic_id}", response_class=HTMLResponse)
def topic_detail(
    topic_id: int,
    request: Request,
    session: Session = Depends(get_session),
):
    """Dettaglio di una voce: la voce e tutti i suoi test.

    '{topic_id}' nell'indirizzo e' una parte variabile: /topic/1, /topic/2...
    """
    topic = session.get(Topic, topic_id)
    if topic is None:
        # Se l'id non esiste, rispondiamo con un errore 404 (pagina non trovata).
        raise HTTPException(status_code=404, detail="Voce non trovata")
    checks = session.exec(select(Check).where(Check.topic_id == topic_id)).all()
    return templates.TemplateResponse(
        request=request,
        name="topic.html",
        context={"topic": topic, "checks": checks, "kind_labels": KIND_LABELS},
    )


# =====================  PROGETTI E FINDINGS  =====================

@app.get("/progetti", response_class=HTMLResponse)
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


@app.post("/progetti")
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


@app.get("/progetti/{project_id}", response_class=HTMLResponse)
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
    return templates.TemplateResponse(
        request=request,
        name="progetto.html",
        context={
            "project": project,
            "findings": findings,
            "targets": targets,
            "grouped": grouped,
            "severities": SEVERITIES,
            "statuses": STATUSES,
            "sel_severity": severity or "",
            "sel_status": status or "",
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
        },
    )


@app.get("/progetti/{project_id}/findings/nuovo", response_class=HTMLResponse)
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


@app.post("/progetti/{project_id}/findings")
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
    _save_new_finding(session, project_id, title, target_id, severity, status,
                      cve, cwe, description, evidence, remediation, topic_id, check_id)
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@app.get("/findings/nuovo", response_class=HTMLResponse)
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


@app.post("/findings")
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
    _save_new_finding(session, project_id, title, target_id, severity, status,
                      cve, cwe, description, evidence, remediation, topic_id, check_id)
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


# =====================  REPORT  =====================

@app.get("/progetti/{project_id}/report", response_class=HTMLResponse)
def report_html(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Report del progetto, in una pagina pensata anche per la stampa / PDF."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    findings = session.exec(select(Finding).where(Finding.project_id == project_id)).all()
    findings = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
    targets = session.exec(select(Target).where(Target.project_id == project_id)).all()
    targets_by_id = {t.id: t for t in targets}
    target_strings = {f.id: finding_target_str(f, targets_by_id) for f in findings}
    sev_counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1
    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "project": project,
            "findings": findings,
            "target_strings": target_strings,
            "sev_counts": sev_counts,
            "severities": SEVERITIES,
            "severity_labels": SEVERITY_LABELS,
            "status_labels": STATUS_LABELS,
            "now": datetime.now(),
        },
    )


@app.get("/progetti/{project_id}/report.md")
def report_md(project_id: int, session: Session = Depends(get_session)):
    """Scarica il report in formato Markdown (un file di testo)."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
    findings = session.exec(select(Finding).where(Finding.project_id == project_id)).all()
    findings = sorted(findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 99), f.id))
    targets = session.exec(select(Target).where(Target.project_id == project_id)).all()
    targets_by_id = {t.id: t for t in targets}
    markdown = build_markdown_report(project, findings, SEVERITY_LABELS, STATUS_LABELS, targets_by_id)
    filename = f"report-progetto-{project.id}.md"
    return PlainTextResponse(
        markdown,
        media_type="text/markdown; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# =====================  MODIFICA / ELIMINA  =====================

@app.get("/findings/{finding_id}/modifica", response_class=HTMLResponse)
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


@app.post("/findings/{finding_id}")
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


@app.post("/findings/{finding_id}/elimina")
def finding_delete(finding_id: int, session: Session = Depends(get_session)):
    """Elimina un finding e torna al suo progetto."""
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding non trovato")
    project_id = finding.project_id
    session.delete(finding)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)


@app.get("/progetti/{project_id}/modifica", response_class=HTMLResponse)
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


@app.post("/progetti/{project_id}")
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


@app.post("/progetti/{project_id}/elimina")
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


# =====================  GESTIONE DEL CATALOGO  =====================

@app.get("/catalogo/nuovo", response_class=HTMLResponse)
def topic_new_form(request: Request):
    """Form per creare una nuova voce del catalogo."""
    values = {
        "kind": "port", "name": "", "port": "", "protocol": "",
        "description": "", "intro": "", "detection": "", "references": "",
    }
    return templates.TemplateResponse(
        request=request,
        name="topic_form.html",
        context={
            "values": values,
            "form_action": "/catalogo",
            "form_title": "Nuova voce del catalogo",
            "submit_label": "Crea voce",
            "back_url": "/catalogo",
            "kinds": list(KIND_LABELS),
            "kind_labels": KIND_LABELS,
        },
    )


@app.post("/catalogo")
def topic_create(
    kind: str = Form("port"),
    name: str = Form(...),
    port: str = Form(""),
    protocol: str = Form(""),
    description: str = Form(""),
    intro: str = Form(""),
    detection: str = Form(""),
    references: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea una voce del catalogo."""
    if kind not in KIND_LABELS:
        kind = KIND_TECH
    topic = Topic(
        kind=kind,
        name=name.strip(),
        port=int_or_none(port),
        protocol=protocol.strip() or None,
        description=description.strip(),
        intro=intro.strip() or None,
        detection=detection.strip() or None,
        references=references.strip() or None,
    )
    session.add(topic)
    session.commit()
    session.refresh(topic)
    return RedirectResponse(url=f"/topic/{topic.id}", status_code=303)


@app.get("/topic/{topic_id}/modifica", response_class=HTMLResponse)
def topic_edit_form(topic_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare una voce del catalogo."""
    topic = session.get(Topic, topic_id)
    if topic is None:
        raise HTTPException(status_code=404, detail="Voce non trovata")
    values = {
        "kind": topic.kind,
        "name": topic.name,
        "port": topic.port or "",
        "protocol": topic.protocol or "",
        "description": topic.description or "",
        "intro": topic.intro or "",
        "detection": topic.detection or "",
        "references": topic.references or "",
    }
    return templates.TemplateResponse(
        request=request,
        name="topic_form.html",
        context={
            "values": values,
            "form_action": f"/topic/{topic.id}",
            "form_title": "Modifica voce",
            "submit_label": "Salva modifiche",
            "back_url": f"/topic/{topic.id}",
            "kinds": list(KIND_LABELS),
            "kind_labels": KIND_LABELS,
        },
    )


@app.post("/topic/{topic_id}")
def topic_update(
    topic_id: int,
    kind: str = Form("port"),
    name: str = Form(...),
    port: str = Form(""),
    protocol: str = Form(""),
    description: str = Form(""),
    intro: str = Form(""),
    detection: str = Form(""),
    references: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna una voce del catalogo."""
    topic = session.get(Topic, topic_id)
    if topic is None:
        raise HTTPException(status_code=404, detail="Voce non trovata")
    if kind not in KIND_LABELS:
        kind = topic.kind
    topic.kind = kind
    topic.name = name.strip()
    topic.port = int_or_none(port)
    topic.protocol = protocol.strip() or None
    topic.description = description.strip()
    topic.intro = intro.strip() or None
    topic.detection = detection.strip() or None
    topic.references = references.strip() or None
    session.add(topic)
    session.commit()
    return RedirectResponse(url=f"/topic/{topic_id}", status_code=303)


@app.post("/topic/{topic_id}/elimina")
def topic_delete(topic_id: int, session: Session = Depends(get_session)):
    """Elimina una voce del catalogo e tutti i suoi test."""
    topic = session.get(Topic, topic_id)
    if topic is None:
        raise HTTPException(status_code=404, detail="Voce non trovata")
    checks = session.exec(select(Check).where(Check.topic_id == topic_id)).all()
    for c in checks:
        session.delete(c)
    session.delete(topic)
    session.commit()
    return RedirectResponse(url="/catalogo", status_code=303)


@app.get("/topic/{topic_id}/test/nuovo", response_class=HTMLResponse)
def check_new_form(topic_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per aggiungere un test a una voce."""
    topic = session.get(Topic, topic_id)
    if topic is None:
        raise HTTPException(status_code=404, detail="Voce non trovata")
    values = {"title": "", "goal": "", "tool": "", "command": "", "interpretation": "", "references": ""}
    return templates.TemplateResponse(
        request=request,
        name="check_form.html",
        context={
            "values": values,
            "topic": topic,
            "form_action": f"/topic/{topic_id}/test",
            "form_title": f"Nuovo test per {topic.name}",
            "submit_label": "Aggiungi test",
            "back_url": f"/topic/{topic_id}",
        },
    )


@app.post("/topic/{topic_id}/test")
def check_create(
    topic_id: int,
    title: str = Form(...),
    goal: str = Form(""),
    tool: str = Form(""),
    command: str = Form(""),
    interpretation: str = Form(""),
    references: str = Form(""),
    session: Session = Depends(get_session),
):
    """Crea un test dentro una voce del catalogo."""
    topic = session.get(Topic, topic_id)
    if topic is None:
        raise HTTPException(status_code=404, detail="Voce non trovata")
    check = Check(
        topic_id=topic_id,
        title=title.strip(),
        goal=goal.strip() or None,
        tool=tool.strip() or None,
        command=command.strip() or None,
        interpretation=interpretation.strip() or None,
        references=references.strip() or None,
    )
    session.add(check)
    session.commit()
    return RedirectResponse(url=f"/topic/{topic_id}", status_code=303)


@app.get("/test/{check_id}/modifica", response_class=HTMLResponse)
def check_edit_form(check_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare un test."""
    check = session.get(Check, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Test non trovato")
    topic = session.get(Topic, check.topic_id)
    values = {
        "title": check.title,
        "goal": check.goal or "",
        "tool": check.tool or "",
        "command": check.command or "",
        "interpretation": check.interpretation or "",
        "references": check.references or "",
    }
    return templates.TemplateResponse(
        request=request,
        name="check_form.html",
        context={
            "values": values,
            "topic": topic,
            "form_action": f"/test/{check.id}",
            "form_title": "Modifica test",
            "submit_label": "Salva modifiche",
            "back_url": f"/topic/{check.topic_id}",
        },
    )


@app.post("/test/{check_id}")
def check_update(
    check_id: int,
    title: str = Form(...),
    goal: str = Form(""),
    tool: str = Form(""),
    command: str = Form(""),
    interpretation: str = Form(""),
    references: str = Form(""),
    session: Session = Depends(get_session),
):
    """Aggiorna un test."""
    check = session.get(Check, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Test non trovato")
    check.title = title.strip()
    check.goal = goal.strip() or None
    check.tool = tool.strip() or None
    check.command = command.strip() or None
    check.interpretation = interpretation.strip() or None
    check.references = references.strip() or None
    session.add(check)
    session.commit()
    return RedirectResponse(url=f"/topic/{check.topic_id}", status_code=303)


@app.post("/test/{check_id}/elimina")
def check_delete(check_id: int, session: Session = Depends(get_session)):
    """Elimina un test."""
    check = session.get(Check, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Test non trovato")
    topic_id = check.topic_id
    session.delete(check)
    session.commit()
    return RedirectResponse(url=f"/topic/{topic_id}", status_code=303)


# =====================  TARGET (bersagli di un progetto)  =====================

@app.get("/progetti/{project_id}/target/nuovo", response_class=HTMLResponse)
def target_new_form(project_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per aggiungere un target a un progetto."""
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
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


@app.post("/progetti/{project_id}/target")
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
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="Progetto non trovato")
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


@app.get("/target/{target_id}/modifica", response_class=HTMLResponse)
def target_edit_form(target_id: int, request: Request, session: Session = Depends(get_session)):
    """Form per modificare un target."""
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target non trovato")
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


@app.post("/target/{target_id}")
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
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target non trovato")
    target.name = name.strip() or None
    target.host = host.strip() or None
    target.port = int_or_none(port)
    target.url = url.strip() or None
    target.notes = notes.strip() or None
    session.add(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{target.project_id}", status_code=303)


@app.post("/target/{target_id}/elimina")
def target_delete(target_id: int, session: Session = Depends(get_session)):
    """Elimina un target. I findings che lo usavano perdono il collegamento."""
    target = session.get(Target, target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target non trovato")
    project_id = target.project_id
    orfani = session.exec(select(Finding).where(Finding.target_id == target_id)).all()
    for f in orfani:
        f.target_id = None
        session.add(f)
    session.delete(target)
    session.commit()
    return RedirectResponse(url=f"/progetti/{project_id}", status_code=303)
