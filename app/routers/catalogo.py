"""
Catalogo: navigazione (elenco e dettaglio voce) e gestione dei contenuti
(creare/modificare/eliminare voci e i loro test).
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import or_
from sqlmodel import Session, func, select

from app.database import get_session
from app.models import KIND_TECH, Check, Topic
from app.web import KIND_LABELS, int_or_none, templates

router = APIRouter()


@router.get("/catalogo", response_class=HTMLResponse)
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


@router.get("/topic/{topic_id}", response_class=HTMLResponse)
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


@router.get("/catalogo/nuovo", response_class=HTMLResponse)
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


@router.post("/catalogo")
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


@router.get("/topic/{topic_id}/modifica", response_class=HTMLResponse)
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


@router.post("/topic/{topic_id}")
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


@router.post("/topic/{topic_id}/elimina")
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


@router.get("/topic/{topic_id}/test/nuovo", response_class=HTMLResponse)
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


@router.post("/topic/{topic_id}/test")
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


@router.get("/test/{check_id}/modifica", response_class=HTMLResponse)
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


@router.post("/test/{check_id}")
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


@router.post("/test/{check_id}/elimina")
def check_delete(check_id: int, session: Session = Depends(get_session)):
    """Elimina un test."""
    check = session.get(Check, check_id)
    if check is None:
        raise HTTPException(status_code=404, detail="Test non trovato")
    topic_id = check.topic_id
    session.delete(check)
    session.commit()
    return RedirectResponse(url=f"/topic/{topic_id}", status_code=303)
