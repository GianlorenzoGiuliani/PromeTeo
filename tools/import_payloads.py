#!/usr/bin/env python3
"""
Importatore di PayloadsAllTheThings -> PromeTeus.

Progetto fonte: https://github.com/swisskyrepo/PayloadsAllTheThings
Licenza fonte:  MIT (c) 2019 Swissky  (manteniamo l'attribuzione in ogni voce).

Cosa fa (schema ETL = Extract, Transform, Load):
  - EXTRACT:   legge una copia LOCALE del repository (clonata con git);
  - TRANSFORM: trasforma ogni categoria (cartella con README.md) in un "Topic"
               di tipo 'technique' con tanti "Check" (una per sezione del README);
  - (il LOAD nel database lo fa poi app/seed.py, leggendo il JSON prodotto qui).

Uso:
    python tools/import_payloads.py --source <cartella_clone> --out data/payloads_seed.json
"""
import argparse
import json
import re
from pathlib import Path
from urllib.parse import quote

REPO_URL = "https://github.com/swisskyrepo/PayloadsAllTheThings"
LICENSE = "MIT (c) 2019 Swissky"

# Sezioni che non sono "test" veri e propri: le saltiamo.
SKIP_SECTIONS = {"summary", "references", "labs", "contributors"}

# Un blocco di codice markdown:  ```lingua\n ...payload... \n```
FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)


def source_url_for(category: str) -> str:
    """Link alla cartella originale su GitHub (per l'attribuzione)."""
    return f"{REPO_URL}/tree/master/{quote(category)}"


def title_of(markdown: str, fallback: str) -> str:
    """Il titolo della categoria = la prima riga '# ...' del README."""
    for line in markdown.splitlines():
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def split_sections(markdown: str) -> list[tuple[str, str]]:
    """Divide il README in coppie (titolo_sezione, corpo) usando gli header '## '."""
    sections: list[tuple[str, str]] = []
    title = None
    buf: list[str] = []
    for line in markdown.splitlines():
        if line.startswith("## "):
            if title is not None:
                sections.append((title, "\n".join(buf).strip()))
            title = line[3:].strip()
            buf = []
        elif title is not None:
            buf.append(line)
    if title is not None:
        sections.append((title, "\n".join(buf).strip()))
    return sections


def extract_code(body: str) -> str:
    """Unisce tutti i blocchi di codice (i payload) di una sezione."""
    blocks = FENCE_RE.findall(body)
    return "\n\n".join(b.strip() for b in blocks).strip()


def strip_code(body: str) -> str:
    """Toglie i blocchi di codice e le immagini, lasciando il testo esplicativo."""
    text = FENCE_RE.sub("", body)
    lines = [l.rstrip() for l in text.splitlines() if not l.strip().startswith("![")]
    return "\n".join(lines).strip()


def first_paragraph(text: str, limit: int = 600) -> str:
    """Il primo paragrafo del testo (fino alla prima riga vuota), accorciato."""
    text = text.strip()
    if not text:
        return ""
    para = text.split("\n\n", 1)[0].strip()
    if len(para) > limit:
        para = para[:limit].rstrip() + "…"
    return para


def import_category(cat_dir: Path) -> dict | None:
    """Trasforma una cartella-categoria in un dizionario topic+checks (o None)."""
    readme = cat_dir / "README.md"
    if not readme.exists():
        return None

    md = readme.read_text(encoding="utf-8", errors="replace")
    name = title_of(md, cat_dir.name)
    src = source_url_for(cat_dir.name)

    checks = []
    for sec_title, body in split_sections(md):
        if sec_title.strip().lower() in SKIP_SECTIONS:
            continue
        code = extract_code(body)
        prose = strip_code(body)
        # saltiamo le sezioni vuote (ne' payload ne' testo utile)
        if not code and len(prose) < 20:
            continue
        checks.append({
            "title": sec_title,
            "goal": first_paragraph(prose),
            "tool": None,
            "command": code or None,
            "interpretation": None,
            "references": src,
        })

    if not checks:
        return None

    return {
        "kind": "technique",
        "name": name,
        "description": f"Payload e tecniche per '{name}'. Fonte: PayloadsAllTheThings ({LICENSE}).",
        "detection": None,
        "source_url": src,
        "checks": checks,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Importa PayloadsAllTheThings in un JSON per PromeTeus.")
    ap.add_argument("--source", required=True, type=Path, help="cartella del clone di PayloadsAllTheThings")
    ap.add_argument("--out", required=True, type=Path, help="file JSON di destinazione")
    args = ap.parse_args()

    categories = sorted(
        d for d in args.source.iterdir()
        if d.is_dir() and not d.name.startswith(".")
    )

    topics = []
    for cat in categories:
        topic = import_category(cat)
        if topic:
            topics.append(topic)

    result = {"source": REPO_URL, "license": LICENSE, "topics": topics}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

    n_checks = sum(len(t["checks"]) for t in topics)
    print(f"Importate {len(topics)} categorie e {n_checks} voci (check).")
    print(f"Scritto: {args.out}")


if __name__ == "__main__":
    main()
