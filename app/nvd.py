"""
Interrogazione dell'NVD (National Vulnerability Database) a partire da un CPE.

Dato il CPE di una tecnologia (es. nginx 1.18.0), chiede all'API pubblica
dell'NVD quali CVE la riguardano. Usiamo la libreria standard urllib: nessuna
dipendenza in piu' e funziona ovunque.

L'API non richiede chiave per un uso leggero (limite ~5 richieste/30s). Con una
chiave (variabile d'ambiente NVD_API_KEY) il limite sale: la aggiungiamo
all'header se presente.

Degradazione elegante: in caso di problemi solleviamo NvdError con un messaggio
leggibile, che la rotta mostra all'utente senza far crashare nulla.
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_DETAIL_URL = "https://nvd.nist.gov/vuln/detail/"

# Un CPE 2.3 completo ha 13 componenti separati da ':'
#   cpe:2.3:part:vendor:product:version:update:edition:lang:sw_ed:tgt_sw:tgt_hw:other
_CPE_PARTS = 13


class NvdError(Exception):
    """Errore 'gestito': il messaggio e' pensato per essere mostrato all'utente."""


def normalize_cpe(cpe: str) -> str:
    """Completa un CPE 2.3 parziale con '*' fino ai 13 componenti richiesti.

    Cosi' accettiamo anche 'cpe:2.3:a:nginx:nginx:1.18.0' e lo trasformiamo in
    'cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*', che e' il formato che l'NVD
    si aspetta nel parametro cpeName."""
    cpe = (cpe or "").strip()
    if not cpe.lower().startswith("cpe:2.3:"):
        return cpe
    parts = cpe.split(":")
    while len(parts) < _CPE_PARTS:
        parts.append("*")
    return ":".join(parts[:_CPE_PARTS])


def cerca_cve(cpe: str, max_results: int = 50) -> list[dict]:
    """Interroga l'NVD e restituisce le CVE che riguardano il CPE dato,
    ordinate dalla piu' grave. Solleva NvdError in caso di problemi."""
    cpe = normalize_cpe(cpe)
    if not cpe.lower().startswith("cpe:2.3:"):
        raise NvdError("CPE non valido: deve iniziare con 'cpe:2.3:' (formato CPE 2.3).")

    url = NVD_URL + "?" + urllib.parse.urlencode({"cpeName": cpe, "resultsPerPage": max_results})
    headers = {"User-Agent": "PromeTeus"}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key

    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # CPE valido ma nessun risultato
        if e.code in (403, 429):
            raise NvdError(
                "L'NVD ha risposto con un limite di richieste (riprova tra qualche "
                "secondo, oppure imposta NVD_API_KEY per alzare il limite)."
            )
        raise NvdError(f"L'NVD ha risposto con un errore HTTP {e.code}.")
    except urllib.error.URLError as e:
        raise NvdError(f"Impossibile raggiungere l'NVD: {e.reason}")
    except (json.JSONDecodeError, ValueError):
        raise NvdError("La risposta dell'NVD non e' interpretabile.")

    vulns = [_parse_vuln(v) for v in data.get("vulnerabilities", [])]
    # Piu' gravi in cima (chi non ha punteggio va in fondo).
    vulns.sort(key=lambda c: c["cvss_score"] if c["cvss_score"] is not None else -1.0, reverse=True)
    return vulns


def _parse_vuln(v: dict) -> dict:
    """Estrae i dati utili di una CVE dalla struttura dell'NVD."""
    cve = v.get("cve", {})
    cid = cve.get("id", "")
    description = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    score, severity, vector = _best_cvss(cve.get("metrics", {}))
    return {
        "id": cid,
        "description": description,
        "cvss_score": score,
        "severity": severity,
        "vector": vector,
        "url": (CVE_DETAIL_URL + cid) if cid else "",
        "published": (cve.get("published") or "")[:10],
    }


def _best_cvss(metrics: dict):
    """Preferisce CVSS v3.1, poi v3.0, poi v2. Ritorna (punteggio, gravita', vettore)."""
    for key in ("cvssMetricV31", "cvssMetricV30"):
        arr = metrics.get(key)
        if arr:
            d = arr[0].get("cvssData", {})
            return d.get("baseScore"), d.get("baseSeverity"), d.get("vectorString")
    arr = metrics.get("cvssMetricV2")
    if arr:
        entry = arr[0]
        d = entry.get("cvssData", {})
        return d.get("baseScore"), entry.get("baseSeverity"), d.get("vectorString")
    return None, None, None
