"""Stage 1: every PDF -> one small JSON file of extracted entities."""
from __future__ import annotations

import hashlib
import json
import multiprocessing as mp
import time
from pathlib import Path

from . import __version__
from .iocs import extract_iocs
from .kb import DATA, Matcher
from .pdftext import is_pdf, pdf_to_text

_matcher = None  # one per worker process


def _init_worker():
    global _matcher
    _matcher = Matcher()


def _sha1(path: Path) -> str:
    h = hashlib.sha1()
    with open(path, "rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def load_metadata() -> dict:
    """APTnotes.json indexed by file name (without extension)."""
    path = DATA / "APTnotes.json"
    index = {}
    if path.exists():
        for row in json.loads(path.read_text(encoding="utf-8")):
            index[row.get("Filename", "")] = row
    return index


def find_reports(root: Path) -> list:
    """All PDFs under root, including files the downloader left without .pdf."""
    files = [p for p in sorted(root.rglob("*")) if p.is_file() and not p.name.startswith(".")]
    return [p for p in files if p.suffix.lower() == ".pdf" or (p.suffix.lower() not in {".xlsx", ".json", ".py", ".txt", ".md", ".csv", ".html"} and is_pdf(p))]


def process_report(args) -> dict:
    path, out_dir, meta, force, keep_private = args
    path = Path(path)
    sha1 = _sha1(path)
    out_file = Path(out_dir) / f"{sha1}.json"
    if out_file.exists() and not force:
        try:
            cached = json.loads(out_file.read_text(encoding="utf-8"))
            if cached.get("pipeline") == __version__ and cached.get("status") != "error":
                return {"file": path.name, "sha1": sha1, "status": "cached", **cached.get("stats", {})}
        except ValueError:
            pass

    started = time.time()
    year = path.parent.name if path.parent.name.isdigit() and len(path.parent.name) == 4 else ""
    rec = {
        "pipeline": __version__,
        "sha1": sha1,
        "file": str(path),
        "report_id": path.stem if path.suffix.lower() == ".pdf" else path.name,
        "title": meta.get("Title", ""),
        "date": meta.get("Date", ""),
        "year": meta.get("Year", "") or year,
        "source": meta.get("Source", ""),
        "link": meta.get("Link", ""),
    }
    try:
        doc = pdf_to_text(path)
    except Exception as exc:  # corrupt / encrypted / not really a PDF
        rec.update(status="error", error=f"{type(exc).__name__}: {exc}", stats={})
        out_file.write_text(json.dumps(rec, indent=1), encoding="utf-8")
        return {"file": path.name, "sha1": sha1, "status": "error", "error": rec["error"]}

    text = doc["text"]
    rec["title"] = rec["title"] or doc["title"] or rec["report_id"].replace("_", " ")
    rec["pages"] = doc["pages"]
    rec["chars"] = len(text)
    rec["status"] = "needs_ocr" if doc["needs_ocr"] else "ok"

    found = (_matcher or Matcher()).find(text)
    iocs = extract_iocs(text, keep_private=keep_private)
    rec["threat_actors"] = [e for e in found if e["type"] == "actor"]
    rec["malware"] = [e for e in found if e["type"] == "malware"]
    rec["cves"] = [i for i in iocs if i["type"] == "cve"]
    rec["iocs"] = [i for i in iocs if i["type"] != "cve"]
    rec["stats"] = {
        "actors": len(rec["threat_actors"]),
        "malware": len(rec["malware"]),
        "cves": len(rec["cves"]),
        "iocs": len(rec["iocs"]),
        "seconds": round(time.time() - started, 2),
    }
    out_file.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    return {"file": path.name, "sha1": sha1, "status": rec["status"], **rec["stats"]}


def run_extract(reports_dir, out_dir, workers=2, force=False, keep_private=False) -> list:
    reports_dir, out_dir = Path(reports_dir), Path(out_dir) / "extracted"
    out_dir.mkdir(parents=True, exist_ok=True)
    files = find_reports(reports_dir)
    if not files:
        raise SystemExit(f"No PDF files found under {reports_dir}")
    index = load_metadata()

    def meta_for(p: Path) -> dict:
        return index.get(p.stem) or index.get(p.name) or {}

    jobs = [(str(p), str(out_dir), meta_for(p), force, keep_private) for p in files]
    print(f"Extracting {len(files)} reports with {workers} worker(s) ...")
    results = []
    if workers <= 1:
        _init_worker()
        stream = map(process_report, jobs)
        pool = None
    else:
        # maxtasksperchild keeps a long run from slowly accumulating memory
        pool = mp.Pool(workers, initializer=_init_worker, maxtasksperchild=25)
        stream = pool.imap_unordered(process_report, jobs)
    for n, res in enumerate(stream, 1):
        results.append(res)
        if res["status"] == "cached":
            note = "cached"
        elif res["status"] == "error":
            note = "ERROR " + res["error"]
        else:
            note = "{actors} actors, {malware} malware, {cves} CVEs, {iocs} IoCs".format(**res)
            if res["status"] == "needs_ocr":
                note += "  [little text: scanned PDF, needs OCR]"
        print(f"  [{n}/{len(files)}] {res['file'][:60]:60s} {note}")
    if pool:
        pool.close()
        pool.join()

    # The graph is built from exactly the reports seen in this run.
    manifest = sorted(r["sha1"] for r in results)
    (out_dir / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    errors = [r for r in results if r["status"] == "error"]
    ocr = [r for r in results if r["status"] == "needs_ocr"]
    print(f"Done: {len(results) - len(errors)} ok, {len(errors)} failed, {len(ocr)} need OCR.")
    return results
