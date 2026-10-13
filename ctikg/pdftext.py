"""PDF -> plain text, one page at a time so memory stays flat."""
from __future__ import annotations

import re
import unicodedata

import pymupdf

# Soft hyphens, zero-width characters and BOMs that PDFs sprinkle through text.
_INVISIBLE = dict.fromkeys(map(ord, "­​‌‍⁠﻿"))
# Control characters (NUL, form feed ...) break XML/GraphML and CSV consumers.
_CONTROL = dict.fromkeys(c for c in range(0x20) if c not in (0x09, 0x0A))
_CONTROL.update(dict.fromkeys(range(0x7F, 0xA0)))
_CONTROL.update({0x0B: " ", 0x0C: " ", 0x0D: " "})  # these separate words, so keep a gap
_DASHES = str.maketrans({c: "-" for c in "‐‑‒–—−"})

MAX_CHARS = 5_000_000  # hard cap per report; far above any real report


def is_pdf(path) -> bool:
    """The aptnotes downloader only adds .pdf when it recognises the type, so sniff."""
    try:
        with open(path, "rb") as fh:
            return b"%PDF" in fh.read(1024)
    except OSError:
        return False


def clean(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)  # also expands ligatures such as "fi"
    text = text.translate(_INVISIBLE).translate(_DASHES).translate(_CONTROL)
    return re.sub(r"[ \t\r\f\v]+", " ", text)


def pdf_to_text(path) -> dict:
    """Return {"text", "pages", "title", "needs_ocr"} for one PDF."""
    parts, size = [], 0
    with pymupdf.open(path) as doc:
        if doc.needs_pass and not doc.authenticate(""):
            raise ValueError("PDF is password protected")
        pages = doc.page_count
        title = (doc.metadata or {}).get("title") or ""
        for page in doc:
            chunk = page.get_text("text")
            parts.append(chunk)
            size += len(chunk)
            if size > MAX_CHARS:
                break
    text = clean("\n".join(parts))
    # Scanned reports have pages but almost no text layer.
    needs_ocr = pages > 0 and len(text.strip()) / pages < 100
    return {"text": text, "pages": pages, "title": clean(title).replace("\n", " ").strip(), "needs_ocr": needs_ocr}
