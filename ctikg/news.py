"""News: read RSS / Atom feeds and find the articles that mention known
malware, threat actors or CVEs.

Only the title and the feed's own summary are read (not the full article), so
an entity named deep in the article body is not picked up.
"""
from __future__ import annotations

import datetime
import hashlib
import html
import re
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .iocs import RE_CVE
from .kb import DATA, Matcher
from .pdftext import clean

DESCRIPTION_CHARS = 300
_TAG = re.compile(r"<[^>]+>")
_TRACKING = re.compile(r"^(utm_|fbclid|gclid|mc_cid|mc_eid|ref$|source$)", re.I)


@dataclass
class Article:
    title: str
    url: str
    description: str = ""
    date: str = ""           # YYYY-MM-DD, empty when the feed gave none
    source: str = ""         # site the feed belongs to
    entities: list = field(default_factory=list)   # [{"type": "malware"|"actor"|"cve", "name": ...}]

    @property
    def id(self) -> str:
        return "article:" + hashlib.sha1(self.url.encode("utf-8")).hexdigest()[:16]


def default_feeds() -> list:
    path = DATA / "news_feeds.txt"
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")]


def _text(value: str) -> str:
    """HTML fragment -> one clean line of text."""
    value = html.unescape(_TAG.sub(" ", html.unescape(value or "")))
    return re.sub(r"\s+", " ", clean(value)).strip()


def _shorten(text: str, limit: int = DESCRIPTION_CHARS) -> str:
    if len(text) <= limit:
        return text
    cut = text[:limit].rsplit(" ", 1)[0].rstrip(",;:-")
    return cut + "…"


def _canonical(url: str) -> str:
    """Drop tracking parameters and fragments so one article has one URL."""
    try:
        p = urlsplit(url.strip())
    except ValueError:
        return url.strip()
    query = urlencode([(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True) if not _TRACKING.match(k)])
    return urlunsplit((p.scheme, p.netloc.lower(), p.path, query, ""))


def _date(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    try:
        return parsedate_to_datetime(value).date().isoformat()          # RSS: "Sun, 11 Oct 2026 08:00:00 GMT"
    except (TypeError, ValueError):
        pass
    try:
        return datetime.datetime.fromisoformat(value.replace("Z", "+00:00")).date().isoformat()   # Atom
    except ValueError:
        m = re.match(r"\d{4}-\d{2}-\d{2}", value)
        return m.group(0) if m else ""


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def parse_feed(xml_bytes: bytes, fallback_source: str = "") -> list:
    """RSS 2.0, RSS 1.0 (RDF) and Atom -> [Article]."""
    root = ET.fromstring(xml_bytes)
    source = fallback_source
    for el in root.iter():
        if _local(el.tag) in ("channel", "feed"):
            title = next((c.text for c in el if _local(c.tag) == "title" and c.text), None)
            if title:
                source = _text(title)
            break
    articles = []
    for item in root.iter():
        if _local(item.tag) not in ("item", "entry"):
            continue
        f = {"title": "", "link": "", "desc": "", "content": "", "date": ""}
        for c in item:
            tag = _local(c.tag)
            text = (c.text or "").strip()
            if tag == "title":
                f["title"] = text
            elif tag == "link":
                href = c.attrib.get("href")
                if href and c.attrib.get("rel", "alternate") == "alternate":
                    f["link"] = f["link"] or href          # Atom
                elif text:
                    f["link"] = f["link"] or text          # RSS
            elif tag in ("description", "summary"):
                f["desc"] = text
            elif tag in ("encoded", "content"):
                f["content"] = text
            elif tag in ("pubdate", "published", "date"):
                f["date"] = text
            elif tag == "updated":
                f["date"] = f["date"] or text
        title, url = _text(f["title"]), _canonical(f["link"])
        if not title or not url.startswith(("http://", "https://")):
            continue
        articles.append(Article(title=title, url=url, description=_shorten(_text(f["desc"] or f["content"])),
                                date=_date(f["date"]), source=source))
    return articles


def fetch(location: str) -> bytes:
    if not location.startswith(("http://", "https://")):
        return Path(location).read_bytes()
    req = urllib.request.Request(location, headers={
        "User-Agent": "Mozilla/5.0 (compatible; ctikg news reader)",
        "Accept": "application/rss+xml, application/atom+xml, application/xml, text/xml, */*"})
    with urllib.request.urlopen(req, timeout=45) as resp:
        return resp.read(8 << 20)


def collect(feeds=None, since_days=None, log=print) -> list:
    """Download every feed, tag each article with the entities it mentions."""
    matcher = Matcher()
    cutoff = (datetime.date.today() - datetime.timedelta(days=since_days)).isoformat() if since_days else ""
    seen, out = set(), []
    for location in feeds or default_feeds():
        host = urlsplit(location).netloc or Path(location).name
        try:
            articles = parse_feed(fetch(location), fallback_source=host)
        except Exception as exc:   # one dead feed must not stop the others
            log(f"  {host}: skipped ({type(exc).__name__}: {str(exc)[:100]})")
            continue
        kept = 0
        for art in articles:
            if art.url in seen or (cutoff and art.date and art.date < cutoff):
                continue
            seen.add(art.url)
            text = f"{art.title}. {art.description}"
            art.entities = [{"type": e["type"], "name": e["name"]} for e in matcher.find(text, relaxed=True)]
            art.entities += [{"type": "cve", "name": c} for c in
                             sorted({f"CVE-{y}-{n}" for y, n in RE_CVE.findall(text)})]
            kept += bool(art.entities)
            out.append(art)
        log(f"  {host}: {len(articles)} article(s), {kept} mention something known")
    return out
