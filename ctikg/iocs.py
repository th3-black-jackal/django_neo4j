"""Regex extraction of IoCs and CVEs, with refanging and noise filters."""
from __future__ import annotations

import datetime
import ipaddress
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import tldextract

DATA = Path(__file__).parent / "data"

# Uses the public-suffix snapshot bundled with tldextract: no network access.
_tld = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# ---------------------------------------------------------------- refanging
_REFANG = [
    (re.compile(r"\bh(?:xx|XX|\*\*|tt)p(s?)\s?(?:\[:\]|:)\s?//", re.I), r"http\1://"),
    (re.compile(r"\[://\]"), "://"),
    (re.compile(r"\s?(?:\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)|\[\.|\.\])\s?", re.I), "."),
    (re.compile(r"\s?(?:\[@\]|\(@\)|\[at\]|\(at\))\s?", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
]


def refang(text: str) -> str:
    for rx, rep in _REFANG:
        text = rx.sub(rep, text)
    return text


# ------------------------------------------------------------------ patterns
_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
RE_IPV4 = re.compile(rf"(?<![\w.])({_OCTET}(?:\.{_OCTET}){{3}})(?:\:(\d{{1,5}}))?(?![\w]|\.\d)")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'“”]+", re.I)
RE_EMAIL = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24})(?![\w-])")
RE_DOMAIN = re.compile(
    r"(?<![\w@./\\-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![\w-]|\.[A-Za-z0-9])"
)
RE_HASH = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![0-9A-Fa-f])")
# A hash broken over two lines by the PDF layout.
RE_SPLIT_HASH = re.compile(r"(?<![0-9A-Fa-f])([0-9A-Fa-f]{8,60}) ?\n ?([0-9A-Fa-f]{4,56})(?![0-9A-Fa-f])")
RE_CVE = re.compile(r"\bCVE[\s_-]{0,2}((?:19|20)\d{2})[\s_-]{1,3}(\d{4,7})(?!\d)", re.I)
_VERSION_BEFORE = re.compile(r"(?:version|ver\.?|v|build|release)\s*$", re.I)

HASH_TYPE = {32: "md5", 40: "sha1", 64: "sha256"}

# TLDs accepted for a *bare, non-defanged* domain. Newer gTLDs (.zip, .app,
# .name, .email ...) collide with file names and code, so they only count when
# the indicator was defanged or appeared inside a URL.
_GTLD = {
    "com", "net", "org", "info", "biz", "edu", "gov", "mil", "int", "mobi", "pro",
    "asia", "xyz", "top", "club", "online", "site", "name", "tel", "cat", "coop",
}
_FILE_EXT_CC = {"sh", "py", "so", "rs", "md", "ps", "pm"}  # ccTLDs that are usually file names
_NOT_DOMAINS = {"asp.net", "vb.net", "ado.net", "ads.net"}
_FREEMAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "mail.com",
    "163.com", "126.com", "qq.com", "sina.com", "mail.ru", "yandex.ru", "yandex.com",
    "protonmail.com", "gmx.com", "live.com", "msn.com", "yahoo.co.uk", "inbox.ru",
}


_BENIGN_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "4.2.2.1", "4.2.2.2", "9.9.9.9", "208.67.222.222", "208.67.220.220"}


def _load_list(name: str) -> set:
    path = DATA / name
    if not path.exists():
        return set()
    return {
        line.strip().lower()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }


BENIGN = _load_list("benign_domains.txt")
_MAX_CVE_YEAR = datetime.date.today().year + 1


def _registered(host: str):
    """(registered_domain, suffix) or (None, None) when the TLD is not real."""
    ext = _tld(host)
    if not ext.suffix or not ext.domain:
        return None, None
    return f"{ext.domain}.{ext.suffix}", ext.suffix


def _is_benign(reg: str) -> bool:
    return reg in BENIGN


def _good_ip(value: str, keep_private: bool) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if all(len(o) == 1 for o in value.split(".")) or value in _BENIGN_IPS:
        return False  # "1.9.2.9" is a version number, 8.8.8.8 is public DNS
    if keep_private:
        return not (ip.is_unspecified or ip.is_multicast)
    return ip.is_global


def _scan(text: str, keep_private: bool = False) -> dict:
    """One pass over text. Returns {(type, value): [count, strict_ok]}."""
    found: dict = {}

    def add(kind, value, strict=True):
        slot = found.setdefault((kind, value), [0, False])
        slot[0] += 1
        slot[1] = slot[1] or strict

    # CVEs (tolerates "CVE 2012 0158" and an id wrapped over two lines)
    for m in RE_CVE.finditer(text):
        if int(m.group(1)) <= _MAX_CVE_YEAR:
            add("cve", f"CVE-{m.group(1)}-{m.group(2)}")

    # Hashes, after re-joining ones split by a line break
    def _join(m):
        a, b = m.group(1), m.group(2)
        if len(a) + len(b) in HASH_TYPE and len(a) not in HASH_TYPE and len(b) not in HASH_TYPE:
            return a + b
        return m.group(0)

    for m in RE_HASH.finditer(RE_SPLIT_HASH.sub(_join, text)):
        h = m.group(1).lower()
        if h.isdigit() or h.isalpha() or len(set(h)) < 6:
            continue  # padding, counters, "ffff..." etc.
        add(HASH_TYPE[len(h)], h)

    # URLs (and the host inside each one)
    spans = []
    for m in RE_URL.finditer(text):
        url = m.group(0).rstrip(".,;:!?)]}'\"")
        try:
            host = (urlsplit(url).hostname or "").lower()
        except ValueError:
            continue
        if not host:
            continue
        spans.append(m.span())
        if RE_IPV4.fullmatch(host):
            if _good_ip(host, keep_private):
                add("url", url)
                add("ipv4", host)
            continue
        reg, _ = _registered(host)
        if not reg or _is_benign(reg) or reg in _FREEMAIL:
            continue
        add("url", url)
        add("domain", host)

    # E-mail addresses
    for m in RE_EMAIL.finditer(text):
        host = m.group(2).lower()
        reg, _ = _registered(host)
        if reg and not _is_benign(reg):
            add("email", f"{m.group(1).lower()}@{host}")

    # IPv4
    for m in RE_IPV4.finditer(text):
        if _VERSION_BEFORE.search(text, max(0, m.start() - 12), m.start()):
            continue
        if _good_ip(m.group(1), keep_private):
            add("ipv4", m.group(1))

    # Bare domains
    for m in RE_DOMAIN.finditer(text):
        raw = m.group(1)
        host = raw.lower().strip(".")
        if host in _NOT_DOMAINS or any(s <= m.start() < e for s, e in spans):
            continue
        reg, suffix = _registered(host)
        if not reg or _is_benign(reg) or reg in _FREEMAIL:
            continue
        label = reg[: -len(suffix) - 1]
        if len(label) < 2 or not any(c.isalpha() for c in label):
            continue  # "e.com" is the tail of a host name broken by a line wrap
        tail = suffix.rsplit(".", 1)[-1]
        strict = (
            (raw == raw.lower() or raw == raw.upper())
            and (tail in _GTLD or (len(tail) == 2 and tail not in _FILE_EXT_CC))
        )
        add("domain", host, strict)

    return found


def extract_iocs(text: str, keep_private: bool = False) -> list:
    """Return [{"type", "value", "count", "defanged"}] for one report's text."""
    fanged = refang(text)
    after = _scan(fanged, keep_private)
    before = _scan(text, keep_private) if fanged != text else after
    out = []
    for (kind, value), (count, strict) in after.items():
        defanged = (kind, value) not in before
        # A loosely-formed domain is only trusted if the author defanged it.
        if kind == "domain" and not strict and not defanged:
            continue
        out.append({"type": kind, "value": value, "count": count, "defanged": defanged})
    out.sort(key=lambda d: (d["type"], -d["count"], d["value"]))
    return out


def summarize(iocs: list) -> Counter:
    return Counter(i["type"] for i in iocs)
