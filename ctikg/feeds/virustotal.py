"""VirusTotal API v3 feed.

Two ways in:
  lookup(hashes)   GET /files/{hash}           works with the free public API
  search(platform) GET /intelligence/search    needs a premium (VT Intelligence) key

Per file it reads: the three hashes, file type (-> platform), the AV-consensus
family and category (popular_threat_classification), CVE tags, the IPs the
sample contacted in sandboxes, and - only with a VT Enterprise / Threat
Landscape licence - the related threat actors.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from . import MalwareFeed, MalwareRecord

API = "https://www.virustotal.com/api/v3"

# VirusTotal file-type tags per platform. The first list is used to build
# search queries (type:...), the second to classify a file that was looked up.
PLATFORM_TYPES = {
    "windows": (["peexe", "pedll"], {"peexe", "pedll", "pe", "windows", "msi", "lnk", "win32", "win64"}),
    "linux": (["elf"], {"elf", "linux"}),
    "macos": (["macho"], {"macho", "mac", "macos", "dmg", "pkg"}),
    "android": (["apk"], {"apk", "android", "dex"}),
    "ios": (["ipa"], {"ipa", "ios"}),
}
# AV "names" that say nothing about the family.
GENERIC = {
    "generic", "malicious", "malware", "agent", "heur", "heuristic", "unsafe", "suspicious",
    "trojan", "virus", "riskware", "gen", "score", "high", "confidence", "variant", "win32",
    "win64", "msil", "linux", "android", "application", "unwanted", "program", "artemis",
}
RE_CVE = re.compile(r"cve[-_ ]?((?:19|20)\d{2})[-_ ]?(\d{4,7})", re.I)
RE_HASH = re.compile(r"^(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


class QuotaExceeded(Exception):
    pass


class VirusTotalFeed(MalwareFeed):
    name = "virustotal"

    def __init__(self, api_key=None, cache_dir=None, rate=4, min_detections=5, want_actors=False,
                 refresh=False, base_url=None, log=print, **_):
        self.api_key = api_key or os.environ.get("VT_API_KEY", "")
        if not self.api_key:
            raise SystemExit("Set your VirusTotal API key first:  export VT_API_KEY=...")
        self.base = (base_url or os.environ.get("VT_API_URL") or API).rstrip("/")
        self.cache = Path(cache_dir) if cache_dir else None
        if self.cache:
            self.cache.mkdir(parents=True, exist_ok=True)
        self.delay = 60.0 / rate if rate else 0.0   # public API: 4 requests a minute
        self.min_detections = min_detections
        self.want_actors = want_actors
        self.refresh = refresh
        self.log = log
        self._last = 0.0
        self.requests = 0

    # ------------------------------------------------------------- HTTP
    def _get(self, path: str, params: dict | None = None):
        """JSON body, or None for 404. Paces itself and backs off on 429."""
        url = f"{self.base}{path}"
        if params:
            url += "?" + urllib.parse.urlencode(params)
        for attempt in range(4):
            wait = self._last + self.delay - time.time()
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()
            self.requests += 1
            req = urllib.request.Request(url, headers={"x-apikey": self.api_key, "accept": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=60) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as err:
                body = err.read().decode("utf-8", "replace")[:300]
                if err.code == 404:
                    return None
                if err.code == 429:   # per-minute limit clears in a minute; the daily one does not
                    if attempt == 3:
                        break
                    self.log(f"  rate limited by VirusTotal, waiting 60 s ({attempt + 1}/3)")
                    time.sleep(60 if self.delay else 0.2)
                    continue
                if err.code == 401:
                    raise SystemExit("VirusTotal rejected the API key (401). Check VT_API_KEY.")
                if err.code == 403:
                    raise PermissionError(body)
                raise RuntimeError(f"VirusTotal HTTP {err.code}: {body}")
            except urllib.error.URLError as err:
                if attempt == 3:
                    raise RuntimeError(f"Cannot reach VirusTotal: {err.reason}")
                time.sleep(5 if self.delay else 0.2)
        raise QuotaExceeded("VirusTotal keeps answering 429: the daily quota is probably used up")

    # --------------------------------------------------------- per file
    def _contacted_ips(self, file_obj: dict) -> list:
        rel = (file_obj.get("relationships") or {}).get("contacted_ips")
        if rel is not None:   # came inline with the file, no extra request
            return [d["id"] for d in rel.get("data", []) if d.get("id")]
        try:
            res = self._get(f"/files/{file_obj['id']}/contacted_ips", {"limit": 40})
        except PermissionError:
            return []
        return [d["id"] for d in (res or {}).get("data", []) if d.get("id")]

    def _actors(self, sha256: str) -> list:
        if not self.want_actors:
            return []
        try:
            res = self._get(f"/files/{sha256}/related_threat_actors", {"limit": 20})
        except PermissionError:
            self.log("  note: this API key cannot read related_threat_actors (needs VT Enterprise "
                     "with Threat Landscape); continuing without VirusTotal actor data")
            self.want_actors = False
            return []
        out = []
        for d in (res or {}).get("data", []):
            attrs = d.get("attributes") or {}
            if attrs.get("name"):
                out.append({"name": attrs["name"], "aliases": list(attrs.get("aliases") or [])})
        return out

    def _record(self, file_obj: dict) -> MalwareRecord:
        a = file_obj.get("attributes") or {}
        sha256 = a.get("sha256") or file_obj.get("id", "")
        stats = a.get("last_analysis_stats") or {}
        ptc = a.get("popular_threat_classification") or {}
        tags = [str(t).lower() for t in (a.get("tags") or [])]
        type_tags = {str(t).lower() for t in (a.get("type_tags") or [])} | {str(a.get("type_tag", "")).lower()}

        names = [(n.get("value", "").lower(), int(n.get("count") or 0)) for n in ptc.get("popular_threat_name") or []]
        names = [(n, c) for n, c in names if n and n not in GENERIC and not RE_CVE.fullmatch(n)]
        cats = [(c.get("value", "").lower(), int(c.get("count") or 0)) for c in ptc.get("popular_threat_category") or []]
        top = max((c for _, c in cats), default=0)
        types = [v for v, c in cats if v and c * 3 >= top][:3]   # drop categories only one stray engine used

        text = " ".join(tags + [n for n, _ in names] + [ptc.get("suggested_threat_label") or ""])
        cves = sorted({f"CVE-{y}-{n}" for y, n in RE_CVE.findall(text)})
        platforms = sorted(p for p, (_, keys) in PLATFORM_TYPES.items() if keys & (type_tags | set(tags)))
        first = a.get("first_submission_date")
        return MalwareRecord(
            source=self.name,
            sample=sha256,
            family=None,   # chosen later from `labels`, once we know which names the graph already has
            labels=[n for n, _ in names[:6]],
            types=types,
            platforms=platforms,
            hashes={k: a[k].lower() for k in ("md5", "sha1", "sha256") if a.get(k)},
            ips=[],
            cves=cves,
            actors=[],
            detections=int(stats.get("malicious") or 0),
            engines=sum(int(v or 0) for v in stats.values()),
            first_seen=datetime.datetime.fromtimestamp(first, datetime.timezone.utc).date().isoformat() if first else "",
            link=f"https://www.virustotal.com/gui/file/{sha256}",
        )

    def _complete(self, file_obj: dict) -> MalwareRecord:
        rec = self._record(file_obj)
        if rec.detections >= self.min_detections:   # do not spend quota on clean files
            rec.ips = sorted(set(self._contacted_ips(file_obj)))
            rec.actors = self._actors(rec.sample)
        return rec

    # ------------------------------------------------------------ cache
    def _cache_get(self, h: str):
        if not self.cache or self.refresh:
            return False, None
        f = self.cache / f"{h}.json"
        if not f.exists():
            return False, None
        data = json.loads(f.read_text(encoding="utf-8"))
        return True, (MalwareRecord(**data) if data else None)

    def _cache_put(self, keys, rec):
        if self.cache:
            body = json.dumps(rec.to_dict() if rec else None)
            for k in keys:
                (self.cache / f"{k}.json").write_text(body, encoding="utf-8")

    # ------------------------------------------------------- public API
    def lookup(self, hashes, platform=None):
        """Yield (hash, record). record is None when VirusTotal has never seen the file."""
        done = set()
        for h in hashes:
            h = h.strip().lower()
            if not RE_HASH.match(h) or h in done:
                continue
            hit, rec = self._cache_get(h)
            if not hit:
                obj = self._get(f"/files/{h}", {"relationships": "contacted_ips"})
                rec = self._complete(obj["data"]) if obj and obj.get("data") else None
                self._cache_put({h} | set(rec.hashes.values() if rec else ()), rec)
            if rec:
                done.update(rec.hashes.values())   # the md5 and sha256 of one file cost one request
                if platform and platform not in rec.platforms:
                    self.log(f"  {h[:16]}…  skipped: platform is {', '.join(rec.platforms) or 'unknown'}, not {platform}")
                    continue
            yield h, rec

    def search(self, platform=None, limit=50, days=7, query=None, **_):
        """Recent malicious files for a platform (premium keys only)."""
        if not query:
            parts = []
            if platform:
                parts.append("(" + " OR ".join(f"type:{t}" for t in PLATFORM_TYPES[platform][0]) + ")")
            parts += [f"p:{self.min_detections}+", f"fs:{days}d+"]
            query = " ".join(parts)
        self.log(f"  VirusTotal Intelligence query: {query}")
        cursor, seen = None, 0
        while seen < limit:
            params = {"query": query, "limit": min(300, limit - seen), "descriptors_only": "false"}
            if cursor:
                params["cursor"] = cursor
            try:
                page = self._get("/intelligence/search", params)
            except PermissionError:
                raise SystemExit(
                    "This API key cannot use VirusTotal Intelligence search (premium feature).\n"
                    "With a free key, look up hashes instead:  --from-graph  or  --hashes-file FILE")
            for obj in (page or {}).get("data", []):
                if obj.get("type") != "file":
                    continue
                rec = self._complete(obj)
                self._cache_put(set(rec.hashes.values()), rec)
                seen += 1
                yield rec
                if seen >= limit:
                    break
            cursor = ((page or {}).get("meta") or {}).get("cursor")
            if not cursor:
                break
