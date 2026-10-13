"""MITRE ATT&CK feed.

ATT&CK is a curated catalogue, not a sample feed: it has no hashes or IPs.
Per software entry (malware or tool) it gives the platforms, the groups that
use it, the techniques it implements, and its aliases. CVEs are picked out of
ATT&CK's own descriptions, and the malware type is read from the first
sentence of the description ("X is a ransomware ..."), because ATT&CK has no
type field.
"""
from __future__ import annotations

import json
import re
import time
import urllib.request
from pathlib import Path

from . import MalwareFeed, MalwareRecord

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/{d}-attack/{d}-attack.json"
DOMAINS = ("enterprise", "mobile", "ics")
MAX_AGE_DAYS = 7

RE_CVE = re.compile(r"CVE-((?:19|20)\d{2})-(\d{4,7})", re.I)
RE_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
RE_CITE = re.compile(r"\(Citation:[^)]*\)")
# Checked in this order against the opening of the description.
TYPE_WORDS = [
    ("ransomware", r"ransomware"), ("wiper", r"\bwiper"), ("bootkit", r"bootkit"), ("rootkit", r"rootkit"),
    ("worm", r"\bworm\b"), ("rat", r"remote access (?:tool|trojan)|\brat\b"), ("backdoor", r"backdoor"),
    ("banker", r"banking (?:trojan|malware)|\bbanker"), ("stealer", r"stealer|credential harvester"),
    ("keylogger", r"keylogger"), ("downloader", r"downloader"), ("dropper", r"dropper"), ("loader", r"\bloader\b"),
    ("botnet", r"botnet|\bbot\b"), ("miner", r"cryptominer|cryptocurrency min|coin ?miner"),
    ("webshell", r"web ?shell"), ("spyware", r"spyware|surveillanceware|surveillance tool"),
    ("pos", r"point[- ]of[- ]sale|\bpos malware"), ("trojan", r"\btrojan\b"),
]
TYPE_WORDS = [(name, re.compile(rx, re.I)) for name, rx in TYPE_WORDS]


def _plain(text: str) -> str:
    return RE_LINK.sub(r"\1", RE_CITE.sub("", text or "")).strip()


def _attack_ref(obj: dict) -> dict:
    return next((r for r in obj.get("external_references", []) if r.get("source_name", "").startswith("mitre")
                 and r.get("external_id")), {})


class MitreFeed(MalwareFeed):
    name = "mitre-attack"

    def __init__(self, cache_dir=None, refresh=False, domain=None, techniques=True, log=print, **_):
        self.cache = Path(cache_dir or ".")
        self.refresh = refresh
        self.domain = domain
        self.techniques = techniques
        self.log = log
        self.requests = 0

    def _load(self, domain: str) -> list:
        self.cache.mkdir(parents=True, exist_ok=True)
        path = self.cache / f"{domain}-attack.json"
        stale = not path.exists() or time.time() - path.stat().st_mtime > MAX_AGE_DAYS * 86400
        if stale or self.refresh:
            url = URL.format(d=domain)
            self.log(f"  downloading {url}")
            self.requests += 1
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "ctikg"})
                with urllib.request.urlopen(req, timeout=180) as resp, open(path.with_suffix(".part"), "wb") as out:
                    while chunk := resp.read(1 << 20):
                        out.write(chunk)
                path.with_suffix(".part").replace(path)
            except Exception as exc:
                if not path.exists():
                    raise SystemExit(f"Cannot download MITRE ATT&CK ({exc}) and there is no cached copy.")
                self.log(f"  download failed ({exc}); using the cached copy")
        return json.loads(path.read_text(encoding="utf-8"))["objects"]

    def lookup(self, hashes, platform=None):
        raise SystemExit("MITRE ATT&CK has no file hashes. Give software names or ATT&CK ids (PlugX, S0013), "
                         "or no names at all to load everything.")

    def search(self, platform=None, limit=None, names=None, **_):
        """Yield one record per ATT&CK software entry.

        platform  only software ATT&CK lists for that platform
        names     only these software names, aliases or ATT&CK ids (case-insensitive)
        """
        domain = self.domain or ("mobile" if platform in ("android", "ios") else "enterprise")
        objects = self._load(domain)
        live = {o["id"]: o for o in objects if not o.get("revoked") and not o.get("x_mitre_deprecated")}
        want = {re.sub(r"[^a-z0-9]", "", n.lower()) for n in names} if names else None

        users, techs, rel_text = {}, {}, {}
        for o in objects:
            if o.get("type") != "relationship" or o.get("relationship_type") != "uses" or o.get("revoked"):
                continue
            src, dst = live.get(o["source_ref"]), live.get(o["target_ref"])
            if not src or not dst:
                continue
            if src["type"] == "intrusion-set" and dst["type"] in ("malware", "tool"):
                users.setdefault(dst["id"], []).append(src)
            elif src["type"] in ("malware", "tool") and dst["type"] == "attack-pattern":
                techs.setdefault(src["id"], []).append(dst)
                rel_text.setdefault(src["id"], []).append(o.get("description") or "")

        count = 0
        for o in sorted((o for o in live.values() if o["type"] in ("malware", "tool")), key=lambda o: o["name"].lower()):
            ref = _attack_ref(o)
            aliases = [a for a in o.get("x_mitre_aliases", []) if a != o["name"]]
            if want is not None:
                keys = {re.sub(r"[^a-z0-9]", "", k.lower()) for k in [o["name"], ref.get("external_id", "")] + aliases}
                if not keys & want:
                    continue
            platforms = [p.lower() for p in o.get("x_mitre_platforms", [])]
            if platform and platform not in platforms:
                continue
            desc = _plain(o.get("description"))
            opening = desc[:350]
            types = [name for name, rx in TYPE_WORDS if rx.search(opening)][:3]
            cves = sorted({f"CVE-{y}-{n}" for y, n in RE_CVE.findall(desc + " " + " ".join(rel_text.get(o["id"], [])))})
            actors = []
            for g in sorted(users.get(o["id"], []), key=lambda g: g["name"]):
                actors.append({"name": g["name"], "aliases": [a for a in g.get("aliases", []) if a != g["name"]],
                               "attack_id": _attack_ref(g).get("external_id", "")})
            techniques = []
            if self.techniques:
                seen = set()
                for t in techs.get(o["id"], []):
                    tid = _attack_ref(t).get("external_id")
                    if tid and tid not in seen:
                        seen.add(tid)
                        techniques.append({"id": tid, "name": t["name"],
                                           "tactics": [p["phase_name"] for p in t.get("kill_chain_phases", [])]})
                techniques.sort(key=lambda t: t["id"])
            yield MalwareRecord(
                source=self.name, sample="", family=o["name"], labels=[], types=types, platforms=platforms,
                cves=cves, actors=actors, techniques=techniques, aliases=aliases,
                attack_id=ref.get("external_id", ""), category=o["type"], link=ref.get("url", ""),
                description=desc.split("\n")[0][:500],
            )
            count += 1
            if limit and count >= limit:
                return
