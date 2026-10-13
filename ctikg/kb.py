"""Knowledge base of threat-actor and malware names, and the text matcher.

Names come from MITRE ATT&CK (Enterprise) and the MISP galaxy clusters
(threat-actor, malpedia, tool). `build_kb()` downloads them and writes a small
kb.json; `Matcher` finds those names in report text.
"""
from __future__ import annotations

import datetime
import json
import re
import urllib.request
from collections import Counter, defaultdict
from pathlib import Path

DATA = Path(__file__).parent / "data"
KB_PATH = DATA / "kb.json"

SOURCES = {
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "misp_actor": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/threat-actor.json",
    "misp_malpedia": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/malpedia.json",
    "misp_tool": "https://raw.githubusercontent.com/MISP/misp-galaxy/main/clusters/tool.json",
    "aptnotes": "https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.json",
}


def norm(name: str) -> str:
    """Matching key: lowercase alphanumerics only, so 'Poison-Ivy' == 'PoisonIvy'."""
    return re.sub(r"[^a-z0-9]", "", name.lower())


def _words(name: str) -> set:
    path = DATA / name
    if not path.exists():
        return set()
    return {
        w.strip().lower()
        for w in path.read_text(encoding="utf-8").splitlines()
        if w.strip() and not w.startswith("#")
    }


# ------------------------------------------------------------------ building
def _fetch(url: str, dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "ctikg"})
    with urllib.request.urlopen(req, timeout=120) as resp, open(dest, "wb") as out:
        while chunk := resp.read(1 << 20):
            out.write(chunk)
    return dest


def _usable(alias: str) -> bool:
    key = norm(alias)
    return (
        len(key) >= 3
        and not key.isdigit()
        and len(alias) <= 40
        and "(" not in alias
        and not alias.lower().startswith("unidentified")
    )


class _Builder:
    def __init__(self):
        self.entities = []            # dicts
        self.claimed = {}             # (type, key) -> entity index

    def add(self, etype, name, aliases, **attrs):
        name = re.sub(r"\s*\(.*?\)\s*", " ", name).strip()
        names = [name] + [a for a in aliases if a]
        keys = [norm(n) for n in names if _usable(n)]
        if not _usable(name):
            return None
        # Merge into an existing entity when the primary name is already known,
        # otherwise when any alias is.
        idx = next((self.claimed[(etype, k)] for k in keys if (etype, k) in self.claimed), None)
        if idx is None:
            idx = len(self.entities)
            self.entities.append({"type": etype, "name": name, "aliases": [], **attrs})
        ent = self.entities[idx]
        for k, v in attrs.items():
            if v and not ent.get(k):
                ent[k] = v
        for n in names:
            if not _usable(n):
                continue
            key = norm(n)
            if self.claimed.setdefault((etype, key), idx) == idx and n != ent["name"] and n not in ent["aliases"]:
                ent["aliases"].append(n)
        return idx


def build_kb(cache_dir: Path | None = None, refresh: bool = True) -> dict:
    """Download the sources and write ctikg/data/kb.json. Peak memory ~0.5 GB."""
    cache = Path(cache_dir or DATA / "cache")
    files = {}
    for key, url in SOURCES.items():
        dest = cache / (key + ".json")
        files[key] = dest if (dest.exists() and not refresh) else _fetch(url, dest)

    b = _Builder()
    relations = []

    # --- MITRE ATT&CK: groups, software and group->software "uses" links
    stix = json.loads(files["attack"].read_text(encoding="utf-8"))["objects"]
    by_stix = {}
    for o in stix:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        kind = o.get("type")
        if kind not in ("intrusion-set", "malware", "tool"):
            continue
        ref = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), {})
        if kind == "intrusion-set":
            idx = b.add("actor", o["name"], o.get("aliases", []), attack_id=ref.get("external_id"), url=ref.get("url"))
        else:
            idx = b.add("malware", o["name"], o.get("x_mitre_aliases", []), category=kind,
                        attack_id=ref.get("external_id"), url=ref.get("url"))
        if idx is not None:
            by_stix[o["id"]] = idx
    for o in stix:
        if o.get("type") == "relationship" and o.get("relationship_type") == "uses" and not o.get("revoked"):
            s, t = by_stix.get(o["source_ref"]), by_stix.get(o["target_ref"])
            if s is not None and t is not None and b.entities[s]["type"] == "actor" and b.entities[t]["type"] == "malware":
                relations.append([s, "USES", t])
    del stix

    # --- MISP galaxies: many more actors / families and their synonyms
    for key, etype, category in (
        ("misp_actor", "actor", None),
        ("misp_tool", "malware", "malware"),
        ("misp_malpedia", "malware", "malware"),
    ):
        for v in json.loads(files[key].read_text(encoding="utf-8")).get("values", []):
            meta = v.get("meta") or {}
            attrs = {"country": meta.get("country")} if etype == "actor" else {"category": category}
            b.add(etype, v.get("value", ""), meta.get("synonyms") or [], **attrs)

    # --- "Sandworm Team" is usually written "Sandworm": add the short form if free
    common = _words("common_words.txt")
    for idx, ent in enumerate(b.entities):
        for n in [ent["name"]] + list(ent["aliases"]):
            m = re.fullmatch(r"(.+?)\s+(?:Group|Team|Gang)", n)
            if m and _usable(m.group(1)) and len(norm(m.group(1))) >= 5 and m.group(1).lower() not in common:
                if b.claimed.setdefault((ent["type"], norm(m.group(1))), idx) == idx and m.group(1) not in ent["aliases"]:
                    ent["aliases"].append(m.group(1))

    for i, ent in enumerate(b.entities):
        ent["id"] = i
    kb = {
        "built": datetime.date.today().isoformat(),
        "sources": {k: v for k, v in SOURCES.items() if k != "aptnotes"},
        "entities": b.entities,
        "relations": sorted({tuple(r) for r in relations}),
    }
    KB_PATH.write_text(json.dumps(kb, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    # Report metadata index used to give reports a title / date / publisher.
    (DATA / "APTnotes.json").write_bytes(files["aptnotes"].read_bytes())
    return kb


def load_kb() -> dict:
    if not KB_PATH.exists():
        raise SystemExit("Knowledge base not found. Run:  python -m ctikg update-kb")
    return json.loads(KB_PATH.read_text(encoding="utf-8"))


# ------------------------------------------------------------------ matching
_TOKEN = re.compile(r"[A-Za-z0-9@_]+")
_GAP = re.compile(r"\s{1,3}|-\s?|[._]")
_SOFT_GAP = re.compile(r"\s{1,3}|-\s?")
_CUE = {
    "malware": re.compile(
        r"malware|trojan|backdoor|\brats?\b|implant|dropper|downloader|loader|ransomware|\bworm\b|botnet|\bbot\b"
        r"|rootkit|famil|variant|stealer|keylogger|wiper|spyware|webshell|web shell|toolkit|exploit kit"
    ),
    "actor": re.compile(
        r"\bgroups?\b|actors?\b|\bapt\b|\bteam\b|campaign|\bgang\b|\bcrew\b|hackers?\b|operation|attackers"
        r"|adversar|espionage|\baka\b|also known as"
    ),
}
MAX_NGRAM = 4
CUE_WINDOW = 30


def _compact(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", s)


class Matcher:
    """Finds knowledge-base names in text.

    * Keys ignore case, spaces and punctuation ("APT 28", "Poison-Ivy").
    * A purely alphabetic name is not matched when the text has it in all
      lowercase ("dark hotel" is not Darkhotel).
    * Names made of ordinary English words, or very short ones, are
      "ambiguous": they must appear with the knowledge-base capitalisation
      AND at least once right next to a context word such as "malware",
      "backdoor", "group" or "campaign".
    * Names in data/stoplist.txt are never matched.
    """

    def __init__(self, kb: dict | None = None):
        kb = kb or load_kb()
        self.entities = kb["entities"]
        stop = _words("stoplist.txt")
        common = _words("common_words.txt")
        self.index = defaultdict(list)       # key -> [(entity idx, compact form, tokens)]
        self.ambiguous = set()
        for ent in self.entities:
            if ent["name"].lower() in stop:
                continue
            for form in [ent["name"]] + ent["aliases"]:
                key = norm(form)
                toks = tuple(t.lower() for t in _TOKEN.findall(form))
                if key in stop or form.lower() in stop or not toks:
                    continue
                plain = all(t.isalpha() for t in toks)
                ordinary = plain and all(t in common or len(t) <= 3 for t in toks)
                if ordinary and form.islower():
                    continue  # e.g. a family literally called "template"
                self.index[key].append((ent["id"], _compact(form), toks))
                if len(key) <= 3 or ordinary:
                    self.ambiguous.add(key)

    def _case_ok(self, key: str, surface: str, forms) -> bool:
        if key in self.ambiguous:
            return any(surface == f or (surface == f.upper() and len(f) > 3) for f in forms)
        if all(f.isalpha() for f in forms) and surface.islower():
            return any(f.islower() for f in forms)
        return True

    @staticmethod
    def _split_ok(words, gaps_soft) -> bool:
        """Text splits a name differently from the KB ("Poison Ivy" vs PoisonIvy)."""
        if not gaps_soft:
            return False
        if len(words) == 2 and words[0].isalpha() and len(words[0]) >= 2 and words[1].isdigit():
            return True  # "APT 28"
        return all(w.isalpha() and len(w) >= 3 and w[0].isupper() for w in words)

    def find(self, text: str, relaxed: bool = False) -> list:
        """Return [{"id","type","name","count","forms"}] sorted by count.

        relaxed is for short texts such as a headline plus summary, where a
        name appears once and a context word may not sit right next to it:
        multi-word names in their exact capitalisation ("Mustang Panda",
        "Cobalt Strike") need no context word, and single ambiguous words
        get a wider window.
        """
        window_size = 120 if relaxed else CUE_WINDOW
        toks = [(m.group(0), m.start(), m.end()) for m in _TOKEN.finditer(text)]
        counts, cued, seen_forms = Counter(), set(), defaultdict(Counter)
        lower = None
        i, n_tok = 0, len(toks)
        while i < n_tok:
            hit = 0
            joined, soft = [toks[i][0]], [True]
            for n in range(1, MAX_NGRAM):
                if i + n >= n_tok or not _GAP.fullmatch(text, toks[i + n - 1][2], toks[i + n][1]):
                    break
                joined.append(toks[i + n][0])
                soft.append(soft[-1] and bool(_SOFT_GAP.fullmatch(text, toks[i + n - 1][2], toks[i + n][1])))
            # Longest candidate first: "Winnti Group" before "Winnti".
            for n in range(len(joined), 0, -1):
                words = joined[:n]
                surface = _compact("".join(words))
                key = surface.lower()
                cands = self.index.get(key)
                if not cands:
                    continue
                text_toks = tuple(w.lower() for w in words)
                per_ent = defaultdict(list)
                for eid, form, ftoks in cands:
                    if n == 1 or ftoks == text_toks or self._split_ok(words, soft[n - 1]):
                        per_ent[eid].append(form)
                start, end = toks[i][1], toks[i + n - 1][2]
                for eid, forms in per_ent.items():
                    if not self._case_ok(key, surface, forms):
                        continue
                    etype = self.entities[eid]["type"]
                    if key in self.ambiguous:
                        if lower is None:
                            lower = text.lower()
                        window = lower[max(0, start - window_size): start] + " " + lower[end: end + window_size]
                        if (relaxed and n > 1) or _CUE[etype].search(window):
                            cued.add(eid)
                        counts[(eid, True)] += 1
                    else:
                        counts[(eid, False)] += 1
                    seen_forms[eid][re.sub(r"\s+", " ", text[start:end])] += 1
                    hit = n
                if hit:
                    break
            i += hit or 1

        total = Counter()
        for (eid, ambiguous), c in counts.items():
            if ambiguous and eid not in cued:
                continue  # ordinary word that never appeared in a CTI context
            total[eid] += c
        out = []
        for eid, c in total.most_common():
            ent = self.entities[eid]
            out.append({
                "id": eid, "type": ent["type"], "name": ent["name"], "count": c,
                "forms": [f for f, _ in seen_forms[eid].most_common(3)],
            })
        return out
