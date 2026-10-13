"""Neo4j writer.

Every node carries the label :Entity and a unique `id` (the same ids the PDF
pipeline uses: "malware:PlugX", "actor:APT28", "cve:CVE-2017-0147",
"ipv4:1.2.3.4", "sha256:..."). All writes are MERGE on that id, so anything
already in the database is reused and only the relationship is added.

Relationships written by feeds
    (Malware)-[:HAS_HASH]->(Indicator md5/sha1/sha256)
    (Malware)-[:COMMUNICATES_WITH]->(Indicator ipv4)
    (Malware)-[:EXPLOITS]->(Vulnerability)
    (Malware)-[:HAS_TYPE]->(MalwareType)
    (Malware)-[:USES_TECHNIQUE]->(Technique)

Relationships written by `news`
    (Malware | ThreatActor | Vulnerability)-[:MENTIONED_IN]->(Article)
    (Article)-[:HAS_URL]->(Url)
    (Article)-[:HAS_DESCRIPTION]->(Description)
    (Article)-[:PUBLISHED_ON]->(Date)
    (ThreatActor)-[:USES]->(Malware)
"""
from __future__ import annotations

import csv
import datetime
import os
from pathlib import Path

from .kb import load_kb, norm

LABELS = {"Report", "ThreatActor", "Malware", "Vulnerability", "Indicator", "MalwareType", "Technique",
          "Article", "Url", "Description", "Date"}
REL_TYPES = {"MENTIONS", "USES", "CO_OCCURS_WITH", "HOSTED_ON", "HAS_HASH", "COMMUNICATES_WITH", "EXPLOITS", "HAS_TYPE"}
BATCH = 1000


def _today() -> str:
    return datetime.date.today().isoformat()


class GraphStore:
    """Thin layer over a `run(cypher, params) -> list of dict rows` function."""

    def __init__(self, run, close=None):
        self.run = run
        self._close = close
        self._kb = None

    @classmethod
    def neo4j(cls, uri=None, user=None, password=None, database=None):
        try:
            from neo4j import GraphDatabase
        except ImportError:
            raise SystemExit("The Neo4j driver is missing. Run:  pip install neo4j")
        uri = uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
        user = user or os.environ.get("NEO4J_USER", "neo4j")
        password = password or os.environ.get("NEO4J_PASSWORD")
        database = database or os.environ.get("NEO4J_DATABASE", "neo4j")
        if not password:
            raise SystemExit("Set the Neo4j password first:  export NEO4J_PASSWORD=...")
        driver = GraphDatabase.driver(uri, auth=(user, password))
        try:
            driver.verify_connectivity()
        except Exception as exc:
            raise SystemExit(f"Cannot connect to Neo4j at {uri}: {exc}")

        def run(query, params=None):
            records, _, _ = driver.execute_query(query, params or {}, database_=database)
            return [r.data() for r in records]

        return cls(run, driver.close)

    def close(self):
        if self._close:
            self._close()

    def ensure_schema(self):
        """Unique id per entity (this also gives the index every MERGE relies on)."""
        try:
            self.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE")
        except Exception:
            try:
                self.run("CREATE INDEX FOR (n:Entity) ON (n.id)")
            except Exception:
                pass  # already there

    # ------------------------------------------------- load the PDF graph
    def load_csv(self, graph_dir) -> dict:
        """Load out/graph/nodes.csv and edges.csv. Safe to repeat."""
        graph_dir = Path(graph_dir)
        self.ensure_schema()
        by_label, n_nodes = {}, 0
        with open(graph_dir / "nodes.csv", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                props = {k: v for k, v in row.items() if v not in ("", None)}
                for k in ("reports", "mentions"):
                    if k in props:
                        props[k] = int(props[k])
                by_label.setdefault(row["type"], []).append(props)
        for label, rows in by_label.items():
            if label not in LABELS:
                continue
            for i in range(0, len(rows), BATCH):
                self.run(f"UNWIND $rows AS row MERGE (n:Entity {{id: row.id}}) SET n += row SET n:{label}",
                         {"rows": rows[i:i + BATCH]})
            n_nodes += len(rows)

        by_type, n_edges = {}, 0
        with open(graph_dir / "edges.csv", newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                props = {"origin": row.get("origin") or "report"}
                for k in ("count", "reports"):
                    if row.get(k):
                        props[k] = int(float(row[k]))
                by_type.setdefault(row["type"], []).append({"s": row["source"], "t": row["target"], "p": props})
        for rel, rows in by_type.items():
            if rel not in REL_TYPES:
                continue
            for i in range(0, len(rows), BATCH):
                self.run(
                    "UNWIND $rows AS row MATCH (a:Entity {id: row.s}) MATCH (b:Entity {id: row.t}) "
                    f"MERGE (a)-[r:{rel}]->(b) SET r += row.p",
                    {"rows": rows[i:i + BATCH]})
            n_edges += len(rows)
        return {"nodes": n_nodes, "edges": n_edges}

    # ------------------------------------------------------ name resolution
    def _kb_index(self):
        if self._kb is None:
            kb = load_kb()
            index = {}
            for ent in kb["entities"]:
                for form in [ent["name"]] + ent["aliases"]:
                    index.setdefault((ent["type"], norm(form)), ent)
            uses = {}
            for actor, _, malware in kb["relations"]:
                uses.setdefault(malware, []).append(kb["entities"][actor])
            self._kb = (index, uses)
        return self._kb

    def resolve(self, kind: str, name: str) -> dict:
        """Map a feed's name to the node it should attach to.

        1. a name or alias known to the knowledge base (MITRE ATT&CK / MISP)
        2. a node of that kind already in the database, ignoring case
        3. otherwise a new node
        """
        label, prefix = ("ThreatActor", "actor:") if kind == "actor" else ("Malware", "malware:")
        index, _ = self._kb_index()
        ent = index.get((kind, norm(name)))
        if ent:
            props = {"name": ent["name"], "aliases": "; ".join(ent.get("aliases", [])[:25])}
            for k in ("attack_id", "category", "country"):
                if ent.get(k):
                    props[k] = ent[k]
            return {"id": prefix + ent["name"], "known": True, "kb_id": ent["id"], "props": props}
        rows = self.run("MATCH (n:Entity) WHERE n.type = $type AND toLower(n.name) = $name RETURN n.id AS id LIMIT 1",
                        {"type": label, "name": name.lower()})
        if rows:
            return {"id": rows[0]["id"], "known": False, "kb_id": None, "props": {}}
        return {"id": prefix + name, "known": False, "kb_id": None, "props": {"name": name}}

    def pick_family(self, labels: list):
        """First name the knowledge base knows, else the feed's top name."""
        index, _ = self._kb_index()
        for name in labels:
            if ("malware", norm(name)) in index:
                return name
        return labels[0] if labels else None

    # ------------------------------------------------------------ feeds
    def malware_names(self) -> list:
        return [r["name"] for r in self.run("MATCH (m:Malware) RETURN m.name AS name") if r["name"]]

    def pending_hashes(self, limit: int, source="virustotal") -> list:
        """Hash indicators already in the graph that this feed has not looked at yet."""
        flag = f"{_prop(source)}_checked"
        rows = self.run(
            f"MATCH (i:Indicator) WHERE i.ioc_type IN ['sha256', 'sha1', 'md5'] AND i.{flag} IS NULL "
            "RETURN i.name AS h ORDER BY coalesce(i.reports, 0) DESC, i.name LIMIT $n", {"n": int(limit)})
        return [r["h"] for r in rows]

    def mark_checked(self, hashes, source: str, detections=None):
        ids = [f"{_algo(h)}:{h}" for h in hashes]
        if not ids:
            return
        source = _prop(source)
        self.run(f"MATCH (i:Entity) WHERE i.id IN $ids SET i.{source}_checked = $now, i.{source}_detections = $d",
                 {"ids": ids, "now": _today(), "d": -1 if detections is None else detections})

    def upsert_malware(self, rec, attack_actors=True, dry_run=False) -> dict:
        """Write one feed record. Returns what was new and what was linked to existing nodes."""
        src, now = rec.source, _today()
        family = rec.family or self.pick_family(rec.labels)
        if family:
            mal = self.resolve("malware", family)
        else:
            kind = rec.types[0] if rec.types else "malware"
            mal = {"id": f"malware:unclassified-{rec.sample[:16]}", "known": False, "kb_id": None,
                   "props": {"name": f"Unclassified {kind} {rec.sample[:12]}", "unclassified": True}}

        fill = {"attack_id": rec.attack_id or None, "category": rec.category or None,
                "aliases": "; ".join(rec.aliases[:25]) or None, "url": rec.link if not rec.sample else None,
                "description": rec.description or None}
        for k, v in mal["props"].items():   # what the knowledge base already says wins
            if k in fill and v:
                fill[k] = v

        groups = []   # (label, relationship, direction, rows)
        rows = [{"id": f"{algo}:{value}", "origin": src,
                 "props": {"type": "Indicator", "name": value, "ioc_type": algo, "reports": 0, "mentions": 0}}
                for algo, value in rec.hashes.items()]
        groups.append(("Indicator", "HAS_HASH", "out", rows))
        groups.append(("Indicator", "COMMUNICATES_WITH", "out", [
            {"id": f"ipv4:{ip}", "origin": src,
             "props": {"type": "Indicator", "name": ip, "ioc_type": "ipv4", "reports": 0, "mentions": 0}}
            for ip in rec.ips]))
        groups.append(("Vulnerability", "EXPLOITS", "out", [
            {"id": f"cve:{c}", "origin": src, "props": {"type": "Vulnerability", "name": c, "reports": 0, "mentions": 0}}
            for c in rec.cves]))
        groups.append(("MalwareType", "HAS_TYPE", "out", [
            {"id": f"malwaretype:{t}", "origin": src, "props": {"type": "MalwareType", "name": t}} for t in rec.types]))

        groups.append(("Technique", "USES_TECHNIQUE", "out", [
            {"id": f"technique:{t['id']}", "origin": src,
             "props": {"type": "Technique", "name": t["name"], "attack_id": t["id"], "tactics": t.get("tactics", [])}}
            for t in rec.techniques]))

        actors = {}
        for a in rec.actors:                                   # named by the feed itself
            r = self.resolve("actor", a["name"])
            props = {"type": "ThreatActor", "reports": 0, "mentions": 0, **r["props"]}
            if a.get("attack_id") and "attack_id" not in props:
                props["attack_id"] = a["attack_id"]
            if a.get("aliases") and "aliases" not in props:
                props["aliases"] = "; ".join(a["aliases"][:25])
            actors[r["id"]] = {"id": r["id"], "origin": src, "props": props}
        if attack_actors and mal["kb_id"] is not None:          # known users of this family per MITRE ATT&CK
            for ent in self._kb_index()[1].get(mal["kb_id"], []):
                r = self.resolve("actor", ent["name"])
                actors.setdefault(r["id"], {"id": r["id"], "origin": "mitre-attack",
                                            "props": {"type": "ThreatActor", "reports": 0, "mentions": 0, **r["props"]}})
        groups.append(("ThreatActor", "USES", "in", list(actors.values())))

        ids = [mal["id"]] + [row["id"] for _, _, _, rows in groups for row in rows]
        existing = {r["id"] for r in self.run("MATCH (n:Entity) WHERE n.id IN $ids RETURN n.id AS id", {"ids": ids})}
        result = {
            "malware": mal["props"].get("name") or mal["id"].split(":", 1)[1],
            "malware_id": mal["id"],
            "malware_existed": mal["id"] in existing,
            "linked_existing": sorted(i for i in ids[1:] if i in existing),
            "created": sorted(i for i in ids[1:] if i not in existing),
        }
        if dry_run:
            return result

        self.run(
            "MERGE (m:Entity {id: $id}) "
            "ON CREATE SET m.type = 'Malware', m.reports = 0, m.mentions = 0, m.created_by = $src, m += $props "
            "SET m:Malware, m.last_enriched = $now, "
            "m.platforms = [x IN coalesce(m.platforms, []) WHERE NOT x IN $platforms] + $platforms, "
            "m.malware_types = [x IN coalesce(m.malware_types, []) WHERE NOT x IN $types] + $types, "
            "m.feed_labels = [x IN coalesce(m.feed_labels, []) WHERE NOT x IN $labels] + $labels, "
            "m.feeds = [x IN coalesce(m.feeds, []) WHERE NOT x IN [$src]] + [$src], "
            "m.attack_id = coalesce(m.attack_id, $fill.attack_id), m.category = coalesce(m.category, $fill.category), "
            "m.aliases = coalesce(m.aliases, $fill.aliases), m.url = coalesce(m.url, $fill.url), "
            "m.description = coalesce(m.description, $fill.description)",
            {"id": mal["id"], "props": mal["props"], "src": src, "now": now, "fill": fill,
             "platforms": rec.platforms, "types": rec.types, "labels": rec.labels})

        for label, rel, direction, rows in groups:
            if not rows:
                continue
            pattern = f"(m)-[r:{rel}]->(n)" if direction == "out" else f"(n)-[r:{rel}]->(m)"
            self.run(
                "MATCH (m:Entity {id: $mid}) UNWIND $rows AS row "
                "MERGE (n:Entity {id: row.id}) ON CREATE SET n += row.props, n.created_by = $src "
                f"SET n:{label} "
                f"MERGE {pattern} ON CREATE SET r.origin = row.origin, r.first_seen = $now, r.sample = $sample",
                {"mid": mal["id"], "rows": rows, "src": src, "now": now, "sample": rec.sample})
        self.mark_checked(rec.hashes.values(), src, rec.detections)
        return result


    # ------------------------------------------------------------- news
    def upsert_article(self, art, only_existing=False, dry_run=False) -> dict:
        """Write one news article and link the entities it mentions.

        only_existing  link only entities that are already in the database
        """
        targets = {}
        for e in art.entities:
            if e["type"] == "cve":
                targets[f"cve:{e['name']}"] = ("Vulnerability", {"type": "Vulnerability", "name": e["name"],
                                                                 "reports": 0, "mentions": 0})
            else:
                r = self.resolve(e["type"], e["name"])
                label = "ThreatActor" if e["type"] == "actor" else "Malware"
                targets[r["id"]] = (label, {"type": label, "reports": 0, "mentions": 0, **r["props"]})
        existing = {r["id"] for r in self.run("MATCH (n:Entity) WHERE n.id IN $ids RETURN n.id AS id",
                                              {"ids": list(targets) + [art.id]})}
        if only_existing:
            targets = {i: t for i, t in targets.items() if i in existing}
        result = {"article_existed": art.id in existing, "entities": sorted(targets),
                  "new_entities": sorted(i for i in targets if i not in existing)}
        if dry_run or not targets:
            return result

        now = _today()
        self.run(
            "MERGE (a:Entity {id: $id}) ON CREATE SET a.type = 'Article', a.first_seen = $now "
            "SET a:Article, a.name = $title, a.title = $title, a.source = $source, a.url = $url, a.published = $date",
            {"id": art.id, "title": art.title, "source": art.source, "url": art.url, "date": art.date, "now": now})
        parts = [("Url", "HAS_URL", f"link:{art.url}", art.url)]
        if art.description:
            parts.append(("Description", "HAS_DESCRIPTION", "description:" + art.id.split(":", 1)[1], art.description))
        if art.date:
            parts.append(("Date", "PUBLISHED_ON", f"date:{art.date}", art.date))
        for label, rel, node_id, value in parts:
            self.run(
                "MATCH (a:Entity {id: $aid}) MERGE (n:Entity {id: $id}) "
                f"ON CREATE SET n.type = '{label}' SET n:{label}, n.name = $value "
                f"MERGE (a)-[:{rel}]->(n)",
                {"aid": art.id, "id": node_id, "value": value})
        for label in ("Malware", "ThreatActor", "Vulnerability"):
            rows = [{"id": i, "props": props} for i, (lab, props) in targets.items() if lab == label]
            if rows:
                self.run(
                    "MATCH (a:Entity {id: $aid}) UNWIND $rows AS row "
                    "MERGE (n:Entity {id: row.id}) ON CREATE SET n += row.props, n.created_by = 'news' "
                    f"SET n:{label} "
                    "MERGE (n)-[r:MENTIONED_IN]->(a) ON CREATE SET r.origin = 'news', r.first_seen = $now",
                    {"aid": art.id, "rows": rows, "now": now})
        return result


def _prop(name: str) -> str:
    """Feed name as a safe property prefix ("mitre-attack" -> "mitre_attack")."""
    return "".join(c if c.isalnum() else "_" for c in name)


def _algo(h: str) -> str:
    return {32: "md5", 40: "sha1", 64: "sha256"}.get(len(h), "sha256")
