"""All Cypher used by the API, as small functions returning plain data.

Node ids follow the graph's convention: "actor:APT28", "malware:PlugX",
"cve:CVE-2017-0147", "ipv4:1.2.3.4", "technique:T1059", "report:<file>".
"""
from __future__ import annotations

import re

from .neo4j import run_read

NODE = "{id: {v}.id, type: {v}.type, name: {v}.name}"
LABELS = ["Report", "ThreatActor", "Malware", "Vulnerability", "Indicator", "MalwareType",
          "Technique", "Article", "Url", "Description", "Date"]
REL_TYPES = ["MENTIONS", "USES", "CO_OCCURS_WITH", "EXPLOITS", "HAS_HASH", "COMMUNICATES_WITH",
             "HAS_TYPE", "USES_TECHNIQUE", "HOSTED_ON", "MENTIONED_IN", "HAS_URL",
             "HAS_DESCRIPTION", "PUBLISHED_ON"]
SEARCHABLE = ["ThreatActor", "Malware", "Vulnerability", "Indicator", "Technique", "Report", "Article"]
# Links taken from a source, as opposed to the statistical CO_OCCURS_WITH.
SOURCED = ["MENTIONS", "USES", "EXPLOITS", "HAS_HASH", "COMMUNICATES_WITH", "HAS_TYPE",
           "USES_TECHNIQUE", "HOSTED_ON", "MENTIONED_IN"]
IOC_TYPES = ["ipv4", "domain", "url", "email", "md5", "sha1", "sha256"]


def node(var: str) -> str:
    return NODE.replace("{v}", var)


# ------------------------------------------------------------------ overview
def stats() -> dict:
    nodes = run_read("MATCH (n:Entity) RETURN n.type AS type, count(*) AS count ORDER BY count DESC")
    rels = run_read("MATCH ()-[r]->() RETURN type(r) AS type, count(*) AS count ORDER BY count DESC")
    iocs = run_read("MATCH (i:Indicator) RETURN i.ioc_type AS type, count(*) AS count ORDER BY count DESC")
    return {
        "nodes": {r["type"]: r["count"] for r in nodes},
        "relationships": {r["type"]: r["count"] for r in rels},
        "indicators": {r["type"]: r["count"] for r in iocs},
    }


def search(q: str, types: list, limit: int) -> list:
    return run_read(
        "MATCH (n:Entity) WHERE n.type IN $types AND ("
        " toLower(n.name) CONTAINS $q"
        " OR (n.aliases IS NOT NULL AND toLower(n.aliases) CONTAINS $q)"
        " OR (n.title IS NOT NULL AND toLower(n.title) CONTAINS $q)"
        " OR (n.attack_id IS NOT NULL AND toLower(n.attack_id) = $q)) "
        "WITH n, CASE WHEN toLower(n.name) = $q OR toLower(coalesce(n.attack_id, '')) = $q THEN 0 "
        "             WHEN toLower(n.name) STARTS WITH $q THEN 1 "
        "             WHEN toLower(n.name) CONTAINS $q THEN 2 ELSE 3 END "
        "     + CASE WHEN n.type IN ['Indicator', 'Report', 'Article'] THEN 4 ELSE 0 END AS rank "
        "RETURN n.id AS id, n.type AS type, n.name AS name, n.title AS title, "
        "       coalesce(n.reports, 0) AS reports "
        "ORDER BY rank, reports DESC, name LIMIT $limit",
        {"q": q.lower(), "types": types, "limit": limit})


# ------------------------------------------------------------- any entity
def entity(entity_id: str) -> dict | None:
    rows = run_read("MATCH (n:Entity {id: $id}) RETURN properties(n) AS props", {"id": entity_id})
    if not rows:
        return None
    links = run_read(
        "MATCH (n:Entity {id: $id})-[r]-(m) "
        "RETURN type(r) AS relation, CASE WHEN startNode(r).id = n.id THEN 'out' ELSE 'in' END AS direction, "
        "       m.type AS type, count(*) AS count ORDER BY count DESC", {"id": entity_id})
    return {"entity": rows[0]["props"], "links": links}


def neighbors(entity_id: str, relations, types, direction: str, limit: int, offset: int) -> list:
    pattern = {"out": "(n)-[r]->(m)", "in": "(n)<-[r]-(m)", "both": "(n)-[r]-(m)"}[direction]
    return run_read(
        f"MATCH (n:Entity {{id: $id}}) MATCH {pattern} "
        "WHERE ($relations IS NULL OR type(r) IN $relations) AND ($types IS NULL OR m.type IN $types) "
        "RETURN type(r) AS relation, CASE WHEN startNode(r).id = n.id THEN 'out' ELSE 'in' END AS direction, "
        f"       properties(r) AS properties, {node('m')} AS node, coalesce(m.ioc_type, m.title) AS detail "
        "ORDER BY coalesce(r.count, r.reports, 0) DESC, node.name SKIP $offset LIMIT $limit",
        {"id": entity_id, "relations": relations, "types": types, "offset": offset, "limit": limit})


def resolve(label: str, prefix: str, name: str) -> str | None:
    """Exact id, then case-insensitive name, then alias."""
    rows = run_read(
        f"MATCH (n:{label}) WHERE n.id = $id OR toLower(n.name) = $lname "
        "   OR (n.attack_id IS NOT NULL AND toLower(n.attack_id) = $lname) "
        "   OR (n.aliases IS NOT NULL AND $lname IN [a IN split(toLower(n.aliases), '; ') | trim(a)]) "
        "RETURN n.id AS id, CASE WHEN n.id = $id THEN 0 WHEN toLower(n.name) = $lname THEN 1 ELSE 2 END AS rank "
        "ORDER BY rank, coalesce(n.reports, 0) DESC LIMIT 1",
        {"id": prefix + name, "lname": name.lower().strip()})
    return rows[0]["id"] if rows else None


# --------------------------------------------------------------- listings
_ORDER = {"reports": "coalesce(n.reports, 0) DESC, n.name", "name": "n.name", "mentions": "coalesce(n.mentions, 0) DESC, n.name"}


def list_actors(q, country, order, limit, offset) -> list:
    return run_read(
        "MATCH (n:ThreatActor) WHERE ($q IS NULL OR toLower(n.name) CONTAINS $q OR toLower(coalesce(n.aliases, '')) CONTAINS $q) "
        "  AND ($country IS NULL OR n.country = $country) "
        "OPTIONAL MATCH (n)-[:USES]->(m:Malware) "
        "WITH n, count(DISTINCT m) AS malware "
        f"RETURN n.id AS id, n.name AS name, n.attack_id AS attack_id, n.country AS country, n.aliases AS aliases, "
        f"       coalesce(n.reports, 0) AS reports, malware ORDER BY {_ORDER[order]} SKIP $offset LIMIT $limit",
        {"q": q, "country": country, "offset": offset, "limit": limit})


def list_malware(q, mtype, platform, feed, category, order, limit, offset) -> list:
    return run_read(
        "MATCH (n:Malware) WHERE ($q IS NULL OR toLower(n.name) CONTAINS $q OR toLower(coalesce(n.aliases, '')) CONTAINS $q) "
        "  AND ($type IS NULL OR $type IN coalesce(n.malware_types, [])) "
        "  AND ($platform IS NULL OR $platform IN coalesce(n.platforms, [])) "
        "  AND ($feed IS NULL OR $feed IN coalesce(n.feeds, [])) "
        "  AND ($category IS NULL OR n.category = $category) "
        f"RETURN n.id AS id, n.name AS name, n.attack_id AS attack_id, n.category AS category, "
        f"       coalesce(n.malware_types, []) AS types, coalesce(n.platforms, []) AS platforms, "
        f"       coalesce(n.feeds, []) AS feeds, coalesce(n.reports, 0) AS reports "
        f"ORDER BY {_ORDER[order]} SKIP $offset LIMIT $limit",
        {"q": q, "type": mtype, "platform": platform, "feed": feed, "category": category,
         "offset": offset, "limit": limit})


def list_vulnerabilities(q, year, order, limit, offset) -> list:
    return run_read(
        "MATCH (n:Vulnerability) WHERE ($q IS NULL OR toLower(n.name) CONTAINS $q) "
        "  AND ($year IS NULL OR n.name STARTS WITH ('CVE-' + $year + '-')) "
        "OPTIONAL MATCH (m:Malware)-[:EXPLOITS]->(n) "
        "WITH n, count(DISTINCT m) AS exploited_by "
        f"RETURN n.id AS id, n.name AS name, coalesce(n.reports, 0) AS reports, exploited_by "
        f"ORDER BY {_ORDER[order]} SKIP $offset LIMIT $limit",
        {"q": q, "year": year, "offset": offset, "limit": limit})


def list_indicators(q, ioc_type, min_reports, order, limit, offset) -> list:
    return run_read(
        "MATCH (n:Indicator) WHERE ($type IS NULL OR n.ioc_type = $type) "
        "  AND ($q IS NULL OR toLower(n.name) CONTAINS $q) AND coalesce(n.reports, 0) >= $min_reports "
        f"RETURN n.id AS id, n.name AS value, n.ioc_type AS type, coalesce(n.reports, 0) AS reports, "
        f"       n.virustotal_detections AS virustotal_detections "
        f"ORDER BY {_ORDER[order]} SKIP $offset LIMIT $limit",
        {"q": q, "type": ioc_type, "min_reports": min_reports, "offset": offset, "limit": limit})


def list_reports(q, year, source, limit, offset) -> list:
    return run_read(
        "MATCH (n:Report) WHERE ($q IS NULL OR toLower(n.title) CONTAINS $q OR toLower(n.name) CONTAINS $q) "
        "  AND ($year IS NULL OR n.year = $year) AND ($source IS NULL OR toLower(n.source) = $source) "
        "OPTIONAL MATCH (n)-[:MENTIONS]->(x) "
        "WITH n, count(x) AS entities "
        "RETURN n.id AS id, n.name AS name, n.title AS title, n.date AS date, n.year AS year, n.source AS source, "
        "       entities ORDER BY n.year DESC, n.title SKIP $offset LIMIT $limit",
        {"q": q, "year": year, "source": source, "offset": offset, "limit": limit})


def list_techniques(q, tactic, limit, offset) -> list:
    return run_read(
        "MATCH (n:Technique) WHERE ($q IS NULL OR toLower(n.name) CONTAINS $q OR toLower(n.attack_id) STARTS WITH $q) "
        "  AND ($tactic IS NULL OR $tactic IN coalesce(n.tactics, [])) "
        "OPTIONAL MATCH (m:Malware)-[:USES_TECHNIQUE]->(n) "
        "WITH n, count(m) AS malware "
        "RETURN n.id AS id, n.attack_id AS attack_id, n.name AS name, coalesce(n.tactics, []) AS tactics, malware "
        "ORDER BY malware DESC, n.attack_id SKIP $offset LIMIT $limit",
        {"q": q, "tactic": tactic, "offset": offset, "limit": limit})


# ---------------------------------------------------------------- profiles
def _reports_of(eid, limit=25):
    return run_read(
        "MATCH (r:Report)-[x:MENTIONS]->(:Entity {id: $id}) "
        "RETURN r.id AS id, r.title AS title, r.source AS source, r.year AS year, x.count AS mentions "
        "ORDER BY mentions DESC, r.year DESC LIMIT $limit", {"id": eid, "limit": limit})


def _news_of(eid, limit=20):
    return run_read(
        "MATCH (:Entity {id: $id})-[:MENTIONED_IN]->(a:Article) "
        "RETURN a.id AS id, a.title AS title, a.url AS url, a.published AS published, a.source AS source "
        "ORDER BY a.published DESC LIMIT $limit", {"id": eid, "limit": limit})


def _props(eid):
    rows = run_read("MATCH (n:Entity {id: $id}) RETURN properties(n) AS p", {"id": eid})
    return rows[0]["p"] if rows else None


def actor_profile(eid: str) -> dict:
    malware = run_read(
        "MATCH (:ThreatActor {id: $id})-[r:USES]->(m:Malware) "
        "RETURN m.id AS id, m.name AS name, coalesce(m.malware_types, []) AS types, r.origin AS origin "
        "ORDER BY m.name", {"id": eid})
    co = run_read(
        "MATCH (:ThreatActor {id: $id})-[r:CO_OCCURS_WITH]->(x) "
        f"RETURN {node('x')} AS node, r.reports AS reports ORDER BY reports DESC LIMIT 30", {"id": eid})
    cves = run_read(
        "MATCH (:ThreatActor {id: $id})-[:USES]->(m:Malware)-[:EXPLOITS]->(v:Vulnerability) "
        "RETURN v.name AS cve, collect(DISTINCT m.name) AS via ORDER BY cve", {"id": eid})
    techniques = run_read(
        "MATCH (:ThreatActor {id: $id})-[:USES]->(m:Malware)-[:USES_TECHNIQUE]->(t:Technique) "
        "RETURN t.attack_id AS attack_id, t.name AS name, coalesce(t.tactics, []) AS tactics, "
        "       count(DISTINCT m) AS malware ORDER BY malware DESC, attack_id", {"id": eid})
    return {"actor": _props(eid), "malware": malware, "cves": cves, "techniques": techniques,
            "co_occurs_with": co, "reports": _reports_of(eid), "news": _news_of(eid)}


def malware_profile(eid: str) -> dict:
    actors = run_read(
        "MATCH (a:ThreatActor)-[r:USES]->(:Malware {id: $id}) "
        "RETURN a.id AS id, a.name AS name, a.country AS country, r.origin AS origin ORDER BY a.name", {"id": eid})
    iocs = run_read(
        "MATCH (:Malware {id: $id})-[r:HAS_HASH|COMMUNICATES_WITH]->(i:Indicator) "
        "RETURN type(r) AS relation, i.ioc_type AS type, i.name AS value, r.origin AS origin, r.sample AS sample "
        "ORDER BY relation, type, value LIMIT 500", {"id": eid})
    cves = run_read(
        "MATCH (:Malware {id: $id})-[r:EXPLOITS|CO_OCCURS_WITH]->(v:Vulnerability) "
        "RETURN v.name AS cve, type(r) AS relation, r.origin AS origin, r.reports AS reports ORDER BY cve", {"id": eid})
    techniques = run_read(
        "MATCH (:Malware {id: $id})-[:USES_TECHNIQUE]->(t:Technique) "
        "RETURN t.attack_id AS attack_id, t.name AS name, coalesce(t.tactics, []) AS tactics ORDER BY attack_id",
        {"id": eid})
    similar = run_read(
        "MATCH (m:Malware {id: $id})-[:USES_TECHNIQUE]->(t:Technique)<-[:USES_TECHNIQUE]-(o:Malware) WHERE o.id <> m.id "
        "RETURN o.id AS id, o.name AS name, count(t) AS shared_techniques "
        "ORDER BY shared_techniques DESC, name LIMIT 10", {"id": eid})
    props = _props(eid)
    return {
        "malware": props, "types": (props or {}).get("malware_types", []),
        "platforms": (props or {}).get("platforms", []), "actors": actors,
        "hashes": [i for i in iocs if i["relation"] == "HAS_HASH"],
        "ips": [i for i in iocs if i["relation"] == "COMMUNICATES_WITH"],
        "cves": cves, "techniques": techniques, "similar": similar,
        "reports": _reports_of(eid), "news": _news_of(eid),
    }


def vulnerability_profile(eid: str) -> dict:
    exploited = run_read(
        "MATCH (m:Malware)-[r:EXPLOITS]->(:Vulnerability {id: $id}) "
        "RETURN m.id AS id, m.name AS name, r.origin AS origin ORDER BY name", {"id": eid})
    co = run_read(
        "MATCH (x)-[r:CO_OCCURS_WITH]->(:Vulnerability {id: $id}) "
        f"RETURN {node('x')} AS node, r.reports AS reports ORDER BY reports DESC LIMIT 30", {"id": eid})
    return {"vulnerability": _props(eid), "exploited_by": exploited, "co_occurs_with": co,
            "reports": _reports_of(eid), "news": _news_of(eid)}


def technique_profile(eid: str) -> dict:
    malware = run_read(
        "MATCH (m:Malware)-[:USES_TECHNIQUE]->(:Technique {id: $id}) "
        "OPTIONAL MATCH (a:ThreatActor)-[:USES]->(m) "
        "RETURN m.id AS id, m.name AS name, collect(DISTINCT a.name) AS actors ORDER BY name", {"id": eid})
    return {"technique": _props(eid), "malware": malware}


def report_profile(eid: str) -> dict:
    rows = run_read(
        "MATCH (:Report {id: $id})-[x:MENTIONS]->(e) "
        "RETURN e.type AS type, e.id AS id, e.name AS name, e.ioc_type AS ioc_type, x.count AS mentions "
        "ORDER BY mentions DESC, name", {"id": eid})
    grouped = {"ThreatActor": [], "Malware": [], "Vulnerability": [], "Indicator": []}
    for r in rows:
        item = {"id": r["id"], "name": r["name"], "mentions": r["mentions"]}
        if r["type"] == "Indicator":
            item["ioc_type"] = r["ioc_type"]
        grouped.setdefault(r["type"], []).append(item)
    return {"report": _props(eid), "threat_actors": grouped["ThreatActor"], "malware": grouped["Malware"],
            "vulnerabilities": grouped["Vulnerability"], "indicators": grouped["Indicator"]}


# -------------------------------------------------------------- indicators
_HEX = re.compile(r"^[0-9a-fA-F]+$")
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def indicator_id(value: str) -> str:
    """Guess the graph id of a raw indicator value."""
    v = value.strip()
    if _IPV4.match(v):
        return f"ipv4:{v}"
    if _HEX.match(v) and len(v) in (32, 40, 64):
        return {32: "md5", 40: "sha1", 64: "sha256"}[len(v)] + ":" + v.lower()
    if re.match(r"^(?:https?|ftp)://", v, re.I):
        return f"url:{v}"
    if "@" in v:
        return f"email:{v.lower()}"
    return f"domain:{v.lower().rstrip('.')}"


def lookup_indicators(values: list) -> list:
    ids = {indicator_id(v): v for v in values if v and v.strip()}
    rows = run_read(
        "UNWIND $ids AS iid MATCH (i:Indicator {id: iid}) "
        "OPTIONAL MATCH (m:Malware)-[:HAS_HASH|COMMUNICATES_WITH]->(i) "
        "OPTIONAL MATCH (a:ThreatActor)-[:USES]->(m) "
        "WITH i, collect(DISTINCT m.name) AS malware, collect(DISTINCT a.name) AS actors "
        "OPTIONAL MATCH (r:Report)-[:MENTIONS]->(i) "
        "WITH i, malware, actors, collect(DISTINCT {id: r.id, title: r.title, year: r.year}) AS reports "
        "OPTIONAL MATCH (i)-[:HOSTED_ON]->(h:Indicator) "
        "RETURN i.id AS id, i.name AS value, i.ioc_type AS type, coalesce(i.reports, 0) AS report_count, "
        "       i.virustotal_detections AS virustotal_detections, malware, actors, reports, "
        "       collect(DISTINCT h.name) AS hosted_on",
        {"ids": list(ids)})
    found = {r["id"]: r for r in rows}
    out = []
    for iid, raw in ids.items():
        r = found.get(iid)
        if r is None:
            out.append({"query": raw, "id": iid, "found": False})
            continue
        r["reports"] = [x for x in r["reports"] if x.get("id")]
        out.append({"query": raw, "found": True, **r})
    return out


# -------------------------------------------------------------------- news
def news(q, since, entity_id, limit, offset) -> list:
    start = "MATCH (:Entity {id: $entity})-[:MENTIONED_IN]->(a:Article) " if entity_id else "MATCH (a:Article) "
    return run_read(
        start +
        "WHERE ($since IS NULL OR a.published >= $since) AND ($q IS NULL OR toLower(a.title) CONTAINS $q) "
        "WITH DISTINCT a ORDER BY a.published DESC, a.title SKIP $offset LIMIT $limit "
        "OPTIONAL MATCH (a)-[:HAS_DESCRIPTION]->(d:Description) "
        "OPTIONAL MATCH (x)-[:MENTIONED_IN]->(a) "
        "WITH a, d, collect(DISTINCT {id: x.id, type: x.type, name: x.name}) AS mentions "
        "RETURN a.id AS id, a.title AS title, a.url AS url, a.published AS published, a.source AS source, "
        "       d.name AS description, mentions ORDER BY published DESC, title",
        {"q": q, "since": since, "entity": entity_id, "offset": offset, "limit": limit})


# -------------------------------------------------------------------- path
def path(a: str, b: str, max_hops: int, sourced_only: bool) -> dict | None:
    rels = (":" + "|".join(SOURCED)) if sourced_only else ""
    rows = run_read(
        "MATCH (a:Entity {id: $a}), (b:Entity {id: $b}) "
        f"MATCH p = shortestPath((a)-[{rels}*..{int(max_hops)}]-(b)) "
        f"RETURN [x IN nodes(p) | {node('x')}] AS nodes, "
        "       [r IN relationships(p) | {type: type(r), from: startNode(r).id, to: endNode(r).id}] AS relationships",
        {"a": a, "b": b})
    return rows[0] if rows else None


def exists(eid: str) -> bool:
    return bool(run_read("MATCH (n:Entity {id: $id}) RETURN n.id AS id", {"id": eid}))
