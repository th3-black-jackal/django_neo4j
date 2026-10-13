"""Stage 2: extracted JSON -> knowledge graph, exports, HTML view and queries.

Node types   Report, ThreatActor, Malware, Vulnerability, Indicator
Edge types   MENTIONS        Report -> anything found in it (count = mentions)
             USES            ThreatActor -> Malware, from MITRE ATT&CK
             CO_OCCURS_WITH  ThreatActor/Malware/Vulnerability pairs that are
                             main subjects of the same report (reports = how many)
             HOSTED_ON       URL indicator -> its domain / IP indicator
"""
from __future__ import annotations

import csv
import itertools
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import urlsplit

import networkx as nx

from .kb import load_kb

COLORS = {
    "Report": "#8a8f98",
    "ThreatActor": "#d1495b",
    "Malware": "#edae49",
    "Vulnerability": "#00798c",
    "Indicator": "#66a182",
}
TOP_K = {"ThreatActor": 3, "Malware": 8, "Vulnerability": 10}  # per report, for CO_OCCURS_WITH
NODE_FIELDS = ["id", "type", "name", "ioc_type", "category", "attack_id", "country", "aliases",
               "title", "date", "year", "source", "file", "reports", "mentions"]
EDGE_FIELDS = ["source", "target", "type", "count", "reports", "origin"]


_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def load_records(out_dir: Path) -> list:
    ext = Path(out_dir) / "extracted"
    manifest = ext / "manifest.json"
    if manifest.exists():
        files = [ext / f"{s}.json" for s in json.loads(manifest.read_text())]
    else:
        files = sorted(p for p in ext.glob("*.json") if p.name != "manifest.json")
    recs = []
    for f in files:
        if f.exists():
            rec = json.loads(f.read_text(encoding="utf-8"))
            if rec.get("status") != "error":
                recs.append(rec)
    if not recs:
        raise SystemExit(f"No extracted reports in {ext}. Run the extract step first.")
    return recs


def build_graph(records, min_mentions=1, salient=3, min_cooccur=1, kb_edges=True) -> nx.MultiDiGraph:
    kb = load_kb()
    ents = kb["entities"]
    g = nx.MultiDiGraph()
    node_of = {}                      # kb entity id -> node id
    pair_reports = defaultdict(set)   # (node a, node b) -> report ids

    def touch(node, rid, count, **attrs):
        if node not in g:
            g.add_node(node, reports=0, mentions=0, **attrs)
        g.nodes[node]["reports"] += 1
        g.nodes[node]["mentions"] += count
        g.add_edge(rid, node, key="MENTIONS", type="MENTIONS", count=count, origin="report")

    for rec in records:
        rid = "report:" + rec["report_id"]
        if rid in g:  # two different files with the same name
            rid += "#" + rec["sha1"][:8]
        g.add_node(rid, type="Report", name=rec["report_id"], title=rec.get("title", ""),
                   date=rec.get("date", ""), year=str(rec.get("year", "")),
                   source=rec.get("source", ""), file=rec.get("file", ""))
        prominent = []
        for kind, label in (("threat_actors", "ThreatActor"), ("malware", "Malware")):
            top = 0
            for e in rec.get(kind, []):  # already sorted by mention count
                if e["count"] < min_mentions:
                    continue
                ent = ents[e["id"]]
                node = ("actor:" if label == "ThreatActor" else "malware:") + ent["name"]
                node_of[e["id"]] = node
                touch(node, rid, e["count"], type=label, name=ent["name"],
                      aliases="; ".join(ent.get("aliases", [])[:25]),
                      attack_id=ent.get("attack_id") or "", category=ent.get("category") or "",
                      country=ent.get("country") or "")
                # Only a report's main subjects are linked to each other, so a
                # yearly round-up that names 40 groups does not connect them all.
                if e["count"] >= salient and top < TOP_K[label]:
                    prominent.append(node)
                    top += 1
        for n, c in enumerate(rec.get("cves", [])):
            node = "cve:" + c["value"]
            touch(node, rid, c["count"], type="Vulnerability", name=c["value"])
            if n < TOP_K["Vulnerability"]:
                prominent.append(node)
        for i in rec.get("iocs", []):
            node = f"{i['type']}:{i['value']}"
            touch(node, rid, i["count"], type="Indicator", name=i["value"], ioc_type=i["type"])
            if i["type"] == "url":
                host = (urlsplit(i["value"]).hostname or "").lower()
                for target in (f"domain:{host}", f"ipv4:{host}"):
                    if target in g and not g.has_edge(node, target, "HOSTED_ON"):
                        g.add_edge(node, target, key="HOSTED_ON", type="HOSTED_ON", origin="url")
        for a, b in itertools.combinations(sorted(set(prominent)), 2):
            if g.nodes[a]["type"] != g.nodes[b]["type"]:
                pair_reports[(a, b)].add(rid)

    # Entity-to-entity links backed by reports
    rank = {"ThreatActor": 0, "Malware": 1, "Vulnerability": 2}
    for (a, b), rids in pair_reports.items():
        if len(rids) < min_cooccur:
            continue
        a, b = sorted((a, b), key=lambda n: rank[g.nodes[n]["type"]])
        g.add_edge(a, b, key="CO_OCCURS_WITH", type="CO_OCCURS_WITH", reports=len(rids), origin="co-occurrence")

    # Curated links from MITRE ATT&CK, only between nodes that are in the graph
    if kb_edges:
        for s, rel, t in kb["relations"]:
            if s in node_of and t in node_of:
                g.add_edge(node_of[s], node_of[t], key=rel, type=rel, origin="mitre-attack")
    return g


# ------------------------------------------------------------------- exports
def export(g: nx.MultiDiGraph, out_dir: Path) -> dict:
    out = Path(out_dir) / "graph"
    out.mkdir(parents=True, exist_ok=True)
    for _, d in g.nodes(data=True):  # belt and braces for XML/CSV consumers
        for k, v in d.items():
            if isinstance(v, str):
                d[k] = _UNSAFE.sub(" ", v)

    with open(out / "nodes.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=NODE_FIELDS, extrasaction="ignore")
        w.writeheader()
        for n, d in g.nodes(data=True):
            w.writerow({"id": n, **d})
    with open(out / "edges.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=EDGE_FIELDS, extrasaction="ignore")
        w.writeheader()
        for u, v, d in g.edges(data=True):
            w.writerow({"source": u, "target": v, **d})

    (out / "neo4j_import.cypher").write_text(_CYPHER, encoding="utf-8")
    summary = summarize(g)
    (out / "summary.json").write_text(json.dumps(summary, indent=1, ensure_ascii=False), encoding="utf-8")

    # The two optional formats must never stop the others from being written.
    for name, writer in (
        ("graph.json", lambda p: p.write_text(
            json.dumps(nx.node_link_data(g, edges="edges"), ensure_ascii=False), encoding="utf-8")),
        ("graph.graphml", lambda p: nx.write_graphml(g, p)),
    ):
        try:
            writer(out / name)
        except Exception as exc:
            (out / name).unlink(missing_ok=True)  # no half-written file
            print(f"  warning: could not write {name}: {type(exc).__name__}: {exc}")
    return summary


def summarize(g, top=15) -> dict:
    types = Counter(d["type"] for _, d in g.nodes(data=True))
    ioc_types = Counter(d["ioc_type"] for _, d in g.nodes(data=True) if d["type"] == "Indicator")
    edges = Counter(d["type"] for _, _, d in g.edges(data=True))

    def ranked(t):
        rows = [(d["name"], d["reports"], d["mentions"]) for _, d in g.nodes(data=True) if d["type"] == t]
        rows.sort(key=lambda r: (-r[1], -r[2], r[0]))
        return [{"name": n, "reports": r, "mentions": m} for n, r, m in rows[:top]]

    shared = [(d["name"], d["ioc_type"], d["reports"]) for _, d in g.nodes(data=True)
              if d["type"] == "Indicator" and d["reports"] > 1]
    shared.sort(key=lambda r: (-r[2], r[0]))
    return {
        "nodes": dict(types), "indicators": dict(ioc_types), "edges": dict(edges),
        "top_threat_actors": ranked("ThreatActor"), "top_malware": ranked("Malware"),
        "top_cves": ranked("Vulnerability"),
        "indicators_shared_between_reports": [{"value": v, "type": t, "reports": r} for v, t, r in shared[:top]],
    }


_CYPHER = """// Neo4j import. Copy nodes.csv and edges.csv into Neo4j's import/ folder,
// then run this file (cypher-shell -f neo4j_import.cypher or paste in Browser).
CREATE CONSTRAINT IF NOT EXISTS FOR (n:Entity) REQUIRE n.id IS UNIQUE;

LOAD CSV WITH HEADERS FROM 'file:///nodes.csv' AS row
MERGE (n:Entity {id: row.id})
SET n += row, n.reports = toInteger(row.reports), n.mentions = toInteger(row.mentions);

MATCH (n:Entity {type: 'Report'}) SET n:Report;
MATCH (n:Entity {type: 'ThreatActor'}) SET n:ThreatActor;
MATCH (n:Entity {type: 'Malware'}) SET n:Malware;
MATCH (n:Entity {type: 'Vulnerability'}) SET n:Vulnerability;
MATCH (n:Entity {type: 'Indicator'}) SET n:Indicator;

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.type = 'MENTIONS'
MATCH (a:Entity {id: row.source}), (b:Entity {id: row.target})
MERGE (a)-[r:MENTIONS]->(b) SET r.count = toInteger(row.count);

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.type = 'USES'
MATCH (a:Entity {id: row.source}), (b:Entity {id: row.target})
MERGE (a)-[r:USES]->(b) SET r.origin = row.origin;

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.type = 'CO_OCCURS_WITH'
MATCH (a:Entity {id: row.source}), (b:Entity {id: row.target})
MERGE (a)-[r:CO_OCCURS_WITH]->(b) SET r.reports = toInteger(row.reports);

LOAD CSV WITH HEADERS FROM 'file:///edges.csv' AS row
WITH row WHERE row.type = 'HOSTED_ON'
MATCH (a:Entity {id: row.source}), (b:Entity {id: row.target})
MERGE (a)-[:HOSTED_ON]->(b);
"""


# ------------------------------------------------------------- visualisation
def _viz_nodes(g, max_nodes: int) -> set:
    """Pick what to draw: a browser cannot lay out tens of thousands of IoCs."""
    keep = set(g.nodes)
    if len(keep) <= max_nodes:
        return keep
    # 1. indicators seen in a single report are the bulk and the least connective
    keep = {n for n in keep if g.nodes[n]["type"] != "Indicator" or g.nodes[n]["reports"] > 1}
    if len(keep) <= max_nodes:
        return keep
    # 2. then keep the most connected nodes, always keeping reports' main entities
    order = sorted(keep, key=lambda n: (g.nodes[n]["type"] == "Indicator", -g.degree(n)))
    return set(order[:max_nodes])


def write_html(g, out_dir: Path, max_nodes=1500) -> tuple:
    from pyvis.network import Network

    keep = _viz_nodes(g, max_nodes)
    sub = g.subgraph(keep)
    net = Network(height="100vh", width="100%", directed=True, bgcolor="#14161a",
                  font_color="#e6e6e6", cdn_resources="in_line", notebook=False)
    for n, d in sub.nodes(data=True):
        t = d["type"]
        label = d["name"] if t != "Report" else (d.get("title") or d["name"])
        if len(label) > 42:
            label = label[:40] + "…"
        tip = [f"{t}: {d.get('title') or d['name']}"]
        if t == "Report":
            tip += [x for x in (d.get("source"), d.get("date") or d.get("year")) if x]
        else:
            tip.append(f"in {d['reports']} report(s), {d['mentions']} mention(s)")
            for k in ("ioc_type", "attack_id", "country", "aliases"):
                if d.get(k):
                    tip.append(f"{k}: {d[k][:200]}")
        size = 8 if t == "Indicator" else min(40, 10 + 3 * sub.degree(n) ** 0.5)
        net.add_node(n, label=label, title="\n".join(tip), color=COLORS[t], size=size,
                     shape="square" if t == "Report" else "dot",
                     font={"size": 0 if t == "Indicator" else 14})
    for u, v, d in sub.edges(data=True):
        t = d["type"]
        if t == "MENTIONS":
            net.add_edge(u, v, color="#3a3f47", width=1, title=f"MENTIONS x{d.get('count', 1)}")
        elif t == "USES":
            net.add_edge(u, v, color="#d1495b", width=3, title="USES (MITRE ATT&CK)")
        elif t == "CO_OCCURS_WITH":
            net.add_edge(u, v, color="#7f6fb0", width=1 + d.get("reports", 1), dashes=True,
                         title=f"CO_OCCURS_WITH in {d.get('reports', 1)} report(s)")
        else:
            net.add_edge(u, v, color="#66a182", width=1, title=t)
    net.set_options(json.dumps({
        "physics": {"solver": "forceAtlas2Based", "stabilization": {"iterations": 150},
                    "forceAtlas2Based": {"gravitationalConstant": -60, "springLength": 90}},
        "interaction": {"hover": True, "tooltipDelay": 120, "navigationButtons": False},
        "edges": {"smooth": False, "arrows": {"to": {"scaleFactor": 0.4}}},
    }))
    path = Path(out_dir) / "graph" / "graph.html"
    html = net.generate_html()
    legend = "".join(
        f'<span style="margin-right:14px"><span style="color:{c}">&#9679;</span> {t}</span>' for t, c in COLORS.items()
    )
    note = f"showing {len(keep)} of {g.number_of_nodes()} nodes" if len(keep) < g.number_of_nodes() else f"{len(keep)} nodes"
    bar = (f'<div style="position:fixed;top:0;left:0;right:0;z-index:9;padding:6px 12px;'
           f'font:13px sans-serif;background:#1d2026;color:#e6e6e6">{legend}'
           f'<span style="opacity:.6">{note} &middot; hover for details, scroll to zoom</span></div>')
    html = html.replace("<body>", "<body style='margin:0;background:#14161a'>" + bar, 1)
    path.write_text(html, encoding="utf-8")
    return path, len(keep)


# -------------------------------------------------------------------- query
def query(out_dir: Path, term: str, limit=25) -> str:
    path = Path(out_dir) / "graph" / "graph.json"
    if not path.exists():
        raise SystemExit("No graph yet. Run the build step first.")
    g = nx.node_link_graph(json.loads(path.read_text(encoding="utf-8")), edges="edges")
    t = term.lower()

    def score(n, d):
        name = str(d.get("name", "")).lower()
        if name == t or n.lower() == t:
            return 0
        if t in [a.strip().lower() for a in d.get("aliases", "").split(";")]:
            return 1
        if t in name or t in str(d.get("title", "")).lower():
            return 2
        return None

    hits = sorted(((score(n, d), -g.degree(n), n) for n, d in g.nodes(data=True) if score(n, d) is not None))
    if not hits:
        return f"Nothing in the graph matches '{term}'."
    node = hits[0][2]
    d = g.nodes[node]
    lines = [f"{d['type']}: {d.get('title') or d['name']}"]
    for k in ("attack_id", "country", "aliases", "source", "date", "reports", "mentions"):
        if d.get(k):
            lines.append(f"  {k}: {d[k]}")
    groups = defaultdict(list)
    for u, v, e in itertools.chain(g.out_edges(node, data=True), g.in_edges(node, data=True)):
        other = v if u == node else u
        od = g.nodes[other]
        arrow = "->" if u == node else "<-"
        kind = od.get("ioc_type") or od["type"]
        weight = e.get("count") or e.get("reports") or 0
        groups[(e["type"], arrow, kind)].append((weight, od.get("title") or od["name"]))
    order = {"USES": 0, "CO_OCCURS_WITH": 1, "MENTIONS": 2, "HOSTED_ON": 3}
    for (etype, arrow, kind), items in sorted(groups.items(), key=lambda kv: (order.get(kv[0][0], 9), kv[0])):
        items.sort(key=lambda x: (-x[0], x[1]))
        lines.append(f"\n{arrow} {etype} {kind} ({len(items)})")
        for w, name in items[:limit]:
            lines.append(f"   {name}" + (f"  [{w}]" if w else ""))
        if len(items) > limit:
            lines.append(f"   ... {len(items) - limit} more")
    if len(hits) > 1:
        others = ", ".join(g.nodes[h[2]]["name"] for h in hits[1:6])
        lines.append(f"\nOther matches: {others}")
    return "\n".join(lines)
