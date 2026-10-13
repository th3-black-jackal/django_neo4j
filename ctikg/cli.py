"""Command line:  python -m ctikg {run,extract,build,query,neo4j-load,feed,update-kb}"""
from __future__ import annotations

import argparse
from pathlib import Path


def _print_summary(s: dict, html, shown):
    print("\nKnowledge graph")
    print("  nodes: " + ", ".join(f"{v} {k}" for k, v in s["nodes"].items()))
    if s["indicators"]:
        print("  indicators: " + ", ".join(f"{v} {k}" for k, v in sorted(s["indicators"].items())))
    print("  edges: " + ", ".join(f"{v} {k}" for k, v in s["edges"].items()))
    for title, key in (("Threat actors", "top_threat_actors"), ("Malware", "top_malware"), ("CVEs", "top_cves")):
        rows = s[key][:8]
        if rows:
            print(f"  top {title.lower()}: " + ", ".join(f"{r['name']} ({r['reports']})" for r in rows))
    print(f"\nWrote {html.parent}/  (nodes.csv, edges.csv, graph.graphml, graph.json, neo4j_import.cypher, summary.json)")
    print(f"Open {html} in a browser ({shown} nodes drawn).")


def _build(args):
    from .graph import build_graph, export, load_records, write_html

    out = Path(args.out)
    g = build_graph(load_records(out), min_mentions=args.min_mentions, salient=args.salient,
                    min_cooccur=args.min_cooccur, kb_edges=not args.no_attack_edges)
    summary = export(g, out)
    html, shown = write_html(g, out, max_nodes=args.viz_max_nodes)
    _print_summary(summary, html, shown)


def _extract(args):
    from .extract import run_extract

    run_extract(args.reports, args.out, workers=args.workers, force=args.force, keep_private=args.keep_private_ips)


def _neo4j_load(args):
    from .store import GraphStore

    store = GraphStore.neo4j(args.uri, args.user, args.password)
    n = store.load_csv(Path(args.out) / "graph")
    store.close()
    print(f"Loaded {n['nodes']} nodes and {n['edges']} relationships into Neo4j.")


def _feed(args):
    from .feeds import get_feed
    from .feeds.virustotal import QuotaExceeded
    from .store import GraphStore

    store = GraphStore.neo4j(args.uri, args.user, args.password)
    store.ensure_schema()
    feed = get_feed(args.feed, cache_dir=Path(args.out) / "feeds" / args.feed, rate=args.rate,
                    min_detections=args.min_detections, want_actors=args.vt_actors, refresh=args.refresh,
                    domain=args.domain, techniques=not args.no_techniques)
    catalogue = args.feed == "mitre"   # a catalogue is browsed by name, not looked up by hash
    if args.limit is None:
        args.limit = 0 if catalogue else 50

    hashes = list(args.hashes)
    if args.hashes_file:
        hashes += [line.split()[0] for line in Path(args.hashes_file).read_text().splitlines()
                   if line.strip() and not line.startswith("#")]
    if args.from_graph:
        hashes += store.malware_names() if catalogue else store.pending_hashes(args.limit, args.feed)
    if not hashes and not args.search and not catalogue:
        raise SystemExit("Nothing to do. Give hashes, --hashes-file FILE, --from-graph, or --search.")

    done = {"malware": 0, "clean": 0, "unknown": 0, "linked": 0, "created": 0}

    def write(rec):
        if rec.engines and rec.detections < args.min_detections:
            done["clean"] += 1
            store.mark_checked(rec.hashes.values(), rec.source, rec.detections)
            print(f"  {rec.sample[:16]}…  {rec.detections}/{rec.engines} detections, below --min-detections: not added")
            return
        res = store.upsert_malware(rec, attack_actors=not args.no_attack_actors, dry_run=args.dry_run)
        done["malware"] += 1
        done["linked"] += len(res["linked_existing"])
        done["created"] += len(res["created"])
        state = "existing" if res["malware_existed"] else "new"
        if not rec.sample:   # catalogue entry: one line each, there can be hundreds
            print(f"  {rec.attack_id or '-':6} {res['malware'][:28]:28} ({state})  type={','.join(rec.types) or '?':18} "
                  f"actors={len(rec.actors):<3} techniques={len(rec.techniques):<3} cves={len(rec.cves):<2} "
                  f"linked {len(res['linked_existing'])}, created {len(res['created'])}")
            return
        print(f"  {rec.sample[:16]}…  {res['malware']} ({state} malware)  "
              f"type={','.join(rec.types) or '?'}  platform={','.join(rec.platforms) or '?'}  "
              f"{rec.detections}/{rec.engines} detections")
        print(f"      linked to {len(res['linked_existing'])} existing node(s), created {len(res['created'])}")
        for node in res["linked_existing"][:8]:
            print(f"        = {node}")

    try:
        if catalogue:
            scope = f"{len(hashes)} named entries" if hashes else "all software"
            print(f"Loading MITRE ATT&CK: {scope}" + (f" for {args.platform}" if args.platform else "") + " ...")
            for rec in feed.search(platform=args.platform, limit=args.limit, names=hashes or None):
                write(rec)
        elif args.search:
            print(f"Searching {args.feed} for recent {args.platform or 'any-platform'} malware ...")
            for rec in feed.search(platform=args.platform, limit=args.limit, days=args.days, query=args.query):
                write(rec)
        else:
            hashes = list(dict.fromkeys(hashes))[: args.limit]
            print(f"Looking up {len(hashes)} hash(es) on {args.feed} ...")
            for h, rec in feed.lookup(hashes, platform=args.platform):
                if rec is None:
                    done["unknown"] += 1
                    store.mark_checked([h], args.feed)
                    print(f"  {h[:16]}…  not known to {args.feed}")
                else:
                    write(rec)
    except QuotaExceeded as exc:
        print(f"Stopped: {exc}. Everything fetched so far is saved; run the same command again later.")
    finally:
        store.close()
    if catalogue and not done["malware"]:
        print("  No ATT&CK software matched. Check the name, alias or id, and the --platform filter.")
    print(f"\n{'Would add' if args.dry_run else 'Added or updated'} {done['malware']} malware record(s): "
          f"{done['linked']} link(s) to existing nodes, {done['created']} new node(s). "
          f"{done['clean']} below the detection threshold, {done['unknown']} unknown. "
          f"{feed.requests} API request(s) used.")


def _news(args):
    from .news import collect
    from .store import GraphStore

    store = GraphStore.neo4j(args.uri, args.user, args.password)
    store.ensure_schema()
    print("Reading news feeds ...")
    articles = collect(args.rss or None, since_days=args.since)
    added = links = created = skipped = 0
    for art in articles:
        res = store.upsert_article(art, only_existing=args.only_existing, dry_run=args.dry_run)
        if not res["entities"]:
            skipped += 1
            continue
        added += 1
        links += len(res["entities"])
        created += len(res["new_entities"])
        names = ", ".join(i.split(":", 1)[1] + ("*" if i in res["new_entities"] else "") for i in res["entities"])
        print(f"  {art.date or '----------'}  {art.title[:70]:70}  -> {names}")
    store.close()
    scope = "already in the graph" if args.only_existing else "known"
    print(f"\n{'Would add' if args.dry_run else 'Added or updated'} {added} article(s) with {links} mention link(s); "
          f"{created} mentioned entit(ies) were new to the graph (marked *). "
          f"{skipped} article(s) mention nothing {scope} and were left out.")


def main(argv=None):
    p = argparse.ArgumentParser(prog="ctikg", description="APT report PDFs -> cyber knowledge graph")
    sub = p.add_subparsers(dest="cmd", required=True)

    def extract_opts(sp):
        sp.add_argument("reports", help="folder with the downloaded reports (searched recursively)")
        sp.add_argument("-o", "--out", default="out", help="output folder (default: out)")
        sp.add_argument("-j", "--workers", type=int, default=2, help="parallel processes (default: 2)")
        sp.add_argument("--force", action="store_true", help="re-extract reports that are already cached")
        sp.add_argument("--keep-private-ips", action="store_true", help="keep RFC1918/loopback addresses")

    def build_opts(sp):
        sp.add_argument("--min-mentions", type=int, default=1,
                        help="ignore an actor/malware named fewer than N times in a report (default: 1)")
        sp.add_argument("--salient", type=int, default=3,
                        help="mentions needed for an actor/malware to take part in CO_OCCURS_WITH (default: 3)")
        sp.add_argument("--min-cooccur", type=int, default=1,
                        help="reports a pair must share to get a CO_OCCURS_WITH edge (default: 1)")
        sp.add_argument("--no-attack-edges", action="store_true", help="skip actor-USES-malware edges from MITRE ATT&CK")
        sp.add_argument("--viz-max-nodes", type=int, default=1500, help="node cap for graph.html (default: 1500)")

    sp = sub.add_parser("run", help="extract + build in one go")
    extract_opts(sp)
    build_opts(sp)
    sp = sub.add_parser("extract", help="PDFs -> out/extracted/*.json")
    extract_opts(sp)
    sp = sub.add_parser("build", help="out/extracted -> out/graph")
    sp.add_argument("-o", "--out", default="out")
    build_opts(sp)
    sp = sub.add_parser("query", help="show what the graph knows about a name, CVE or indicator")
    sp.add_argument("term")
    sp.add_argument("-o", "--out", default="out")
    sp.add_argument("-n", "--limit", type=int, default=25)
    def neo4j_opts(sp):
        sp.add_argument("--uri", help="Neo4j address (default: $NEO4J_URI or bolt://localhost:7687)")
        sp.add_argument("--user", help="default: $NEO4J_USER or neo4j")
        sp.add_argument("--password", help="default: $NEO4J_PASSWORD")

    sp = sub.add_parser("neo4j-load", help="load out/graph into Neo4j (no import folder or cypher file needed)")
    sp.add_argument("-o", "--out", default="out")
    neo4j_opts(sp)

    sp = sub.add_parser("feed", help="enrich the Neo4j graph with malware data from an external feed")
    sp.add_argument("feed", choices=["virustotal", "mitre"])
    sp.add_argument("hashes", nargs="*", metavar="item",
                    help="virustotal: md5 / sha1 / sha256 values. mitre: software names or ATT&CK ids (default: all)")
    sp.add_argument("--hashes-file", help="text file with one hash per line")
    sp.add_argument("--from-graph", action="store_true",
                    help="virustotal: look up hash indicators already in Neo4j. mitre: only malware already in Neo4j")
    sp.add_argument("--domain", choices=["enterprise", "mobile", "ics"],
                    help="mitre: ATT&CK matrix (default: enterprise, or mobile for android/ios)")
    sp.add_argument("--no-techniques", action="store_true", help="mitre: skip ATT&CK technique nodes")
    sp.add_argument("--search", action="store_true", help="search the feed for recent malware (VirusTotal: premium key)")
    sp.add_argument("--platform", choices=["windows", "linux", "macos", "android", "ios"],
                    help="only malware for this platform")
    sp.add_argument("--limit", type=int, help="maximum entries this run (default: 50 for virustotal, all for mitre)")
    sp.add_argument("--min-detections", type=int, default=5,
                    help="engines that must flag a file before it counts as malware (default: 5)")
    sp.add_argument("--days", type=int, default=7, help="--search: first seen within N days (default: 7)")
    sp.add_argument("--query", help="--search: your own VirusTotal Intelligence query")
    sp.add_argument("--rate", type=float, default=4, help="API requests per minute (default: 4, the free limit)")
    sp.add_argument("--vt-actors", action="store_true",
                    help="also ask VirusTotal for related threat actors (needs VT Enterprise)")
    sp.add_argument("--no-attack-actors", action="store_true",
                    help="do not add actors that MITRE ATT&CK lists as users of the family")
    sp.add_argument("--refresh", action="store_true", help="ignore cached feed answers")
    sp.add_argument("--dry-run", action="store_true", help="show what would be written, change nothing")
    sp.add_argument("-o", "--out", default="out", help="folder for the feed cache (default: out)")
    neo4j_opts(sp)

    sp = sub.add_parser("news", help="link malware, actors and CVEs to news articles that mention them")
    sp.add_argument("--rss", action="append", metavar="URL",
                    help="feed URL or local file; repeatable (default: the list in ctikg/data/news_feeds.txt)")
    sp.add_argument("--since", type=int, metavar="DAYS", help="ignore articles older than this")
    sp.add_argument("--only-existing", action="store_true",
                    help="link only malware, actors and CVEs that are already in Neo4j")
    sp.add_argument("--dry-run", action="store_true", help="show what would be written, change nothing")
    neo4j_opts(sp)

    sub.add_parser("update-kb", help="refresh actor/malware names from MITRE ATT&CK and MISP (needs internet)")

    args = p.parse_args(argv)
    if args.cmd == "update-kb":
        from .kb import build_kb

        kb = build_kb()
        n = {t: sum(e["type"] == t for e in kb["entities"]) for t in ("actor", "malware")}
        print(f"Knowledge base updated: {n['actor']} threat actors, {n['malware']} malware/tools, "
              f"{len(kb['relations'])} ATT&CK 'uses' links.")
    elif args.cmd == "extract":
        _extract(args)
    elif args.cmd == "build":
        _build(args)
    elif args.cmd == "run":
        _extract(args)
        _build(args)
    elif args.cmd == "neo4j-load":
        _neo4j_load(args)
    elif args.cmd == "news":
        _news(args)
    elif args.cmd == "feed":
        _feed(args)
    elif args.cmd == "query":
        from .graph import query

        print(query(Path(args.out), args.term, args.limit))


if __name__ == "__main__":
    main()
