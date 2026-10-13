"""API tests against an embedded Cypher engine (FalkorDBLite), so no Neo4j
server is needed:   pip install falkordblite   then   python manage.py test threatgraph

The tests build a small graph with the same labels, ids and relationships the
ctikg pipeline writes, then call every endpoint through DRF's test client.
"""
import tempfile
import unittest

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from . import neo4j as graph

BASE = "/api/cti-graph/v1/"

try:
    from redislite.falkordb_client import FalkorDB
except ImportError:  # pragma: no cover
    FalkorDB = None

SEED = """
CREATE (r1:Entity:Report {id:'report:DEEP_PANDA_Sakula', type:'Report', name:'DEEP_PANDA_Sakula', title:'Deep Panda Uses Sakula', year:'2014', date:'07/01/2014', source:'CrowdStrike'}),
       (r2:Entity:Report {id:'report:Other', type:'Report', name:'Other', title:'Another report', year:'2015', source:'FireEye'}),
       (a:Entity:ThreatActor {id:'actor:Deep Panda', type:'ThreatActor', name:'Deep Panda', aliases:'Shell Crew; Black Vine; KungFu Kittens', attack_id:'G0009', country:'CN', reports:2, mentions:20}),
       (a2:Entity:ThreatActor {id:'actor:APT17', type:'ThreatActor', name:'APT17', aliases:'Deputy Dog', reports:1, mentions:2}),
       (m:Entity:Malware {id:'malware:Sakula', type:'Malware', name:'Sakula', aliases:'Sakurel; VIPER', attack_id:'S0074', category:'malware', platforms:['windows'], malware_types:['rat','trojan'], feeds:['mitre-attack','virustotal'], reports:2, mentions:12}),
       (m2:Entity:Malware {id:'malware:PlugX', type:'Malware', name:'PlugX', attack_id:'S0013', category:'malware', platforms:['windows'], malware_types:['rat'], feeds:['mitre-attack'], reports:1, mentions:3}),
       (v:Entity:Vulnerability {id:'cve:CVE-2014-0322', type:'Vulnerability', name:'CVE-2014-0322', reports:1, mentions:2}),
       (ip:Entity:Indicator {id:'ipv4:180.210.206.246', type:'Indicator', name:'180.210.206.246', ioc_type:'ipv4', reports:2, mentions:3}),
       (h:Entity:Indicator {id:'md5:ae6f33f6cdc25dc4bda24b2bccff79fe', type:'Indicator', name:'ae6f33f6cdc25dc4bda24b2bccff79fe', ioc_type:'md5', reports:1, mentions:1, virustotal_detections:55}),
       (u:Entity:Indicator {id:'url:http://evil.example.com/a/b.php', type:'Indicator', name:'http://evil.example.com/a/b.php', ioc_type:'url', reports:1, mentions:1}),
       (d:Entity:Indicator {id:'domain:evil.example.com', type:'Indicator', name:'evil.example.com', ioc_type:'domain', reports:1, mentions:1}),
       (t1:Entity:Technique {id:'technique:T1059', type:'Technique', name:'Command and Scripting Interpreter', attack_id:'T1059', tactics:['execution']}),
       (t2:Entity:Technique {id:'technique:T1071', type:'Technique', name:'Application Layer Protocol', attack_id:'T1071', tactics:['command-and-control']}),
       (mt:Entity:MalwareType {id:'malwaretype:rat', type:'MalwareType', name:'rat'}),
       (art:Entity:Article {id:'article:abc', type:'Article', name:'Sakula malware resurfaces', title:'Sakula malware resurfaces', url:'https://blog.example.net/sakula', published:'2026-10-07', source:'Blog'}),
       (url:Entity:Url {id:'link:https://blog.example.net/sakula', type:'Url', name:'https://blog.example.net/sakula'}),
       (desc:Entity:Description {id:'description:abc', type:'Description', name:'A fresh Sakula sample.'}),
       (day:Entity:Date {id:'date:2026-10-07', type:'Date', name:'2026-10-07'}),
       (r1)-[:MENTIONS {count:10, origin:'report'}]->(a), (r1)-[:MENTIONS {count:9, origin:'report'}]->(m),
       (r1)-[:MENTIONS {count:1, origin:'report'}]->(v), (r1)-[:MENTIONS {count:2, origin:'report'}]->(ip),
       (r1)-[:MENTIONS {count:1, origin:'report'}]->(h), (r2)-[:MENTIONS {count:2, origin:'report'}]->(ip),
       (r2)-[:MENTIONS {count:3, origin:'report'}]->(a), (r2)-[:MENTIONS {count:1, origin:'report'}]->(u),
       (u)-[:HOSTED_ON {origin:'url'}]->(d),
       (a)-[:USES {origin:'mitre-attack'}]->(m), (a2)-[:USES {origin:'mitre-attack'}]->(m2), (a)-[:USES {origin:'mitre-attack'}]->(m2),
       (a)-[:CO_OCCURS_WITH {reports:1, origin:'co-occurrence'}]->(v),
       (m)-[:EXPLOITS {origin:'virustotal', sample:'aaa'}]->(v),
       (m)-[:HAS_HASH {origin:'virustotal', sample:'aaa'}]->(h), (m)-[:COMMUNICATES_WITH {origin:'virustotal', sample:'aaa'}]->(ip),
       (m)-[:HAS_TYPE {origin:'virustotal'}]->(mt), (m2)-[:HAS_TYPE {origin:'mitre-attack'}]->(mt),
       (m)-[:USES_TECHNIQUE {origin:'mitre-attack'}]->(t1), (m)-[:USES_TECHNIQUE {origin:'mitre-attack'}]->(t2),
       (m2)-[:USES_TECHNIQUE {origin:'mitre-attack'}]->(t1),
       (m)-[:MENTIONED_IN {origin:'news'}]->(art), (a)-[:MENTIONED_IN {origin:'news'}]->(art),
       (art)-[:HAS_URL]->(url), (art)-[:HAS_DESCRIPTION]->(desc), (art)-[:PUBLISHED_ON]->(day)
"""


@unittest.skipIf(FalkorDB is None, "pip install falkordblite to run the API tests without Neo4j")
class GraphApiTests(TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._dir = tempfile.TemporaryDirectory()
        db = FalkorDB(f"{cls._dir.name}/graph.db")
        cls.g = db.select_graph("test")
        cls.g.query(SEED)

        def run(query, params):
            res = cls.g.query(query, params)
            cols = [h[1] for h in (res.header or [])]
            return [dict(zip(cols, row)) for row in (res.result_set or [])]

        graph.set_runner(run)

    @classmethod
    def tearDownClass(cls):
        graph.set_runner(None)
        cls._dir.cleanup()
        super().tearDownClass()

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user("analyst", password="x")
        self.admin = User.objects.create_user("admin", password="x", is_staff=True)
        self.api = APIClient()
        self.api.force_authenticate(self.user)

    def get(self, url, **params):
        return self.api.get(BASE + url, params)

    # ------------------------------------------------------------ basics
    def test_service_prefix_header_and_names(self):
        from django.urls import reverse
        self.assertEqual(reverse("cti-graph:malware", args=["PlugX"]), BASE + "malware/PlugX/")
        res = self.get("stats/")
        self.assertEqual(res["X-Service"], "cti-graph/v1")
        self.assertEqual(APIClient().get("/api/graph/stats/").status_code, 404)

    def test_health_needs_no_token(self):
        res = APIClient().get(BASE + "health/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data, {"service": "cti-graph", "version": "v1", "status": "ok", "neo4j": "up"})

    def test_requires_authentication(self):
        res = APIClient().get(BASE + "stats/")
        self.assertIn(res.status_code, (401, 403))

    def test_stats_and_schema(self):
        res = self.get("stats/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["nodes"]["Malware"], 2)
        self.assertEqual(res.data["relationships"]["MENTIONS"], 8)
        self.assertEqual(res.data["indicators"]["ipv4"], 1)
        self.assertIn("Technique", self.get("schema/").data["labels"])

    def test_search(self):
        res = self.get("search/", q="black vine")
        self.assertEqual(res.data["results"][0]["id"], "actor:Deep Panda")
        res = self.get("search/", q="s0013")
        self.assertEqual(res.data["results"][0]["name"], "PlugX")
        res = self.get("search/", q="sak", type="Malware")
        self.assertEqual([r["name"] for r in res.data["results"]], ["Sakula"])
        self.assertEqual(self.get("search/", q="x").status_code, 400)
        self.assertEqual(self.get("search/", q="sak", type="Nope").status_code, 400)

    # ------------------------------------------------------ any entity
    def test_entity_and_neighbors(self):
        res = self.get("entities/malware:Sakula/")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["entity"]["attack_id"], "S0074")
        rels = {(l["relation"], l["direction"]) for l in res.data["links"]}
        self.assertIn(("USES", "in"), rels)
        self.assertIn(("HAS_HASH", "out"), rels)

        res = self.get("entities/", id="url:http://evil.example.com/a/b.php")
        self.assertEqual(res.data["entity"]["ioc_type"], "url")

        res = self.get("entities/malware:Sakula/neighbors/", relation="USES_TECHNIQUE", direction="out")
        self.assertEqual(sorted(r["node"]["name"] for r in res.data["results"]),
                         ["Application Layer Protocol", "Command and Scripting Interpreter"])
        res = self.get("entities/neighbors/", id="actor:Deep Panda", type="Report", limit=1)
        self.assertEqual(res.data["results"][0]["properties"]["count"], 10)
        self.assertEqual(res.data["next_offset"], 1)
        self.assertEqual(self.get("entities/malware:Nope/").status_code, 404)
        self.assertEqual(self.get("entities/malware:Sakula/neighbors/", direction="up").status_code, 400)

    # -------------------------------------------------------- listings
    def test_lists(self):
        res = self.get("actors/", country="cn")
        self.assertEqual([r["name"] for r in res.data["results"]], ["Deep Panda"])
        self.assertEqual(res.data["results"][0]["malware"], 2)
        res = self.get("malware/", type="rat", platform="windows", order="name")
        self.assertEqual([r["name"] for r in res.data["results"]], ["PlugX", "Sakula"])
        res = self.get("malware/", feed="virustotal")
        self.assertEqual([r["name"] for r in res.data["results"]], ["Sakula"])
        res = self.get("vulnerabilities/", year="2014")
        self.assertEqual(res.data["results"][0]["exploited_by"], 1)
        res = self.get("indicators/", type="ipv4", min_reports=2)
        self.assertEqual(res.data["results"][0]["value"], "180.210.206.246")
        res = self.get("reports/", year="2014")
        self.assertEqual(res.data["results"][0]["entities"], 5)
        res = self.get("techniques/", tactic="execution")
        self.assertEqual(res.data["results"][0]["malware"], 2)
        self.assertEqual(self.get("malware/", limit=0).status_code, 400)
        self.assertEqual(self.get("actors/", order="age").status_code, 400)

    # -------------------------------------------------------- profiles
    def test_actor_profile(self):
        res = self.get("actors/kungfu kittens/")      # by alias
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.data["actor"]["name"], "Deep Panda")
        self.assertEqual([m["name"] for m in res.data["malware"]], ["PlugX", "Sakula"])
        self.assertEqual(res.data["cves"][0]["cve"], "CVE-2014-0322")
        self.assertEqual(res.data["techniques"][0]["attack_id"], "T1059")
        self.assertEqual(res.data["reports"][0]["mentions"], 10)
        self.assertEqual(res.data["news"][0]["published"], "2026-10-07")
        self.assertEqual(self.get("actors/G0009/").data["actor"]["name"], "Deep Panda")
        self.assertEqual(self.get("actors/nobody/").status_code, 404)

    def test_malware_profile(self):
        res = self.get("malware/sakurel/")
        self.assertEqual(res.data["malware"]["name"], "Sakula")
        self.assertEqual(res.data["types"], ["rat", "trojan"])
        self.assertEqual(res.data["hashes"][0]["value"], "ae6f33f6cdc25dc4bda24b2bccff79fe")
        self.assertEqual(res.data["ips"][0]["value"], "180.210.206.246")
        self.assertEqual(res.data["actors"][0]["name"], "Deep Panda")
        self.assertEqual(res.data["similar"][0], {"id": "malware:PlugX", "name": "PlugX", "shared_techniques": 1})

    def test_vulnerability_technique_report(self):
        res = self.get("vulnerabilities/cve-2014-0322/")
        self.assertEqual(res.data["exploited_by"][0]["name"], "Sakula")
        self.assertEqual(res.data["co_occurs_with"][0]["node"]["name"], "Deep Panda")
        self.assertEqual(self.get("vulnerabilities/CVE-2099-0001/").status_code, 404)
        self.assertEqual(self.get("vulnerabilities/not-a-cve/").status_code, 400)
        res = self.get("techniques/t1059/")
        self.assertEqual(sorted(m["name"] for m in res.data["malware"]), ["PlugX", "Sakula"])
        res = self.get("reports/DEEP_PANDA_Sakula/")
        self.assertEqual(res.data["threat_actors"][0]["name"], "Deep Panda")
        self.assertEqual(len(res.data["indicators"]), 2)

    # ------------------------------------------------------ indicators
    def test_indicator_lookup(self):
        res = self.get("indicators/lookup/", value="180.210.206.246")
        self.assertTrue(res.data["found"])
        self.assertEqual(res.data["malware"], ["Sakula"])
        self.assertEqual(res.data["actors"], ["Deep Panda"])
        self.assertEqual(len(res.data["reports"]), 2)
        res = self.api.post(BASE + "indicators/lookup/", {"values": [
            "AE6F33F6CDC25DC4BDA24B2BCCFF79FE", "http://evil.example.com/a/b.php", "10.0.0.1"]}, format="json")
        self.assertEqual(res.data["found"], 2)
        by = {r["query"]: r for r in res.data["results"]}
        self.assertEqual(by["AE6F33F6CDC25DC4BDA24B2BCCFF79FE"]["virustotal_detections"], 55)
        self.assertEqual(by["http://evil.example.com/a/b.php"]["hosted_on"], ["evil.example.com"])
        self.assertFalse(by["10.0.0.1"]["found"])
        bad = self.api.post(BASE + "indicators/lookup/", {"values": "x"}, format="json")
        self.assertEqual(bad.status_code, 400)

    # ----------------------------------------------------------- news
    def test_news(self):
        res = self.get("news/", since="2026-10-01")
        art = res.data["results"][0]
        self.assertEqual(art["description"], "A fresh Sakula sample.")
        self.assertEqual(sorted(m["name"] for m in art["mentions"]), ["Deep Panda", "Sakula"])
        self.assertEqual(len(self.get("news/", entity="malware:PlugX").data["results"]), 0)
        self.assertEqual(len(self.get("news/", since="2026-10-08").data["results"]), 0)
        self.assertEqual(self.get("news/", since="yesterday").status_code, 400)

    # ------------------------------------------------------ raw Cypher
    def test_cypher_is_admin_only_and_read_only(self):
        body = {"query": "MATCH (n:Malware) RETURN n.name AS name ORDER BY name"}
        self.assertEqual(self.api.post(BASE + "query/", body, format="json").status_code, 403)
        self.api.force_authenticate(self.admin)
        res = self.api.post(BASE + "query/", body, format="json")
        self.assertEqual(res.data["rows"], [{"name": "PlugX"}, {"name": "Sakula"}])
        res = self.api.post(BASE + "query/", {"query": "MATCH (n) DETACH DELETE n"}, format="json")
        self.assertEqual(res.status_code, 400)
        res = self.api.post(BASE + "query/", {"query": "MATCH (n) WHERE n.name = 'SET' RETURN count(n) AS c"},
                            format="json")
        self.assertEqual(res.status_code, 200)

    # ----------------------------------------------------- unavailable
    def test_neo4j_down_gives_502(self):
        def down(query, params):
            raise graph.GraphUnavailable("connection refused")
        graph.set_runner(down)
        try:
            res = self.get("stats/")
            health = APIClient().get(BASE + "health/")
        finally:
            graph.set_runner(self._runner_backup())
        self.assertEqual(res.status_code, 502)
        self.assertIn("unavailable", res.data["error"])
        self.assertEqual(health.status_code, 503)
        self.assertEqual(health.data["neo4j"], "down")

    def _runner_backup(self):
        g = self.g

        def run(query, params):
            res = g.query(query, params)
            cols = [h[1] for h in (res.header or [])]
            return [dict(zip(cols, row)) for row in (res.result_set or [])]
        return run
