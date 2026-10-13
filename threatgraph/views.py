"""DRF views. Conventions follow the attack_rag API:
JSON in and out, `Authorization: Token ...`, errors as {"error": "..."},
400 bad input, 404 unknown entity, 502 when Neo4j is unreachable.
"""
from __future__ import annotations

import re

from rest_framework import status
from rest_framework.permissions import AllowAny, IsAdminUser, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from . import queries as Q
from . import service
from .neo4j import GraphQueryError, GraphUnavailable, run_read

MAX_LIMIT = 500
MAX_LOOKUP = 1000


class BadRequest(Exception):
    pass


class NotFound(Exception):
    pass


# ------------------------------------------------------------- parameters
def _int(request, name, default, lo, hi):
    raw = request.query_params.get(name)
    if raw in (None, ""):
        return default
    try:
        value = int(raw)
    except ValueError:
        raise BadRequest(f"'{name}' must be an integer")
    if not lo <= value <= hi:
        raise BadRequest(f"'{name}' must be between {lo} and {hi}")
    return value


def _str(request, name, lower=False, choices=None):
    raw = (request.query_params.get(name) or "").strip()
    if not raw:
        return None
    if lower:
        raw = raw.lower()
    if choices is not None and raw not in choices:
        raise BadRequest(f"'{name}' must be one of: {', '.join(choices)}")
    return raw


def _list(request, name, choices=None):
    """?type=A,B  or  ?type=A&type=B"""
    values = []
    for raw in request.query_params.getlist(name):
        values += [v.strip() for v in raw.split(",") if v.strip()]
    if not values:
        return None
    if choices is not None:
        bad = [v for v in values if v not in choices]
        if bad:
            raise BadRequest(f"unknown {name}: {', '.join(bad)}. Allowed: {', '.join(choices)}")
    return values


def _page(request):
    return _int(request, "limit", 50, 1, MAX_LIMIT), _int(request, "offset", 0, 0, 10_000_000)


def _listing(results, limit, offset):
    return {"results": results, "limit": limit, "offset": offset,
            "next_offset": offset + limit if len(results) == limit else None}


# ------------------------------------------------------------------- base
class GraphView(APIView):
    #permission_classes = [IsAuthenticated]

    def finalize_response(self, request, response, *args, **kwargs):
        response = super().finalize_response(request, response, *args, **kwargs)
        response["X-Service"] = service.header()   # which microservice answered
        return response

    def handle_exception(self, exc):
        if isinstance(exc, BadRequest):
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        if isinstance(exc, NotFound):
            return Response({"error": str(exc)}, status=status.HTTP_404_NOT_FOUND)
        if isinstance(exc, GraphUnavailable):
            return Response({"error": f"graph database unavailable: {exc}"}, status=status.HTTP_502_BAD_GATEWAY)
        if isinstance(exc, GraphQueryError):
            return Response({"error": f"graph query failed: {exc}"}, status=status.HTTP_502_BAD_GATEWAY)
        return super().handle_exception(exc)


def _resolve(label, prefix, name, kind):
    eid = Q.resolve(label, prefix, name)
    if not eid:
        raise NotFound(f"{kind} '{name}' not found")
    return eid


# ---------------------------------------------------------------- overview
class HealthView(GraphView):
    """Liveness/readiness probe for the gateway or orchestrator. No token needed."""

    #permission_classes = [AllowAny]
    #authentication_classes = []

    def get(self, request):
        body = {"service": service.service_id(), "version": service.version()}
        try:
            run_read("RETURN 1 AS ok")
        except (GraphUnavailable, GraphQueryError) as exc:
            return Response({**body, "status": "degraded", "neo4j": "down", "error": str(exc)},
                            status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response({**body, "status": "ok", "neo4j": "up"})


class StatsView(GraphView):
    def get(self, request):
        return Response(Q.stats())


class SchemaView(GraphView):
    def get(self, request):
        return Response({"labels": Q.LABELS, "relationships": Q.REL_TYPES, "indicator_types": Q.IOC_TYPES,
                         "searchable": Q.SEARCHABLE})


class SearchView(GraphView):
    def get(self, request):
        q = _str(request, "q")
        if not q or len(q) < 2:
            raise BadRequest("'q' is required (at least 2 characters)")
        types = _list(request, "type", Q.SEARCHABLE) or Q.SEARCHABLE
        limit = _int(request, "limit", 25, 1, 200)
        return Response({"results": Q.search(q, types, limit)})


# ---------------------------------------------------------- any entity by id
def _entity_id(request, entity_id):
    entity_id = entity_id or _str(request, "id")
    if not entity_id:
        raise BadRequest("'id' is required, e.g. ?id=malware:PlugX")
    return entity_id


class EntityView(GraphView):
    def get(self, request, entity_id=None):
        entity_id = _entity_id(request, entity_id)
        data = Q.entity(entity_id)
        if data is None:
            raise NotFound(f"entity '{entity_id}' not found")
        return Response(data)


class NeighborsView(GraphView):
    def get(self, request, entity_id=None):
        entity_id = _entity_id(request, entity_id)
        if not Q.exists(entity_id):
            raise NotFound(f"entity '{entity_id}' not found")
        limit, offset = _page(request)
        rows = Q.neighbors(entity_id, _list(request, "relation", Q.REL_TYPES), _list(request, "type", Q.LABELS),
                           _str(request, "direction", lower=True, choices=["in", "out", "both"]) or "both",
                           limit, offset)
        return Response(_listing(rows, limit, offset))


# ----------------------------------------------------------------- listings
_ORDERS = ["reports", "name", "mentions"]


class ActorListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        country = _str(request, "country")
        rows = Q.list_actors(_str(request, "q", lower=True), country.upper() if country else None,
                             _str(request, "order", choices=_ORDERS) or "reports", limit, offset)
        return Response(_listing(rows, limit, offset))


class ActorDetailView(GraphView):
    def get(self, request, name):
        return Response(Q.actor_profile(_resolve("ThreatActor", "actor:", name, "threat actor")))


class MalwareListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        rows = Q.list_malware(
            _str(request, "q", lower=True), _str(request, "type", lower=True), _str(request, "platform", lower=True),
            _str(request, "feed", lower=True), _str(request, "category", lower=True, choices=["malware", "tool"]),
            _str(request, "order", choices=_ORDERS) or "reports", limit, offset)
        return Response(_listing(rows, limit, offset))


class MalwareDetailView(GraphView):
    def get(self, request, name):
        return Response(Q.malware_profile(_resolve("Malware", "malware:", name, "malware")))


class VulnerabilityListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        year = _str(request, "year")
        if year and not re.fullmatch(r"(19|20)\d\d", year):
            raise BadRequest("'year' must look like 2017")
        rows = Q.list_vulnerabilities(_str(request, "q", lower=True), year,
                                      _str(request, "order", choices=_ORDERS) or "reports", limit, offset)
        return Response(_listing(rows, limit, offset))


class VulnerabilityDetailView(GraphView):
    def get(self, request, cve):
        cve = cve.upper()
        if not re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve):
            raise BadRequest("expected a CVE id such as CVE-2017-0144")
        if not Q.exists(f"cve:{cve}"):
            raise NotFound(f"{cve} is not in the graph")
        return Response(Q.vulnerability_profile(f"cve:{cve}"))


class IndicatorListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        rows = Q.list_indicators(_str(request, "q", lower=True), _str(request, "type", lower=True, choices=Q.IOC_TYPES),
                                 _int(request, "min_reports", 0, 0, 100_000),
                                 _str(request, "order", choices=_ORDERS) or "reports", limit, offset)
        return Response(_listing(rows, limit, offset))


class IndicatorLookupView(GraphView):
    """GET ?value=x (one) or POST {"values": [...]} (up to 1000)."""

    def get(self, request):
        value = _str(request, "value")
        if not value:
            raise BadRequest("'value' is required")
        return Response(Q.lookup_indicators([value])[0])

    def post(self, request):
        values = request.data.get("values") if isinstance(request.data, dict) else None
        if not isinstance(values, list) or not values or not all(isinstance(v, str) for v in values):
            raise BadRequest("body must be {\"values\": [\"<ip, domain, url, email or hash>\", ...]}")
        if len(values) > MAX_LOOKUP:
            raise BadRequest(f"at most {MAX_LOOKUP} values per request")
        results = Q.lookup_indicators(values)
        return Response({"results": results, "found": sum(r["found"] for r in results)})


class ReportListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        rows = Q.list_reports(_str(request, "q", lower=True), _str(request, "year"),
                              _str(request, "source", lower=True), limit, offset)
        return Response(_listing(rows, limit, offset))


class ReportDetailView(GraphView):
    def get(self, request, name):
        eid = name if name.startswith("report:") else f"report:{name}"
        if not Q.exists(eid):
            raise NotFound(f"report '{name}' not found")
        return Response(Q.report_profile(eid))


class TechniqueListView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        rows = Q.list_techniques(_str(request, "q", lower=True), _str(request, "tactic", lower=True), limit, offset)
        return Response(_listing(rows, limit, offset))


class TechniqueDetailView(GraphView):
    def get(self, request, attack_id):
        attack_id = attack_id.upper()
        if not re.fullmatch(r"T\d{4}(?:\.\d{3})?", attack_id):
            raise BadRequest("expected an ATT&CK technique id such as T1059 or T1059.001")
        eid = f"technique:{attack_id}"
        if not Q.exists(eid):
            raise NotFound(f"{attack_id} is not in the graph")
        return Response(Q.technique_profile(eid))


class NewsView(GraphView):
    def get(self, request):
        limit, offset = _page(request)
        since = _str(request, "since")
        if since and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", since):
            raise BadRequest("'since' must be a date like 2026-10-01")
        rows = Q.news(_str(request, "q", lower=True), since, _str(request, "entity"), limit, offset)
        return Response(_listing(rows, limit, offset))


class PathView(GraphView):
    def get(self, request):
        a, b = _str(request, "from"), _str(request, "to")
        if not a or not b:
            raise BadRequest("'from' and 'to' entity ids are required")
        for eid in (a, b):
            if not Q.exists(eid):
                raise NotFound(f"entity '{eid}' not found")
        hops = _int(request, "max_hops", 4, 1, 6)
        sourced = (request.query_params.get("sourced_only", "false").lower() in ("1", "true", "yes"))
        found = Q.path(a, b, hops, sourced)
        if not found:
            return Response({"found": False, "nodes": [], "relationships": []})
        return Response({"found": True, **found})


# ---------------------------------------------------------------- raw Cypher
_WRITE = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b|\bCALL\s+(dbms|db\.create|apoc)",
                     re.I)
MAX_ROWS = 1000


class CypherView(GraphView):
    """Read-only Cypher for administrators. Writes are refused twice: by this
    check, and by Neo4j itself because the query runs in a read transaction."""

    #permission_classes = [IsAdminUser]

    def post(self, request):
        data = request.data if isinstance(request.data, dict) else {}
        query, params = data.get("query"), data.get("params") or {}
        if not isinstance(query, str) or not query.strip():
            raise BadRequest("field 'query' is required")
        if not isinstance(params, dict):
            raise BadRequest("'params' must be an object")
        if _WRITE.search(re.sub(r"(['\"]).*?\1", "", query)):
            raise BadRequest("only read queries are allowed")
        try:
            rows = run_read(query, params)
        except GraphQueryError as exc:
            raise BadRequest(f"query rejected by Neo4j: {exc}")
        return Response({"rows": rows[:MAX_ROWS], "truncated": len(rows) > MAX_ROWS})
