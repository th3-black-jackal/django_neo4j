"""Neo4j connection: one driver per process, read-only queries.

Settings (any of them can also come from the environment):

    NEO4J = {
        "URI": "bolt://localhost:7687",      # NEO4J_URI
        "USER": "neo4j",                     # NEO4J_USER
        "PASSWORD": "...",                   # NEO4J_PASSWORD
        "DATABASE": "neo4j",                 # NEO4J_DATABASE
        "QUERY_TIMEOUT": 15,                 # seconds, per query
    }
"""
from __future__ import annotations

import datetime
import os
import threading

from django.conf import settings

_driver = None
_lock = threading.Lock()
_runner = None   # tests swap in another engine with set_runner()


class GraphUnavailable(Exception):
    """Neo4j cannot be reached or refused the credentials."""


class GraphQueryError(Exception):
    """Neo4j rejected the query (syntax, unknown function, write in a read transaction ...)."""


def config() -> dict:
    cfg = dict(getattr(settings, "NEO4J", {}) or {})
    return {
        "URI": cfg.get("URI") or os.environ.get("NEO4J_URI", "bolt://localhost:7687"),
        "USER": cfg.get("USER") or os.environ.get("NEO4J_USER", "neo4j"),
        "PASSWORD": cfg.get("PASSWORD") or os.environ.get("NEO4J_PASSWORD", ""),
        "DATABASE": cfg.get("DATABASE") or os.environ.get("NEO4J_DATABASE", "neo4j"),
        "QUERY_TIMEOUT": float(cfg.get("QUERY_TIMEOUT") or os.environ.get("NEO4J_QUERY_TIMEOUT", 15)),
    }


def get_driver():
    global _driver
    if _driver is None:
        with _lock:
            if _driver is None:
                from neo4j import GraphDatabase

                cfg = config()
                _driver = GraphDatabase.driver(cfg["URI"], auth=(cfg["USER"], cfg["PASSWORD"]),
                                               connection_timeout=5, max_connection_pool_size=20)
    return _driver


def close():
    global _driver
    with _lock:
        if _driver is not None:
            _driver.close()
            _driver = None


def set_runner(fn):
    """Replace how queries are executed (used by the tests)."""
    global _runner
    _runner = fn


def _plain(value):
    """Driver values -> JSON-safe Python values."""
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, (datetime.date, datetime.datetime)):
        return value.isoformat()
    if hasattr(value, "iso_format"):          # neo4j.time.Date / DateTime
        return value.iso_format()
    if hasattr(value, "items"):               # neo4j Node / Relationship
        return {k: _plain(v) for k, v in value.items()}
    return str(value)


def run_read(query: str, params: dict | None = None) -> list:
    """Run a query in a READ transaction and return a list of row dicts.

    Neo4j refuses writes inside a read transaction, so even a bad query
    cannot change the graph through this function.
    """
    params = params or {}
    if _runner is not None:
        return [_plain(r) for r in _runner(query, params)]

    from neo4j import Query, RoutingControl
    from neo4j.exceptions import AuthError, ClientError, Neo4jError, ServiceUnavailable, SessionExpired

    cfg = config()
    try:
        records, _, _ = get_driver().execute_query(
            Query(query, timeout=cfg["QUERY_TIMEOUT"]), params,
            database_=cfg["DATABASE"], routing_=RoutingControl.READ)
    except (ServiceUnavailable, SessionExpired) as exc:
        raise GraphUnavailable(f"cannot reach Neo4j at {cfg['URI']}: {exc}") from exc
    except AuthError as exc:
        raise GraphUnavailable(f"Neo4j refused the credentials: {exc}") from exc
    except ClientError as exc:
        raise GraphQueryError(exc.message or str(exc)) from exc
    except Neo4jError as exc:
        raise GraphUnavailable(f"Neo4j error: {exc.message or exc}") from exc
    return [_plain(r.data()) for r in records]
