"""Service identity, for running behind an API gateway with other microservices.

Every URL of this app starts with  api/<SERVICE_ID>/<VERSION>/  (default
api/cti-graph/v1/), and every response carries an X-Service header, so a
gateway can route and trace requests without ambiguity. Override in settings:

    THREATGRAPH = {"SERVICE_ID": "cti-graph", "VERSION": "v1"}
"""
from django.conf import settings


def _cfg() -> dict:
    return getattr(settings, "THREATGRAPH", {}) or {}


def service_id() -> str:
    return _cfg().get("SERVICE_ID", "cti-graph")


def version() -> str:
    return _cfg().get("VERSION", "v1")


def prefix() -> str:
    """URL prefix without a leading slash, e.g. "api/cti-graph/v1/"."""
    return f"api/{service_id()}/{version()}/"


def header() -> str:
    return f"{service_id()}/{version()}"
