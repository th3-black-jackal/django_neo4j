"""URL routes of the threat-graph service.

Mount in the project urls.py with the service prefix (api/cti-graph/v1/ by default):

    from threatgraph.urls import mount
    urlpatterns = [..., mount()]

Route names are namespaced by the service id, e.g. reverse("cti-graph:malware", args=["PlugX"]).
"""
from django.urls import include, path

from . import service
from . import views as v

app_name = "threatgraph"

urlpatterns = [
    path("health/", v.HealthView.as_view(), name="health"),
    path("stats/", v.StatsView.as_view(), name="stats"),
    path("schema/", v.SchemaView.as_view(), name="schema"),
    path("search/", v.SearchView.as_view(), name="search"),
    path("path/", v.PathView.as_view(), name="path"),
    path("query/", v.CypherView.as_view(), name="query"),

    path("actors/", v.ActorListView.as_view(), name="actors"),
    path("actors/<path:name>/", v.ActorDetailView.as_view(), name="actor"),
    path("malware/", v.MalwareListView.as_view(), name="malware-list"),
    path("malware/<path:name>/", v.MalwareDetailView.as_view(), name="malware"),
    path("vulnerabilities/", v.VulnerabilityListView.as_view(), name="vulnerabilities"),
    path("vulnerabilities/<str:cve>/", v.VulnerabilityDetailView.as_view(), name="vulnerability"),
    path("indicators/", v.IndicatorListView.as_view(), name="indicators"),
    path("indicators/lookup/", v.IndicatorLookupView.as_view(), name="indicator-lookup"),
    path("reports/", v.ReportListView.as_view(), name="reports"),
    path("reports/<path:name>/", v.ReportDetailView.as_view(), name="report"),
    path("techniques/", v.TechniqueListView.as_view(), name="techniques"),
    path("techniques/<str:attack_id>/", v.TechniqueDetailView.as_view(), name="technique"),
    path("news/", v.NewsView.as_view(), name="news"),

    # Any node by its graph id. Preferred: ?id=<id> (safe for URL indicators, whose ids contain
    # "//"); the path form /entities/ipv4:1.2.3.4/ also works for simple ids.
    path("entities/", v.EntityView.as_view(), name="entity-by-param"),
    path("entities/neighbors/", v.NeighborsView.as_view(), name="neighbors-by-param"),
    path("entities/<path:entity_id>/neighbors/", v.NeighborsView.as_view(), name="neighbors"),
    path("entities/<path:entity_id>/", v.EntityView.as_view(), name="entity"),
]


def mount():
    """path("api/<service>/<version>/", ...) for the project's urlpatterns."""
    return path(service.prefix(), include((urlpatterns, app_name), namespace=service.service_id()))
