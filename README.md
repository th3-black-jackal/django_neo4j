# threatgraph: Django REST API for the Neo4j threat graph

* `threatgraph/` is the Django app (the `cti-graph` microservice, mounted at `/api/cti-graph/v1/`) to copy into the backend next to `attack_rag/`.
* `GRAPH_API_DOCUMENTATION.md` documents every endpoint and the setup steps (section 7).
* `demo/` and `manage.py` are a minimal project used only to run the tests:

```bash
pip install django djangorestframework "neo4j>=5.20" falkordblite
python manage.py test threatgraph
```
