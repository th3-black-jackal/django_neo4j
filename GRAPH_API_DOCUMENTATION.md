# Threat Graph API — Documentation (Qt/QML client)

REST API over the cyber threat-intelligence knowledge graph in Neo4j (threat actors, malware,
CVEs, indicators, ATT&CK techniques, reports and news). It is the `cti-graph` microservice,
served by the `threatgraph` Django app, and follows the same conventions as `attack_rag`.
The graph model itself is described in `SCHEMA.md`.

All endpoints are **read-only**. The graph is filled by the `ctikg` command-line tools
(`neo4j-load`, `feed`, `news`), not through this API.

---

## 1. Conventions

| Item | Value |
|------|-------|
| Base URL | `http://<gateway-or-backend-host>:8000` |
| API root | `/api/cti-graph/v1/` (service id + version, see §1.1) |
| Method | `GET` everywhere, except the bulk indicator lookup and the admin query (`POST`, JSON body) |
| Response body | `application/json`, UTF-8 |
| Authentication | `Authorization: Token <your-token>` (same token as `/api/attack/`) |
| Lists | `?limit=` (default 50, max 500) and `?offset=`; see §3.1 |
| Multi-value filters | comma-separated or repeated: `?type=Malware,ThreatActor` or `?type=Malware&type=ThreatActor` |

### 1.1 Service identity

Every path starts with `/api/<service-id>/<version>/`, here `/api/cti-graph/v1/`, so an API
gateway can route on the second path segment and no route collides with another service.

| Part | Default | Set in Django settings |
|------|---------|------------------------|
| service id | `cti-graph` | `THREATGRAPH["SERVICE_ID"]` |
| version | `v1` | `THREATGRAPH["VERSION"]` |

Every response, including errors, carries the header `X-Service: cti-graph/v1`, so logs and
traces show which service answered. Route names are namespaced by the service id
(`reverse("cti-graph:malware", args=["PlugX"])`).

A breaking change to the API gets a new version (`v2`) mounted beside `v1`, so the desktop app
and other services can move over one at a time.

### 1.2 Entity ids

Every node has a unique `id` made of a prefix and its name. Ids appear in every response and
can be passed back to `/entities/`, `/news/?entity=` and `/path/`.

| Kind | `id` looks like |
|------|-----------------|
| Threat actor | `actor:APT28` |
| Malware | `malware:PlugX` |
| Vulnerability | `cve:CVE-2017-0144` |
| Indicator | `ipv4:1.2.3.4`, `domain:evil.com`, `url:http://evil.com/a`, `email:x@y.com`, `md5:…`, `sha1:…`, `sha256:…` |
| ATT&CK technique | `technique:T1059.001` |
| Malware type | `malwaretype:ransomware` |
| Report | `report:Mandiant_APT1_Report` |
| News article | `article:3c9e6d76376b8f40` |

Ids contain spaces, colons and, for URL indicators, slashes. Always URL-encode them, and prefer
the query-parameter form (`/entities/?id=…`) over the path form.

---

## 2. Errors

Same shape as the chat API: a JSON body with an `error` string.

| Status | Body | Cause |
|--------|------|-------|
| 400 | `{"error": "'limit' must be between 1 and 500"}` | invalid parameter (message names it) |
| 401 | — | missing or invalid token |
| 403 | — | `/query/` called by a non-admin user |
| 404 | `{"error": "malware 'Foo' not found"}` | unknown actor, malware, CVE, technique, report or id |
| 502 | `{"error": "graph database unavailable: ..."}` | Neo4j down, unreachable or wrong credentials |

---

## 3. Data models

### 3.1 List envelope

Every list endpoint returns:

```json
{
  "results": [ ... ],
  "limit": 50,
  "offset": 0,
  "next_offset": 50
}
```

`next_offset` is `null` on the last page. To page, repeat the request with `offset=next_offset`.

### 3.2 Node reference

Used wherever a response points at another node:

```json
{"id": "malware:PlugX", "type": "Malware", "name": "PlugX"}
```

`type` is one of `ThreatActor`, `Malware`, `Vulnerability`, `Indicator`, `Technique`,
`MalwareType`, `Report`, `Article`, `Url`, `Description`, `Date`.

### 3.3 Provenance (`origin`)

Links carry an `origin` saying where they came from, which matters when showing them to an
analyst:

| `origin` | Meaning |
|----------|---------|
| `mitre-attack` | curated by MITRE ATT&CK |
| `virustotal` | from VirusTotal sample data |
| `report` | found in a threat-intelligence PDF report |
| `co-occurrence` | discussed together in reports; a hint, not attribution |
| `news` | named in a news article |

---

## 4. Endpoints

### 4.1 Overview

#### `GET /api/cti-graph/v1/health/`

Liveness and readiness probe for the gateway or orchestrator. **No token needed.**

```json
{"service": "cti-graph", "version": "v1", "status": "ok", "neo4j": "up"}
```

When Neo4j cannot be reached it answers **503** with `"status": "degraded", "neo4j": "down"`
and an `error` message, so the gateway can take the instance out of rotation.

#### `GET /api/cti-graph/v1/stats/`

Counts of nodes, relationships and indicators. Good for a dashboard header.

```json
{
  "nodes": {"Indicator": 9723, "Malware": 857, "Technique": 490, "ThreatActor": 185, "Report": 136, "Vulnerability": 112},
  "relationships": {"MENTIONS": 10922, "USES_TECHNIQUE": 10191, "USES": 1011, "CO_OCCURS_WITH": 837},
  "indicators": {"md5": 4176, "domain": 2758, "ipv4": 1052, "url": 629}
}
```

#### `GET /api/cti-graph/v1/schema/`

Labels, relationship types and indicator types, for building filter drop-downs.

#### `GET /api/cti-graph/v1/search/?q=<text>`

Global search box. Matches names, aliases, report titles and ATT&CK ids (`S0013`, `G0007`).
Actors, malware, CVEs and techniques rank above indicators, reports and articles.

| Param | Required | Meaning |
|-------|----------|---------|
| `q` | yes | at least 2 characters, case-insensitive |
| `type` | no | restrict to labels, e.g. `ThreatActor,Malware` |
| `limit` | no | default 25, max 200 |

```json
{
  "results": [
    {"id": "actor:Deep Panda", "type": "ThreatActor", "name": "Deep Panda", "title": null, "reports": 6},
    {"id": "actor:APT1", "type": "ThreatActor", "name": "APT1", "title": null, "reports": 9}
  ]
}
```

### 4.2 Threat actors

#### `GET /api/cti-graph/v1/actors/`

| Param | Meaning |
|-------|---------|
| `q` | text in name or aliases |
| `country` | two-letter code, e.g. `CN`, `RU`, `KP` |
| `order` | `reports` (default), `name`, `mentions` |
| `limit`, `offset` | paging |

```json
{
  "results": [
    {"id": "actor:APT1", "name": "APT1", "attack_id": "G0006", "country": "CN",
     "aliases": "Comment Crew; Comment Group; Comment Panda; PLA Unit 61398", "reports": 9, "malware": 14}
  ],
  "limit": 50, "offset": 0, "next_offset": null
}
```

`aliases` is one string separated by `; `. `malware` is how many malware families the actor uses.

#### `GET /api/cti-graph/v1/actors/<name>/`

Full actor profile. `<name>` can be the name, any alias or the ATT&CK id (`apt28`,
`fancy bear`, `G0007`), case-insensitive.

```json
{
  "actor": {"id": "actor:APT28", "name": "APT28", "attack_id": "G0007", "country": "RU", "aliases": "...", "reports": 6},
  "malware": [{"id": "malware:CHOPSTICK", "name": "CHOPSTICK", "types": ["backdoor"], "origin": "mitre-attack"}],
  "cves": [{"cve": "CVE-2015-1701", "via": ["CHOPSTICK"]}],
  "techniques": [{"attack_id": "T1071.001", "name": "Web Protocols", "tactics": ["command-and-control"], "malware": 9}],
  "co_occurs_with": [{"node": {"id": "cve:CVE-2014-4114", "type": "Vulnerability", "name": "CVE-2014-4114"}, "reports": 2}],
  "reports": [{"id": "report:...", "title": "...", "source": "FireEye", "year": "2014", "mentions": 31}],
  "news": [{"id": "article:...", "title": "...", "url": "https://...", "published": "2026-10-10", "source": "..."}]
}
```

`cves` and `techniques` are reached through the actor's malware. `techniques[].malware` is how
many of its families use that technique.

### 4.3 Malware

#### `GET /api/cti-graph/v1/malware/`

| Param | Meaning |
|-------|---------|
| `q` | text in name or aliases |
| `type` | e.g. `ransomware`, `rat`, `backdoor`, `rootkit`, `wiper` |
| `platform` | `windows`, `linux`, `macos`, `android`, `ios` |
| `feed` | `virustotal` or `mitre-attack` |
| `category` | `malware` or `tool` |
| `order` | `reports` (default), `name`, `mentions` |
| `limit`, `offset` | paging |

```json
{
  "results": [
    {"id": "malware:Akira", "name": "Akira", "attack_id": "S1129", "category": "malware",
     "types": ["ransomware"], "platforms": ["windows"], "feeds": ["mitre-attack"], "reports": 0}
  ],
  "limit": 50, "offset": 0, "next_offset": null
}
```

#### `GET /api/cti-graph/v1/malware/<name>/`

Full malware profile; `<name>` is a name, alias or ATT&CK id.

```json
{
  "malware": {"id": "malware:WannaCry", "name": "WannaCry", "attack_id": "S0366", "category": "malware",
              "aliases": "WanaCry; WanaCrypt; WCry; WannaCryptor", "description": "WannaCry is ransomware ...",
              "feeds": ["mitre-attack", "virustotal"], "url": "https://attack.mitre.org/software/S0366"},
  "types": ["worm", "ransomware", "trojan"],
  "platforms": ["windows"],
  "actors": [{"id": "actor:Lazarus Group", "name": "Lazarus Group", "country": "KP", "origin": "mitre-attack"}],
  "hashes": [{"relation": "HAS_HASH", "type": "md5", "value": "84c82835a5d21bbcf75a61706d8ab549",
              "origin": "virustotal", "sample": "ed01ebfb..."}],
  "ips": [{"relation": "COMMUNICATES_WITH", "type": "ipv4", "value": "197.231.221.211", "origin": "virustotal", "sample": "ed01ebfb..."}],
  "cves": [{"cve": "CVE-2017-0144", "relation": "EXPLOITS", "origin": "virustotal", "reports": null}],
  "techniques": [{"attack_id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"]}],
  "similar": [{"id": "malware:NotPetya", "name": "NotPetya", "shared_techniques": 9}],
  "reports": [],
  "news": []
}
```

- `hashes` and `ips` hold at most 500 entries together; use `/entities/neighbors/` for more.
- In `cves`, `relation` is `EXPLOITS` (from a feed) or `CO_OCCURS_WITH` (discussed together in
  reports, with `reports` = how many).
- `similar` lists malware sharing the most ATT&CK techniques.

### 4.4 Vulnerabilities

#### `GET /api/cti-graph/v1/vulnerabilities/`

| Param | Meaning |
|-------|---------|
| `q` | text in the CVE id |
| `year` | CVE year, e.g. `2017` |
| `order` | `reports` (default), `name`, `mentions` |

Each result: `{"id", "name", "reports", "exploited_by"}` (`exploited_by` = number of malware).

#### `GET /api/cti-graph/v1/vulnerabilities/<CVE-id>/`

```json
{
  "vulnerability": {"id": "cve:CVE-2012-0158", "name": "CVE-2012-0158", "reports": 23, "mentions": 107},
  "exploited_by": [],
  "co_occurs_with": [
    {"node": {"id": "malware:PlugX", "type": "Malware", "name": "PlugX"}, "reports": 5},
    {"node": {"id": "actor:Naikon", "type": "ThreatActor", "name": "Naikon"}, "reports": 3}
  ],
  "reports": [ ... ],
  "news": [ ... ]
}
```

Returns 400 for a malformed id and 404 for a CVE not in the graph.

### 4.5 Indicators

#### `GET /api/cti-graph/v1/indicators/`

| Param | Meaning |
|-------|---------|
| `type` | `ipv4`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256` |
| `q` | text in the value |
| `min_reports` | only indicators seen in at least N reports |
| `order` | `reports` (default), `name`, `mentions` |

Each result: `{"id", "value", "type", "reports", "virustotal_detections"}`.

#### `GET /api/cti-graph/v1/indicators/lookup/?value=<ip|domain|url|email|hash>`

**The endpoint for enriching HIDS alerts.** Give it an IP, domain, URL, e-mail or file hash seen
on a device and get back everything the graph knows about it. The type is detected from the
value; hashes are case-insensitive.

```json
{
  "query": "180.210.206.246",
  "found": true,
  "id": "ipv4:180.210.206.246",
  "value": "180.210.206.246",
  "type": "ipv4",
  "report_count": 1,
  "virustotal_detections": null,
  "malware": [],
  "actors": [],
  "reports": [{"id": "report:DEEP_PANDA_Sakula", "title": "I Am Ironman: Deep Panda Uses Sakula Malware ...", "year": "2014"}],
  "hosted_on": []
}
```

- `malware`: families that have this hash or contacted this IP (VirusTotal data).
- `actors`: groups known to use those families.
- `reports`: threat reports that list the indicator.
- `hosted_on`: for a URL, its host.
- An unknown value returns `{"query": "...", "id": "...", "found": false}` with status 200, not 404.

#### `POST /api/cti-graph/v1/indicators/lookup/`

The same for up to 1000 values in one call, e.g. every indicator in a batch of alerts.

```http
POST /api/cti-graph/v1/indicators/lookup/
Authorization: Token <token>
Content-Type: application/json

{"values": ["180.210.206.246", "84C82835A5D21BBCF75A61706D8AB549", "10.0.0.5"]}
```

```json
{
  "results": [ {"query": "180.210.206.246", "found": true, ...}, {"query": "10.0.0.5", "id": "ipv4:10.0.0.5", "found": false} ],
  "found": 2
}
```

### 4.6 Reports

#### `GET /api/cti-graph/v1/reports/`

| Param | Meaning |
|-------|---------|
| `q` | text in the title or file name |
| `year` | e.g. `2014` |
| `source` | publisher, case-insensitive, exact (`fireeye`) |

Each result: `{"id", "name", "title", "date", "year", "source", "entities"}`.

#### `GET /api/cti-graph/v1/reports/<name>/`

Everything one report mentions, grouped, strongest first:

```json
{
  "report": {"id": "report:Mandiant_APT1_Report", "title": "Apt1 Exposing One Of China's Cyber Espionage Units", "year": "2013", "source": "Mandiant"},
  "threat_actors": [{"id": "actor:APT1", "name": "APT1", "mentions": 312}],
  "malware": [{"id": "malware:WEBC2", "name": "WEBC2", "mentions": 24}],
  "vulnerabilities": [],
  "indicators": [{"id": "domain:hugesoft.org", "name": "hugesoft.org", "mentions": 3, "ioc_type": "domain"}]
}
```

### 4.7 ATT&CK techniques

#### `GET /api/cti-graph/v1/techniques/`

| Param | Meaning |
|-------|---------|
| `q` | text in the name, or the start of the id (`t1059`) |
| `tactic` | e.g. `execution`, `persistence`, `credential-access` |

Each result: `{"id", "attack_id", "name", "tactics", "malware"}`, most used first.

#### `GET /api/cti-graph/v1/techniques/<T-id>/`

```json
{
  "technique": {"id": "technique:T1486", "attack_id": "T1486", "name": "Data Encrypted for Impact", "tactics": ["impact"]},
  "malware": [{"id": "malware:WannaCry", "name": "WannaCry", "actors": ["Lazarus Group"]}]
}
```

### 4.8 News

#### `GET /api/cti-graph/v1/news/`

Newest first.

| Param | Meaning |
|-------|---------|
| `since` | `YYYY-MM-DD`; only articles published on or after |
| `entity` | an id (`malware:PlugX`); only articles mentioning it |
| `q` | text in the headline |

```json
{
  "results": [
    {
      "id": "article:3c9e6d76376b8f40",
      "title": "New PlugX Variant Targets Telecoms Using CVE-2024-3400",
      "url": "https://news.example.org/2026/10/plugx-telecoms.html?id=7",
      "published": "2026-10-10",
      "source": "The Example Security News",
      "description": "Researchers say Mustang Panda deployed a new PlugX backdoor variant ...",
      "mentions": [
        {"id": "malware:PlugX", "type": "Malware", "name": "PlugX"},
        {"id": "actor:Mustang Panda", "type": "ThreatActor", "name": "Mustang Panda"},
        {"id": "cve:CVE-2024-3400", "type": "Vulnerability", "name": "CVE-2024-3400"}
      ]
    }
  ],
  "limit": 50, "offset": 0, "next_offset": null
}
```

### 4.9 Generic graph access

#### `GET /api/cti-graph/v1/entities/?id=<id>`

Any node's properties plus a summary of its links, for a generic detail panel.

```json
{
  "entity": {"id": "malware:Sakula", "type": "Malware", "name": "Sakula", "attack_id": "S0074", "...": "..."},
  "links": [
    {"relation": "USES_TECHNIQUE", "direction": "out", "type": "Technique", "count": 23},
    {"relation": "MENTIONS", "direction": "in", "type": "Report", "count": 5},
    {"relation": "USES", "direction": "in", "type": "ThreatActor", "count": 1}
  ]
}
```

#### `GET /api/cti-graph/v1/entities/neighbors/?id=<id>`

The node's relationships one at a time, paged, for drilling into the graph.

| Param | Meaning |
|-------|---------|
| `id` | required |
| `relation` | relationship types, e.g. `USES,EXPLOITS` |
| `type` | neighbour labels, e.g. `Report` |
| `direction` | `out`, `in` or `both` (default) |
| `limit`, `offset` | paging |

```json
{
  "results": [
    {"relation": "USES", "direction": "out", "properties": {"origin": "mitre-attack"},
     "node": {"id": "malware:BISCUIT", "type": "Malware", "name": "BISCUIT"}, "detail": null}
  ],
  "limit": 50, "offset": 0, "next_offset": 50
}
```

`detail` holds the indicator type or report title when the neighbour is an indicator or report.
Simple ids also work in the path form `/entities/<id>/` and `/entities/<id>/neighbors/`.

#### `GET /api/cti-graph/v1/path/?from=<id>&to=<id>`

Shortest connection between two nodes, e.g. "how is this IP tied to that actor?".

| Param | Meaning |
|-------|---------|
| `from`, `to` | ids, required |
| `max_hops` | 1 to 6, default 4 |
| `sourced_only` | `true` to ignore `CO_OCCURS_WITH` links |

```json
{
  "found": true,
  "nodes": [
    {"id": "actor:Deep Panda", "type": "ThreatActor", "name": "Deep Panda"},
    {"id": "malware:Sakula", "type": "Malware", "name": "Sakula"},
    {"id": "cve:CVE-2014-0322", "type": "Vulnerability", "name": "CVE-2014-0322"}
  ],
  "relationships": [
    {"type": "USES", "from": "actor:Deep Panda", "to": "malware:Sakula"},
    {"type": "EXPLOITS", "from": "malware:Sakula", "to": "cve:CVE-2014-0322"}
  ]
}
```

No connection within `max_hops` gives `{"found": false, "nodes": [], "relationships": []}`.

#### `POST /api/cti-graph/v1/query/` — admin only

Runs a read-only Cypher query (staff users only, 403 for others). Any query that writes is
refused with 400, and Neo4j itself also rejects writes because the query runs in a read
transaction. At most 1000 rows are returned.

```http
POST /api/cti-graph/v1/query/
Authorization: Token <admin-token>
Content-Type: application/json

{"query": "MATCH (m:Malware) WHERE $p IN m.platforms RETURN m.name AS name LIMIT 5", "params": {"p": "linux"}}
```

```json
{"rows": [{"name": "Mirai"}, {"name": "XorDDoS"}], "truncated": false}
```

Query syntax errors return 400 with Neo4j's message.

---

## 5. Status code summary

| Code | Meaning |
|------|---------|
| 200 | OK (also for an indicator lookup that finds nothing: `found: false`) |
| 400 | Bad parameter; body has `error` |
| 401 | Token missing or invalid |
| 403 | Not allowed (`/query/` without staff rights) |
| 404 | Named actor, malware, CVE, technique, report or id not in the graph |
| 502 | Neo4j unavailable or failing; body has `error` |
| 503 | `/health/` only: the service runs but Neo4j is down |

---

## 6. Qt/QML integration guide

### 6.1 Structure

Put the calls in a C++ `QObject` next to the existing `ChatClient`, reusing its base URL and
token. All calls are short `GET`s, so a plain `QNetworkAccessManager` request per call is enough.

```
GraphClient (C++ QObject)
  Q_INVOKABLE void search(const QString &text);
  Q_INVOKABLE void malware(const QString &name);
  Q_INVOKABLE void actor(const QString &name);
  Q_INVOKABLE void lookupIndicator(const QString &value);
  Q_INVOKABLE void lookupIndicators(const QStringList &values);
  signals:
    void resultReady(const QString &endpoint, const QVariant &data);
    void errorOccurred(const QString &endpoint, const QString &message);
```

### 6.2 Building URLs safely

Names and ids contain spaces, colons and slashes, so never paste them into a URL by hand. Use
`QUrlQuery` for parameters and `QUrl::toPercentEncoding` for a name in the path.

```cpp
QUrl GraphClient::url(const QString &path, const QUrlQuery &query = {}) const {
    QUrl u(m_baseUrl + "/api/cti-graph/v1/" + path);
    u.setQuery(query);
    return u;
}

void GraphClient::get(const QString &endpoint, const QUrl &url) {
    QNetworkRequest req(url);
    req.setRawHeader("Authorization", "Token " + m_token.toUtf8());
    req.setRawHeader("Accept", "application/json");
    req.setTransferTimeout(20000);
    QNetworkReply *reply = m_nam->get(req);
    connect(reply, &QNetworkReply::finished, this, [this, reply, endpoint]() {
        const QJsonDocument doc = QJsonDocument::fromJson(reply->readAll());
        if (reply->error() == QNetworkReply::NoError)
            emit resultReady(endpoint, doc.toVariant());
        else
            emit errorOccurred(endpoint, doc.object().value("error").toString(reply->errorString()));
        reply->deleteLater();
    });
}

void GraphClient::search(const QString &text) {
    QUrlQuery q;  q.addQueryItem("q", text);
    get("search", url("search/", q));
}

void GraphClient::malware(const QString &name) {      // "Cobalt Strike", "S0154", ...
    get("malware", url("malware/" + QString::fromUtf8(QUrl::toPercentEncoding(name)) + "/"));
}

void GraphClient::entityNeighbors(const QString &id, const QString &relation) {
    QUrlQuery q;  q.addQueryItem("id", id);  q.addQueryItem("relation", relation);
    get("neighbors", url("entities/neighbors/", q));
}
```

### 6.3 Enriching an alert

When an alert from the Linux service carries an IP, domain or file hash, look it up and show
what is known next to the alert:

```cpp
void GraphClient::lookupIndicators(const QStringList &values) {
    QNetworkRequest req(url("indicators/lookup/"));
    req.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    req.setRawHeader("Authorization", "Token " + m_token.toUtf8());
    const QJsonObject body{{"values", QJsonArray::fromStringList(values)}};
    QNetworkReply *reply = m_nam->post(req, QJsonDocument(body).toJson());
    connect(reply, &QNetworkReply::finished, this, [this, reply]() {
        const QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
        if (reply->error() == QNetworkReply::NoError)
            emit resultReady("lookup", obj.value("results").toArray().toVariantList());
        else
            emit errorOccurred("lookup", obj.value("error").toString(reply->errorString()));
        reply->deleteLater();
    });
}
```

```qml
Connections {
    target: graphClient
    function onResultReady(endpoint, data) {
        if (endpoint === "lookup")
            for (const hit of data)
                if (hit.found)
                    alertDetails.addThreatContext(hit.query, hit.malware, hit.actors, hit.reports)
    }
    function onErrorOccurred(endpoint, message) { errorBanner.show(message) }
}
```

### 6.4 Gotchas

- **Treat `found: false` as normal.** Most indicators on a device are not in the graph.
- **`CO_OCCURS_WITH` and `origin: "co-occurrence"` are hints.** Label them differently in the
  UI from `mitre-attack` or `virustotal` links, so analysts do not read them as attribution.
- **Page long lists** with `next_offset` instead of raising `limit`.
- **Batch lookups.** For many indicators use one `POST /indicators/lookup/` instead of many `GET`s.

---

## 7. Backend setup

The `threatgraph` app has no database models and needs no migrations.

1. Copy the `threatgraph/` folder next to `attack_rag/` and install the driver:
   `pip install "neo4j>=5.20"`.
2. In `settings.py`:

   ```python
   INSTALLED_APPS += ["threatgraph"]

   NEO4J = {
       "URI": "bolt://<neo4j-host>:7687",
       "USER": "neo4j",
       "PASSWORD": os.environ["NEO4J_PASSWORD"],
       "DATABASE": "neo4j",
       "QUERY_TIMEOUT": 15,          # seconds per query
   }
   ```

   Each value can also come from the environment (`NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`,
   `NEO4J_DATABASE`, `NEO4J_QUERY_TIMEOUT`).
   Optionally change the service identity (defaults shown):

   ```python
   THREATGRAPH = {"SERVICE_ID": "cti-graph", "VERSION": "v1"}
   ```
3. In the project `urls.py`, mount the app with its service prefix:

   ```python
   from threatgraph.urls import mount

   urlpatterns = [
       ...,
       mount(),          # -> /api/cti-graph/v1/...
   ]
   ```

4. Optional, for faster name lookups on a large graph, run once in Neo4j:
   `CREATE INDEX entity_name IF NOT EXISTS FOR (n:Entity) ON (n.name);`

Authentication and permissions come from the project's DRF settings, like the chat endpoints;
`/query/` additionally requires `is_staff`.

Tests run without a Neo4j server, against an embedded Cypher engine:

```bash
pip install falkordblite
python manage.py test threatgraph
```

---

## 8. Quick reference

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/api/cti-graph/v1/health/` | liveness and Neo4j status (no token) |
| GET | `/api/cti-graph/v1/stats/` | node, relationship and indicator counts |
| GET | `/api/cti-graph/v1/schema/` | labels, relationship and indicator types |
| GET | `/api/cti-graph/v1/search/?q=` | search everything |
| GET | `/api/cti-graph/v1/actors/` | list threat actors |
| GET | `/api/cti-graph/v1/actors/<name>/` | actor profile |
| GET | `/api/cti-graph/v1/malware/` | list malware |
| GET | `/api/cti-graph/v1/malware/<name>/` | malware profile |
| GET | `/api/cti-graph/v1/vulnerabilities/` | list CVEs |
| GET | `/api/cti-graph/v1/vulnerabilities/<CVE>/` | CVE profile |
| GET | `/api/cti-graph/v1/indicators/` | list indicators |
| GET | `/api/cti-graph/v1/indicators/lookup/?value=` | what is known about one indicator |
| POST | `/api/cti-graph/v1/indicators/lookup/` | same for up to 1000 values |
| GET | `/api/cti-graph/v1/reports/` | list reports |
| GET | `/api/cti-graph/v1/reports/<name>/` | what a report mentions |
| GET | `/api/cti-graph/v1/techniques/` | list ATT&CK techniques |
| GET | `/api/cti-graph/v1/techniques/<T-id>/` | malware using a technique |
| GET | `/api/cti-graph/v1/news/` | news articles |
| GET | `/api/cti-graph/v1/entities/?id=` | any node and its link summary |
| GET | `/api/cti-graph/v1/entities/neighbors/?id=` | a node's relationships, paged |
| GET | `/api/cti-graph/v1/path/?from=&to=` | shortest connection between two nodes |
| POST | `/api/cti-graph/v1/query/` | read-only Cypher (admin only) |

All requests except `health/`: `Authorization: Token <token>`. Every response has `X-Service: cti-graph/v1`.
