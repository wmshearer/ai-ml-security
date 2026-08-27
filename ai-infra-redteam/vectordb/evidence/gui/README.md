# GUI evidence: ChromaDB / Qdrant cross-tenant and no-auth findings

All images in this directory are real screen captures of real GUI tools driven
against live, freshly-started containers on this box. Nothing here is
hand-drawn, mocked up, or rendered from HTML/CSS to look like an application.
Every image was read back and visually confirmed before being kept.

The underlying finding (ChromaDB does not enforce tenant/database path
segments on data reads) is proven with curl/terminal evidence in
`../chroma/10-cross-tenant-confirm.txt` and `../chroma/00-commands.txt`. This
directory reproduces that same finding, plus the related no-default-auth
finding for Qdrant, visually.

Setup used for all captures below: ChromaDB and Qdrant were started fresh with
`scripts/run_chroma.sh` and `scripts/run_qdrant.sh` (default, out-of-the-box
configuration, no auth env vars, digest-pinned images, same as the rest of the
project's evidence). Two tenants/collections were recreated in Chroma
(`default_tenant/db_a/secrets_a` holding `TENANT_A_SECRET_VALUE_af92f1`, and
`tenant_b/db_b/secrets_b` holding `TENANT_B_SECRET_VALUE_ce31d4`), matching the
setup already documented in `../chroma/00-commands.txt`. Because containers
are ephemeral, the collection UUID differs from the one in the original
terminal evidence (`a78465d6-ed35-4a3c-bec6-8d23aa5fd88c` here vs
`61350239-747e-408f-bc05-612c82323b7b` there) - the behavior is identical
either way, which is itself part of the point (the UUID is the only thing
that matters, not the tenant path).

## Images

### 01-chroma-swagger-overview.png
**Tool:** Chromium (via Playwright, real non-headless browser window on the
live X display), showing ChromaDB's built-in Swagger/OpenAPI UI.
**Shows:** the `chroma-frontend` OpenAPI 1.0.0 spec rendered at
`http://localhost:18000/docs/`, listing the real REST surface including the
`/api/v2/tenants/{tenant}/databases/{database}/collections/...` endpoints.
**Reproduce:**
```
./scripts/run_chroma.sh
# then open http://localhost:18000/docs/ in a browser (Chroma redirects
# /docs -> /docs/ with a 303)
```

### 02-chroma-swagger-request-filled.png
**Tool:** same Chromium/Swagger UI, using the "Try it out" feature to build a
real request in the browser.
**Shows:** the `POST /api/v2/tenants/{tenant}/databases/{database}/collections/{collection_id}/get`
operation expanded, with the path parameters filled in as `tenant =
nonexistent_tenant`, `database = nonexistent_db`, and `collection_id` set to
tenant B's real collection UUID, body `{}`. This tenant and database were
never created on this Chroma instance.
**Reproduce:** in the Swagger UI, expand `POST .../collections/{collection_id}/get`,
click "Try it out", fill `tenant=nonexistent_tenant`, `database=nonexistent_db`,
`collection_id=<tenant B's UUID>`, body `{}`.

### 03-chroma-swagger-response-leak.png
**Tool:** same Chromium/Swagger UI, after clicking "Execute" on the request
above.
**Shows:** the executed cURL command and request URL
(`http://localhost:18000/api/v2/tenants/nonexistent_tenant/databases/nonexistent_db/collections/<uuid>/get`),
a `200` response code, and the response body containing
`"documents": ["TENANT_B_SECRET_VALUE_ce31d4"]` - tenant B's planted secret,
served through a tenant/database path that was never created. This is the
finding, executed and displayed entirely inside a browser GUI, not curl.
**Reproduce:** click "Execute" after filling the fields above; scroll to the
"Server response" section.

### 04-qdrant-dashboard-collections.png
**Tool:** Chromium (Playwright), Qdrant's own built-in web dashboard.
**Shows:** `http://localhost:16333/dashboard` (Qdrant's default dashboard)
listing all three collections created for this test (`collection_a`,
`collection_b`, `shared_multitenant`) with point counts, segments, and vector
config, reached directly with **no login prompt of any kind**.
**Reproduce:**
```
./scripts/run_qdrant.sh
curl -X PUT http://localhost:16333/collections/shared_multitenant -H "Content-Type: application/json" -d '{"vectors":{"size":4,"distance":"Cosine"}}'
curl -X PUT "http://localhost:16333/collections/shared_multitenant/points?wait=true" -H "Content-Type: application/json" -d '{"points":[{"id":1,"vector":[0.1,0.2,0.3,0.4],"payload":{"tenant_id":"alpha","secret":"ALPHA_TENANT_SECRET_11a"}},{"id":2,"vector":[0.9,0.8,0.7,0.6],"payload":{"tenant_id":"beta","secret":"BETA_TENANT_SECRET_22b"}}]}'
# then open http://localhost:16333/dashboard in a browser
```

### 05-qdrant-dashboard-collection-detail.png
**Tool:** same Qdrant dashboard, `shared_multitenant` collection's Points tab.
**Shows:** Point 1's full payload rendered directly in the dashboard,
including `tenant_id: alpha` and `secret: ALPHA_TENANT_SECRET_11a`, browsable
by anyone who can reach the HTTP port, with no filter and no credential.
Illustrates the finding recorded in FINDINGS.md that Qdrant's documented
multitenancy-by-payload pattern has no default or mandatory server-side
boundary.
**Reproduce:** in the dashboard, click into the `shared_multitenant`
collection, "Points" tab.

### 06-burp-repeater-cross-tenant-leak.png
**Tool:** Burp Suite Community Edition 2026.7.3, Repeater tab, request sent
via Burp's MCP server (`send-to-repeater` tool over the `burpmcp` MCP
connection at `http://localhost:8181/mcp/sse`), which uses Burp's own HTTP
client - this is a real Burp-originated request/response pair, not a
screenshot of curl output pasted into Burp.
**Shows:** Repeater tab "chroma-nonexistent-tenant" with the request pane
showing `POST /api/v2/tenants/nonexistent_tenant/databases/nonexistent_db/collections/<uuid>/get
HTTP/1.1` targeted at `localhost:18000`, and the response pane showing
`HTTP/1.1 200 OK` with body `"documents":["TENANT_B_SECRET_VALUE_ce31d4"]` -
the same leak, captured as a penetration tester would actually document it.
**Reproduce:** with Burp running and its MCP server enabled, call the
`send-to-repeater` MCP tool with:
- `host`: `localhost`, `port`: `18000`, `secure`: `false`
- `data`: a raw HTTP/1.1 request reading
  `POST /api/v2/tenants/nonexistent_tenant/databases/nonexistent_db/collections/<collection_B_uuid>/get HTTP/1.1`
  with `Host: localhost:18000`, `Content-Type: application/json`, a
  `Content-Length` matching an empty JSON body `{}`, and `Connection: close`.
- `tabName`: any label, e.g. `chroma-nonexistent-tenant`.

Then in the Burp GUI, select that Repeater tab and click "Send" (or send it
via MCP first so the response is already populated), and capture the window.

### 07-findings-summary-chart.png
**Tool:** matplotlib (Python), a generated static figure - not a screenshot of
any application. Explicitly labeled "Summary figure" in its own caption so it
is never confused with a live capture.
**Shows:** all four products tested in this project (ChromaDB, Qdrant,
Weaviate, Milvus) against two columns: "auth required by default" (all "No",
per FINDINGS.md) and "tenant A can read tenant B's data" (ChromaDB and Qdrant:
yes/cross-tenant leak; Weaviate and Milvus: no/isolated). Every data point is
taken verbatim from the summary table and per-product sections in
`../../FINDINGS.md`; none of it is invented for this figure. A footnote notes
the caveat that Qdrant's leak applies specifically to its documented
multitenancy-by-payload pattern, not to flat named collections, which isolate
correctly.
**Reproduce:** see `build_chart.py` logic (values transcribed from
`FINDINGS.md`'s summary table); regenerate with matplotlib using the same four
rows.

## What was NOT captured

Nothing was skipped from the original four target items - all four (Burp,
Chroma OpenAPI UI, Qdrant dashboard, comparison chart) produced real,
verified captures.

## Cleanup

All containers started for this evidence set
(`vectordb-chroma`, `vectordb-chroma-client`, `vectordb-qdrant`,
`vectordb-qdrant-client`) were stopped and removed with `docker rm -f` after
capture. The shared `vectordb-net` Docker network (created idempotently by the
project's own run scripts, also used by the rest of the project's evidence)
was left in place. Burp Suite itself was left running because it was started
by the operator/coordinator, not by this capture pass; the only durable
change made to it is the one added Repeater tab described above (unrelated
pre-existing Repeater/Proxy history from an earlier, different session was not
touched or captured).
