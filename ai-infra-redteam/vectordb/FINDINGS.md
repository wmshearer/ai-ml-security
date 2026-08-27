# Vector database multi-tenant isolation: does it exist by default?

**Question:** when a self-hosted vector database is run with its default,
out-of-the-box configuration, does a client scoped to one
tenant/collection/database get blocked from reading, listing, or querying
another tenant's data? This was not answered anywhere found during research
(no CVE, no vendor doc, no blog post states this plainly for all four
products). Every published CVE for these products found during research is a
full authentication bypass, not a cross-tenant data leak on an
already-authenticated (or, since none require auth by default, already
network-reachable) connection. This is the original contribution of this
component: hands-on testing to answer the isolation question directly.

All four products were tested with **default configuration** - no auth env
vars, no config file changes, nothing that would alter the out-of-the-box
posture. Exact image digests, commands, and raw captured output are in
`evidence/<product>/`. No CVE IDs are cited anywhere in this document (see the
project's hard constraint on unverified CVE citation).

## Summary table

| Product | Image (pinned) | Default bind | Auth required by default | Tenancy model | Can tenant A read tenant B's data? |
|---|---|---|---|---|---|
| ChromaDB | `chromadb/chroma@sha256:1e0b73a1...cdedce1acdf6` (v1.4.4) | `0.0.0.0:8000` | No | First-class: tenant + database + collection | **Yes** - data-read/query/get endpoints ignore the tenant/database path segments; only the collection UUID matters |
| Qdrant | `qdrant/qdrant@sha256:d122138f...61f8135ee412362` (v1.15.1) | `0.0.0.0:6333` (HTTP), `0.0.0.0:6334` (gRPC) | No | No first-class tenancy; flat collections only, "multitenancy" is a documented client-side payload-filter pattern | **Not applicable to flat collections (isolated by name); yes for the documented multitenancy pattern** - a query against a shared collection with no filter returns all tenants' data in one response |
| Weaviate | `semitechnologies/weaviate@sha256:5c62e5cb...8135ee412362` (v1.39.2) | `0.0.0.0:8080` (REST), `0.0.0.0:50051` (gRPC) | No | Flat classes by default; opt-in first-class multi-tenancy per class (`multiTenancyConfig.enabled`) | **No** - both flat classes and the opt-in multi-tenancy feature enforce isolation correctly server-side. Caveat: with no auth, tenant names are enumerable by anyone who can reach the API |
| Milvus | `milvusdb/milvus@sha256:49371c30af46b1013e4d3e0b980e691d81376d69cdbe1b372725baf1d7255862` (v3.0.0) | `0.0.0.0:19530` (gRPC), `0.0.0.0:9091` (metrics/health) | No | First-class: database + collection. RBAC system exists (`root` user, `admin`/`public` roles) but is not enforced by default | **No** - collections are namespaced server-side by `(database, name)` with distinct internal collection IDs; a client bound to one database cannot see or resolve a collection that exists only in another database |

Every one of these instances was reachable, unauthenticated, from both the
host and from an unrelated container on the same Docker user-defined bridge
network. None of the four requires any credential to reach the API surface at
all in its default configuration.

## ChromaDB - detailed finding

**Default bind:** `0.0.0.0:8000` (confirmed via `/proc/net/tcp` inside the
container and via the Docker port mapping). Evidence:
`evidence/chroma/01-bind-address.txt`.

**Auth:** none. The shipped `/config.yaml` contains only `persist_path: "/data"`
- no authn/authz block is present unless explicitly added. Confirmed reachable
from the host and from a peer container with zero credentials.
Evidence: `evidence/chroma/02-`, `03-`, `04-`.

**Tenancy model:** Chroma has a real, first-class tenancy hierarchy in its v2
API: `tenant` -> `database` -> `collection`. A caller can create a `tenant_b`
and a `db_b` distinct from `default_tenant`/`db_a`, and each of those has its
own separate `POST /tenants`, `POST .../databases`, `POST .../collections`
lifecycle. Evidence: `evidence/chroma/05-tenancy-model.txt`.

**Isolation result: NOT isolated for read/query/get, once a collection ID is
known.** Two collections were created - `secrets_a` in
`default_tenant/db_a`, and `secrets_b` in `tenant_b/db_b` - each with one
document containing a unique known string. Listing collections is correctly
scoped: `GET .../default_tenant/databases/db_a/collections` returns only
`secrets_a`, and tenant B's collection ID is never leaked through listing
(`evidence/chroma/11-listing-leak-check.txt`). But once collection B's UUID is
known by any means, the `/get` and `/query` endpoints will serve its data
through **any** tenant/database path in the URL, including
`default_tenant/db_a` (the wrong tenant) and even a completely fabricated
`nonexistent_tenant/nonexistent_db` path that was never created:

```
POST /api/v2/tenants/default_tenant/databases/db_a/collections/<collection_B_uuid>/get
-> 200 OK
{"ids":["doc-b-1"],"documents":["TENANT_B_SECRET_VALUE_ce31d4"], ...}

POST /api/v2/tenants/nonexistent_tenant/databases/nonexistent_db/collections/<collection_B_uuid>/get
-> 200 OK
{"ids":["doc-b-1"],"documents":["TENANT_B_SECRET_VALUE_ce31d4"], ...}
```

Full transcript, repeated to rule out a fluke, and including the vector
similarity `/query` endpoint (also cross-tenant readable): see
`evidence/chroma/09-cross-tenant-test.txt` and
`evidence/chroma/10-cross-tenant-confirm.txt`.

**What this means in practice:** the tenant/database segments in Chroma's v2
REST paths function as an addressing convenience, not an authorization
boundary. Access control is effectively "possession of the collection UUID,"
not "membership in the tenant." Collection UUIDs are random UUIDv4 (not
sequential/guessable), and listing does not leak other tenants' UUIDs, so this
is not trivially exploitable by mass enumeration - but any application bug,
logging leak, cache confusion, or IDOR-style parameter tampering that exposes
or accepts a collection ID from the wrong tenant will read that tenant's data
regardless of which tenant/database the request claims to be scoped to. This
is separate from ChromaToast (an authentication-bypass CVE) and was not
reproduced or investigated further per the project's scope.

## Qdrant - detailed finding

**Default bind:** `0.0.0.0:6333` (HTTP) and `0.0.0.0:6334` (gRPC). Confirmed
via `/proc/net/tcp` and Docker port mapping.
Evidence: `evidence/qdrant/01-bind-address.txt`.

**Auth:** none. `QDRANT__SERVICE__API_KEY` is unset by default; every endpoint
tested returned data with no credentials, from host and peer container.
Evidence: `evidence/qdrant/02-`, `03-`.

**Tenancy model:** Qdrant has **no first-class tenant/namespace object** in
its API. Its own documentation describes "multitenancy" as an application
pattern: put all tenants in one collection, add a `tenant_id` payload field,
index it, and have the client always filter on it. This is a genuinely
different situation from Chroma/Weaviate/Milvus and must be reported
differently - there is nothing in the server for a client to "get scoped to"
beyond a collection name. Evidence: `evidence/qdrant/04-tenancy-model-check.txt`.

**Isolation result - two parts:**

1. **Flat collections (Qdrant's real isolation primitive) are correctly
   isolated by name.** `collection_a` and `collection_b` were created with
   distinct points holding the same point ID (`1`) but different payload
   secrets. Every request against `/collections/collection_a/...` only ever
   returned collection A's own data; there is no cross-collection leak by
   name or by point ID collision. Evidence:
   `evidence/qdrant/05-`, `06-`, `07-cross-collection-test.txt`.

2. **The documented multitenancy-by-payload pattern provides zero
   server-side enforcement.** A single shared collection was created with two
   points tagged `tenant_id: alpha` and `tenant_id: beta`. A query with no
   filter returned both tenants' payloads, including both secrets, in one
   response:

   ```
   POST /collections/shared_multitenant/points/query
   {"query":[0.5,0.5,0.5,0.5],"limit":10,"with_payload":true}
   -> {"result":{"points":[
        {"payload":{"tenant_id":"beta","secret":"BETA_TENANT_SECRET_22b"}},
        {"payload":{"tenant_id":"alpha","secret":"ALPHA_TENANT_SECRET_11a"}}
      ]}}
   ```

   Adding the filter (`{"filter":{"must":[{"key":"tenant_id","match":{"value":"alpha"}}]}}`)
   correctly restricts results - the filtering mechanism itself works. The
   finding is the absence of any default or mandatory boundary: nothing in
   Qdrant prevents, warns on, or defaults toward tenant-scoped queries. If an
   application built on Qdrant's documented multitenancy pattern has a bug
   that omits the filter on any single query path, that one omission returns
   every tenant's data. This is expected behavior per Qdrant's own docs, not
   a defect, but it is a sharp edge worth stating plainly since "Qdrant
   supports multitenancy" reads, to an unfamiliar reader, like a claim of
   built-in isolation. It is not. Evidence:
   `evidence/qdrant/08-`, `09-multitenancy-leak-test.txt`, `10-`.

## Weaviate - detailed finding

**Default bind:** `0.0.0.0:8080` (REST) and `0.0.0.0:50051` (gRPC). Confirmed
via Docker port mapping and in-container `/proc/net/tcp`.
Evidence: `evidence/weaviate/01-bind-address.txt`.

**Auth:** none. Neither `AUTHENTICATION_APIKEY_ENABLED` nor
`AUTHENTICATION_OIDC_ENABLED` is set by default; Weaviate's own default is
anonymous access. Confirmed from host and peer container.
Evidence: `evidence/weaviate/02-`, `03-`.

**Tenancy model:** flat "classes" (collections) by default
(`multiTenancyConfig.enabled: false` unless a class explicitly opts in).
Weaviate also ships a genuine, opt-in, first-class multi-tenancy feature per
class, with actual `tenant` objects that can be created, listed, and
referenced. Evidence: `evidence/weaviate/04-tenancy-model-check.txt`.

**Isolation result: isolated, in both modes tested.**

1. **Flat classes:** `ClassA` and `ClassB` were created with distinct
   objects. GraphQL `Get` queries scoped to one class only ever returned that
   class's data. Fetching `ClassB`'s object UUID through `ClassA`'s
   class-scoped REST endpoint (`/v1/objects/ClassA/<classB_uuid>`) returned
   `404`, not the data - this is correctly enforced, not a leak. The only
   route that resolves an object by UUID alone, `/v1/objects/{id}` with no
   class specified, is a documented global-UUID lookup (Weaviate UUIDs are
   unique per instance by design, not per-class), not a class-boundary
   bypass. Evidence: `evidence/weaviate/05-`, `06-`, `07-status-code-check.txt`.

2. **Opt-in multi-tenancy feature:** a class was created with
   `multiTenancyConfig.enabled: true`, two tenants (`tenantA`, `tenantB`)
   created, and each given one object with a distinct secret. Every isolation
   test against this setup enforced the boundary correctly:
   - GraphQL `Get` scoped to `tenantA` never returned `tenantB`'s data.
   - GraphQL `Get` with **no** tenant parameter at all was rejected outright
     with an explicit error (`"class ... has multi-tenancy enabled, but
     request was without tenant"`) rather than defaulting to "return
     everything" - this is a meaningfully safer default than Qdrant's
     pattern.
   - Fetching `tenantB`'s object UUID while passing `?tenant=tenantA` in the
     query string returned `404`, not the data.

   Evidence: `evidence/weaviate/08-`, `09-`, `10-multitenancy-cross-tenant-test.txt`.

**Caveat that must be reported alongside the positive result:** because there
is no authentication by default, tenant *names* are enumerable by anyone who
can reach the API - `GET /v1/schema/<class>/tenants` returns the full tenant
list with zero credentials
(`evidence/weaviate/11-tenant-enumeration-check.txt`). The per-tenant data
boundary is real and enforced, but it is a boundary between tenants who
already know each other's names, sitting behind no authentication at all.
On a shared, unauthenticated instance this is a materially weaker guarantee
than "isolated" alone implies, even though the underlying enforcement worked
in every test performed here.

## Milvus - detailed finding

**Default bind:** `0.0.0.0:19530` (gRPC, the main data-plane API) and
`0.0.0.0:9091` (metrics/health). Confirmed via Docker port mapping.
Evidence: `evidence/milvus/01-bind-address.txt`.

**Auth:** none enforced by default. `common.security.authorizationEnabled` is
opt-in and was left untouched. A pymilvus `MilvusClient` connected with zero
credentials and could immediately call `list_collections()`,
`list_users()` (returned `['root']`), and `list_roles()` (returned
`['admin', 'public']`) - meaning the RBAC object model exists in Milvus, but
nothing gates access to it or to data by default.
Evidence: `evidence/milvus/02-`, `08-`, `09-rbac-model-check.txt`.

Milvus was the heaviest stack to stand up: it requires etcd and MinIO as
mandatory dependencies (this is Milvus's own documented architecture, not a
choice made for this test - see the official standalone
`docker-compose.yml`). Total image pull for Milvus + etcd + MinIO was
approximately 2.9 GB; combined with the other three products, total new image
data pulled for this component was roughly 4 GB. Milvus reported itself
healthy (`/healthz` returning `OK`) about 10 seconds after container start in
this run, well under the 90-second `start_period` in the upstream healthcheck.

**Tenancy model:** first-class `database` object, sitting above `collection`,
created via `client.create_database(db_name=...)`. This is structurally the
same idea as Chroma's tenant/database hierarchy.
Evidence: `evidence/milvus/03-tenancy-model-check.txt`.

**Isolation result: isolated.** Two databases, `tenant_db_a` and
`tenant_db_b`, were created, each given a collection named identically
(`secrets`) but with distinct data - a deliberately adversarial setup, since
same-name collisions across tenants are exactly where a cross-tenant bug
would most likely surface. Results:

- `client_a.describe_collection('secrets')` and
  `client_b.describe_collection('secrets')` returned **different internal
  `collection_id` values** (`468659560957609174` vs `468659560958980318`)
  despite the identical name - confirming Milvus namespaces collections
  server-side by the `(database, name)` pair, not by name alone.
- A collection created only in `tenant_db_b` (`only_in_db_b`) was correctly
  invisible to a client bound to `tenant_db_a`:
  `client_a.has_collection('only_in_db_b')` returned `False`, while
  `client_b.has_collection('only_in_db_b')` returned `True`.
- The pymilvus client API binds the database at connection time
  (`db_name=` on `MilvusClient(...)` / `connections.connect(...)`) and does
  not expose any per-call override that would let a connection scoped to one
  database address another database's collection in the same call.

Evidence: `evidence/milvus/04-`, `05-`, `06-`, `07-server-side-enforcement-test.txt`.

One early test attempted to pass an unsupported `db_name=` keyword argument
directly into `.query()` expecting it to either override the connection's
database or raise an error; pymilvus's `**kwargs` silently absorbed and
ignored it, and the client returned its own bound database's data
unchanged. That result is captured verbatim in
`evidence/milvus/05-cross-database-test.txt` for transparency, but it does
not demonstrate anything about server-side enforcement (the parameter was
never a real one) - the corrected, decisive test is
`07-server-side-enforcement-test.txt`, which confirms isolation via internal
collection IDs and `has_collection` rather than a client kwarg that doesn't
exist.

## The most notable finding

**ChromaDB is the only one of the four where the tenant/database concept in
the API does not actually gate data access.** Chroma is also the only product
of the four that markets tenant+database as first-class, structured concepts
(matching Milvus's design) - and it is the one where that structure turns out
to be cosmetic for read/query operations. Anyone who obtains a collection
UUID, from any tenant, can read and vector-query that collection's data
through a request that names any other tenant and database, including tenants
and databases that were never created. Milvus, which has the same
tenant-hierarchy shape, enforces it correctly (distinct internal collection
IDs per database, `has_collection` correctly scoped). This is a clean,
like-for-like comparison: two products offering the identical mental model of
"tenant > database > collection," one enforces the boundary at the point of
data access and one does not.

## What "isolation" does and does not mean here

- **Chroma:** tenancy exists as a real object model, but does not gate
  read/query access once a collection ID is known. Not isolated.
- **Qdrant:** no tenancy model exists in the engine. Flat collections are
  correctly isolated by name. The documented multitenancy-by-payload pattern
  has no server-side enforcement at all - this is not a defect, it is exactly
  what Qdrant's own docs describe, but it means "isolation" for Qdrant
  multitenancy depends entirely on the calling application never forgetting
  the filter.
- **Weaviate:** tenancy is opt-in and, when enabled, is enforced correctly
  server-side in every test performed. The gap is that with no
  authentication, tenant names themselves are visible to any network-reachable
  caller.
- **Milvus:** tenancy exists as a real object model and is enforced correctly
  server-side, including the adversarial same-name-collection-in-two-databases
  case.

None of the four require authentication by default, so in every case the real
security boundary observed here is "can you reach the port," not "are you the
right tenant." Isolation between tenants who can already reach an
unauthenticated instance is the narrower and more interesting question this
component answers, and the answer differs by product even among the ones that
appear to offer the same tenancy model.
