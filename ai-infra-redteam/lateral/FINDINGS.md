# Lateral movement across a realistic AI stack

**Question:** every published vulnerability in AI serving infrastructure is
documented one component at a time - one issue for the vector database, one
for the inference server, one for the orchestrator. None of that answers
what an attacker who reaches ONE component in a typical AI stack can then
reach across the rest of it. This component builds a small, realistic
three-tier AI stack (RAG application, vector database, inference server),
assumes a foothold in one container, and measures exactly what that
foothold reaches. That chain, not any single bug, is this component's
contribution.

No CVE is cited anywhere in this document. A prior agent on this project
cited a CVE that does not exist; every claim below is either a direct,
reproduced observation on this box, or a citation to the sibling
`vectordb/` or `container/` components' own already-verified findings.

## The stack

Three containers on one Docker user-defined bridge network (`lateral-net`),
which is how a real small deployment is normally built:

- `lateral-app` - a small FastAPI app (`app/rag_app.py`, written for this
  test) that does a naive RAG query: fetch a note from its own ChromaDB
  collection, hand it to Ollama as context, return the answer. This is the
  **foothold container**.
- `lateral-chroma` - ChromaDB, `chromadb/chroma@sha256:1e0b73a1...cdedce1acdf6`
  (same pinned digest already verified in `vectordb/FINDINGS.md`), default
  configuration, no auth.
- `lateral-ollama` - Ollama, `ollama/ollama:0.5.7@sha256:7e672211...c105800e`,
  default configuration (`OLLAMA_HOST=0.0.0.0:11434` is the image's own
  default, no auth), with the small model `tinyllama` (637 MB) pulled after
  startup.

Host port mappings used only so this operator can poke the stack from
outside: `18001->8000` (chroma), `11434->11434` (ollama, this port was free
on the host), `19000->9000` (app). Host ports 8000 and 8080 were already
bound by pre-existing services (`splunkd`, `java`) on this box and were
never used. None of these host mappings matter to the chain itself - see
`evidence/02-` for proof the container-to-container reachability below does
not depend on any host port publish at all.

Startup: `scripts/00-build-app-image.sh`, `scripts/01-start-stack.sh`,
`scripts/02-plant-tenant-data.sh`. Cleanup: `scripts/99-cleanup.sh`.

## The assumed foothold (stated honestly)

**Premise: assume an attacker has plain code execution inside `lateral-app`,
for example via a compromised Python dependency or an application-layer bug
in a real version of this kind of RAG service.** No such exploit was
performed or is claimed here - `lateral-app` was written for this test and
was not itself attacked. This is the standard assumed-breach starting point
used in red team engagements: the interesting question is not "how did they
get in," it is "given that they are in, what does that reach." Every step
below was executed with `docker exec lateral-app <command>`, i.e. literally
running code inside that one container, using tools and libraries already
present in it (Python's `requests`, already a dependency of the app itself)
- nothing was added to the container to make the chain work.

## The chain

```
 [attacker]
     |
     v
 +-------------------+        no auth, same bridge net
 |  lateral-app       |------------------------------+
 |  (assumed foothold)|                               |
 +-------------------+                                v
     |                                        +-------------------+
     | no auth, same bridge net               |  lateral-chroma    |
     v                                        |  (vector DB)       |
 +-------------------+                        |                    |
 |  lateral-ollama    |                        | tenant_a: secret A |
 |  (inference server)|                        | tenant_b: secret B |
 |                    |                        +-------------------+
 | list / pull /      |                          both read from the
 | delete / infer     |                          foothold, cross-tenant
 +-------------------+
```

### Step 1 - Network reachability from the foothold, no published ports involved

From inside `lateral-app`, both peer services resolve and connect on their
internal ports, even though neither was linked, and only the app's own port
(9000) was published to the host.
Evidence: `evidence/01-network-reachability-from-foothold.txt`,
`evidence/02-app-container-has-no-port-publish-or-links-to-peers.txt`.

A blind sweep of the bridge subnet, using raw IPs only (no container names,
no DNS, no env var read from the app's own config) independently finds the
same two open ports, confirming this is a property of the shared network,
not an artifact of the app being told its peers' hostnames.
Evidence: `evidence/03-blind-subnet-sweep-no-dns-names-used.txt`.

**ATT&CK:** T1046 (Network Service Discovery). **ATLAS:** no clean
mapping - this step is generic network reconnaissance, not AI-specific.

### Step 2 - No authentication on either peer service

`GET /api/v2/heartbeat` on chroma and `GET /api/tags` on ollama both return
`200 OK` from the foothold with zero credentials supplied.
Evidence: `evidence/04-no-auth-required-from-foothold.txt`. This reuses and
directly reproduces, from a genuinely different container in a genuinely
different stack, the "no auth by default" finding already established for
both products in `vectordb/FINDINGS.md` and the Ollama fact stated in this
project's brief.

**ATT&CK:** T1133 is not right here (no external remote service was used);
the closest fit is T1210 (Exploitation of Remote Services) is also not
accurate since nothing was exploited - the services simply require no
credential. **No clean ATT&CK ID for "reachable service with no auth by
design."** **ATLAS:** no clean mapping.

### Step 3 - Cross-tenant data read on the vector DB, from the foothold

Two synthetic tenants (`tenant_a`/`db_a`/`secrets_a` and
`tenant_b`/`db_b`/`secrets_b`) were planted directly in chroma
(`scripts/02-plant-tenant-data.sh`), each holding one obviously-fake secret
string. The foothold app was never given either tenant's name or collection
ID - it only knows its own `default_tenant/default_database`.

Using the collection UUIDs (obtained here from the planting script's own
output, standing in for however an attacker would really discover them: a
logging leak, a shared cache, an IDOR-style parameter in another app), the
foothold reads **both** tenants' secrets through its own, unrelated
tenant/database path, and even through a completely fabricated one:

```
POST /api/v2/tenants/default_tenant/databases/default_database/collections/<coll_A>/get -> 200, LATERAL_TENANT_A_SECRET_VALUE_71bd2f
POST /api/v2/tenants/default_tenant/databases/default_database/collections/<coll_B>/get -> 200, LATERAL_TENANT_B_SECRET_VALUE_ae930c
POST /api/v2/tenants/nonexistent_tenant/databases/nonexistent_db/collections/<coll_B>/get -> 200, LATERAL_TENANT_B_SECRET_VALUE_ae930c
```

Evidence: `evidence/05-cross-tenant-read-from-foothold.txt`. This directly
reuses the weakness already proven in
`vectordb/evidence/chroma/10-cross-tenant-confirm.txt` - the contribution
here is showing it works identically when read from a **different
container in a different application's stack**, which is the realistic
lateral-movement case, not just from a test client talking to chroma
directly.

A second, easier path was also found and is reported honestly since it
changes the practical difficulty of this step: because chroma requires no
authentication for **any** tenant/database path, an attacker does not need
to be handed a collection UUID by any side channel at all. Listing
collections under a **guessed** tenant/database name pair
(`tenant_a`/`db_a`) succeeds outright and returns that tenant's own
collection UUID directly:

```
GET /api/v2/tenants/tenant_a/databases/db_a/collections -> 200, [{"id": "...", "name": "secrets_a", ...}]
```

Chroma does not expose a single "list every tenant" endpoint
(`GET /api/v2/tenants` returns 405), so guessing or otherwise learning a
candidate tenant/database name is still required - but no UUID leak is
needed once a name is guessed correctly.
Evidence: `evidence/06-listing-other-tenants-still-works-because-no-auth.txt`.

**ATT&CK:** T1530 (Data from Cloud Storage) is the closest general
analogue but is not a precise fit for a self-hosted vector DB; more
accurately this is unauthorized data access enabled by T1046-style service
discovery plus an authorization gap, for which ATT&CK has no single ID.
**ATLAS:** AML.T0025 (Exfiltration via Cyber Means) does not fit either
since nothing left the local test environment; the closest ATLAS concept is
unauthorized access to an AI system's data store, which ATLAS frames under
reconnaissance/resource-development tactics rather than a single technique
ID that matches this exact case. **Reporting this as "no precise
established mapping" rather than forcing one.**

### Step 4 - Full read/write/destroy control at the inference layer

From the foothold, against `lateral-ollama`, with zero credentials:

| Action | Endpoint | Result |
|---|---|---|
| List models | `GET /api/tags` | Works |
| Arbitrary inference | `POST /api/generate` | Works |
| Pull a new model never requested by the app | `POST /api/pull` | Works |
| Delete a model | `DELETE /api/delete` | Works |

Evidence: `evidence/07-ollama-inference-and-model-pull.txt`,
`evidence/08-ollama-model-delete.txt`. Every one of the four actions tested
succeeded; none failed or required a credential. A negative control
(deleting a model name that genuinely does not exist) correctly returned
`404`, confirming the successful deletes above were real state changes and
not an endpoint that always returns success.
Evidence: `evidence/10-additional-writes-and-negative-controls.txt`.

The same "no credential gates writes, not just reads" pattern holds on the
vector DB side too: deleting a chroma collection by name, with no auth,
also succeeds (tested only against a throwaway collection created for this
purpose, never against the planted tenant data - confirmed intact
afterward in `evidence/11-planted-data-still-intact-after-testing.txt`).

**ATT&CK:** T1565 (Data Manipulation) fits the model-delete/collection-delete
actions (destructive write to a system the attacker should not control).
Arbitrary inference and model pull do not map cleanly to an ATT&CK
technique; ATT&CK is written for general IT systems, not AI model-serving
APIs. **ATLAS:** AML.T0034 (Cost Harvesting) does not fit (no cost/resource
exhaustion was attempted); AML.T0018 (Manipulate AI Model) is the closest
concept for the delete/replace-model actions but ATLAS's own definition of
that technique is about tampering with model artifacts or weights, which
is close but not exact for "delete the whole model via its own management
API." **Reporting the model-delete/pull findings as a genuine, novel
model-layer impact with no exact pre-existing ATT&CK or ATLAS ID, rather
than forcing a mapping.**

### Step 5 - Credential recovery inside the foothold

A fake internal token (`INTERNAL_API_TOKEN_PLANTED_9f3a7c`, planted in this
test's own `docker run` command and application code to simulate a
realistic pattern - real app containers routinely hold secrets for
downstream services outside a given assessment's scope) is recoverable two
ways with plain code execution and no extra capability:

- reading the container's own environment (`env` / `os.environ`)
- reading a config file the app wrote to its own filesystem at startup
  (`/app/config.json`)

A `/proc`-based process listing (the `ps` binary is absent from the slim
base image, so `/proc/*/cmdline` was read directly) found no additional
secrets in any process's command line.
Evidence: `evidence/09-credential-recovery-inside-foothold.txt`. This is
not a Docker isolation weakness - it is the ordinary consequence of code
execution in a container that legitimately holds a secret - and is
reported as such.

**ATT&CK:** T1552.001 (Unsecured Credentials: Credentials In Files) for the
config file; ATT&CK's Unsecured Credentials technique family also
explicitly covers credentials exposed via container environment variables,
which fits the env var path. **ATLAS:** no AI-specific angle to this
particular step; it would apply identically to a non-AI containerized app.

## What did NOT work

- **Chroma's `GET /api/v2/tenants`** (a hoped-for "list every tenant"
  endpoint) returns `405 Method Not Allowed`. There is no single
  unauthenticated way to enumerate all tenant names that exist; a candidate
  name still has to be known or guessed. Evidence:
  `evidence/06-listing-other-tenants-still-works-because-no-auth.txt`.
- **Deleting a chroma collection by its UUID** under the tenant/database
  path returns `404`; only delete-by-name on that same path works. This is
  a real quirk of Chroma's v2 API, not a security control - reported for
  accuracy. Evidence: `evidence/10-additional-writes-and-negative-controls.txt`.
- **Ollama correctly 404s** when asked to delete a model name that does not
  exist - included as a negative control, not a weakness.
- **CAP_SYS_MODULE / privileged escapes / cgroup release_agent** were not
  attempted at all in this component; those were already tested and
  reported in `container/FINDINGS.md` and are out of this component's
  scope. This chain never used `--privileged`, `--pid=host`, capability
  additions, or a Docker socket mount anywhere - every step above works
  from a completely default, unprivileged container using only
  network-layer reachability and the absence of authentication on its
  peers.

## The defensive conclusion

**The single control that would have broken this chain earliest: put the
application tier, the vector database, and the inference server on
separate Docker networks instead of one shared bridge network**, publishing
only the specific ports each tier genuinely needs from the tier that calls
it (app -> chroma, app -> ollama), and nothing peer-to-peer beyond that.

This was tested directly, not just asserted: a control container placed on
a different user-defined bridge network could not even resolve
`lateral-chroma` or `lateral-ollama` by name - DNS resolution itself failed,
before any auth or application-layer question was reached. Evidence:
`evidence/12-network-segmentation-control-different-network-blocked.txt`.
Every step in this chain from Step 1 onward depends on the foothold being
able to reach chroma and ollama at the network layer at all; segmentation
removes that precondition entirely, for free, with no change to either
product's own authentication posture.

Authentication on chroma and ollama would also have helped and should
still be done - it is the correct fix for Steps 2 through 5 individually -
but network segmentation is the one control that blocks the entire chain
at its first step, before any of the individual product-level gaps (no
auth, cross-tenant reads, unauthenticated model management) even come into
play. This matches, and is now confirmed a second time on a different,
purpose-built stack, the network finding already reported in
`container/FINDINGS.md` section 3.

## Honest gaps

- The collection UUID used in the "known UUID" cross-tenant read (Step 3,
  first path) was obtained from the planting script's own console output
  for reproducibility, not independently discovered by the foothold via a
  genuine side channel. The second, UUID-free path found during this work
  (guessing a plausible tenant/database name pair directly) does not have
  this caveat and is the more realistic version of this step.
- No real embedding model is used in `rag_app.py`'s retrieval step (a fixed
  stub vector); this does not affect any finding above, since every attack
  step operates on the vector DB and inference server's management/data
  APIs directly, not on retrieval quality.
- This component did not attempt any container-escape technique
  (`--privileged`, capability abuse, Docker socket mounts) - that ground
  was already covered in `container/FINDINGS.md` and intentionally not
  repeated here to keep this component's scope to what is genuinely new:
  the cross-service chain once a foothold exists.
