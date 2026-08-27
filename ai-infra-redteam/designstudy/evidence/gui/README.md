# GUI evidence: Ray and Triton default-exposure findings

The dashboard image (01-) is a real, non-headless Chromium browser
screenshot taken via Playwright against a live Ray container started with
the component's own `scripts/run_ray.sh`. The two terminal images (02-, 03-)
use `wshearer-site/tools/termcap.sh`, which runs the command in a real
qterminal window on the live X display and photographs only that window,
never the desktop. Nothing here is hand-drawn, mocked up, or rendered from
HTML/CSS to look like an application. Every image was read back and
visually confirmed before being kept.

## Images

### 01-ray-dashboard-no-login.png
**Tool:** Chromium (via Playwright, real non-headless browser window on the
live X display), page screenshot (not a window/desktop capture, so no
browser chrome or other windows can appear in it).
**Shows:** the Ray Dashboard's Overview page, fully loaded, at
`http://localhost:12265/` - Cluster utilization, Recent jobs, Serve
Deployments, Node Status, Resource Status, and an Events panel - reached
directly with **no login prompt of any kind**. This is the single clearest
illustration of `FINDINGS.md`'s central Ray finding: the dashboard and job
submission API ship reachable and unauthenticated by default, with no
`RAY_AUTH_MODE` set.
**Reproduce:**
```
./scripts/run_ray.sh
# then open http://localhost:12265/ in a browser
```

### 02-ray-unauth-job-submit-and-run.png
**Tool:** qterminal (via `termcap.sh`), running plain `curl` against the
Ray Jobs HTTP API.
**Shows:** a `POST /api/jobs/` submission with body
`{"entrypoint": "echo DESIGNSTUDY_UNAUTH_JOB_SUBMIT_TEST && whoami && hostname"}`
and no `Authorization` header, returning a submission ID; polling
`GET /api/jobs/<id>` until `"status": "SUCCEEDED"` with
`"driver_exit_code": 0`; and `GET /api/jobs/<id>/logs` showing the command
genuinely executed inside the container (`whoami` -> `ray`, `hostname` ->
the container ID). This is a harmless demonstration command, not a payload.
Illustrates `FINDINGS.md`'s hands-on confirmation that a job can be
submitted and actually run with zero credentials.
**Reproduce:**
```
./scripts/run_ray.sh
curl -X POST http://localhost:12265/api/jobs/ -H 'Content-Type: application/json' \
  -d '{"entrypoint": "echo TEST && whoami && hostname"}'
curl http://localhost:12265/api/jobs/<submission_id>
curl http://localhost:12265/api/jobs/<submission_id>/logs
```

### 03-triton-none-vs-explicit-mode-contrast.png
**Tool:** qterminal (via `termcap.sh`), running the component's own
`scripts/run_triton_none.sh` and `scripts/run_triton_explicit.sh` in
sequence, plus plain `curl` against the model-control API in between.
**Shows:** Triton started in default (`MODE_NONE`) configuration refuses a
`POST /v2/repository/models/identity_demo/load` with `503` and the
documented error message ("explicit model load / unload is not allowed if
polling is enabled"); then, after restarting the same container with
`--model-control-mode=explicit`, the identical unauthenticated request
returns `200`, and a follow-up `GET /v2/models/identity_demo` confirms the
model is genuinely loaded (full I/O schema returned). This is the exact
contrast documented in `FINDINGS.md` section 2: the control endpoint is
refused outright by default, and accepts unauthenticated requests the
moment an operator opts in.
**Reproduce:**
```
./scripts/run_triton_none.sh
curl -X POST http://localhost:12000/v2/repository/models/identity_demo/load   # expect 503
docker rm -f triton-designstudy-none; docker network rm designstudy-triton-net
./scripts/run_triton_explicit.sh
curl -X POST http://localhost:12000/v2/repository/models/identity_demo/load   # expect 200
curl http://localhost:12000/v2/models/identity_demo                          # confirm loaded
```
**Capture note:** `termcap.sh`'s `--rows auto` mode runs the target command
twice (once to measure output length, once for the real capture), which
collides with this script's own port bindings on the second run. This
capture used a fixed `--rows 24` instead of `auto` to avoid that double
execution.

## What was NOT captured

The brief's optional "unauthenticated Ray job submission succeeding" item
was captured (see 02- above), so nothing from the requested scope was
skipped.

## Cleanup

`ray-designstudy`, `ray-designstudy-authmode`, `triton-designstudy-none`,
and `triton-designstudy-explicit` containers, plus the `designstudy-ray-net`
and `designstudy-triton-net` networks, were all removed with the
component's own `scripts/99-cleanup.sh` immediately after the last capture.
Confirmed empty afterward with `docker ps -a` and `docker network ls`. No
Ray or Triton process was left listening on any port.
