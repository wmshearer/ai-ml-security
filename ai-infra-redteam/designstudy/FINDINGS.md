# Insecure by design vs insecure by default: Ray and Triton

Scope: two components in the AI serving ecosystem, Ray (distributed compute
and orchestration) and NVIDIA Triton Inference Server (model serving), that
made opposite decisions about what ships enabled out of the box. Ray ships
its dashboard and job submission API with no authentication at all, and its
vendor disputes that this is a vulnerability. Triton ships with the runtime
model-management API turned off by default, and only exposes it (still with
no authentication) once an operator explicitly asks for it. Both are
legitimate design philosophies. Both hand a real gap to whoever runs the
software without reading the fine print. Everything below was run against
containers started on this machine for this test; nothing was run against
any external target. Exact commands and raw output are in `evidence/`, and
`tests/` pins every claim to the file that backs it.

## Summary table

| | Ray (job submission API) | Triton (model control API) |
|---|---|---|
| Default state | Enabled, reachable, unauthenticated | Disabled (`MODE_NONE`); load/unload requests are refused |
| What the operator must do to get exposure | Nothing - it is on from `ray start --head` | Add `--model-control-mode=explicit` |
| Auth once exposed | Off by default; a real token-auth feature exists (Ray >= 2.52.0, `RAY_AUTH_MODE=token`) but must be turned on separately | None. No authentication option exists for this endpoint at all |
| Vendor's stated assumption | Trusted network only; Ray "expects to run in a safe network environment and to act upon trusted code" | Not directly stated for this specific endpoint, but implied by the same opt-in design: turning it on is a deliberate operator choice |
| CVE status | CVE-2023-48022, filed, disputed by Anyscale, no fix shipped for the underlying design | CVE-2025-23316, filed, real, patched - exploits the same class of endpoint (model control APIs, Python backend) once exposed |
| Confirmed in this test | Yes, hands-on (see below) | Yes, hands-on (see below) |

Ray version tested: **2.58.0** (`rayproject/ray:2.58.0-py311`,
`sha256:5b4128ad47050e80b08a9fac96187e04e7e6dd13abe3f074813818bc86460afe`).
Triton version tested: **24.12-py3**, server version 2.53.0
(`nvcr.io/nvidia/tritonserver:24.12-py3`,
`sha256:e6d844f6cfd96bf91f021798c20bcdb59b75e490d2c778daec724deaf5221052`).

## 1. Ray: no auth by default, and the vendor disputes that this is a bug

### The vendor dispute, quoted exactly

GitHub Security Advisory **GHSA-6wgj-66m2-xxp2** (CVE-2023-48022, CVSS 9.8,
"Ray has arbitrary code execution via jobs submission API") carries this note
in its own description field, captured via the GitHub Advisories API
(`evidence/ray/ghsa-6wgj-66m2-xxp2.json`):

> "Anyscale Ray allows a remote attacker to execute arbitrary code via the
> job submission API. NOTE: the vendor's position is that this report is
> irrelevant because Ray, as stated in its documentation, is not intended
> for use outside of a strictly controlled network environment."
> -- https://github.com/advisories/GHSA-6wgj-66m2-xxp2

The advisory is marked `"type": "reviewed"` (accepted into the GitHub
Advisory Database) with `"withdrawn_at": null` - it was not pulled, only
disputed. `first_patched_version` is `null`: no version of Ray fixes this
specific report, because Anyscale does not consider it a defect to fix.

### Ray's own documentation backs the vendor's position

This is not spin invented after the fact. Ray's security documentation,
fetched directly from `docs.ray.io` (`evidence/ray/ray-security-index.txt`,
snapshot of `https://docs.ray.io/en/latest/ray-security/index.html`), says
plainly:

> "If you expose these services (Ray Dashboard, Ray Jobs, Ray Client),
> anybody who can access the associated ports can execute arbitrary code on
> your Ray Cluster... The Ray Dashboard, Ray Jobs and Ray Client are
> developer tools that you should only use with the necessary access
> controls in place to restrict access to trusted parties only."

And under "Best practices":

> "Security and isolation must be enforced outside of the Ray Cluster. Ray
> expects to run in a safe network environment and to act upon trusted
> code."

Anyscale's argument is coherent and stated in good faith, not a strawman.
Ray is a distributed compute engine. Its entire job is to run code a client
hands it, across many machines, as fast as possible. Building an
authorization and sandboxing layer into that path would slow down every
legitimate workload to stop a threat model (an untrusted network) that Ray's
own docs say is out of scope by design. Treating "arbitrary code execution
by design" as a defect in a compute engine is a bit like calling `bash -c`
a vulnerability in `bash`.

### What was demonstrated hands-on

Ray 2.58.0 was started in a container with `ray start --head
--dashboard-host=0.0.0.0` and no other flags (`scripts/run_ray.sh`). No
`RAY_AUTH_MODE` or other credential-related environment variable was set.

- `docker exec ray-designstudy env | grep -i RAY_AUTH` returned nothing:
  confirmed no auth-related setting is present in this default container
  (`evidence/ray/07-no-auth-env-var-set.txt`).
- The dashboard's version endpoint answered with zero credentials:
  `curl http://localhost:12265/api/version` returned `200` with the real
  Ray version and session name (`evidence/ray/02-unauth-version-endpoint.txt`).
- The jobs list endpoint answered with zero credentials:
  `curl http://localhost:12265/api/jobs/` returned `200` and `[]`
  (`evidence/ray/03-unauth-list-jobs.txt`).
- **A job was submitted with zero credentials and it actually ran.**
  `POST /api/jobs/` with body
  `{"entrypoint": "echo DESIGNSTUDY_UNAUTH_JOB_SUBMIT_TEST && whoami && hostname"}`
  returned `200` and a job ID
  (`evidence/ray/04-unauth-job-submit-request.txt`). Polling the job showed
  `"status": "SUCCEEDED"` with `"driver_exit_code": 0`
  (`evidence/ray/05-unauth-job-status.txt`), and the captured logs show the
  command actually executed inside the container: `echo`'s marker string,
  `whoami` returning `ray`, and `hostname` returning the container ID
  (`evidence/ray/06-unauth-job-logs.txt`). This is a harmless demonstration
  command, not a payload, and it was not the public ShadowRay proof of
  concept.

### Does this Ray version offer an auth option, and is it on by default?

Yes, and this is a genuinely new development worth flagging plainly: **Ray
added a real, built-in token authentication feature in version 2.52.0**, per
`docs.ray.io/en/latest/ray-security/token-auth.html`
(`evidence/ray/ray-security-token-auth.txt`):

> "To enable token authentication, set the environment variable
> RAY_AUTH_MODE=token before starting your Ray cluster."

And, critically:

> "Authentication is disabled by default in Ray 2.52.0. Ray plans to enable
> token authentication by default in a future release. We recommend enabling
> token authentication to protect your cluster from unauthorized access."

This was confirmed hands-on, not just read from docs:

- Starting a second Ray container with `RAY_AUTH_MODE=token` set but no
  token generated or supplied made Ray **refuse to start at all**, raising
  `ray.exceptions.AuthenticationError: Token authentication is enabled but
  no authentication token was found`
  (`evidence/ray/09-auth-mode-refuses-start-without-token.txt`). Ray does
  not silently start unauthenticated in this mode; it fails closed.
- With `RAY_AUTH_MODE=token` and a token supplied via `RAY_AUTH_TOKEN`, the
  identical unauthenticated request that succeeded against the default
  cluster now returned `401 Unauthorized: Missing authentication token`
  (`evidence/ray/11-authmode-unauth-request-rejected.txt`), and the same
  request with `Authorization: Bearer <token>` returned `200`
  (`evidence/ray/12-authmode-authenticated-request-succeeds.txt`).

So the accurate statement for Ray 2.58.0 is: the auth option exists, it
works as documented, and it is off by default. Anyscale's own documentation
says they intend to flip that default in a future release, which reads as
an implicit acknowledgment that "trusted network only" has not been
sufficient in practice, even while the CVE dispute stands.

## 2. Triton: no auth ever, gated behind an opt-in control mode

### What NVIDIA's own documentation says

Triton's Model Management documentation
(`evidence/triton/triton-model-management.txt`, snapshot of
`https://docs.nvidia.com/deeplearning/triton-inference-server/user-guide/docs/user_guide/model_management.html`)
states three model control modes exist: NONE, EXPLICIT, and POLL. For NONE:

> "Triton attempts to load all models in the model repository at startup...
> Changes to the model repository while the server is running will be
> ignored. Model load and unload requests using the model control protocol
> will have no affect and will return an error response... This is the
> default model control mode."

For EXPLICIT:

> "At startup, Triton loads only those models specified explicitly with the
> --load-model command-line option... This model control mode is enabled by
> specifying --model-control-mode=explicit."

Nothing in this documentation mentions authentication for the model control
API in either mode - there is no auth option to turn on, unlike Ray.

### What was demonstrated hands-on

Triton 24.12-py3 (server version 2.53.0) was started twice against the same
minimal model repository (one Python-backend "identity" model that echoes
its input, `scripts/triton-models/identity_demo/`, chosen because it is
trivial and does no real inference - this test is about the control plane,
not model quality).

**Default (NONE) mode** - `tritonserver --model-repository=/models`, no
other flags (`scripts/run_triton_none.sh`):

- Startup log confirms `model_control_mode | MODE_NONE`
  (`evidence/triton/01-none-mode-startup-log.txt`), matching the documented
  default exactly.
- `POST /v2/repository/models/nonexistent_model/load` returned `503` with
  `{"error":"explicit model load / unload is not allowed if polling is
  enabled"}` (`evidence/triton/03-none-mode-load-endpoint-refused.txt`).
- The same request against `/unload` returned the identical `503` refusal
  (`evidence/triton/04-none-mode-unload-endpoint-refused.txt`).
- In this mode the control endpoint is refused outright, regardless of who
  is asking. There is nothing to authenticate against because the feature
  is off.

**Explicit (opt-in) mode** - the same container image and model repository,
restarted with `--model-control-mode=explicit` added
(`scripts/run_triton_explicit.sh`):

- Startup log confirms `model_control_mode | MODE_EXPLICIT`.
- A load request against a model that does not exist now returns a
  different failure (`500`, "failed to poll from model repository") instead
  of the `503` refusal - proof the endpoint is now live and actually
  processing requests (`evidence/triton/05-explicit-mode-load-nonexistent-model.txt`).
- **`POST /v2/repository/models/identity_demo/load`, with no credentials of
  any kind, returned `200`**
  (`evidence/triton/06-explicit-mode-unauth-load-real-model.txt`). Following
  up with `GET /v2/models/identity_demo` confirmed the model was genuinely
  loaded and ready, returning its full I/O schema
  (`evidence/triton/07-explicit-mode-model-now-ready.txt`).
- **`POST /v2/repository/models/identity_demo/unload`, again with no
  credentials, returned `200`**
  (`evidence/triton/08-explicit-mode-unauth-unload.txt`), and a follow-up
  `GET` on the same model then returned `404 Request for unknown model`
  (`evidence/triton/09-explicit-mode-model-unloaded-confirm.txt`), proving
  the unload actually took effect.

That contrast is the whole finding: the operator has to make an explicit,
documented choice to expose the model control API, and the moment they do,
it accepts unauthenticated requests from anyone who can reach the port. This
is exactly the shape of **CVE-2025-23316**
(GHSA-j8qm-q2p6-5p6q, verified via GitHub's advisory database, CVSS 9.8),
which achieves remote code execution by manipulating the model name
parameter passed to the model control API's Python backend - a vulnerability
that only exists to find because the control API was reachable in the first
place. NVIDIA patched the specific input-validation bug; the underlying
design (opt-in exposure, then no auth) was not changed by that patch.

## 3. Same category, opposite defaults, and what that means

Ray defaults to on and undefends it, on the argument that the network
perimeter is the real boundary and Ray's job is compute, not access control.
Triton defaults to off and, when turned on, provides no defense either - the
opt-in itself is treated as the security control, on the (unstated but
implied) assumption that an operator who explicitly asks for a feature has
already decided to trust whoever can reach it.

Both arguments hold up in the abstract. Neither survives contact with how
these products are actually shipped and run:

- Ray and Triton both ship as container images, meant to be pulled and run
  on cloud VMs, Kubernetes clusters, and shared GPU boxes. "Trusted network
  only" is a deployment-topology assumption baked into documentation prose;
  it is not enforced by the software, the image, or the default port
  binding, all of which default to `0.0.0.0`. Nothing about `docker run
  rayproject/ray` or a Helm chart for Triton stops someone from putting it
  on a network that is not, in fact, trusted.
- The ShadowRay campaign (tracked against CVE-2023-48022, referenced but not
  reproduced in this test) is the direct, observed consequence: real Ray
  dashboards left reachable from the internet, running arbitrary code
  belonging to attackers, years after the vendor's dispute was filed. The
  dispute being correct about Ray's documented intent did not stop the
  documented assumption and the deployed reality from diverging at scale.
  "We told you in the docs" is a true statement about the vendor's
  obligations and an insufficient one about what actually happens to a
  fleet of clusters run by people who never read `ray-security/index.html`.
- Triton's opt-in model is a real improvement over Ray's always-on default -
  fewer instances will ever have the control API exposed at all - but for
  the subset of operators who do turn it on (because they need runtime model
  loading, which is not a rare requirement in a serving platform), the
  outcome is identical to Ray's: zero authentication, full trust in network
  position. The opt-in raises the bar for how many deployments are affected;
  it does not raise the bar for how badly an affected one is exposed.

### The defender's takeaway

Anyone who inherits an AI platform built on components like these needs to
treat "the vendor says this is intended" as a statement about liability, not
a statement about safety. Concretely:

1. **Read the security model before you deploy, not after an incident.**
   Ray's documentation is explicit and public about the trust boundary it
   expects. If that boundary (network isolation) is not something your
   environment actually guarantees, Ray is unsafe to expose in that
   environment regardless of what CVE status its known gaps carry.
2. **Treat "requires an opt-in flag" as a warning label, not a safety net.**
   Triton's `--model-control-mode=explicit` is not a security control; it is
   a feature switch that happens to also be the only thing standing between
   default-safe and default-open. If your deployment pipeline sets that
   flag (or any equivalent one, in any product) for operational convenience,
   confirm what authentication exists behind it before assuming the opt-in
   itself was the safeguard.
3. **Enable what auth exists, immediately, even if it is not the default.**
   Ray's `RAY_AUTH_MODE=token` is a real, working control, confirmed above
   to fail closed and correctly reject unauthenticated requests. It is off
   by default today. Anyscale's own docs say they plan to flip that default
   later. Waiting for the vendor to change the default is optional; turning
   it on now is not.
4. **Assume "designed for trusted networks" means "designed with no
   authentication," and build the trust boundary yourself.** Network
   policies, service mesh authentication, or simply not exposing the
   dashboard/API port beyond a bastion are the actual controls here, not
   anything the software will do for you.

### Connection to the sibling findings

This is the same class of assumption documented elsewhere in this project.
`vectordb/FINDINGS.md` found that all four tested vector databases (Chroma,
Qdrant, Weaviate, Milvus) require no authentication in their default
configuration - the same "reachability is the only real boundary" pattern
seen here for Ray and Triton, just in a different product category.
`container/FINDINGS.md` found that Docker's own default networking model
exposes every unpublished port between containers on the same user-defined
bridge network - meaning that in a typical AI stack (orchestrator, vector
database, and inference server sharing one Compose network), none of these
unauthenticated services are actually protected from each other just
because none of them published a port to the host. An operator who reads
only one of these three components' documentation and concludes "the others
must handle their own security" is repeating the exact reasoning gap this
document set out to find.

## Honest gaps

- The Ray token-auth feature (`RAY_AUTH_MODE=token`) was tested only for the
  pass/fail authentication behavior shown above. Its internal cryptographic
  design, rotation story, and behavior across multi-node clusters were not
  reviewed.
- Triton's model repository used here is a single trivial Python-backend
  model chosen to exercise the control plane. No claim is made about
  Triton's inference-serving behavior, performance, or any backend other
  than `python`.
- CVE-2025-23316's root cause (command injection via the model name
  parameter in the Python backend) was not reproduced. It is cited only to
  establish that the endpoint this document demonstrates being reachable
  without authentication is the same endpoint class a real, patched RCE
  targeted, not as a claim that this test triggered or verified that
  specific bug.
- This document does not evaluate Ray Client or Ray Serve specifically,
  only the Dashboard/Jobs HTTP API, which is what CVE-2023-48022 and the
  hands-on demonstration above both target.
