# AI serving infrastructure: an offensive assessment

Most security work on AI systems points at the model. This points at everything
around it: the inference server, the vector database, the orchestrator, and the
containers all of it runs in.

The distinction matters because those two things fail differently. A model that
can be talked into saying something it should not is a model problem. A vector
database that hands a stranger another tenant's documents is an infrastructure
problem, and no amount of prompt filtering fixes it.

Everything here was run on one machine, against containers started for the test.
Nothing was run against an external system. Every number points at the file that
produced it.

## What was found

**A vector database that ignores its own tenant boundaries.** ChromaDB presents a
tenant, database, and collection hierarchy. On read, the first two are decorative.
A request naming a tenant and database that were never created still returns
another tenant's documents. Milvus offers the same mental model to a developer and
enforces it correctly. Two products, identical-looking API, opposite behaviour.

**The most-repeated container escape technique does not work on a current system.**
Search for container escape and you will find the cgroup `release_agent` method
described as the way out of a privileged container. It is a cgroup v1 feature. This
host runs cgroup v2 only, the file the technique writes to does not exist, and the
kernel refuses to mount the legacy hierarchy to create it. Verified by trying,
including under `--privileged` with AppArmor unconfined, then reading the kernel's
own answer with `strace`.

**AI workloads do not need `--privileged` for GPU access, and the tutorials that
say otherwise are giving away 24 capabilities for nothing.** A container using
`--gpus all` has a capability set byte-for-byte identical to an ordinary
unprivileged container. A `--privileged` container has the full set of 38 plus the
raw host disk.

**One foothold reaches the whole stack.** Given code execution in the application
tier of a normal three-service AI deployment, everything else on that Docker network
is reachable with no credentials, whether or not its ports were published. The
attacker can read every tenant's vectors, and list, pull, run, and delete models on
the inference server.

**Two vendors, opposite answers to the same question.** Ray ships its job submission
API enabled and unauthenticated; a CVE was filed and the vendor disputes it, on the
grounds that the documentation always said to run it on a trusted network. Triton
ships the equivalent endpoint switched off and makes the operator ask for it. Both
positions are defensible. Only one of them survives contact with a team that
deployed the container image without reading the security page.

## The components

| Directory | Question it answers |
|---|---|
| [`vectordb/`](vectordb/FINDINGS.md) | Do vector databases isolate tenants by default? |
| [`container/`](container/FINDINGS.md) | What do Docker flags actually grant, and which escapes still work? |
| [`lateral/`](lateral/FINDINGS.md) | What does one compromised container in an AI stack reach? |
| [`designstudy/`](designstudy/FINDINGS.md) | Insecure by design or insecure by default, and does the difference help a defender? |

Each has its own findings document, its own `evidence/` directory holding the raw
captured output, and its own tests pinning the claims.

## Running it

Each component is self-contained. Image tags and digests are pinned.

```bash
cd vectordb && ./scripts/run_chroma.sh      # then see FINDINGS.md
cd container && ./scripts/run_all.sh
cd lateral && ./scripts/01-start-stack.sh
cd designstudy && ./scripts/run_ray.sh
```

Tests run without any containers present. The ones needing a live service skip
rather than fail:

```bash
python3 -m pytest <component>/tests/
```

Every component has a cleanup script. Nothing is left listening.

## What this is not

**No published vulnerability is reproduced here.** Ollama's path traversal, Ray's
unauthenticated job API, ChromaDB's authentication ordering bug, and the Triton
shared-memory chain all have thorough public writeups from the firms that found
them. Repeating that work would add nothing. The contributions here are the four
questions above, which were not already answered.

**Nothing was attacked that is not on this machine.** The lateral movement component
assumes a foothold rather than earning one, and says so. That is the standard
assumed-breach premise, not a claim to have found a way in.

**One technique was deliberately not tested.** `CAP_SYS_MODULE` lets a container load
a kernel module, which is host kernel code execution. Testing it belongs on a
disposable virtual machine, not on a working laptop. It is documented from sources
and marked untested.

**Where a system turned out to be patched, that is what the writeup says.** This host
runs NVIDIA Container Toolkit 1.20.0 and runc 1.3.6, both well past the relevant
container escape fixes. The assessment covers what the configuration exposes, which
is a live question on a fully patched machine.

## A note on sources

Every CVE referenced in any component was checked against NVD, MITRE, or the
project's own security advisory before it was written down. That gate exists because
during research an agent reported CVE-2024-41892 as a Qdrant flaw, sourced from a
search-engine summary. It does not exist. NVD returns nothing, MITRE returns
`CVE_RECORD_DNE`, and the ID appears nowhere in Qdrant's advisories. It would have
been trivially checkable by anyone reading the finished writeup, which is exactly why
it was checked before publishing rather than after.
