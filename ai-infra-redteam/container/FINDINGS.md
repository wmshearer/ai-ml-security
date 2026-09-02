# Container and network isolation: findings

Scope: what a Docker-hosted workload actually exposes on this box, and which
widely-repeated container escape techniques still work on a current default
system. Everything below was run against containers started for this test on
this machine. Nothing was run against an external target. Exact commands and
raw output are in `evidence/`; every claim below points at the file that backs
it.

Host facts confirmed during this work: kernel 7.0.12+kali-amd64, Docker
28.5.2+dfsg4, runc 1.3.6+ds1, cgroup v2 only (systemd driver), AppArmor and
seccomp enabled by default, NVIDIA Container Toolkit 1.20.0, GPU is an RTX
3080 Laptop.

## Summary table

| Area | Finding | Evidence |
|---|---|---|
| release_agent escape (cgroup v1) | Does not apply. This host is cgroup v2 only, no v1 hierarchy exists anywhere, and the file the technique writes to does not exist. | `evidence/01-*`, `evidence/02-*`, `evidence/05-*` |
| `--privileged` | Grants the full capability set (41 capabilities vs 14 default, decoded from CapEff 0x1ffffffffff vs 0xa80425fb) and access to every host device node, including the raw disk. Not blocked by cgroup version. | `evidence/06-*`, `evidence/07-*`, `evidence/08-*` |
| Docker socket mount | Full Docker Engine API reachable from inside the container. Container listing, version, and (per Docker's own docs) host root all follow from this. | `evidence/09-*` |
| `--pid=host` | Every host process, including PID 1, is visible from inside the container. | `evidence/10-*` |
| `--cap-add=SYS_ADMIN` / `SYS_PTRACE` / `DAC_READ_SEARCH` | Each adds exactly the named capability on top of the default set. Measured precisely via `/proc/self/status`. | `evidence/06-*` |
| `CAP_SYS_MODULE` | Not tested. Would give host kernel code execution; excluded because this is the operator's primary machine. Documented from sources instead. | `evidence/17-*` |
| Docker bridge network isolation | Confirmed as documented: same user-defined network exposes all ports to each other regardless of publishing; different networks cannot reach each other at all. | `evidence/11-*` through `13-*`, Docker docs |
| GPU passthrough | `--gpus all` works fully without `--privileged`. Capability set is identical to the unprivileged default; only four NVIDIA device nodes are added. | `evidence/14-*`, `evidence/15-*` |
| CVE-2024-0132 (NVIDIA Container Toolkit TOCTOU) | Fixed in 1.16.2. This box runs 1.20.0. Not vulnerable. | `evidence/16-*` |
| CVE-2025-23359 (incomplete fix for the above, found independently during this review) | Affects default config on toolkit <= 1.17.3, or 1.17.4+ only if the non-default `allow-cuda-compat-libs-from-container` option is enabled. This box runs 1.20.0 with the default `cuda-compat-mode = "ldconfig"`. Not vulnerable. | `evidence/16-*` |
| runc container-breakout CVEs (CVE-2019-5736, CVE-2024-21626) | Both predate this host's runc 1.3.6. Not checked further beyond version comparison; no exploit attempted. | `evidence/00-toolkit-version.txt`, host facts above |

## 1. The release_agent folklore does not apply here

This is the escape technique that shows up in almost every "container escape"
blog post: write a `release_agent` script into a crafted cgroup v1 hierarchy,
trigger it, and it runs as the host. It requires cgroup v1.

This host boots with cgroup v2 only.

- `stat -fc %T /sys/fs/cgroup/` returns `cgroup2fs` (`evidence/01-host-cgroup-facts.txt`).
- `mount | grep cgroup` shows exactly one mount, type `cgroup2`, no v1
  hierarchy mounted anywhere on the host (`evidence/01-host-cgroup-facts.txt`).
- `find /sys/fs/cgroup -iname release_agent` returns nothing, on the host and
  inside a `--privileged` container (`evidence/01-*`, `evidence/02-*`).
- Inside a `--privileged` Alpine container, the classic PoC's first step
  (create a cgroup and expect a `release_agent` knob in it) fails: the new
  cgroup has no such file (`evidence/02-privileged-release-agent-attempt.txt`).
- The PoC's fallback move, explicitly mounting the legacy `cgroup` filesystem
  type for a controller (`mount -t cgroup -o rdma cgroup /mnt`), fails even
  with `--privileged`, even with AppArmor set to `unconfined`
  (`evidence/03-cgroupv1-mount-blocked-even-unconfined.txt`). `strace` on that
  mount call shows the kernel returning `EPERM`
  (`evidence/05-cgroupv1-mount-strace.txt`). The reason: on this host every
  cgroup controller is already attached to the unified (v2) hierarchy, and the
  kernel will not let the same controller also be mounted through the legacy
  v1 interface at the same time. `cgroup` (v1) is still a registered
  filesystem type in `/proc/filesystems`, but there is nothing left for it to
  attach to.

**Verdict: the release_agent technique's precondition does not exist on this
system. The most commonly repeated container-escape blog post technique does
not work here.**

This is a statement about cgroup v2 hosts, not a claim that privileged
containers are safe in general. See the next section: `--privileged` still
hands out very real access on this exact host, just through different doors.

## 2. What each flag actually grants

Baseline (default container, no extra flags): 14 effective capabilities
(`cap_chown, cap_dac_override, cap_fowner, cap_fsetid, cap_kill, cap_setgid,
cap_setuid, cap_setpcap, cap_net_bind_service, cap_net_raw, cap_sys_chroot,
cap_mknod, cap_audit_write, cap_setfcap`), own PID namespace, no host device
nodes beyond the minimal safe set (`/dev/null`, `/dev/zero`, ttys, etc).
Source: `evidence/06-capability-comparison.txt`.

**`--privileged`**: effective capability set jumps from 14 to 41 (everything
the kernel defines, including `cap_sys_admin`, `cap_sys_module`,
`cap_sys_ptrace`, `cap_dac_read_search`, `cap_sys_boot`, `cap_mac_admin`, and
so on) (`evidence/06-capability-comparison.txt`). `/dev` inside the container
gains real device nodes for the host's NVMe disk, `/dev/mem`, `/dev/kmsg`,
`/dev/dm-*`, the NVIDIA GPU devices, `/dev/kvm`, and more
(`evidence/07-privileged-device-visibility.txt`). This was confirmed with a
read-only `dd` of the first 64 bytes of `/dev/nvme0n1` from inside the
container, which succeeded (`evidence/08-privileged-device-node-access.txt`).
No write was performed against any host device.

**`-v /var/run/docker.sock:/var/run/docker.sock`**: with the socket mounted,
a plain `curl --unix-socket` from inside the container reaches the full
Docker Engine API: `/version` returns the host's Docker/runc/containerd
versions, and `/containers/json?all=true` lists every container on the host,
including itself (`evidence/09-docker-socket-mount.txt`). This test stopped
there. Docker's own documentation states plainly that mounting the daemon
socket into a container is equivalent to giving that container root on the
host, because the API can be used to launch a new container with arbitrary
host bind mounts and privileges. That step was not performed here, only cited:
see "Docker security" at
https://docs.docker.com/engine/security/#docker-daemon-attack-surface, which
warns that anyone with access to the daemon socket has effective root on the
host.

**`--pid=host`**: `ps aux` inside a default container shows exactly one
process (itself). With `--pid=host` it shows the full host process table,
571 lines including the host's real PID 1 (`/sbin/init splash`)
(`evidence/10-pid-host-comparison.txt`). Anything running on the host with
secrets in its command line is visible to anything running with this flag.

**`--cap-add=SYS_ADMIN`**: default set plus `cap_sys_admin` only. `SYS_ADMIN`
is broad on its own (multiple `mount`, cgroup, and namespace operations
gate on it) but this test only measured the capability grant itself, not
what can be built from it (`evidence/06-capability-comparison.txt`).

**`--cap-add=SYS_PTRACE`**: default set plus `cap_sys_ptrace` only. This
lets the container `ptrace` other processes it can otherwise see (which,
without `--pid=host`, is just its own PID namespace)
(`evidence/06-capability-comparison.txt`).

**`--cap-add=DAC_READ_SEARCH`**: default set plus `cap_dac_read_search` only.
This bypasses file read/directory-search permission checks and also implies
the ability to use `open_by_handle_at`, a known building block in published
container-escape chains, though that chain was not built or tested here
(`evidence/06-capability-comparison.txt`).

**`CAP_SYS_MODULE`**: not tested. This capability lets a container load an
arbitrary kernel module into the host's running kernel; the module executes
as the host kernel, with no container boundary at all. Testing it live would
mean loading code into the kernel of the machine this session is running on.
Documented instead of demonstrated: Docker's own docs list `SYS_MODULE`
among the capabilities excluded from the default set precisely because of
this risk (`evidence/17-cap-sys-module-not-tested.txt`,
https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities).

## 3. Docker network isolation: the common assumption is backwards

Most people assume that if a container's port isn't published with `-p`, no
other container can reach it either. Docker's own documentation says the
opposite for containers sharing a user-defined bridge network:

> "Containers connected to the same user-defined bridge network effectively
> expose all ports to each other. For a port to be accessible to containers
> or non-Docker hosts on different networks, that port must be published
> using the -p or --publish flag."
> -- https://docs.docker.com/engine/network/drivers/bridge/
> (snapshot: `evidence/docker-bridge-docs-snapshot.html`)

Confirmed directly:

- Two user-defined bridge networks were created, `redteam-net-a` and
  `redteam-net-b` (`evidence/11-network-isolation-setup.txt`).
- A listener container on `redteam-net-a` opened port 9999 with **no**
  `-p` flag at all. `docker port` on it returns nothing, confirming zero
  ports are published to the host (`evidence/12-network-listener-setup.txt`).
- A second container also on `redteam-net-a` connected to that unpublished
  port directly by container IP and retrieved its response
  (`evidence/13-network-isolation-tests.txt`, Test A). The unpublished port
  was fully reachable from another container on the same network.
- A third container on the different network, `redteam-net-b`, tried the
  same connection to the same IP and port and timed out
  (`evidence/13-network-isolation-tests.txt`, Test B). Different
  user-defined networks are isolated from each other by default.
- From the host itself, the port was unreachable (`curl` failed, exit 7)
  (`evidence/13-network-isolation-tests.txt`, Test C), confirming that
  publishing controls reachability from outside Docker, not reachability
  between containers.

This matters directly for AI stacks: an inference server, a vector database,
and an orchestrator on one Docker Compose network can all reach every port
each other exposes, whether or not any of them were published, purely by
being on the same network. Segmenting services onto separate user-defined
networks, not just omitting `-p`, is what actually restricts that.

## 4. GPU containers do not need `--privileged`

Common advice, especially in AI/ML tutorials, is to run GPU workloads with
`--privileged` "to be safe" or because passthrough didn't work otherwise.
On this box, with NVIDIA Container Toolkit 1.20.0, that is unnecessary and
over-grants access.

- `docker run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi`
  (no `--privileged`) succeeded and correctly reported the RTX 3080 Laptop
  GPU, driver 550.163.01 (`evidence/14-gpu-container-nonprivileged.txt`).
- The effective capability set inside that container is
  `00000000a80425fb`, byte-for-byte identical to the unprivileged default
  baseline. `--gpus all` adds zero Linux capabilities
  (`evidence/15-gpu-capability-and-device-comparison.txt`, compare against
  `evidence/06-capability-comparison.txt`).
- The only devices it adds are four NVIDIA-specific nodes: `nvidia0`,
  `nvidiactl`, `nvidia-uvm`, `nvidia-uvm-tools`. It has none of the host
  devices `--privileged` exposes: `/dev/nvme0n1`, `/dev/mem`, and `/dev/kmsg`
  are all absent (`evidence/15-gpu-capability-and-device-comparison.txt`).

**Finding: the toolkit's device-injection model grants exactly what's needed
for GPU compute and nothing else. Tutorials that recommend `--privileged`
for GPU access are over-granting: the same GPU capability is achievable with
zero extra Linux capabilities and no host device exposure beyond the GPU
itself.**

Toolkit version and CVE status, checked directly rather than assumed:

- Installed: NVIDIA Container Toolkit 1.20.0
  (`evidence/00-toolkit-version.txt`).
- **CVE-2024-0132** (TOCTOU vulnerability allowing a crafted container image
  to reach the host filesystem): fixed upstream in 1.16.2, per NVIDIA's own
  GitHub Security Advisory GHSA-q2v4-jw5g-9xxj
  (`evidence/github-advisory-GHSA-q2v4-jw5g-9xxj.html`). This box runs
  1.20.0, four minor releases past the fix. **Not vulnerable.**
- While verifying that, this review found a second, distinct CVE that the
  original task brief did not mention: **CVE-2025-23359**
  (GHSA-4hmh-pm5p-9j7j, verified via the GitHub Advisory Database API,
  `evidence/github-advisory-GHSA-4hmh-pm5p-9j7j.json`), which documents that
  NVIDIA's initial 1.16.2 fix for the TOCTOU issue was incomplete. Per Trend
  Micro's technical writeup (`evidence/trendmicro-incomplete-patch-snapshot.html`),
  default configurations of toolkit versions up to 1.17.3 remained
  vulnerable, and 1.17.4 and later are only exploitable if the non-default
  `allow-cuda-compat-libs-from-container` option is turned on. This box runs
  1.20.0 (past 1.17.4) with the default `cuda-compat-mode = "ldconfig"`
  setting confirmed in `/etc/nvidia-container-runtime/config.toml`
  (`evidence/16-cve-verification-nvidia-toolkit.txt`). **Not vulnerable to
  this one either, given version and default configuration.**

## Honest gaps

- `CAP_SYS_MODULE` was not tested live, by design (see above). The claim
  about it is sourced, not measured on this box.
- The exact kernel-internal reason a controller cannot be attached to both
  v1 and v2 hierarchies simultaneously was confirmed via observed `EPERM`
  behavior (`strace`), not by reading kernel source. The behavior is
  consistent and reproducible on this host across two independent attempts
  (`--privileged` alone, and `--privileged` plus AppArmor unconfined), which
  is enough to support the finding without needing the source-level proof.
- `SYS_ADMIN`, `SYS_PTRACE`, and `DAC_READ_SEARCH` were measured only for
  the capability grant itself, not for what a full exploit chain built on
  top of them could reach. That was out of scope for this pass.
- CVE-2019-5736 and CVE-2024-21626 (runc) were checked by version comparison
  only (runc 1.3.6 postdates both fixes); no exploit was attempted against
  either.
