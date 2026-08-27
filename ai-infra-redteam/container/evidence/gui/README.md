# GUI evidence: container/network isolation findings

All images in this directory are real captures: terminal windows running real
`docker run` commands against freshly-built local images, and one generated
matplotlib chart clearly labeled as such. Nothing here is hand-drawn, mocked
up, or rendered from HTML/CSS to look like an application. Every image was
read back and visually confirmed before being kept.

Terminal captures use `wshearer-site/tools/termcap.sh`, which runs the given
command in a real qterminal window on the live X display and photographs only
that window (`import -window <id>`), never the desktop. The underlying
findings are proven in `../` (the numbered `.txt` evidence files cited in
`../../FINDINGS.md`); this directory reproduces the same commands and output
visually, with a real terminal frame around them.

## Images

### 01-capability-comparison-default-privileged-gpus.png
**Tool:** qterminal (via `termcap.sh`), running `docker run` three times
against the project's own `redteam/capcheck:latest` image.
**Shows:** the decoded `CapEff` capability set and count for a default
(unprivileged) container, a `--privileged` container, and a `--gpus all`
container, side by side in one terminal capture. Default and `--gpus all`
both measure 14 effective capabilities; `--privileged` measures 41 on this
kernel (7.0.12+kali-amd64). This directly illustrates the
`FINDINGS.md` claim that `--gpus all`'s capability set is byte-for-byte
identical to the unprivileged default, and that `--privileged` massively
over-grants relative to both.
**Note on the count:** `../../FINDINGS.md`'s summary table cites the
commonly-quoted figure of "38" capabilities for `--privileged`. This box's
own evidence file (`../06-capability-comparison.txt`, decoded and counted
directly) shows 41 on this specific kernel, which defines more capabilities
than older kernels the "38" figure originates from. This image reports the
number actually measured on this box, consistent with `../06-*.txt` and
`../15-*.txt`, not the historical figure.
**Reproduce:**
```
docker build -t redteam/capcheck:latest -f scripts/Dockerfile.capcheck scripts/
docker run --rm redteam/capcheck:latest sh -c 'grep ^CapEff /proc/self/status'
docker run --rm --privileged redteam/capcheck:latest sh -c 'grep ^CapEff /proc/self/status'
docker run --rm --gpus all redteam/capcheck:latest sh -c 'grep ^CapEff /proc/self/status'
# decode each hex value with: capsh --decode=<hex>
```

### 02-cgroupv2-and-no-release-agent.png
**Tool:** qterminal (via `termcap.sh`).
**Shows:** `stat -fc %T /sys/fs/cgroup/` returning `cgroup2fs` and
`mount | grep cgroup` showing exactly one `cgroup2` mount, both run on the
host; then the same `stat` check run inside a `--privileged` container,
plus a `find /sys/fs/cgroup -iname '*release_agent*'` search (inside that
same container) returning nothing. Illustrates the `FINDINGS.md` finding
that the classic `release_agent` cgroup v1 escape does not apply on this
host because no v1 hierarchy, and no `release_agent` file, exists anywhere,
even inside a fully privileged container.
**Reproduce:**
```
stat -fc %T /sys/fs/cgroup/
mount | grep cgroup
docker run --rm --privileged redteam/capcheck:latest sh -c \
  'stat -fc %T /sys/fs/cgroup/; find /sys/fs/cgroup -iname "*release_agent*"'
```

### 03-capability-count-summary-chart.png
**Tool:** matplotlib (Python), a generated static figure - not a screenshot
of any application. Titled "Summary figure" in its own caption so it is
never confused with a live capture.
**Shows:** a bar chart of effective capability counts across six variants
(default, `--gpus all`, `--cap-add=SYS_PTRACE`, `--cap-add=SYS_ADMIN`,
`--cap-add=DAC_READ_SEARCH`, `--privileged`). Every value (14, 14, 15, 15,
15, 41) was counted directly from the decoded `CapEff` lists in
`../06-capability-comparison.txt` and `../15-gpu-capability-and-device-comparison.txt`;
none were invented for the chart. A footnote on the chart itself notes the
discrepancy between the measured 41 and `FINDINGS.md`'s quoted historical
figure of 38.
**Reproduce:** counts are `grep -o 'cap_[a-z_]*' <file> | wc -l` run against
each decoded `CapEff` block in the two evidence files named above; chart
built with matplotlib `bar()` using those six values.

### 04-network-isolation-same-vs-different-network.png
**Tool:** qterminal (via `termcap.sh`), running `docker network create`,
`docker run -d` (a listener, no `-p` flag), and two client containers.
**Shows:** two isolated user-defined bridge networks created fresh; a
listener container on network A opens port 9999 with `docker port` showing
nothing published; a client container also on network A reaches that
unpublished port directly by container IP and prints its response; a client
container on network B, given the identical IP and port, fails with a
connection timeout. This is the live network-isolation demonstration behind
`FINDINGS.md` section 3: containers on the same user-defined bridge network
reach each other's unpublished ports, and containers on a different network
cannot reach either.
**Reproduce:**
```
docker network create redteam-net-a-demo
docker network create redteam-net-b-demo
docker run -d --rm --name netA-listener-demo --network redteam-net-a-demo \
  redteam/capcheck:latest sh -c 'while true; do echo secret-service-on-9999 | nc -l -p 9999; done'
IP=$(docker inspect -f '{{(index .NetworkSettings.Networks "redteam-net-a-demo").IPAddress}}' netA-listener-demo)
docker run --rm --network redteam-net-a-demo redteam/capcheck:latest sh -c "echo | nc -w 2 $IP 9999"
docker run --rm --network redteam-net-b-demo redteam/capcheck:latest sh -c "echo | nc -w 2 -v $IP 9999"
```

## What was NOT captured

Nothing from the requested scope was skipped. All four target items
(capability comparison, cgroup v2 evidence, summary chart, network
isolation) produced real, verified captures.

## Cleanup

All containers and networks created for this capture pass
(`redteam-net-a-demo`, `redteam-net-b-demo`, the `netA-listener-demo`
container, and the temporary `capcheck` runs) were removed with
`docker rm -f` / `docker network rm` immediately after capture; none were
left running. The `redteam/capcheck:latest` image itself (built by the
component's own `scripts/02_flag_comparison.sh`, not by this capture pass)
was left in the local image cache, matching how the rest of the component's
own scripts expect to find it - no running resource was left behind.
