#!/bin/bash
# Empirically checks whether the classic cgroup v1 release_agent container-escape
# precondition exists on this host, and shows what --privileged still exposes
# by other means. Writes evidence to ../evidence/.
#
# Safe: reads host state only, attempts one mount that is expected to fail,
# does not write to any host filesystem.
set -uo pipefail
cd "$(dirname "$0")/.."
EV=evidence
mkdir -p "$EV"

echo "[1/5] Host cgroup facts"
{
  echo "\$ stat -fc %T /sys/fs/cgroup/"
  stat -fc %T /sys/fs/cgroup/
  echo
  echo "\$ mount | grep cgroup"
  mount | grep cgroup
  echo
  echo "\$ cat /proc/filesystems | grep cgroup"
  cat /proc/filesystems | grep cgroup
  echo
  echo "\$ ls /sys/fs/cgroup/ | head -30"
  ls /sys/fs/cgroup/ | head -30
  echo
  echo "\$ find /sys/fs/cgroup -maxdepth 2 -iname '*release_agent*'"
  find /sys/fs/cgroup -maxdepth 2 -iname '*release_agent*' 2>&1
  echo "(exit code: $?)"
  echo
  echo "\$ find / -xdev -maxdepth 4 -iname 'cgroup' -type d 2>/dev/null"
  find / -xdev -maxdepth 4 -iname 'cgroup' -type d 2>/dev/null
} > "$EV/01-host-cgroup-facts.txt" 2>&1

echo "[2/5] Attempt the classic release_agent PoC steps inside --privileged"
docker run --rm --privileged alpine sh -c '
  echo "--- inside container ---";
  echo "mount | grep cgroup:";
  mount | grep cgroup;
  echo;
  echo "ls /sys/fs/cgroup:";
  ls /sys/fs/cgroup | head -30;
  echo;
  echo "Does a v1-style release_agent file exist anywhere under /sys/fs/cgroup?";
  find /sys/fs/cgroup -iname "release_agent" 2>&1;
  echo "find exit code: $?";
  echo;
  mkdir -p /sys/fs/cgroup/poc_test 2>&1;
  ls /sys/fs/cgroup/poc_test 2>&1;
  test -f /sys/fs/cgroup/poc_test/release_agent && echo "PRESENT (v1 behavior)" || echo "ABSENT - v1 release_agent file does not exist on cgroup v2";
  rmdir /sys/fs/cgroup/poc_test 2>&1;
  echo;
  mkdir -p /mnt/cgroupv1_test;
  mount -t cgroup -o rdma cgroup /mnt/cgroupv1_test 2>&1;
  echo "mount exit code: $?";
  umount /mnt/cgroupv1_test 2>/dev/null;
' > "$EV/02-privileged-release-agent-attempt.txt" 2>&1

echo "[3/5] Confirm the mount attempt fails even with AppArmor unconfined"
docker run --rm --privileged --security-opt apparmor=unconfined alpine sh -c \
  'mkdir -p /mnt/t; mount -t cgroup -o rdma cgroup /mnt/t 2>&1; echo "mount exit:$?"' \
  > "$EV/03-cgroupv1-mount-blocked-even-unconfined.txt" 2>&1

echo "[4/5] Root cause: strace the mount syscall for the real errno"
docker run --rm --privileged --security-opt apparmor=unconfined --security-opt seccomp=unconfined alpine sh -c \
  'apk add --no-cache strace >/dev/null 2>&1; mkdir -p /mnt/t3; strace -f -e trace=mount mount -t cgroup -o rdma cgroup /mnt/t3 2>&1' \
  > "$EV/05-cgroupv1-mount-strace.txt" 2>&1

echo "[5/5] Done. See evidence/01-*.txt through evidence/05-*.txt"
