"""
Pins the release_agent finding: this host is cgroup v2 only, and the
classic cgroup v1 release_agent escape precondition is absent, including
inside a --privileged container.

The evidence-parsing tests run without Docker. The live tests re-verify
against the running system and are skipped cleanly if Docker is unavailable.
"""
import subprocess

from conftest import read_evidence, requires_docker


def test_host_cgroup_is_v2():
    text = read_evidence("01-host-cgroup-facts.txt")
    assert "cgroup2fs" in text
    assert "type cgroup2" in text


def test_host_has_no_v1_hierarchy_mounted():
    text = read_evidence("01-host-cgroup-facts.txt")
    # mount | grep cgroup should show only the cgroup2 line, never a
    # legacy "type cgroup" (v1) mount.
    mount_lines = [
        line for line in text.splitlines() if " on " in line and "cgroup" in line
    ]
    assert mount_lines, "expected at least one cgroup mount line in evidence"
    for line in mount_lines:
        assert "type cgroup2" in line, f"unexpected v1-style mount found: {line}"


def test_no_release_agent_file_found_on_host():
    text = read_evidence("01-host-cgroup-facts.txt")
    assert "(exit code: 0)" in text
    # find with no matches still exits 0 and prints nothing; confirm the
    # find command block produced no path output before its exit code line.
    idx = text.find("find /sys/fs/cgroup -maxdepth 2 -iname")
    assert idx != -1
    following = text[idx:idx + 300]
    assert "release_agent" not in following.split("\n", 1)[1].split("(exit code")[0]


def test_privileged_container_lacks_v1_release_agent_file():
    text = read_evidence("02-privileged-release-agent-attempt.txt")
    assert "ABSENT - v1 release_agent file does not exist on cgroup v2" in text
    assert "find exit code: 0" in text


def test_cgroupv1_mount_blocked_even_unconfined():
    text = read_evidence("03-cgroupv1-mount-blocked-even-unconfined.txt")
    assert "mount exit:1" in text or "permission denied" in text


def test_cgroupv1_mount_fails_with_eperm():
    text = read_evidence("05-cgroupv1-mount-strace.txt")
    assert "EPERM" in text
    assert 'mount("cgroup"' in text


@requires_docker
def test_live_privileged_container_has_no_release_agent_file():
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--privileged", "alpine", "sh", "-c",
            "find /sys/fs/cgroup -iname release_agent | wc -l",
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "0"


@requires_docker
def test_live_privileged_container_sees_cgroup2_only():
    result = subprocess.run(
        [
            "docker", "run", "--rm", "--privileged", "alpine", "sh", "-c",
            "mount | grep cgroup",
        ],
        capture_output=True, text=True, timeout=60,
    )
    assert result.returncode == 0
    assert "cgroup2" in result.stdout
    for line in result.stdout.splitlines():
        assert "type cgroup2" in line or "cgroup" not in line
