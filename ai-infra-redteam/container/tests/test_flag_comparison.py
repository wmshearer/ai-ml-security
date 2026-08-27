"""
Pins the capability/device comparison findings across container flags:
default baseline, --privileged, docker.sock mount, --pid=host, and each
--cap-add variant.
"""
import re
import subprocess

from conftest import read_evidence, requires_docker

DEFAULT_CAP_HEX = "00000000a80425fb"
PRIVILEGED_CAP_HEX = "000001ffffffffff"


def _extract_capeff_values(text: str):
    return re.findall(r"decoded CapEff \(([0-9a-f]+)\)", text)


def test_default_baseline_capability_set():
    text = read_evidence("06-capability-comparison.txt")
    values = _extract_capeff_values(text)
    assert DEFAULT_CAP_HEX in values


def test_privileged_grants_full_capability_set():
    text = read_evidence("06-capability-comparison.txt")
    assert PRIVILEGED_CAP_HEX in _extract_capeff_values(text)
    # privileged effective set must strictly contain the default set's bits
    default_bits = int(DEFAULT_CAP_HEX, 16)
    priv_bits = int(PRIVILEGED_CAP_HEX, 16)
    assert (priv_bits & default_bits) == default_bits
    assert priv_bits > default_bits


def test_privileged_includes_dangerous_capabilities():
    text = read_evidence("06-capability-comparison.txt")
    priv_section = text.split("=== --privileged ===")[1].split("=== --cap-add")[0]
    for cap in ("cap_sys_admin", "cap_sys_module", "cap_sys_ptrace", "cap_dac_read_search"):
        assert cap in priv_section


def test_cap_add_sys_admin_adds_exactly_that_capability():
    text = read_evidence("06-capability-comparison.txt")
    values = _extract_capeff_values(text)
    default_bits = int(DEFAULT_CAP_HEX, 16)
    sys_admin_bit = 1 << 21  # CAP_SYS_ADMIN = 21
    expected = default_bits | sys_admin_bit
    assert f"{expected:016x}" in values


def test_cap_add_sys_ptrace_adds_exactly_that_capability():
    text = read_evidence("06-capability-comparison.txt")
    values = _extract_capeff_values(text)
    default_bits = int(DEFAULT_CAP_HEX, 16)
    sys_ptrace_bit = 1 << 19  # CAP_SYS_PTRACE = 19
    expected = default_bits | sys_ptrace_bit
    assert f"{expected:016x}" in values


def test_cap_add_dac_read_search_adds_exactly_that_capability():
    text = read_evidence("06-capability-comparison.txt")
    values = _extract_capeff_values(text)
    default_bits = int(DEFAULT_CAP_HEX, 16)
    dac_read_search_bit = 1 << 2  # CAP_DAC_READ_SEARCH = 2
    expected = default_bits | dac_read_search_bit
    assert f"{expected:016x}" in values


def test_default_container_lacks_host_device_nodes():
    text = read_evidence("08-privileged-device-node-access.txt")
    default_section = text.split("=== DEFAULT")[1].split("=== --privileged")[0]
    assert "/dev/nvme0n1: ABSENT" in default_section
    assert "/dev/mem: ABSENT" in default_section


def test_privileged_container_has_host_disk_device_node():
    text = read_evidence("08-privileged-device-node-access.txt")
    priv_section = text.split("=== --privileged")[1]
    assert "/dev/nvme0n1: PRESENT" in priv_section
    assert "/dev/mem: PRESENT" in priv_section


def test_privileged_container_can_read_host_disk_readonly():
    text = read_evidence("08-privileged-device-node-access.txt")
    assert "dd+od exit: 0" in text


def test_docker_socket_mount_reaches_engine_api():
    text = read_evidence("09-docker-socket-mount.txt")
    assert '"ApiVersion"' in text
    assert '"Version"' in text


def test_docker_socket_mount_enumerates_containers():
    text = read_evidence("09-docker-socket-mount.txt")
    assert '"Id":"' in text
    assert '"Mounts"' in text


def test_pid_host_exposes_full_host_process_table():
    text = read_evidence("10-pid-host-comparison.txt")
    default_section = text.split("=== DEFAULT")[1].split("=== --pid=host")[0]
    pid_host_section = text.split("=== --pid=host")[1]
    # default container sees only itself
    default_ps_lines = [l for l in default_section.splitlines() if re.match(r"\S+\s+\d+", l)]
    assert len(default_ps_lines) <= 1
    assert "(total lines):" in pid_host_section
    total = int(pid_host_section.split("(total lines):")[1].strip().splitlines()[0])
    assert total > 100  # host process table is large; default was <= 1


def test_pid_host_shows_host_init_process():
    text = read_evidence("10-pid-host-comparison.txt")
    assert "/sbin/init" in text


@requires_docker
def test_live_default_container_capability_count_below_privileged():
    default_result = subprocess.run(
        ["docker", "run", "--rm", "alpine", "sh", "-c", "grep CapEff /proc/self/status"],
        capture_output=True, text=True, timeout=60,
    )
    priv_result = subprocess.run(
        ["docker", "run", "--rm", "--privileged", "alpine", "sh", "-c", "grep CapEff /proc/self/status"],
        capture_output=True, text=True, timeout=60,
    )
    assert default_result.returncode == 0
    assert priv_result.returncode == 0
    default_hex = default_result.stdout.split()[1]
    priv_hex = priv_result.stdout.split()[1]
    assert int(priv_hex, 16) > int(default_hex, 16)
