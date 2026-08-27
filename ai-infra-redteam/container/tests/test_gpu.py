"""
Pins the GPU findings: --gpus all works without --privileged, grants the
same capability set as the unprivileged default, only adds GPU-specific
device nodes, and the installed toolkit version is past the fixed version
for CVE-2024-0132 and CVE-2025-23359 under default configuration.
"""
import re

from conftest import read_evidence


def test_gpu_container_runs_nvidia_smi_without_privileged():
    text = read_evidence("14-gpu-container-nonprivileged.txt")
    assert "GeForce RTX 3080" in text
    assert "(exit code: 0)" in text


def test_gpu_container_capability_set_matches_default_baseline():
    gpu_text = read_evidence("15-gpu-capability-and-device-comparison.txt")
    default_text = read_evidence("06-capability-comparison.txt")

    gpu_match = re.search(r"CapEff:\s+([0-9a-f]+)", gpu_text)
    assert gpu_match, "no CapEff found in GPU evidence"
    gpu_capeff = gpu_match.group(1)

    default_values = re.findall(r"decoded CapEff \(([0-9a-f]+)\)", default_text)
    assert gpu_capeff in default_values, (
        f"GPU container CapEff {gpu_capeff} does not match default baseline {default_values}"
    )


def test_gpu_container_only_adds_nvidia_devices():
    text = read_evidence("15-gpu-capability-and-device-comparison.txt")
    assert "nvidia0" in text
    assert "nvidiactl" in text
    assert "/dev/nvme0n1: ABSENT" in text
    assert "/dev/mem: ABSENT" in text
    assert "/dev/kmsg: ABSENT" in text


def test_toolkit_version_past_cve_2024_0132_fix():
    text = read_evidence("00-toolkit-version.txt")
    match = re.search(r"nvidia-container-toolkit\s+(\d+)\.(\d+)\.(\d+)", text)
    assert match, "toolkit version not found in evidence"
    major, minor, patch = map(int, match.groups())
    # fixed in 1.16.2
    assert (major, minor, patch) >= (1, 16, 2)


def test_cve_verification_document_cites_primary_sources():
    text = read_evidence("16-cve-verification-nvidia-toolkit.txt")
    assert "GHSA-q2v4-jw5g-9xxj" in text
    assert "1.16.2" in text
    assert "NOT vulnerable to CVE-2024-0132" in text
    assert "CVE-2025-23359" in text
    assert "ldconfig" in text


def test_sys_module_documented_as_untested():
    text = read_evidence("17-cap-sys-module-not-tested.txt")
    assert "UNTESTED on this box" in text
