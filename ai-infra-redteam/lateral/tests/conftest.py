import shutil
import socket
import subprocess
from pathlib import Path

import pytest

LATERAL_ROOT = Path(__file__).resolve().parent.parent
EVIDENCE_ROOT = LATERAL_ROOT / "evidence"


def read_evidence(filename: str) -> str:
    """Read a captured evidence file. Fails the test (not skip) if missing -
    evidence files are checked-in artifacts, not runtime state."""
    path = EVIDENCE_ROOT / filename
    assert path.exists(), f"missing evidence file: {path}"
    return path.read_text()


def port_open(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def container_running(name: str) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        out = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True, text=True, timeout=5,
        )
        return out.returncode == 0 and out.stdout.strip() == "true"
    except (subprocess.TimeoutExpired, OSError):
        return False


def require_live(name: str, host: str, port: int):
    """Skip (not fail) a live test when the target container/port isn't up."""
    if not container_running(name):
        pytest.skip(f"container '{name}' is not running - start the stack with "
                     f"scripts/01-start-stack.sh to run this live test")
    if not port_open(host, port):
        pytest.skip(f"{host}:{port} is not reachable even though '{name}' "
                     f"appears to be running")
