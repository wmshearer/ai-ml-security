import shutil
import subprocess
from pathlib import Path

import pytest

CONTAINER_DIR = Path(__file__).resolve().parent.parent
EVIDENCE_DIR = CONTAINER_DIR / "evidence"


def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"], capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


requires_docker = pytest.mark.skipif(
    not docker_available(), reason="Docker is not available on this system"
)


def read_evidence(name: str) -> str:
    path = EVIDENCE_DIR / name
    if not path.exists():
        pytest.skip(f"evidence file not captured: {name}")
    return path.read_text(errors="replace")
