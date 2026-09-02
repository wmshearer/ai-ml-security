"""
Live tests against the actual running stack. Each one SKIPS cleanly if the
relevant container is not running (start it with scripts/01-start-stack.sh),
rather than failing the suite when containers are absent. These re-run the
same checks captured as evidence, directly against a live stack, so the
chain can be independently re-verified rather than only replayed from
captured text.
"""
import subprocess

import pytest
import requests

from tests.conftest import require_live

CHROMA_HOST_PORT = 18001
OLLAMA_HOST_PORT = 11434
APP_HOST_PORT = 19000


def test_app_health_live():
    require_live("lateral-app", "localhost", APP_HOST_PORT)
    r = requests.get(f"http://localhost:{APP_HOST_PORT}/health", timeout=5)
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_chroma_no_auth_required_live():
    require_live("lateral-chroma", "localhost", CHROMA_HOST_PORT)
    r = requests.get(f"http://localhost:{CHROMA_HOST_PORT}/api/v2/heartbeat", timeout=5)
    assert r.status_code == 200


def test_ollama_no_auth_required_live():
    require_live("lateral-ollama", "localhost", OLLAMA_HOST_PORT)
    r = requests.get(f"http://localhost:{OLLAMA_HOST_PORT}/api/tags", timeout=5)
    assert r.status_code == 200


def test_foothold_reaches_peers_by_container_dns_live():
    """Re-runs step 1 live: exec into lateral-app and confirm it can reach
    both peers on their internal ports, exactly as evidence/01- captured."""
    require_live("lateral-app", "localhost", APP_HOST_PORT)
    require_live("lateral-chroma", "localhost", CHROMA_HOST_PORT)
    require_live("lateral-ollama", "localhost", OLLAMA_HOST_PORT)
    script = (
        "import socket\n"
        "for host, port in [('lateral-chroma', 8000), ('lateral-ollama', 11434)]:\n"
        "    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    s.settimeout(3)\n"
        "    s.connect((host, port))\n"
        "    s.close()\n"
        "print('OK')\n"
    )
    out = subprocess.run(
        ["docker", "exec", "lateral-app", "python3", "-c", script],
        capture_output=True, text=True, timeout=15,
    )
    assert out.returncode == 0, out.stderr
    assert "OK" in out.stdout


def test_network_segmentation_control_live():
    """Re-runs the defensive-conclusion control live: a fresh container on
    a DIFFERENT network cannot resolve either peer by name. Creates and
    tears down its own throwaway network/container; does not touch the
    stack's own lateral-net."""
    require_live("lateral-chroma", "localhost", CHROMA_HOST_PORT)
    require_live("lateral-ollama", "localhost", OLLAMA_HOST_PORT)

    net = "lateral-net-pytest-control"
    container = "lateral-pytest-control-isolated"
    subprocess.run(["docker", "network", "create", net], capture_output=True)
    try:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        run = subprocess.run(
            ["docker", "run", "-d", "--name", container, "--network", net,
             "python:3.12-slim", "sleep", "60"],
            capture_output=True, text=True, timeout=60,
        )
        assert run.returncode == 0, run.stderr

        script = (
            "import socket\n"
            "for host, port in [('lateral-chroma', 8000), ('lateral-ollama', 11434)]:\n"
            "    try:\n"
            "        socket.gethostbyname(host)\n"
            "        print(f'{host}: RESOLVED (unexpected)')\n"
            "    except socket.gaierror:\n"
            "        print(f'{host}: DNS FAILED')\n"
        )
        out = subprocess.run(
            ["docker", "exec", container, "python3", "-c", script],
            capture_output=True, text=True, timeout=15,
        )
        assert "lateral-chroma: DNS FAILED" in out.stdout
        assert "lateral-ollama: DNS FAILED" in out.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True)
        subprocess.run(["docker", "network", "rm", net], capture_output=True)
