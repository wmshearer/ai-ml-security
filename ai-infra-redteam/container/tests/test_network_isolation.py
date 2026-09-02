"""
Pins the Docker bridge network isolation findings: same user-defined
network exposes unpublished ports between containers; different
user-defined networks do not reach each other; the host cannot reach an
unpublished port either.
"""
import re
import subprocess
import time

from conftest import read_evidence, requires_docker


def test_listener_had_no_published_ports():
    text = read_evidence("12-network-listener-setup.txt")
    assert "empty output confirmed = no published ports" in text


def test_same_network_container_reaches_unpublished_port():
    text = read_evidence("13-network-isolation-tests.txt")
    test_a = text.split("=== Test A")[1].split("=== Test B")[0]
    assert "secret-service-on-9999" in test_a
    assert "(exit code: 0)" in test_a


def test_different_network_container_cannot_reach_target():
    text = read_evidence("13-network-isolation-tests.txt")
    test_b = text.split("=== Test B")[1].split("=== Test C")[0]
    assert "exit:1" in test_b or "Connection timed out" in test_b


def test_host_cannot_reach_unpublished_port():
    text = read_evidence("13-network-isolation-tests.txt")
    test_c = text.split("=== Test C")[1]
    assert "host-curl-exit:7" in test_c or "host-curl-exit:" in test_c
    assert "host-curl-exit:0" not in test_c


def test_docker_bridge_docs_citation_present():
    html = read_evidence("docker-bridge-docs-snapshot.html")
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)
    assert "expose all ports to each other" in text


@requires_docker
def test_live_network_isolation_end_to_end():
    net_a, net_b = "pytest-redteam-net-a", "pytest-redteam-net-b"
    listener = "pytest-redteam-listener"
    try:
        subprocess.run(["docker", "network", "rm", net_a, net_b],
                        capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", "-f", listener],
                        capture_output=True, timeout=30)

        assert subprocess.run(["docker", "network", "create", net_a],
                               capture_output=True, timeout=30).returncode == 0
        assert subprocess.run(["docker", "network", "create", net_b],
                               capture_output=True, timeout=30).returncode == 0

        run = subprocess.run(
            ["docker", "run", "-d", "--rm", "--name", listener,
             "--network", net_a, "alpine",
             "sh", "-c", "nc -lk -p 9999 -e /bin/echo pytest-secret || "
                         "while true; do echo pytest-secret | nc -l -p 9999; done"],
            capture_output=True, text=True, timeout=60,
        )
        assert run.returncode == 0, run.stderr
        time.sleep(1)

        # confirm no published ports
        port_check = subprocess.run(["docker", "port", listener],
                                     capture_output=True, text=True, timeout=30)
        assert port_check.stdout.strip() == ""

        ip_result = subprocess.run(
            ["docker", "inspect", "-f",
             f'{{{{(index .NetworkSettings.Networks "{net_a}").IPAddress}}}}', listener],
            capture_output=True, text=True, timeout=30,
        )
        listener_ip = ip_result.stdout.strip()
        assert listener_ip

        same_net = subprocess.run(
            ["docker", "run", "--rm", "--network", net_a, "alpine",
             "sh", "-c", f"echo | nc -w 2 {listener_ip} 9999"],
            capture_output=True, text=True, timeout=30,
        )
        assert "pytest-secret" in same_net.stdout

        diff_net = subprocess.run(
            ["docker", "run", "--rm", "--network", net_b, "alpine",
             "sh", "-c", f"echo | nc -w 2 {listener_ip} 9999; echo RC:$?"],
            capture_output=True, text=True, timeout=30,
        )
        assert "pytest-secret" not in diff_net.stdout
    finally:
        subprocess.run(["docker", "rm", "-f", listener], capture_output=True, timeout=30)
        subprocess.run(["docker", "network", "rm", net_a, net_b], capture_output=True, timeout=30)
