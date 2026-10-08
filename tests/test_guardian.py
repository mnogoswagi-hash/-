from __future__ import annotations

import json
import os
import select
import signal
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from brawl_proxy.guardian import lease_ttl


@pytest.mark.parametrize("value", [0.01, 1, 30])
def test_guardian_accepts_only_short_positive_leases(value):
    assert lease_ttl(json.dumps({"ttl": value}).encode()) == float(value)


@pytest.mark.parametrize("message", [
    b'{"ttl":0}', b'{"ttl":-1}', b'{"ttl":31}', b'{"ttl":true}',
    b'{"ttl":"30"}', b'{"ttl":null}', b'{"ttl":NaN}', b'{"ttl":Infinity}',
    b'{"ttl":30,"ttl":1}', b'{"ttl":30,"other":1}', b'[]', b'{}',
    b'{"ttl":' + b'9' * 220 + b'}', b' ' * 257, b'{"ttl":',
])
def test_guardian_rejects_invalid_or_unbounded_leases(message):
    with pytest.raises(ValueError):
        lease_ttl(message)


@pytest.fixture
def guardian_process(tmp_path):
    with socket.socket() as free_socket:
        free_socket.bind(("127.0.0.1", 0))
        port = free_socket.getsockname()[1]
    child = tmp_path / "fake-xray"
    child.write_text(
        "#!" + sys.executable + "\n"
        "import json, os, socket, sys\n"
        "from pathlib import Path\n"
        "config = json.loads(Path(sys.argv[-1]).read_text())\n"
        "listener = socket.socket()\n"
        "listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
        "listener.bind(('127.0.0.1', config['port']))\n"
        "listener.listen()\n"
        "Path(config['pidfile']).write_text(str(os.getpid()))\n"
        "connections = []\n"
        "while True:\n"
        "    connections.append(listener.accept()[0])\n"
    )
    child.chmod(0o700)
    pidfile = tmp_path / "xray.pid"
    configuration = tmp_path / "configuration.json"
    configuration.write_text(json.dumps({"port": port, "pidfile": str(pidfile)}))
    process = subprocess.Popen(
        [sys.executable, "-m", "brawl_proxy.guardian", "--xray", str(child),
         "--config", str(configuration), "--listen-port", str(port)],
        cwd=Path(__file__).resolve().parents[1],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    yield process, port, pidfile
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    for stream in (process.stdin, process.stdout, process.stderr):
        if stream and not stream.closed:
            stream.close()


def start_guardian(process, ttl=1.5):
    process.stdin.write(json.dumps({"ttl": ttl}).encode() + b"\n")
    process.stdin.flush()
    assert select.select([process.stdout], [], [], 3)[0], "No guardian readiness acknowledgement"
    assert json.loads(process.stdout.readline()) == {"ready": True}


def test_expired_lease_closes_an_existing_connection_and_stops_core(guardian_process):
    process, port, pidfile = guardian_process
    start_guardian(process)
    child_pid = int(pidfile.read_text())
    with socket.create_connection(("127.0.0.1", port), timeout=2) as established:
        process.wait(timeout=3)
        assert process.returncode != 0
        established.settimeout(1)
        assert established.recv(1) == b""
    with pytest.raises(ProcessLookupError):
        os.kill(child_pid, 0)


def test_manager_channel_eof_stops_core_before_the_lease_ends(guardian_process):
    process, port, _ = guardian_process
    start_guardian(process, ttl=30)
    with socket.create_connection(("127.0.0.1", port), timeout=2) as established:
        process.stdin.close()
        process.wait(timeout=2)
        established.settimeout(1)
        assert established.recv(1) == b""


def test_guardian_sigkill_cannot_leave_authenticated_core_running(guardian_process):
    process, port, pidfile = guardian_process
    start_guardian(process, ttl=30)
    assert pidfile.exists()
    with socket.create_connection(("127.0.0.1", port), timeout=2) as established:
        process.send_signal(signal.SIGKILL)
        process.wait(timeout=2)
        established.settimeout(2)
        assert established.recv(1) == b""


def test_invalid_initial_lease_never_starts_core(guardian_process):
    process, _port, pidfile = guardian_process
    process.stdin.write(b'{"ttl":900}\n')
    process.stdin.flush()
    process.wait(timeout=2)
    assert process.returncode != 0
    assert not pidfile.exists()
