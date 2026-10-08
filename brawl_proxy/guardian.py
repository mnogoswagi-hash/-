"""Keep Xray alive only while its manager renews a short lease.

The lease is independent of the HTTP server's event loop. Expiry kills Xray,
including established connections; a cached VLESS key cannot outlive it.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import math
import os
import selectors
import signal
import socket
import subprocess
import sys
import time


MAX_TTL = 30.0
INITIAL_TTL = 5.0
MAX_MESSAGE = 256


def parent_death_signal(signum: int) -> None:
    if sys.platform != "linux":
        raise RuntimeError("The Xray guardian requires Linux")
    parent = os.getppid()
    library = ctypes.CDLL(None, use_errno=True)
    if library.prctl(1, signum, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "Cannot protect child process lifetime")
    # Cover the race where the parent dies before prctl is installed.
    if parent == 1 or os.getppid() != parent:
        os.kill(os.getpid(), signum)


def lease_ttl(message: bytes) -> float:
    if len(message) > MAX_MESSAGE:
        raise ValueError("Lease message is too large")

    def unique_keys(items):
        values = {}
        for key, value in items:
            if key in values:
                raise ValueError("Duplicate lease field")
            values[key] = value
        return values

    data = json.loads(message, object_pairs_hook=unique_keys)
    if not isinstance(data, dict) or set(data) != {"ttl"}:
        raise ValueError("Invalid lease message")
    value = data["ttl"]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("Invalid lease duration")
    if not 0 < value <= MAX_TTL:
        raise ValueError("Lease duration is outside the allowed range")
    value = float(value)
    if not math.isfinite(value):
        raise ValueError("Lease duration is outside the allowed range")
    return value


def listening(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.05):
            return True
    except OSError:
        return False


def stop_child(child: subprocess.Popen) -> None:
    if child.poll() is not None:
        return
    # Xray does not own durable shop state. Kill immediately so a graceful
    # shutdown cannot keep authenticated connections alive beyond the lease.
    child.kill()
    child.wait(timeout=2)


def supervise(xray: str, configuration: str, port: int) -> int:
    parent_death_signal(signal.SIGTERM)
    stopping = False

    def stop(_signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    if listening(port):
        raise RuntimeError("The Xray listener port is already in use")
    child = None
    deadline = None
    ready = False
    buffer = bytearray()
    input_fd = sys.stdin.fileno()
    os.set_blocking(input_fd, False)
    selector = selectors.DefaultSelector()

    def receive() -> None:
        nonlocal buffer, deadline
        chunk = os.read(input_fd, MAX_MESSAGE + 1)
        if not chunk:
            raise RuntimeError("The manager closed the lease channel")
        buffer.extend(chunk)
        while b"\n" in buffer:
            message, _, tail = buffer.partition(b"\n")
            buffer = bytearray(tail)
            ttl = lease_ttl(message)
            deadline = time.monotonic() + ttl
        if len(buffer) > MAX_MESSAGE:
            raise ValueError("Lease message is too large")

    try:
        selector.register(input_fd, selectors.EVENT_READ)
        initial_deadline = time.monotonic() + INITIAL_TTL
        while deadline is None and not stopping:
            if time.monotonic() >= initial_deadline:
                return 1
            if selector.select(timeout=0.1):
                receive()
        if stopping:
            return 0
        # There is no listener and no live connection during the initial wait.
        if deadline is None or time.monotonic() >= deadline:
            return 1
        child = subprocess.Popen(
            [xray, "run", "-config", configuration],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=lambda: parent_death_signal(signal.SIGKILL),
        )
        started = time.monotonic()
        while not stopping:
            now = time.monotonic()
            if child.poll() is not None or now >= deadline:
                return 1
            if not ready:
                if now - started > 2.5:
                    return 1
                if listening(port):
                    # Let a failed startup settle before acknowledging readiness.
                    time.sleep(0.05)
                    if child.poll() is not None or time.monotonic() >= deadline:
                        return 1
                    print(json.dumps({"ready": True}), flush=True)
                    ready = True
            for _key, _events in selector.select(timeout=min(0.1, deadline - now)):
                if time.monotonic() >= deadline:
                    return 1
                receive()
        return 0
    finally:
        selector.close()
        if child is not None:
            stop_child(child)


def main() -> None:
    parser = argparse.ArgumentParser(description="Supervise Xray with renewable short leases")
    parser.add_argument("--xray", required=True)
    parser.add_argument("--config", required=True)
    parser.add_argument("--listen-port", type=int, default=443)
    args = parser.parse_args()
    if not 1 <= args.listen_port <= 65535:
        parser.error("Listener port must be between 1 and 65535")
    try:
        result = supervise(args.xray, args.config, args.listen_port)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
        # Never expose Xray configuration contents or command output.
        print("Xray supervision failed; access has been stopped", file=sys.stderr)
        result = 1
    raise SystemExit(result)


if __name__ == "__main__":
    main()
