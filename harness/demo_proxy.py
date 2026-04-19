"""Scenario 13 — Loopback-only HTTP proxy that logs request lines.

This proxy is deliberately simple: it binds 127.0.0.1 only, accepts a
connection, reads the request/CONNECT line, logs it to `DEMO_PROXY_LOG`, then
returns 502 so the upstream git operation falls back to its configured
origin. No TLS interception. No payload inspection. Its only job is to
demonstrate that a malicious plugin could insert a git proxy directive and
observe the targets of clone/fetch operations.
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
import time
from datetime import UTC, datetime
from pathlib import Path


def _log_line(entry: dict[str, object]) -> None:
    path = Path(os.environ.get("DEMO_PROXY_LOG", "capture/proxy.log"))
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps({"ts": datetime.now(tz=UTC).isoformat(), **entry}) + "\n")


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline(1024).decode("latin-1", "replace").strip()
        peer_host = self.client_address[0] if self.client_address else ""
        _log_line({"target": request_line, "peer": peer_host})
        # Drain headers, then close. Git falls back to direct origin on proxy failure.
        while True:
            line = self.rfile.readline(4096)
            if line in (b"\r\n", b"\n", b""):
                break
        self.wfile.write(b"HTTP/1.1 502 Demo Proxy\r\nConnection: close\r\n\r\n")


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def start(
    host: str = "127.0.0.1",
    port: int = 0,
    lifetime_s: int = 60,
) -> tuple[_ThreadedServer, int]:
    """Start the loopback proxy. Refuses any non-loopback host."""
    if host != "127.0.0.1":
        raise RuntimeError(f"demo_proxy refuses non-loopback bind: {host!r}")
    srv = _ThreadedServer((host, port), _Handler)
    actual_port: int = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()

    def _stop_later() -> None:
        time.sleep(lifetime_s)
        srv.shutdown()

    threading.Thread(target=_stop_later, daemon=True).start()
    return srv, actual_port


if __name__ == "__main__":
    _srv, _port = start()
    print(f"demo_proxy on 127.0.0.1:{_port}")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _srv.shutdown()
