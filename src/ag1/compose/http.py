"""Plain HTTP and JSON between services, on the standard library."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable
from urllib.error import HTTPError
from urllib.request import Request, urlopen

Handler = Callable[[dict], dict]


class RemoteError(RuntimeError):
    def __init__(self, status: int, body: dict) -> None:
        super().__init__(f"{status}: {body.get('error', body)}")
        self.status = status
        self.body = body


def call(url: str, body: dict | None = None, timeout: float = 120) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, method="POST" if body is not None else "GET",
                  headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read() or b"{}")
    except HTTPError as exc:
        try:
            payload = json.loads(exc.read() or b"{}")
        except ValueError:
            payload = {"error": f"HTTP {exc.code}"}
        raise RemoteError(exc.code, payload) from None


class Rejected(Exception):
    """Raised by a handler for an expected refusal; returned as 409 with the message."""


def make_server(routes: dict[str, Handler], port: int, host: str = "0.0.0.0") -> ThreadingHTTPServer:
    """`routes` maps "GET /path" or "POST /path" to a handler taking and returning JSON."""

    class _Handler(BaseHTTPRequestHandler):
        def _dispatch(self, method: str) -> None:
            handler = routes.get(f"{method} {self.path}")
            if handler is None:
                return self._send(404, {"error": f"no route {method} {self.path}"})
            try:
                length = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(length) or b"{}") if length else {}
                self._send(200, handler(body))
            except Rejected as exc:
                self._send(409, {"error": str(exc)})
            except Exception as exc:  # report, never leave the caller hanging
                self._send(500, {"error": f"{type(exc).__name__}: {exc}"})

        def do_GET(self) -> None:
            self._dispatch("GET")

        def do_POST(self) -> None:
            self._dispatch("POST")

        def _send(self, status: int, body: dict) -> None:
            data = json.dumps(body, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args) -> None:
            pass

    server = ThreadingHTTPServer((host, port), _Handler)
    server.daemon_threads = True
    return server


def serve_in_thread(routes: dict[str, Handler], host: str = "127.0.0.1") -> tuple[ThreadingHTTPServer, str]:
    """Start a server on a free port; returns it and its base URL (for tests)."""
    server = make_server(routes, 0, host)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_address[1]}"
