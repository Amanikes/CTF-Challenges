"""Lost in DNS — artifact download application (NET-02).

A deliberately small standard-library HTTP server. It serves the landing page,
the fixed capture artifact and a health probe, and it never touches the runtime
flag: the entrypoint generates the capture, removes GZCTF_FLAG from the
environment and only then starts this process.
"""

import json
import logging
import os
import signal
import sys
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from config import ConfigError, configure_logging, load_config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(BASE_DIR)
TEMPLATE_PATH = os.path.join(PROJECT_DIR, "templates", "index.html")
STATIC_DIR = os.path.join(PROJECT_DIR, "static")

CAPTURE_NAME = "capture.pcap"
PCAP_CONTENT_TYPE = "application/vnd.tcpdump.pcap"
MAX_STATIC_BYTES = 512 * 1024

# Only these files are ever served from static/. There is no user-controlled
# path component anywhere in the application, so traversal is not possible.
STATIC_FILES = {
    "/static/style.css": ("style.css", "text/css; charset=utf-8"),
    "/static/favicon.svg": ("favicon.svg", "image/svg+xml"),
}

logger = logging.getLogger("net02.app")


def render_landing(capture_size):
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as handle:
        template = handle.read()

    if capture_size is None:
        size_text = "pending"
    elif capture_size < 1024:
        size_text = f"{capture_size} bytes"
    else:
        size_text = f"{capture_size / 1024:.1f} KB"

    return (
        template.replace("{{CAPTURE_NAME}}", CAPTURE_NAME)
        .replace("{{CAPTURE_SIZE}}", size_text)
        .replace("{{CAPTURE_BYTES}}", str(capture_size or 0))
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "LostInDNS/1.0"
    sys_version = ""

    # --- helpers ---------------------------------------------------------

    def _capture_path(self):
        return self.server.capture_path  # fixed at startup; no user input

    def _capture_size(self):
        path = self._capture_path()
        try:
            return os.path.getsize(path)
        except OSError:
            return None

    def _send(self, status, body, content_type, extra_headers=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "script-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()

        if body:
            self.wfile.write(body)

    def _send_json(self, status, payload):
        self._send(
            status,
            json.dumps(payload).encode("utf-8"),
            "application/json; charset=utf-8",
            {"Cache-Control": "no-store"},
        )

    # --- routes ----------------------------------------------------------

    def do_GET(self):  # noqa: N802 - required by BaseHTTPRequestHandler
        path = self.path.split("?", 1)[0]

        if path == "/":
            self._landing()
        elif path == "/download":
            self._download()
        elif path == "/health":
            self._health()
        elif path in STATIC_FILES:
            self._static_file(path)
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_HEAD(self):  # noqa: N802
        self.do_GET()

    def _landing(self):
        try:
            body = render_landing(self._capture_size()).encode("utf-8")
        except OSError:
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "template_unavailable"})
            return

        self._send(HTTPStatus.OK, body, "text/html; charset=utf-8", {"Cache-Control": "no-store"})

    def _download(self):
        path = self._capture_path()

        if not os.path.exists(path):
            self._send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"error": "capture_unavailable"})
            return

        try:
            with open(path, "rb") as handle:
                payload = handle.read()
        except OSError:
            logger.error("capture could not be read")
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "capture_unreadable"})
            return

        self._send(
            HTTPStatus.OK,
            payload,
            PCAP_CONTENT_TYPE,
            {
                "Content-Disposition": f'attachment; filename="{CAPTURE_NAME}"',
                "Cache-Control": "no-store",
            },
        )

    def _health(self):
        if self._capture_size() is None:
            self._send_json(
                HTTPStatus.SERVICE_UNAVAILABLE,
                {"status": "starting", "service": "lost-in-dns", "capture": "missing"},
            )
            return

        self._send_json(HTTPStatus.OK, {"status": "ok", "service": "lost-in-dns", "capture": "ready"})

    def _static_file(self, route):
        filename, content_type = STATIC_FILES[route]
        path = os.path.join(STATIC_DIR, filename)

        try:
            if os.path.getsize(path) > MAX_STATIC_BYTES:
                raise OSError("static file too large")
            with open(path, "rb") as handle:
                payload = handle.read()
        except OSError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return

        self._send(HTTPStatus.OK, payload, content_type, {"Cache-Control": "max-age=300"})

    def log_message(self, fmt, *args):  # route access logs through logging
        logger.debug("%s - %s", self.address_string(), fmt % args)


def build_server(host, port, capture_path):
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    server.capture_path = capture_path
    return server


def main():
    try:
        config = load_config(require_flag=False)
    except ConfigError as error:
        print(f"[net02] {error}", file=sys.stderr)
        return 1

    configure_logging(config.log_level)

    if not os.path.exists(config.capture_path):
        logger.error("capture artifact is missing at startup: %s", os.path.basename(config.capture_path))
        return 1

    server = build_server("0.0.0.0", config.port, config.capture_path)

    def shutdown(signum, _frame):
        logger.info("received signal %s, shutting down", signum)
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    logger.info("listening on 0.0.0.0:%d", config.port)

    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
