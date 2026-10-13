#!/usr/bin/env python3
"""A local Anthropic Messages relay with a narrowly scoped classifier rewrite.

UPSTREAM must explicitly name a compatible API root. Authentication, model
selection, upstream verdicts and all other requests remain the caller's own.
Requires only the Python standard library.
"""

import http.client
import json
import math
import os
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from classifier import rewrite_request


HOST = os.environ.get("PROXY_HOST", "127.0.0.1")
PORT = int(os.environ.get("PROXY_PORT", "8008"))
UPSTREAM = os.environ.get("UPSTREAM", "").strip()
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "300"))
ALLOW_SMALL_BUDGET = os.environ.get("CLASSIFIER_ALLOW_SMALL_BUDGET", "0") == "1"
BUFFER = 8192
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "proxy-connection",
}


def validate_upstream(value):
    """Validate a configured HTTP(S) root without accepting embedded secrets."""
    if not value:
        raise ValueError("UPSTREAM is required; set it to an Anthropic Messages-compatible API root")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError("UPSTREAM must not contain whitespace or control characters")
    if "?" in value or "#" in value or "\\" in value:
        raise ValueError("UPSTREAM must not contain a query, fragment, or backslash")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("UPSTREAM must be an absolute http:// or https:// API root")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("UPSTREAM must not contain credentials; use the client's auth headers")
    # Accessing port also validates malformed and out-of-range port numbers.
    if parsed.port == 0:
        raise ValueError("UPSTREAM port must be between 1 and 65535")
    return parsed


def upstream_path(prefix, request_path):
    """Join an API root and client path without duplicating a final /v1."""
    prefix = prefix.rstrip("/")
    route = urlsplit(request_path)
    path = route.path
    if prefix.endswith("/v1") and (path == "/v1" or path.startswith("/v1/")):
        path = path[len("/v1"):]
    return prefix + path + ("?" + route.query if "?" in request_path else "")


def _hop_headers(headers):
    excluded = set(_HOP_BY_HOP)
    for key, value in headers:
        if key.lower() == "connection":
            excluded.update(token.strip().lower() for token in value.split(","))
    return excluded


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _error(self, status, message):
        payload = json.dumps({"type": "proxy_error", "message": message}).encode("utf-8")
        self.close_connection = True
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _forward(self):
        # The stdlib HTTP server does not decode incoming chunked bodies.
        # Reject them explicitly instead of silently forwarding an empty body.
        if self.headers.get("Transfer-Encoding") is not None:
            self._error(501, "Chunked request bodies are unsupported; send Content-Length")
            return
        lengths = self.headers.get_all("Content-Length", [])
        try:
            if len(lengths) > 1 or (lengths and not lengths[0].isdigit()):
                raise ValueError
            length = int(lengths[0]) if lengths else 0
            route = urlsplit(self.path)
            if route.scheme or route.netloc or route.fragment or not self.path.startswith("/"):
                raise ValueError
        except ValueError:
            self._error(400, "Invalid request path or Content-Length")
            return
        body = self.rfile.read(length) if length else b""
        if len(body) != length:
            self._error(400, "Incomplete request body")
            return
        matched = False
        if self.command == "POST":
            body, matched = rewrite_request(self.path, body, ALLOW_SMALL_BUDGET)

        parsed = self.server.upstream
        headers = list(self.headers.items())
        excluded = _hop_headers(headers) | {"host", "content-length"}
        headers = {key: value for key, value in headers if key.lower() not in excluded}
        # http.client generates Host (including nondefault ports) and the new
        # Content-Length. Caller authentication and provider headers pass through.
        connection_type = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection = connection_type(parsed.hostname, parsed.port, timeout=UPSTREAM_TIMEOUT)
        response_started = False
        try:
            connection.request(self.command, upstream_path(parsed.path, self.path), body=body, headers=headers)
            response = connection.getresponse()
            response_headers = response.getheaders()
            excluded = _hop_headers(response_headers)
            if response.chunked:
                excluded.add("content-length")
            self.close_connection = True
            self.send_response_only(response.status, response.reason)
            for key, value in response_headers:
                if key.lower() not in excluded:
                    self.send_header(key, value)
            # http.client decodes upstream chunk framing. Closing the downstream
            # connection frames responses that have no Content-Length, including SSE.
            self.send_header("Connection", "close")
            self.end_headers()
            response_started = True
            tag = "CLASSIFIER->NO_THINK" if matched else "PASSTHROUGH"
            print("[%s] %s %s -> %s" % (tag, self.command, route.path, response.status), flush=True)
            if self.command != "HEAD":
                while True:
                    # read() can wait to fill BUFFER and stall a small SSE event.
                    chunk = response.read1(BUFFER)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
                    self.wfile.flush()
        except (OSError, http.client.HTTPException) as error:
            self.close_connection = True
            if not response_started:
                status = 504 if isinstance(error, (TimeoutError, socket.timeout)) else 502
                self._error(status, "Upstream request failed (%s)" % type(error).__name__)
            else:
                # Never append a fabricated verdict or JSON error to an SSE body.
                print("[UPSTREAM-ERROR] response interrupted (%s)" % type(error).__name__, flush=True)
        finally:
            connection.close()

    def log_message(self, *args):
        pass

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = do_HEAD = _forward


def main():
    try:
        upstream = validate_upstream(UPSTREAM)
        if not math.isfinite(UPSTREAM_TIMEOUT) or UPSTREAM_TIMEOUT <= 0:
            raise ValueError("UPSTREAM_TIMEOUT must be a positive number of seconds")
        if not 0 < PORT <= 65535:
            raise ValueError("PROXY_PORT must be between 1 and 65535")
    except ValueError as error:
        raise SystemExit("Configuration error: %s" % error)
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.upstream = upstream
    print("cc-securitycheck listening on http://%s:%s" % (HOST, PORT), flush=True)
    print("Upstream: %s" % UPSTREAM, flush=True)
    print("Classifier: tool-free classifier role and verdict signature; thinking disabled for matches", flush=True)
    print("Legacy small-budget detection: %s" % ("enabled" if ALLOW_SMALL_BUDGET else "disabled"), flush=True)
    print("All safety verdicts and model choices come from your configured upstream.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
