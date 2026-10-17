"""Real local TCP tests; these never contact a model provider or spend tokens."""

from contextlib import contextmanager
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import sys
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Synthetic XML fixture. The security-monitor identity prefix is reported in
# https://github.com/deepseek-ai/DeepSeek-V3/issues/1464; the XML instruction is
# test-authored and does not purport to reproduce the full captured prompt.
CLASSIFIER_BODY = json.dumps({
    "model": "provider-model", "max_tokens": 64,
    "system": "You are a security monitor for autonomous AI coding agents. Output <severity>N</severity>.",
    "thinking": {"type": "enabled", "budget_tokens": 8192},
    "output_config": {"effort": "max"},
}).encode()
DENIAL = b'{"content":[{"type":"text","text":"<severity>9</severity>"}],"stop_reason":"end_turn"}'
FIRST_EVENT = b'event: message_start\ndata: {"type":"message_start"}\n\n'
LAST_EVENT = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def clean_environment():
    env = os.environ.copy()
    for key in ("UPSTREAM", "PROXY_HOST", "PROXY_PORT", "UPSTREAM_TIMEOUT", "CLASSIFIER_ALLOW_SMALL_BUDGET", "MODEL_OVERRIDE"):
        env.pop(key, None)
    env["PYTHONUNBUFFERED"] = "1"
    return env


@contextmanager
def relay(upstream, **extra_env):
    port = unused_port()
    env = clean_environment()
    env.update(UPSTREAM=upstream, PROXY_HOST="127.0.0.1", PROXY_PORT=str(port))
    env.update(extra_env)
    proc = subprocess.Popen(
        [sys.executable, str(ROOT / "proxy.py")], cwd=ROOT, env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
    )
    try:
        deadline = time.monotonic() + 6
        while True:
            if proc.poll() is not None:
                raise AssertionError("Relay exited during startup: " + proc.stdout.read().decode(errors="replace"))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError("Relay did not listen within six seconds")
                time.sleep(0.02)
        yield port
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate(timeout=3)


class FakeUpstream:
    def __init__(self):
        self.requests = queue.Queue()
        self.status = 200
        self.body = DENIAL
        self.mode = "response"
        self.extra_headers = {}
        self.release = threading.Event()
        self.finished = threading.Event()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.requests.put((self.command, self.path, dict(self.headers.items()), body))
                if owner.mode == "timeout":
                    owner.release.wait(3)
                    return
                if owner.mode == "reset":
                    # Force a TCP RST when the handler closes, before HTTP headers.
                    linger = struct.pack("HH" if os.name == "nt" else "ii", 1, 0)
                    self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, linger)
                    self.close_connection = True
                    return
                self.send_response(owner.status)
                self.send_header("Content-Type", "text/event-stream" if owner.mode == "stream" else "application/json")
                self.send_header("X-Request-Id", "offline-fixture-request")
                self.send_header("Connection", "close")
                for key, value in owner.extra_headers.items():
                    self.send_header(key, value)
                if owner.mode == "stream":
                    self.send_header("Transfer-Encoding", "chunked")
                else:
                    self.send_header("Content-Length", str(len(owner.body)))
                    if owner.status == 429:
                        self.send_header("Retry-After", "7")
                self.end_headers()
                try:
                    if owner.mode == "stream":
                        self.wfile.write(("%x\r\n" % len(FIRST_EVENT)).encode() + FIRST_EVENT + b"\r\n")
                        self.wfile.flush()
                        owner.release.wait(3)
                        self.wfile.write(("%x\r\n" % len(LAST_EVENT)).encode() + LAST_EVENT + b"\r\n0\r\n\r\n")
                    else:
                        self.wfile.write(owner.body)
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    owner.finished.set()
                    self.close_connection = True

            do_POST = do_GET = do_PUT = handle_request

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)

    @property
    def url(self):
        return "http://127.0.0.1:%s" % self.server.server_port

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def request(port, body=CLASSIFIER_BODY, path="/v1/messages", method="POST", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        conn.request(method, path, body=body, headers=headers or {"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


class ProxyTests(unittest.TestCase):
    def test_requires_explicit_upstream_configuration(self):
        proc = subprocess.run([sys.executable, str(ROOT / "proxy.py")], cwd=ROOT, env=clean_environment(), capture_output=True, timeout=3)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn(b"UPSTREAM", proc.stdout + proc.stderr)

    def test_upstream_credentials_query_and_fragment_are_rejected(self):
        for upstream in (
            "http://user:dummy-secret@127.0.0.1/api",
            "http://127.0.0.1/api?token=dummy-secret",
            "http://127.0.0.1/api#fragment",
        ):
            with self.subTest(upstream=upstream):
                env = clean_environment()
                env["UPSTREAM"] = upstream
                proc = subprocess.run([sys.executable, str(ROOT / "proxy.py")], cwd=ROOT, env=env, capture_output=True, timeout=3)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(b"UPSTREAM", proc.stdout + proc.stderr)
                self.assertNotIn(b"dummy-secret", proc.stdout + proc.stderr)

    def test_connection_nominated_headers_are_removed_in_both_directions(self):
        headers = {"Connection": "keep-alive, X-Client-Hop", "X-Client-Hop": "must-not-forward", "X-End-To-End": "preserved"}
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            upstream.extra_headers = {"Connection": "X-Upstream-Hop", "X-Upstream-Hop": "must-not-forward", "X-Upstream-End-To-End": "preserved"}
            _, response_headers, _ = request(port, headers=headers)
            received_headers = {key.lower(): value for key, value in upstream.requests.get(timeout=1)[2].items()}
        response_headers = {key.lower(): value for key, value in response_headers.items()}
        self.assertNotIn("x-client-hop", received_headers)
        self.assertEqual(received_headers["x-end-to-end"], "preserved")
        self.assertNotIn("x-upstream-hop", response_headers)
        self.assertEqual(response_headers["x-upstream-end-to-end"], "preserved")

    def test_rewrites_classifier_preserves_auth_and_denial_response(self):
        headers = {"Content-Type": "application/json", "Authorization": "Bearer offline-test-only", "X-Api-Key": "offline-test-only", "Anthropic-Version": "2023-06-01", "Anthropic-Beta": "test-beta"}
        with FakeUpstream() as upstream, relay(upstream.url + "/anthropic") as port:
            status, response_headers, body = request(port, headers=headers)
            method, path, received_headers, received_body = upstream.requests.get(timeout=1)
        self.assertEqual(status, 200)
        self.assertEqual(body, DENIAL)
        self.assertEqual(response_headers["X-Request-Id"], "offline-fixture-request")
        self.assertEqual((method, path), ("POST", "/anthropic/v1/messages"))
        lower_headers = {k.lower(): v for k, v in received_headers.items()}
        for key, value in headers.items():
            self.assertEqual(lower_headers[key.lower()], value)
        expected = dict(json.loads(CLASSIFIER_BODY), thinking={"type": "disabled"})
        self.assertEqual(json.loads(received_body), expected)

    def test_main_request_preserves_bytes_model_and_thinking(self):
        original = b'{ "model":"user-selected", "max_tokens":64, "thinking":{"type":"adaptive"}, "output_config":{"effort":"max"} }\n'
        with FakeUpstream() as upstream, relay(upstream.url, MODEL_OVERRIDE="must-be-ignored") as port:
            request(port, body=original)
            self.assertEqual(upstream.requests.get(timeout=1)[3], original)

    def test_deeply_nested_body_is_forwarded_byte_identically(self):
        original = b"[" * 4000 + b"]" * 4000
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            status, _, body = request(port, body=original)
            received = upstream.requests.get(timeout=1)[3]
        self.assertEqual(status, 200)
        self.assertEqual(body, DENIAL)
        self.assertEqual(received, original)

    def test_ordinary_bug_triage_request_with_xml_and_tools_passes_through(self):
        original = json.dumps({
            "model": "bug-triage-model",
            "system": "Triage this bug. Return <severity>N</severity> and a repair plan.",
            "max_tokens": 4096,
            "tools": [{"name": "read_issue", "input_schema": {"type": "object"}}],
            "thinking": {"type": "enabled", "budget_tokens": 2048},
        }, indent=2).encode() + b"\n"
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            request(port, body=original)
            self.assertEqual(upstream.requests.get(timeout=1)[3], original)

    def test_high_budget_allow_block_classifier_only_changes_thinking(self):
        # Adapted from the illustrative curl in DeepSeek-V3 issue #1464, not
        # from a full captured production request. The model is neutralized.
        original = {
            "model": "any-provider-model", "max_tokens": 2112, "stream": False,
            "system": "You are a security monitor for autonomous AI coding agents. Think thoroughly, then output ALLOW or BLOCK.",
            "messages": [{"role": "user", "content": "Evaluate: echo sample"}],
        }
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            request(port, body=json.dumps(original).encode())
            received = json.loads(upstream.requests.get(timeout=1)[3])
        self.assertEqual(received, dict(original, thinking={"type": "disabled"}))

    def test_reconstructed_reported_block_stop_envelope_is_rewritten(self):
        # Reconstructed from reported metadata in phaedrus1992/omlx issue #1;
        # its complete production system prompt and messages are not public.
        original = {
            "model": "any-provider-model", "max_tokens": 2112, "stream": False,
            "system": "You are a security monitor for autonomous AI coding agents.",
            "tools": [], "stop_sequences": ["</block>"],
        }
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            request(port, body=json.dumps(original).encode())
            received = json.loads(upstream.requests.get(timeout=1)[3])
        self.assertEqual(received, dict(original, thinking={"type": "disabled"}))

    def test_count_tokens_preserves_body_and_query(self):
        with FakeUpstream() as upstream, relay(upstream.url + "/anthropic") as port:
            request(port, path="/v1/messages/count_tokens?beta=true&value=a%2Fb")
            _, path, _, body = upstream.requests.get(timeout=1)
        self.assertEqual(path, "/anthropic/v1/messages/count_tokens?beta=true&value=a%2Fb")
        self.assertEqual(body, CLASSIFIER_BODY)

    def test_messages_query_preserved_while_classifier_rewritten(self):
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            request(port, path="/v1/messages?beta=true&value=a%2Fb")
            _, path, _, body = upstream.requests.get(timeout=1)
        self.assertEqual(path, "/v1/messages?beta=true&value=a%2Fb")
        self.assertEqual(json.loads(body)["thinking"], {"type": "disabled"})

    def test_non_post_messages_request_is_not_rewritten(self):
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            request(port, method="PUT")
            self.assertEqual(upstream.requests.get(timeout=1)[3], CLASSIFIER_BODY)

    def test_v1_upstream_prefix_is_not_duplicated(self):
        for prefix in ("/v1", "/anthropic/v1", "/anthropic/v1/"):
            with self.subTest(prefix=prefix), FakeUpstream() as upstream, relay(upstream.url + prefix) as port:
                request(port)
                self.assertEqual(upstream.requests.get(timeout=1)[1], prefix.rstrip("/") + "/messages")

    def test_non_ascii_request_target_is_rejected_with_a_proxy_error(self):
        # The target arrives latin-1 decoded, so a byte >= 0x80 survives and
        # http.client cannot ASCII-encode the request line. The relay must
        # answer with the same 400 as every other malformed target instead of
        # dropping the connection.
        body = b'{"model":"m","max_tokens":64}'
        raw = (
            b"POST /v1/messag\xc3\xa9 HTTP/1.1\r\nHost: 127.0.0.1\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            with socket.create_connection(("127.0.0.1", port), timeout=3) as sock:
                sock.sendall(raw)
                received = b""
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    received += chunk
            forwarded = not upstream.requests.empty()
        head, _, payload = received.partition(b"\r\n\r\n")
        self.assertEqual(head.split(b"\r\n", 1)[0], b"HTTP/1.1 400 Bad Request")
        self.assertEqual(
            json.loads(payload),
            {"type": "proxy_error", "message": "Invalid request path or Content-Length"},
        )
        self.assertFalse(forwarded, "relay forwarded a non-ASCII request target")

    def test_small_budget_compatibility_option_is_explicit(self):
        original = b'{"model":"same","max_tokens":64,"thinking":{"type":"adaptive"}}'
        with FakeUpstream() as upstream, relay(upstream.url, CLASSIFIER_ALLOW_SMALL_BUDGET="1") as port:
            request(port, body=original)
            received = json.loads(upstream.requests.get(timeout=1)[3])
        self.assertEqual(received, {"model": "same", "max_tokens": 64, "thinking": {"type": "disabled"}})

    def test_upstream_error_status_headers_and_body_are_preserved(self):
        for expected_status in (400, 401, 429, 503):
            with self.subTest(status=expected_status), FakeUpstream() as upstream, relay(upstream.url) as port:
                upstream.status = expected_status
                upstream.body = b'{"type":"error","error":{"message":"upstream refused request"}}'
                status, headers, body = request(port)
                self.assertEqual(status, expected_status)
                self.assertEqual(body, upstream.body)
                self.assertEqual(headers["X-Request-Id"], "offline-fixture-request")
                if expected_status == 429:
                    self.assertEqual(headers["Retry-After"], "7")

    def test_unavailable_upstream_is_an_error_without_fabricated_verdict(self):
        # Reserve a non-listening port so another local process cannot take it.
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            with relay("http://127.0.0.1:%s" % reserved.getsockname()[1]) as port:
                status, _, body = request(port)
        self.assertGreaterEqual(status, 500)
        self.assertIn(b"error", body.lower())
        self.assertNotIn(b"<severity>", body)

    def test_truncated_classifier_response_is_preserved_without_a_verdict(self):
        truncated = b'{"content":[],"stop_reason":"max_tokens","usage":{"output_tokens":64}}'
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            upstream.body = truncated
            status, _, body = request(port)
        self.assertEqual(status, 200)
        self.assertEqual(body, truncated)
        self.assertNotIn(b"<severity>", body)

    def test_upstream_timeout_is_an_error_without_fabricated_verdict(self):
        with FakeUpstream() as upstream, relay(upstream.url, UPSTREAM_TIMEOUT="0.15") as port:
            upstream.mode = "timeout"
            started = time.monotonic()
            status, _, body = request(port)
            elapsed = time.monotonic() - started
        self.assertGreaterEqual(status, 500)
        self.assertLess(elapsed, 2)
        self.assertIn(b"error", body.lower())
        self.assertNotIn(b"<severity>", body)

    def test_upstream_reset_before_headers_returns_a_proxy_error(self):
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            upstream.mode = "reset"
            status, _, body = request(port)
        self.assertEqual(status, 502)
        self.assertIn(b"error", body.lower())
        self.assertNotIn(b"<severity>", body)

    def test_sse_first_event_arrives_before_upstream_finishes(self):
        with FakeUpstream() as upstream, relay(upstream.url) as port:
            upstream.mode = "stream"
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            try:
                conn.request("POST", "/v1/messages", body=CLASSIFIER_BODY, headers={"Content-Type": "application/json"})
                response = conn.getresponse()
                self.assertEqual(response.status, 200)
                first = b""
                while not first.endswith(b"\n\n"):
                    line = response.readline()
                    self.assertTrue(line, "stream ended before first complete SSE event")
                    first += line
                self.assertEqual(first, FIRST_EVENT)
                self.assertFalse(upstream.finished.is_set(), "relay buffered until upstream completed")
                upstream.release.set()
                self.assertEqual(response.read(), LAST_EVENT)
            finally:
                upstream.release.set()
                conn.close()


if __name__ == "__main__":
    unittest.main()
