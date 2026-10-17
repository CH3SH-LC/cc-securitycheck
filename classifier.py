"""Pure, provider-independent recognition and rewriting of classifier requests."""

import json
import re
from urllib.parse import urlsplit


CLASSIFIER_MAX_TOKENS = 256
_SEVERITY_VERDICT = re.compile(r"<severity\s*>.*?</severity\s*>", re.I | re.S)
_BLOCK_VERDICT = re.compile(r"<block\s*>.*?</block\s*>", re.I | re.S)
_BINARY_VERDICT = re.compile(r"\bALLOW\s*(?:\bor\b|/)\s*BLOCK\b", re.I)
_CLASSIFIER_IDENTITY = re.compile(
    r"\b(?:security|safety)\s+classifier\b"
    r"|\bsecurity\s+monitor\s+for\s+autonomous\s+AI\s+coding\s+agents\b",
    re.I,
)


def _system_text(system):
    if isinstance(system, str):
        return system
    if isinstance(system, list):
        return "\n".join(
            block["text"]
            for block in system
            if isinstance(block, dict)
            and block.get("type", "text") == "text"
            and isinstance(block.get("text"), str)
        )
    return ""


def is_classifier(body, allow_small_budget=False):
    """Recognize a tool-free security classifier role and verdict format.

    Neither short budgets nor XML tags alone identify a classifier. Strict
    matching requires a security/safety classifier role (or the known security
    monitor role), plus either a severity/block XML or ALLOW/BLOCK verdict
    signature, or an exact closing severity/block tag in the stop-sequence list.
    The legacy budget heuristic is opt-in; nonempty tools are always excluded.
    """
    if not isinstance(body, dict) or body.get("tools"):
        return False
    system = _system_text(body.get("system"))
    stops = body.get("stop_sequences")
    verdict_stop = isinstance(stops, list) and any(
        isinstance(stop, str) and stop in ("</severity>", "</block>")
        for stop in stops
    )
    verdict_text = any(
        pattern.search(system)
        for pattern in (_SEVERITY_VERDICT, _BLOCK_VERDICT, _BINARY_VERDICT)
    )
    if _CLASSIFIER_IDENTITY.search(system) and (verdict_text or verdict_stop):
        return True
    budget = body.get("max_tokens")
    return bool(
        allow_small_budget
        and type(budget) is int
        and 0 < budget <= CLASSIFIER_MAX_TOKENS
    )


def rewrite_request(path, body, allow_small_budget=False):
    """Return (request bytes, matched) for a POST /v1/messages request.

    The HTTP caller must restrict this function to POST requests. The pure core
    checks the exact route (with an optional trailing slash and query string),
    then changes only the matched request's ``thinking`` field. It never reads
    or manufactures a safety verdict. Unmatched bytes are returned unchanged.
    """
    try:
        route = urlsplit(path)
        if route.scheme or route.netloc or route.fragment:
            return body, False
        if route.path not in ("/v1/messages", "/v1/messages/"):
            return body, False
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError, RecursionError):
        return body, False
    if not is_classifier(data, allow_small_budget):
        return body, False
    if data.get("thinking") == {"type": "disabled"}:
        return body, True
    data["thinking"] = {"type": "disabled"}
    try:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), True
    except (ValueError, RecursionError):
        return body, False
