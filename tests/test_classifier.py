"""Offline contract tests for the provider-neutral request transformation."""

import json
from pathlib import Path
import sys
import unittest


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from classifier import is_classifier, rewrite_request


# Synthetic XML-format fixture: the identity prefix is reported in
# https://github.com/deepseek-ai/DeepSeek-V3/issues/1464, but the appended XML
# instruction below is invented for this contract test, not a captured prompt.
CLASSIFIER_SYSTEM = (
    "You are a security monitor for autonomous AI coding agents. "
    "Return exactly <severity>N</severity> for this tool request."
)
# This full text appears in that issue's explicitly illustrative curl repro.
# The issue reports only the identity prefix for the actual captured prompt.
ILLUSTRATIVE_ALLOW_BLOCK_SYSTEM = (
    "You are a security monitor for autonomous AI coding agents. "
    "Think thoroughly, then output ALLOW or BLOCK."
)


class ClassifierTests(unittest.TestCase):
    def test_recognizes_explicit_signature_in_system_text_or_blocks(self):
        systems = [
            CLASSIFIER_SYSTEM,
            CLASSIFIER_SYSTEM.upper(),
            [{"type": "text", "text": CLASSIFIER_SYSTEM}],
        ]
        for system in systems:
            with self.subTest(system=system):
                self.assertTrue(is_classifier({"system": system}))

    def test_ordinary_short_requests_are_not_classifiers_by_default(self):
        systems = [
            "Assess the severity of this bug.",
            "Explain <severity> in this XML example.",
            "This text contains only </severity>.",
            "", None,
        ]
        for system in systems:
            with self.subTest(system=system):
                self.assertFalse(is_classifier({"system": system, "max_tokens": 64}))

    def test_bug_triage_with_paired_severity_tags_preserves_exact_bytes(self):
        tool = {"name": "read_issue", "input_schema": {"type": "object"}}
        for budget, tools in ((64, None), (4096, None), (4096, [tool])):
            with self.subTest(budget=budget, tools=tools):
                request = {
                    "model": "bug-triage-model",
                    "system": "You triage software bugs. Return <severity>N</severity> and explain the impact.",
                    "max_tokens": budget,
                    "thinking": {"type": "adaptive"},
                    "output_config": {"effort": "max"},
                }
                if tools is not None:
                    request["tools"] = tools
                original = json.dumps(request, indent=2).encode() + b"\n"
                self.assertEqual(rewrite_request("/v1/messages", original), (original, False))

    def test_identity_and_verdict_format_are_both_required(self):
        for system in (
            "You are a security monitor for autonomous AI coding agents. Explain this command.",
            "You are a bug triage assistant. Think thoroughly, then output ALLOW or BLOCK.",
            "Return exactly <severity>N</severity>.",
        ):
            with self.subTest(system=system):
                self.assertFalse(is_classifier({"system": system, "max_tokens": 2112}))

    def test_illustrative_reported_classifier_supports_high_budget(self):
        # Reported shape: 2112 tokens, non-streaming, no thinking field/tools.
        # Messages are a harmless synthetic replacement; no live model is used.
        request = {
            "model": "any-provider-model",
            "system": ILLUSTRATIVE_ALLOW_BLOCK_SYSTEM,
            "max_tokens": 2112,
            "stream": False,
            "messages": [{"role": "user", "content": "Evaluate: echo sample"}],
        }
        body, matched = rewrite_request("/v1/messages", json.dumps(request).encode())
        self.assertTrue(matched)
        self.assertEqual(json.loads(body), dict(request, thinking={"type": "disabled"}))

    def test_tool_bearing_agent_request_is_not_rewritten(self):
        for system in (CLASSIFIER_SYSTEM, ILLUSTRATIVE_ALLOW_BLOCK_SYSTEM):
            with self.subTest(system=system):
                request = {
                    "model": "main-agent-model",
                    "system": system,
                    "max_tokens": 64,
                    "tools": [{"name": "read_file", "input_schema": {"type": "object"}}],
                    "thinking": {"type": "adaptive"},
                }
                original = json.dumps(request, indent=2).encode()
                self.assertEqual(rewrite_request("/v1/messages", original), (original, False))
                self.assertEqual(rewrite_request("/v1/messages", original, allow_small_budget=True), (original, False))

    def test_reconstructed_reported_envelope_uses_block_stop_marker(self):
        # https://github.com/phaedrus1992/omlx/issues/1 reports this prefix,
        # budget, streaming flag, empty tools, and block stop marker for CC
        # 2.1.246. This is a reconstructed envelope: the full system prompt
        # and messages were not published, and no live provider is contacted.
        request = {
            "model": "provider-neutral-fixture",
            "system": "You are a security monitor for autonomous AI coding agents.",
            "max_tokens": 2112,
            "stream": False,
            "tools": [],
            "stop_sequences": ["</block>"],
        }
        body, matched = rewrite_request("/v1/messages", json.dumps(request).encode())
        self.assertTrue(matched)
        self.assertEqual(json.loads(body), dict(request, thinking={"type": "disabled"}))

    def test_stop_markers_require_classifier_identity_and_exact_list_entries(self):
        identity = "You are a security monitor for autonomous AI coding agents."
        for marker in ("</block>", "</severity>"):
            with self.subTest(marker=marker):
                self.assertTrue(is_classifier({"system": identity, "stop_sequences": [marker]}))
                self.assertFalse(is_classifier({"system": "You triage bugs.", "stop_sequences": [marker]}))
        for invalid in ("</block>", {"stop": "</block>"}, [1], [None], ["prefix </block>"], [" </block> "], ["</Block>"], []):
            with self.subTest(invalid=invalid):
                self.assertFalse(is_classifier({"system": identity, "stop_sequences": invalid}))

    def test_synthetic_identity_and_verdict_variants(self):
        # These alternatives are contract fixtures, not published captures.
        for identity in ("You are a security classifier.", "You are a safety classifier."):
            for verdict in ("Return <block>yes</block>.", "Output ALLOW/BLOCK."):
                with self.subTest(identity=identity, verdict=verdict):
                    self.assertTrue(is_classifier({"system": identity + " " + verdict, "max_tokens": 2112}))

    def test_signature_in_user_message_does_not_trigger_rewrite(self):
        body = {"messages": [{"role": "user", "content": CLASSIFIER_SYSTEM}]}
        self.assertFalse(is_classifier(body))

    def test_legacy_small_budget_detection_requires_opt_in(self):
        for budget in (1, 64, 256):
            with self.subTest(budget=budget):
                self.assertFalse(is_classifier({"max_tokens": budget}))
                self.assertTrue(is_classifier({"max_tokens": budget}, allow_small_budget=True))

    def test_legacy_detection_rejects_invalid_or_large_budgets(self):
        for budget in (None, 0, -1, 257, 4096, True, False, "64", 64.0, [], {}):
            with self.subTest(budget=budget):
                self.assertFalse(is_classifier({"max_tokens": budget}, allow_small_budget=True))

    def test_matched_request_only_changes_thinking(self):
        original = {
            "model": "provider-chosen-model",
            "system": CLASSIFIER_SYSTEM,
            "max_tokens": 64,
            "thinking": {"type": "enabled", "budget_tokens": 8192},
            "output_config": {"effort": "max", "format": {"type": "json_schema"}},
            "messages": [{"role": "user", "content": "检查此命令"}],
            "stream": True,
            "metadata": {"user_id": "sample"},
            "unknown_extension": {"preserve": True},
        }
        expected = dict(original, thinking={"type": "disabled"})
        body, matched = rewrite_request("/v1/messages", json.dumps(original).encode())
        self.assertTrue(matched)
        self.assertEqual(json.loads(body), expected)

    def test_matched_request_with_no_thinking_adds_disabled(self):
        original = {"system": CLASSIFIER_SYSTEM, "max_tokens": 64}
        body, matched = rewrite_request("/v1/messages", json.dumps(original).encode())
        self.assertTrue(matched)
        self.assertEqual(json.loads(body), dict(original, thinking={"type": "disabled"}))

    def test_main_request_preserves_exact_bytes(self):
        original = b'{ "model": "other-model", "max_tokens": 64, "thinking": {"type":"adaptive"}, "output_config":{"effort":"max"} }\n'
        body, matched = rewrite_request("/v1/messages", original)
        self.assertFalse(matched)
        self.assertEqual(body, original)

    def test_only_messages_endpoint_is_rewritten(self):
        original = json.dumps({"system": CLASSIFIER_SYSTEM}).encode()
        for path in ("/v1/messages", "/v1/messages/", "/v1/messages?beta=true"):
            with self.subTest(path=path):
                self.assertTrue(rewrite_request(path, original)[1])
        for path in ("/v1/messages/count_tokens", "/other/v1/messages", "/v1/message", "/v1/messages-extra"):
            with self.subTest(path=path):
                self.assertEqual(rewrite_request(path, original), (original, False))

    def test_invalid_json_and_nonobject_json_are_preserved(self):
        for original in (b"", b"{bad json", b"\xff", b"null", b"[]", b'"hello"', b"64"):
            with self.subTest(original=original):
                self.assertEqual(rewrite_request("/v1/messages", original), (original, False))

    def test_rewrite_exposes_opt_in_legacy_detection(self):
        original = b'{"max_tokens":64,"model":"unchanged"}'
        body, matched = rewrite_request("/v1/messages", original, allow_small_budget=True)
        self.assertTrue(matched)
        self.assertEqual(json.loads(body), {"max_tokens": 64, "model": "unchanged", "thinking": {"type": "disabled"}})


if __name__ == "__main__":
    unittest.main()
