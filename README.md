# cc-securitycheck

A local relay that helps Claude Code's **auto-mode safety classifier return a verdict when reasoning consumes its output budget**. Python standard library only. No provider SDK or DeepSeek dependency.

The relay sets `thinking: {"type": "disabled"}` on recognized classifier requests. The upstream model still evaluates the action, and Claude Code still enforces the result. Requests outside the classifier match retain their model, thinking settings, and body bytes.

| Branch | Purpose |
| --- | --- |
| [`main`](https://github.com/CH3SH-LC/cc-securitycheck/tree/main) | Provider-neutral relay and reusable classifier module. You choose the upstream. |
| [`ds`](https://github.com/CH3SH-LC/cc-securitycheck/tree/ds) | Original DeepSeek-specific version, preserved at [`6479e68`](https://github.com/CH3SH-LC/cc-securitycheck/commit/6479e68687fe6cc9cc158f3d4798bb3319c9b678). |

## Why auto mode can fail

Auto mode makes separate classification requests before allowing certain tool actions. In the [original August 3 investigation](https://github.com/anthropics/claude-code/issues/74248#issuecomment-5163453620), those requests had a `max_tokens` budget of 64 or 256 and requested `<severity>N</severity>`.

On the tested DeepSeek Anthropic-compatible endpoint, reasoning consumed that small budget before the model emitted the verdict. Claude Code then failed closed. The maintainer's historical A/B test observed no verdict with thinking enabled and a short verdict with thinking disabled. Lowering effort also worked in that specific setup.

A related [community reproduction](https://github.com/deepseek-ai/DeepSeek-V3/issues/1464) reports non-streaming classifier reasoning exceeding the caller's timeout. Inspect the actual classifier response and timing to distinguish budget exhaustion from latency.

This is **one cause, not a diagnosis for every auto-mode failure**. Effort behavior depends on the provider and version. Claude Code's [v2.1.154 changelog](https://github.com/anthropics/claude-code/blob/bf2323b3021c9d3db7a31e1e7d61068c3f704497/CHANGELOG.md#L4769) already records a fix for classifier reasoning exhausting output tokens. Update Claude Code and inspect current evidence before applying this workaround.

## Compatibility

Use this relay with an **Anthropic Messages-compatible API** that accepts `thinking: {"type": "disabled"}` for the selected classifier model, when missing verdicts are associated with reasoning consuming the output budget. Traffic must reach the relay through `ANTHROPIC_BASE_URL`.

Provider-neutral code does not mean universal model compatibility. [Issue #98962](https://github.com/anthropics/claude-code/issues/98962) reports Bedrock models rejecting disabled thinking with HTTP 400. This relay does not implement Bedrock signing, Vertex authentication, OpenAI API conversion, subscription authentication, or separate classifier model selection.

Changing classifier reasoning can change classification quality. Returning an actual verdict does not establish the same accuracy: validate both allowed and denied actions with your provider/model. Later model-specific reports in [DeepSeek issue #284](https://github.com/deepseek-ai/awesome-deepseek-agent/issues/284) prefer low reasoning over disabled thinking; this relay implements the disabled-thinking workaround only.

## Quick start

Requires **Python 3.10+** and an existing working Anthropic-compatible API configuration. Replace the example URL with your provider's API root, including any prefix such as `/anthropic`. Do not include `/messages`.

```sh
git clone https://github.com/CH3SH-LC/cc-securitycheck.git
cd cc-securitycheck
```

Start the relay in one terminal:

```sh
# macOS / Linux
UPSTREAM=https://your-provider.example/anthropic python3 proxy.py
```

```powershell
# Windows PowerShell
$env:UPSTREAM = "https://your-provider.example/anthropic"
python proxy.py
```

Windows users can also run `start.bat` after setting `UPSTREAM`. In a **second terminal**, keep your existing provider credentials and model settings, change the API base URL, and launch Claude Code:

```sh
# macOS / Linux
export ANTHROPIC_BASE_URL=http://127.0.0.1:8008
claude
```

```powershell
# Windows PowerShell
$env:ANTHROPIC_BASE_URL = "http://127.0.0.1:8008"
claude
```

Keep your provider's authentication method, such as `ANTHROPIC_AUTH_TOKEN` or `ANTHROPIC_API_KEY`. The relay forwards incoming credentials to `UPSTREAM`; it does not store keys or rewrite models. The upstream must support the model Claude Code actually selects for classification, which can differ from the conversation model.

Keep the listener on loopback: it has no inbound authentication and forwards credentials. Stop it with **Ctrl+C**. To roll back, restore your previous `ANTHROPIC_BASE_URL` and restart Claude Code.

## Configuration

| Environment variable | Default | Meaning |
| --- | --- | --- |
| `UPSTREAM` | Required | Anthropic-compatible API root. No provider is selected automatically. |
| `PROXY_HOST` | `127.0.0.1` | Listening address. |
| `PROXY_PORT` | `8008` | Listening port. |
| `UPSTREAM_TIMEOUT` | `300` | Upstream socket timeout in seconds. |
| `CLASSIFIER_ALLOW_SMALL_BUDGET` | `0` | Set to `1` to also match a positive integer `max_tokens` of at most 256. |

An upstream root ending in `/v1` is supported without duplicating that segment. Other path prefixes and incoming query strings are retained.

### Request matching and forwarding

Only JSON `POST /v1/messages` requests without tools are candidates; a trailing slash and query string are supported. Default matching requires a system instruction identifying a security/safety classifier or an autonomous-coding security monitor, together with a verdict signature: paired severity/block XML tags, an ALLOW/BLOCK output instruction, or a closing verdict tag in `stop_sequences`. String and text-block system prompts are supported. An ordinary XML-formatting instruction, the word `severity`, or a small output budget alone does not trigger the rewrite.

`CLASSIFIER_ALLOW_SMALL_BUDGET=1` enables the original budget-based fallback for integrations without the signature. It also matches unrelated short-output messages without tools, so enable it only after inspecting your requests. Classifier prompts are an internal Claude Code detail and may change; unmatched requests pass through unchanged.

For a match, only the `thinking` field is replaced. Other fields, including `model`, `max_tokens`, and `output_config`, remain. Other request bodies, including `/v1/messages/count_tokens`, pass through unchanged. Actual upstream verdicts, HTTP errors, and SSE bodies return to the client; the relay never manufactures an approval. Client request bodies must use `Content-Length`; chunked request uploads are rejected with HTTP 501. Chunked upstream responses, including SSE, are supported.

## Reuse the core

[`classifier.py`](classifier.py) is independent of the HTTP server, environment, credentials, and provider selection. Import it into an existing gateway:

```python
from classifier import rewrite_request

if method == "POST":
    forwarded_body, matched = rewrite_request(path, raw_body)
else:
    forwarded_body, matched = raw_body, False

# Forward forwarded_body and return the upstream's actual response.
```

The result is `(body_bytes, matched)`. Unmatched or invalid JSON bodies are returned unchanged. Pass `allow_small_budget=True` to opt into the budget heuristic.

## Verify and troubleshoot

Logs identify rewrites and status codes without logging prompts or credentials:

```text
[CLASSIFIER->NO_THINK] POST /v1/messages -> 200
[PASSTHROUGH] POST /v1/messages -> 200
```

These lines establish routing, **not a valid verdict or successful tool approval**. Inspect the actual classifier response and Claude Code's handling of it. Preserve genuine denials.

| Classifier evidence | Action |
| --- | --- |
| Reasoning uses the output budget; no verdict | Compare the same request with thinking disabled on a compatible endpoint. This is the intended use. |
| HTTP 400 rejects disabled thinking | Use the provider's supported settings. This rewrite is unsuitable. |
| HTTP 401/403 or unknown/disallowed model | Fix authentication, access, or classifier model routing. |
| HTTP 429/5xx, connection failure, intermittent timeout | Investigate rate limits and serving/network availability. This relay adds no retries or fallback model. |
| Valid verdict denies the action | Review the action and permission policy; the denial is preserved. |

Inspect `claude --debug` output locally and redact credentials, prompts, and tool arguments before sharing. The [original #74248 report](https://github.com/anthropics/claude-code/issues/74248) documents intermittent serving failures with the same visible symptom.

## Development

```sh
python -m unittest discover -s tests -v
```

Tests use local fake upstream servers to check matching, body and credential forwarding, retained denials/errors, URL handling, and streaming delivery before completion. Fixtures include a reconstruction of the publicly reported request fields in [oMLX issue #1](https://github.com/phaedrus1992/omlx/issues/1), rather than a private captured prompt, and the illustrative monitor prompt from [DeepSeek issue #1464](https://github.com/deepseek-ai/DeepSeek-V3/issues/1464). They do not establish current model accuracy or live provider compatibility. The historical model experiment above is separate evidence.

## Migrating from `ds`

Set `UPSTREAM` explicitly; `main` has no DeepSeek default. `MODEL_OVERRIDE` is removed: configure model selection in Claude Code or your gateway. Small-budget detection is now opt-in. The [`ds` branch](https://github.com/CH3SH-LC/cc-securitycheck/tree/ds) retains the original files and behavior.

MIT license. An independent community relay, not an official Anthropic plugin or a `/plugin install` package.
