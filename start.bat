@echo off
setlocal
rem Set UPSTREAM to your Anthropic Messages-compatible API root before running.
rem The endpoint must accept thinking={"type":"disabled"} on classifier calls.
rem Example in cmd.exe: set UPSTREAM=https://your-provider.example/anthropic
rem Optional: PROXY_HOST (default 127.0.0.1), PROXY_PORT (default 8008).
rem Optional: CLASSIFIER_ALLOW_SMALL_BUDGET=1 enables the legacy budget heuristic.

if not defined UPSTREAM (
    echo UPSTREAM is required. Set it to your compatible API root first.
    exit /b 1
)
python "%~dp0proxy.py"
exit /b %errorlevel%
