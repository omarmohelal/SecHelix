#!/usr/bin/env python3
"""Manual capability probe for an OpenAI-compatible chat gateway.

Not a CI test: it makes real, paid network calls and is run deliberately when a
provider is configured. It hits the endpoint with raw ``urllib`` so the result
reflects the gateway itself, not the SecHelix adapter, and reports which of the
features SecHelix routing cares about actually work:

    chat · token+cost accounting · tool calling · streaming · JSON mode · errors

Credentials are read from the environment and never printed. Defaults target
OpenRouter; point ``--key-env``/``--base`` elsewhere to probe another gateway
(for example the wasm gateway) with the same harness.

    python scripts/probe_provider.py                       # OpenRouter from env
    python scripts/probe_provider.py --key-env SECHELIX_WASM_API_KEY \\
        --base https://ai.wasmjsvm.com/v1 --model deepseek-v4.1-flash
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def _post(base: str, headers: dict, body: dict, *, stream: bool = False, timeout: float = 60.0):
    req = urllib.request.Request(
        f"{base}/chat/completions", data=json.dumps(body).encode(), method="POST", headers=headers
    )
    resp = urllib.request.urlopen(req, timeout=timeout)  # noqa: S310 - fixed https gateway
    if stream:
        out = []
        for raw in resp:
            line = raw.decode("utf-8", "replace").strip()
            if line.startswith("data: "):
                out.append(line[6:])
        return out
    return json.loads(resp.read().decode("utf-8", "replace"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--key-env", default="SECHELIX_OPENROUTER_API_KEY")
    parser.add_argument("--model-env", default="SECHELIX_OPENROUTER_MODEL")
    parser.add_argument("--model", default=None, help="override model (else from --model-env)")
    parser.add_argument("--base", default=os.environ.get("SECHELIX_OPENROUTER_BASE_URL",
                                                          "https://openrouter.ai/api/v1"))
    args = parser.parse_args(argv)

    key = os.environ.get(args.key_env)
    if not key:
        print(f"{args.key_env} not set", file=sys.stderr)
        return 2
    model = args.model or os.environ.get(args.model_env)
    if not model:
        print(f"no model: pass --model or set {args.model_env}", file=sys.stderr)
        return 2
    base = args.base.rstrip("/")
    headers = {
        "Authorization": f"Bearer {key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/omarmohelal/SecHelix",
        "X-Title": "SecHelix",
    }
    print(f"model={model}  base={base}")

    try:
        o = _post(base, headers, {"model": model, "usage": {"include": True},
                                  "messages": [{"role": "user", "content": "Reply with: pong"}]})
        u = o.get("usage", {})
        txt = o["choices"][0]["message"]["content"].strip()[:40]
        print(f"chat:            OK  content={txt!r} in={u.get('prompt_tokens')} "
              f"out={u.get('completion_tokens')} cost={u.get('cost')}")
    except Exception as exc:
        print(f"chat:            FAIL {type(exc).__name__}: {str(exc)[:120]}")

    try:
        tools = [{"type": "function", "function": {
            "name": "get_weather", "description": "Get weather for a city",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}},
                           "required": ["city"]}}}]
        o = _post(base, headers, {"model": model, "tools": tools,
                                  "messages": [{"role": "user",
                                                "content": "What's the weather in Cairo? Call the tool."}]})
        tc = o["choices"][0]["message"].get("tool_calls")
        if tc:
            fn = tc[0].get("function", {})
            print(f"tool_calling:    OK  called={fn.get('name')} args={str(fn.get('arguments'))[:60]}")
        else:
            print("tool_calling:    NO_TOOL_CALL (model answered in prose)")
    except Exception as exc:
        print(f"tool_calling:    FAIL {type(exc).__name__}: {str(exc)[:120]}")

    try:
        chunks = _post(base, headers, {"model": model, "stream": True,
                                       "messages": [{"role": "user", "content": "Count: one two three"}]},
                       stream=True)
        data = [c for c in chunks if c and c != "[DONE]"]
        print(f"streaming:       OK  sse_chunks={len(data)} done_marker={'[DONE]' in chunks}")
    except Exception as exc:
        print(f"streaming:       FAIL {type(exc).__name__}: {str(exc)[:120]}")

    try:
        o = _post(base, headers, {"model": model, "response_format": {"type": "json_object"},
                                  "messages": [{"role": "user",
                                                "content": "Return a JSON object with keys a=1 and b=2. Only JSON."}]})
        parsed = json.loads(o["choices"][0]["message"]["content"])
        print(f"json_mode:       OK  parsed_keys={sorted(parsed.keys())}")
    except json.JSONDecodeError:
        print("json_mode:       WEAK (non-JSON despite response_format)")
    except Exception as exc:
        print(f"json_mode:       FAIL {type(exc).__name__}: {str(exc)[:120]}")

    try:
        _post(base, headers, {"model": "definitely/not-a-real-model-xyz",
                              "messages": [{"role": "user", "content": "hi"}]})
        print("error_shape:     UNEXPECTED_200")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            msg = json.loads(body).get("error", {}).get("message", body)
        except Exception:
            msg = body
        print(f"error_shape:     OK  http={exc.code} message={str(msg)[:80]!r}")
    except Exception as exc:
        print(f"error_shape:     {type(exc).__name__}: {str(exc)[:120]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
