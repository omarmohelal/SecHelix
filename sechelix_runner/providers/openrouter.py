"""Reasoning through an OpenRouter OpenAI-compatible chat-completions endpoint.

OpenRouter is an explicit, user-selected reasoning provider. A node's projected
Evidence block is sent to it exactly as it is sent to any other executor; this
adapter does not silently reroute to it. The owner opts in with ``--executor
openrouter`` and supplies the key out of band.

Design constraints, same as every adapter here:

* **Standard library only.** The runner's zero-dependency invariant is tested.
  HTTP is done with :mod:`urllib`, TLS verification is left on, and no SDK is
  pulled in.
* **Fail closed.** A non-2xx status, a malformed body, or an empty completion
  raises :class:`ProviderError`; downstream graph nodes are blocked rather than
  fed a guessed result.
* **Unmeasured is ``None``.** Token counts and cost are copied from the
  response's ``usage`` block when present and left ``None`` when absent -- never
  defaulted to ``0``, which would understate a budget.
* **The key never leaves the request.** It is read from the environment, placed
  only in the ``Authorization`` header, and never written to ``raw``, an
  exception message, or a log line. Error bodies from the server are truncated
  and surfaced, but the outbound header is never echoed.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Any

from .base import ProviderError, ProviderResult, strictify

KEY_ENV = "SECHELIX_OPENROUTER_API_KEY"
ENV_MODEL = "SECHELIX_OPENROUTER_MODEL"
ENV_BASE_URL = "SECHELIX_OPENROUTER_BASE_URL"
DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouterExecutor:
    """Invoke one narrow reasoning task through OpenRouter chat completions."""

    name = "openrouter"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str | None = None,
        base_url: str | None = None,
        referer: str | None = None,
        title: str | None = None,
    ) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get(KEY_ENV)
        self.model = model or os.environ.get(ENV_MODEL)
        self.base_url = (base_url or os.environ.get(ENV_BASE_URL) or DEFAULT_BASE_URL).rstrip("/")
        # OpenRouter uses these only for its public app-attribution leaderboard;
        # they carry no secret and default to a neutral identifier.
        self.referer = referer or "https://github.com/omarmohelal/SecHelix"
        self.title = title or "SecHelix"
        self._response: Any = None

    @property
    def available(self) -> bool:
        """A usable key is the only hard requirement to select this executor.

        A missing model is reported at invoke time with an actionable message,
        because the key is what distinguishes "configured" from "not"; the model
        is a per-run choice.
        """
        return bool(self.api_key)

    def cancel(self) -> None:
        response = self._response
        if response is not None:
            try:
                response.close()
            except Exception:
                pass

    def invoke(
        self,
        prompt: str,
        *,
        timeout: float = 300.0,
        response_schema: dict[str, Any] | None = None,
    ) -> ProviderResult:
        if not self.api_key:
            raise ProviderError(
                f"{KEY_ENV} is not set; export an OpenRouter key or choose another executor"
            )
        if not self.model:
            raise ProviderError(
                f"no OpenRouter model selected; pass --model or set {ENV_MODEL} "
                "(for example 'openai/gpt-4o-mini')"
            )

        request_body: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            # Ask OpenRouter to fold spend into the usage block so cost is
            # measured rather than guessed. Ignored by hosts that do not
            # support it, which is why cost stays Optional below.
            "usage": {"include": True},
        }
        if response_schema is not None:
            # Constrain the model to the node's schema. strictify() makes it an
            # OpenAI-strict-compatible shape; the downstream validator still runs,
            # so this only raises the odds of a conforming response.
            request_body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "sechelix_node",
                    "strict": True,
                    "schema": strictify(response_schema),
                },
            }
        body = json.dumps(request_body).encode("utf-8")

        request = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "HTTP-Referer": self.referer,
                "X-Title": self.title,
            },
        )

        try:
            self._response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310 - fixed https endpoint
            try:
                status = getattr(self._response, "status", 200)
                payload = self._response.read().decode("utf-8", "replace")
            finally:
                self._response.close()
                self._response = None
        except urllib.error.HTTPError as exc:
            detail = _safe_error_body(exc)
            raise ProviderError(
                f"OpenRouter returned HTTP {exc.code}: {detail}"
            ) from None
        except urllib.error.URLError as exc:
            # Keep the reason, not the exception repr, so a key in a redirected
            # URL (there is none here, but be strict) can never ride along.
            raise ProviderError(f"could not reach OpenRouter: {exc.reason}") from None
        except TimeoutError:
            raise ProviderError(f"OpenRouter timed out after {timeout:.0f}s") from None

        if status < 200 or status >= 300:
            raise ProviderError(f"OpenRouter returned HTTP {status}")

        return _parse_completion(payload, fallback_model=self.model)


def _safe_error_body(exc: urllib.error.HTTPError) -> str:
    """Return a short, key-free description of a server error body."""
    try:
        raw = exc.read().decode("utf-8", "replace")
    except Exception:
        return "no response body"
    raw = raw.strip()
    # Prefer the structured message OpenRouter returns, but never surface the
    # whole document.
    try:
        obj = json.loads(raw)
        if isinstance(obj, dict):
            error = obj.get("error")
            if isinstance(error, dict) and isinstance(error.get("message"), str):
                return error["message"][:300]
            if isinstance(error, str):
                return error[:300]
    except json.JSONDecodeError:
        pass
    return raw[:300] or "no response body"


def _parse_completion(
    payload: str, *, fallback_model: str, provider: str = "openrouter"
) -> ProviderResult:
    try:
        obj = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ProviderError(f"OpenRouter response is not valid JSON: {exc}") from exc
    if not isinstance(obj, dict):
        raise ProviderError("OpenRouter response is not a JSON object")

    error = obj.get("error")
    if error:
        message = (
            error.get("message")
            if isinstance(error, dict) and isinstance(error.get("message"), str)
            else str(error)
        )
        raise ProviderError(f"OpenRouter reported an error: {message[:300]}")

    choices = obj.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ProviderError("OpenRouter response had no choices")
    message = choices[0].get("message") if isinstance(choices[0], dict) else None
    content = message.get("content") if isinstance(message, dict) else None
    if not isinstance(content, str) or not content.strip():
        raise ProviderError("OpenRouter completed without a non-empty message")

    usage = obj.get("usage") if isinstance(obj.get("usage"), dict) else {}
    input_tokens = _int_or_none(usage.get("prompt_tokens"))
    output_tokens = _int_or_none(usage.get("completion_tokens"))
    cost_usd = _float_or_none(usage.get("cost"))

    finish_reason = choices[0].get("finish_reason") if isinstance(choices[0], dict) else None

    return ProviderResult(
        text=content,
        model=_string_or_none(obj.get("model")) or fallback_model,
        provider=provider,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd,
        session_id=_string_or_none(obj.get("id")),
        raw={"finish_reason": finish_reason} if finish_reason is not None else {},
    )


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float_or_none(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


__all__ = ["OpenRouterExecutor", "KEY_ENV", "ENV_MODEL", "ENV_BASE_URL", "DEFAULT_BASE_URL"]
