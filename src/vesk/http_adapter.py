"""Generic HTTP target adapter: configurable request template and response path.

Lets vesk test an application endpoint that is not OpenAI-compatible. It exposes the same
interface as `ChatClient` (`complete_detailed`, `generation_params`, `aclose`).
"""

from __future__ import annotations

import asyncio
import json
import time
from datetime import datetime, timezone
from typing import Any

import httpx

from vesk import __version__
from vesk.client import Completion, EndpointError


def render_template(template: str, messages: list[dict[str, str]], api_key: str = "") -> str:
    """Fill {{system}}, {{prompt}}, {{messages}} and {{api_key}} into a JSON/text template.

    {{system}} and {{prompt}} are JSON-string-escaped (use them inside quotes);
    {{messages}} is the whole message list as a JSON array (use it unquoted).
    """
    system = next((m["content"] for m in messages if m["role"] == "system"), "")
    prompt = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")

    def esc(s: str) -> str:
        return json.dumps(s, ensure_ascii=False)[1:-1]

    return (
        template.replace("{{messages}}", json.dumps(messages, ensure_ascii=False))
        .replace("{{system}}", esc(system))
        .replace("{{prompt}}", esc(prompt))
        .replace("{{api_key}}", esc(api_key))
    )


def extract_path(body: Any, path: str) -> Any:
    """Dotted path into parsed JSON; integers index lists (e.g. choices.0.text)."""
    cur = body
    for part in path.split("."):
        if isinstance(cur, list):
            cur = cur[int(part)]
        elif isinstance(cur, dict):
            cur = cur[part]
        else:
            raise KeyError(part)
    return cur


class HttpClient:
    def __init__(
        self,
        url: str,
        request_template: str,
        response_path: str,
        reasoning_path: str | None = None,
        method: str = "POST",
        headers: dict[str, str] | None = None,
        api_key: str | None = None,
        timeout_s: float = 30,
        max_retries: int = 2,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._url = url
        self._template = request_template
        self._path = response_path
        self._reasoning_path = reasoning_path
        self._method = method.upper()
        self._api_key = api_key or ""
        self._headers = {"User-Agent": f"vesk/{__version__}", **(headers or {})}
        self._retries = max_retries
        self._http = httpx.AsyncClient(timeout=timeout_s, transport=transport)

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def generation_params(self) -> dict[str, Any]:
        return {"adapter": "http", "note": "generation parameters are set by the target"}

    async def complete_detailed(self, messages: list[dict[str, str]]) -> Completion:
        raw = render_template(self._template, messages, self._api_key)
        try:
            payload = json.loads(raw)
        except ValueError:
            raise EndpointError("request_template does not produce valid JSON") from None
        headers = {k: render_template(v, messages, self._api_key) for k, v in self._headers.items()}
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        t0 = time.monotonic()
        last = "no attempt made"
        for attempt in range(self._retries + 1):
            if attempt:
                await asyncio.sleep(0.5 * 2 ** (attempt - 1))
            try:
                resp = await self._http.request(
                    self._method, self._url, json=payload, headers=headers
                )
            except httpx.TransportError as e:
                last = type(e).__name__
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                continue
            if resp.status_code >= 400:
                raise EndpointError(f"HTTP {resp.status_code} from endpoint")
            return self._parse(resp, payload, started_at, time.monotonic() - t0)
        raise EndpointError(f"endpoint unavailable after {self._retries + 1} attempts ({last})")

    def _parse(self, resp: httpx.Response, request: Any, started_at: str, latency: float):
        try:
            body = resp.json()
            content = extract_path(body, self._path)
        except (ValueError, KeyError, IndexError, TypeError):
            raise EndpointError(f"response has no value at response_path {self._path!r}") from None
        reasoning: Any = ""
        if self._reasoning_path:
            try:
                reasoning = extract_path(body, self._reasoning_path)
            except (KeyError, IndexError, TypeError, ValueError):
                reasoning = ""
        return Completion(
            content=content if isinstance(content, str) else "",
            reasoning=reasoning if isinstance(reasoning, str) else "",
            finish_reason="stop",  # the adapter cannot see truncation; documented limitation
            http_status=resp.status_code,
            latency_s=round(latency, 3),
            started_at=started_at,
            request={"body": request} if not isinstance(request, dict) else request,
        )
