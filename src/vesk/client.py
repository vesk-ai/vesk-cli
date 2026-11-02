"""Minimal async client for OpenAI-compatible chat completions endpoints."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import httpx

from vesk import __version__


class EndpointError(Exception):
    """The target endpoint could not produce a usable answer."""


@dataclass
class Completion:
    """Everything the endpoint returned for one request, kept for the evidence record."""

    content: str
    reasoning: str = ""
    finish_reason: str | None = None
    http_status: int = 200
    usage: dict[str, Any] = field(default_factory=dict)
    latency_s: float = 0.0
    started_at: str = ""
    request: dict[str, Any] = field(default_factory=dict)


Sleep = Callable[[float], Awaitable[None]]


class ChatClient:
    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str | None = None,
        timeout_s: float = 30,
        max_retries: int = 2,
        max_tokens: int = 256,
        reasoning_effort: str | None = None,
        temperature: float = 0,
        transport: httpx.AsyncBaseTransport | None = None,
        sleep: Sleep = asyncio.sleep,
    ) -> None:
        headers = {"User-Agent": f"vesk/{__version__}"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        self._http = httpx.AsyncClient(
            base_url=base_url.rstrip("/") + "/",
            headers=headers,
            timeout=timeout_s,
            transport=transport,
        )
        self._model = model
        self._retries = max_retries
        self._max_tokens = max_tokens
        self._reasoning_effort = reasoning_effort
        self._temperature = temperature
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    @property
    def generation_params(self) -> dict[str, Any]:
        """The parameters actually sent with every request."""
        params: dict[str, Any] = {
            "temperature": self._temperature,
            "max_tokens": self._max_tokens,
        }
        if self._reasoning_effort:
            params["reasoning_effort"] = self._reasoning_effort
        return params

    async def complete(self, messages: list[dict[str, str]]) -> str:
        return (await self.complete_detailed(messages)).content

    async def complete_detailed(self, messages: list[dict[str, str]]) -> Completion:
        payload = {"model": self._model, "messages": messages, **self.generation_params}
        started_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
        t0 = time.monotonic()
        last = "no attempt made"
        for attempt in range(self._retries + 1):
            if attempt:
                await self._sleep(0.5 * 2 ** (attempt - 1))
            try:
                resp = await self._http.post("chat/completions", json=payload)
            except httpx.TransportError as e:
                last = f"{type(e).__name__}: {e}" if str(e) else type(e).__name__
                continue
            if resp.status_code == 429 or resp.status_code >= 500:
                last = f"HTTP {resp.status_code}"
                continue
            if resp.status_code >= 400:
                # Client errors (bad key, bad model) will not fix themselves; do not retry.
                raise EndpointError(f"HTTP {resp.status_code} from endpoint")
            return _parse(resp, payload, started_at, time.monotonic() - t0)
        raise EndpointError(f"endpoint unavailable after {self._retries + 1} attempts ({last})")


def _parse(
    resp: httpx.Response, request: dict[str, Any], started_at: str, latency_s: float
) -> Completion:
    try:
        body = resp.json()
        choice = body["choices"][0]
        message = choice["message"]
        content = message["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise EndpointError("response is not an OpenAI-style chat completion") from None
    # Ollama's /v1 uses "reasoning"; other servers use "reasoning_content".
    reasoning = message.get("reasoning") or message.get("reasoning_content") or ""
    usage = body.get("usage")
    finish = choice.get("finish_reason")
    return Completion(
        content=content if isinstance(content, str) else "",
        reasoning=reasoning if isinstance(reasoning, str) else "",
        finish_reason=finish if isinstance(finish, str) else None,
        http_status=resp.status_code,
        usage=usage if isinstance(usage, dict) else {},
        latency_s=round(latency_s, 3),
        started_at=started_at,
        request=request,
    )
