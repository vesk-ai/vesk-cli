"""Minimal async client for OpenAI-compatible chat completions endpoints."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

import httpx

from vesk import __version__


class EndpointError(Exception):
    """The target endpoint could not produce a usable answer."""


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
        self._sleep = sleep

    async def aclose(self) -> None:
        await self._http.aclose()

    async def complete(self, messages: list[dict[str, str]]) -> str:
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": 0,
            "max_tokens": self._max_tokens,
        }
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
            return _extract_text(resp)
        raise EndpointError(f"endpoint unavailable after {self._retries + 1} attempts ({last})")


def _extract_text(resp: httpx.Response) -> str:
    try:
        content = resp.json()["choices"][0]["message"]["content"]
    except (ValueError, KeyError, IndexError, TypeError):
        raise EndpointError("response is not an OpenAI-style chat completion") from None
    return content if isinstance(content, str) else ""
