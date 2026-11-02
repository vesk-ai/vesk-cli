import asyncio
import json

import httpx

from vesk.client import ChatClient


def _client(body, **kw):
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(json.loads(req.content))
        return httpx.Response(200, json=body)

    return ChatClient("http://t/v1", "m", transport=httpx.MockTransport(handler), **kw), seen


def test_thinking_model_empty_content_is_captured_not_discarded():
    body = {
        "choices": [
            {"message": {"content": "", "reasoning": "thinking..."}, "finish_reason": "length"}
        ],
        "usage": {"completion_tokens": 256},
    }
    c, _ = _client(body)
    r = asyncio.run(c.complete_detailed([{"role": "user", "content": "hi"}]))
    assert r.content == "" and r.reasoning == "thinking..."
    assert r.finish_reason == "length" and r.usage == {"completion_tokens": 256}
    assert r.http_status == 200 and r.latency_s >= 0 and r.started_at


def test_reasoning_effort_and_max_tokens_sent_and_recorded():
    body = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}
    c, seen = _client(body, max_tokens=1024, reasoning_effort="low")
    asyncio.run(c.complete_detailed([{"role": "user", "content": "hi"}]))
    assert seen[0]["max_tokens"] == 1024 and seen[0]["reasoning_effort"] == "low"
    assert c.generation_params == {
        "temperature": 0,
        "max_tokens": 1024,
        "reasoning_effort": "low",
    }


def test_reasoning_effort_omitted_by_default():
    c, seen = _client({"choices": [{"message": {"content": "ok"}}]})
    asyncio.run(c.complete([{"role": "user", "content": "hi"}]))
    assert "reasoning_effort" not in seen[0]
