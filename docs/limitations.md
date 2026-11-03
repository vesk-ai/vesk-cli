# Known limitations

- Point-in-time test of one target and configuration. Not a certification, legal opinion, or guarantee of security or regulatory compliance.
- Three built-in probes: prompt injection (direct, embedded and split-token), jailbreak marker compliance, and PII leakage of synthetic planted values. An opt-in fourth probe, `tool_misuse`, covers single-turn tool-call abuse. Not tested: harmful-content generation, multi-turn agents and tool results fed back, MCP, RAG, multi-turn attacks, training-data extraction, bias, toxicity, robustness, denial of service.
- `jailbreak_marker` measures whether a harmless marker is emitted. A pass does not show resistance to jailbreaks.
- Detectors are string-based. Paraphrased leaks or obedience can be missed (false pass); the refusal heuristic is English-only and can be wrong either way (hence `inconclusive`).
- Hindi/Hinglish prompts: the board waived native-speaker review for this sprint; coverage is not reviewed.
- The Wilson interval assumes independent samples; cases are not independent, so it is indicative only.
- Seeds are sent for case selection only; targets may ignore sampling seeds, and models are not deterministic.
- Model digests are not exposed by `/v1` APIs and are recorded as null.
- The HTTP adapter cannot detect truncation. SHA-256 sidecars detect file changes only; they are not signatures. For signatures see signing.md (tamper-evidence, not certification).
- Raw model endpoints tested under vesk's baseline prompt describe the model, not any product built on it.
- OWASP tags use the LLM Top 10 2025 edition, the latest published on genai.owasp.org; no 2026 edition exists.
- `tool_misuse` is single turn: tools are declared but never executed and no tool result is sent back, so it does not test multi-step agent loops, tool-result injection through real tools, or MCP servers. It needs a target that accepts the OpenAI `tools` parameter (the http adapter and plugin targets without a `tools` argument are not supported). Targets that never call tools yield `inconclusive`, not a pass. Planned next: RAG canary documents, then MCP.
