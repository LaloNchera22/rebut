# ADR-0009: Local model by default for the rival agent

## Status

Accepted.

## Context

The rival agent (`rebut-adversary`) asks an LLM where a change might break. Its
first generator called the Anthropic API, which costs money per PR and sends the
diff and PR body to a third party. Rebut's local edition is free and runs on the
contributor's machine; a paid API can't be a requirement for it.

## Decision

- The rival agent is **off by default** in the CLI and the MCP server. It runs only
  when asked for (`rebut verify --adversary ...` or `REBUT_ADVERSARY`).
- When it is on, the expected choice is a **local model** behind an OpenAI-compatible
  chat completions endpoint: Ollama (`--adversary ollama`, default
  `qwen2.5-coder:7b`), llama.cpp, LM Studio or vLLM (`--adversary openai-compat`).
  The Anthropic generator stays available as an opt-in. The control plane keeps
  using Anthropic when `ANTHROPIC_API_KEY` is set, unless `REBUT_ADVERSARY`
  chooses another provider.
- Local models are sloppier, so their answers are parsed leniently (code fences,
  leading prose, trailing commas, unknown fields), each malformed hypothesis is
  dropped on its own, and an unreachable server or unparsable answer means zero
  hypotheses and a warning, never a failed run. Hypotheses per PR, replays per PR
  and request time stay bounded.

## Consequences

- This is only safe because of [ADR-6](0006-llm-output-is-not-evidence.md): every
  hypothesis is replayed and only a reproducing execution is a finding. A weaker
  model proposes fewer inputs that reproduce; it can't produce a false finding, and
  lenient parsing can't either.
- Results depend on the model the contributor runs, so the rival agent's output is
  not comparable across machines. It is an extra that can surface bugs, not a check
  whose absence means anything.
