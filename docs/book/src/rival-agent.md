# Rival agent with a local model

The differential and challenge engines generate inputs from types and ranges.
Some bugs need an input with meaning: a header whose length field lies, a date
on February 29th, a string that is valid UTF-8 but not valid for your parser.
The **rival agent** asks a language model to read the change and propose such
inputs.

It is **off by default**. Turn it on with a local model through
[Ollama](https://ollama.com), so nothing leaves your machine and there is no
API key:

```sh
ollama pull qwen2.5-coder:7b
ollama serve                  # if it isn't already running
rebut verify --base main --adversary ollama
```

## Choosing a model

| Flag | What it does |
|---|---|
| `--adversary ollama` | Ollama at `http://localhost:11434/v1`, model `qwen2.5-coder:7b`. |
| `--adversary ollama:<model>` | Another Ollama model, e.g. `ollama:llama3.1:8b`. |
| `--adversary openai-compat --adversary-url <url> --adversary-model <name>` | Any OpenAI-compatible chat completions server: llama.cpp `llama-server`, LM Studio, vLLM. |
| `--adversary anthropic` | The hosted Anthropic API. Needs `ANTHROPIC_API_KEY`; costs money. |
| `--adversary-url <url>` | Overrides the endpoint (also for `ollama`). |
| `--adversary-model <name>` | Overrides the model. |

The same settings can come from the environment: `REBUT_ADVERSARY`,
`REBUT_ADVERSARY_URL`, `REBUT_ADVERSARY_MODEL`, and `REBUT_ADVERSARY_API_KEY`
for a server that wants a bearer token.

If the model server isn't running, `verify` prints a warning and carries on
without the rival agent. A mistake in the flags (an unknown provider,
`openai-compat` without a URL) is an error; the same mistake coming only from
`REBUT_ADVERSARY` is a warning, so a stray variable can't break `verify`.
At most 8 hypotheses are asked for and replayed per run, and a model that
takes longer than 3 minutes is treated as having proposed nothing.

Small models often wrap their answer in prose or code fences, or leave
trailing commas. rebut reads such answers anyway and drops whatever it can't
use; an unusable answer means zero hypotheses, never a failed run.

## The model's output is never evidence

Whatever the model says is a **hypothesis**: "`parse_header` probably panics on
this input". rebut then runs the base and head on that input. Only if the
execution actually panics, or the head diverges from the base where the intent
says it shouldn't, does it become a finding, with the recorded execution as its
reproduction. Everything else is counted as "could not be reproduced and was
discarded" and never shown as a problem.

This is deliberate ([ADR-6](https://github.com/LaloNchera22/rebut/blob/main/docs/adr/0006-llm-output-is-not-evidence.md)):

- a model that hallucinates costs some build and run time, never a false
  finding;
- the pull request (code, comments, body) is attacker-controlled text that the
  model reads. A prompt injection can at worst make the model *miss* bugs. It
  can't fabricate one, because fabricated findings don't reproduce.

A small local model misses more than a large hosted one, and that is the only
cost: it lowers recall, not precision.
