# Rival agent with a local model

The differential and challenge engines generate inputs from types and ranges.
Some bugs need an input with meaning: a header whose length field lies, a date
on February 29th, a string that is valid UTF-8 but not valid for your parser.
The **rival agent** asks a language model to read the change and propose such
inputs.

It runs against a local model through [Ollama](https://ollama.com), so nothing
leaves your machine and there is no API key:

```sh
ollama pull qwen2.5-coder     # or any code model you like
ollama serve                  # if it isn't already running
rebut verify --base main --adversary ollama
```

`rebut verify --help` lists the options for choosing the model and the Ollama
URL.

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
