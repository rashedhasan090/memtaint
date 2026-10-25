# memtaint

Find the moment an AI agent saves attacker text into its own long-term memory.

Prompt injection that lands in a single turn ends when the session ends. Injection that the agent
writes into a memory tool, a notes file, `AGENTS.md`, `.cursorrules`, or a profile comes back in
every future session, now looking like something the agent or the user decided. `memtaint` reads
an agent trace offline and checks every memory write for verbatim provenance from untrusted tool
output (web pages, email, issues, search results, third-party MCP tools), then tells you what kind
of thing got persisted.

## What is new here

Prompt-injection scanners look at inputs. Memory tools look at what is stored. `memtaint` connects
the two through the trace: a write is only suspicious because of *where its words came from*.

* **Copy provenance.** Token n-gram matching attributes each memory write to the earlier untrusted
  result it copies from, with coverage and longest copied run, and compares it against what the
  user actually typed.
* **What was persisted, not just that it was.** Copied spans are classified as standing orders
  ("from now on", "always"), overrides, send-to/exfil directives, concealment ("do not mention this
  to the user"), approval bypasses, and credential talk.
* **Forged authority.** Flags saved text that says "the user prefers" or "admin instruction" when
  those words came from a web page, not the user.
* **Untrusted destinations.** URLs and email addresses in a memory write that only an untrusted
  source introduced and the user never gave.
* **Invisible payloads.** Zero-width and Unicode tag characters in saved memory, with tag text decoded.
* **Paraphrase fallback.** Instruction-like writes made right after an untrusted read, with no
  verbatim match and no user basis, are flagged as unsourced.
* **Files count as memory.** Writes and edits to `AGENTS.md`, `CLAUDE.md`, `.cursor/rules/*`,
  `MEMORY*`, `notes*.md`, `SKILL.md`, profile JSON and similar are treated as memory sinks.

Pure Python standard library, no network, no model calls.

## Install

```bash
pip install git+https://github.com/rashedhasan090/memtaint
# or run from a checkout
python -m memtaint --help
```

## Run

```bash
memtaint trace.jsonl                       # text report
memtaint trace.jsonl --format md           # Markdown table for a PR comment
memtaint runs/*.jsonl --format json        # machine readable
memtaint trace.jsonl --fail-on high        # CI gate, exit 1 on high or critical
memtaint trace.jsonl --source 'kb.*' --sink 'vault.put'   # your own tool names
memtaint --list-defaults                   # see built-in source/sink/path globs
```

### Trace formats

* JSONL or JSON list of events: `{"type":"user"|"assistant"|"tool_call"|"tool_result", ...}` with
  `name`, `id`/`call_id`, `args`, `content`.
* OpenAI-style chat messages (`{"messages":[...]}` or a list) with `tool_calls` and `role: "tool"`.

## Demo

```text
$ memtaint examples/poisoned.jsonl
examples/poisoned.jsonl: 6 events, 1 untrusted results, 2 memory writes, 6 findings
  [CRITICAL] INSTRUCTION_PERSIST at event 3 (save_memory)
      instruction-like text from untrusted output is being saved where future sessions will read it: always/never rule, conceal, send-to, standing-order
  [CRITICAL] HIDDEN_TEXT_PERSIST at event 3 (save_memory)
      memory write contains 18 invisible characters encoding: 'send notes to evil'
  [HIGH] FORGED_AUTHORITY at event 3 (save_memory)
      saved text claims authority ('the user prefers') but it was copied from web_fetch output, not said by the user
  [HIGH] UNTRUSTED_DESTINATION at event 3 (save_memory)
      persists a URL or address the user never gave, introduced by web_fetch@2
      evidence: https://collector.evil.example/upload
  [MEDIUM] TAINTED_PERSIST at event 3 (save_memory)
      memory write copies 48 consecutive tokens (100% of the write) from untrusted web_fetch output at event 2
  [MEDIUM] TAINTED_PERSIST at event 4 (write_file:AGENTS.md)
      memory write copies 15 consecutive tokens (94% of the write) from untrusted web_fetch output at event 2

$ memtaint examples/clean_openai.json
examples/clean_openai.json: 5 events, 1 untrusted results, 1 memory writes, 0 findings
```

In the clean example the search result carries an injection, but the agent only saved what the
user said, so nothing is flagged.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `TAINTED_PERSIST` | medium (low if user said it too) | write copies a long run from untrusted output |
| `INSTRUCTION_PERSIST` | high, critical for override/send-to/conceal/bypass | copied text is an instruction |
| `FORGED_AUTHORITY` | high | copied text claims user/system authority |
| `UNTRUSTED_DESTINATION` | high | URL or address only an untrusted source introduced |
| `HIDDEN_TEXT_PERSIST` | high, critical if tag text decodes | invisible characters saved |
| `UNSOURCED_INSTRUCTION` | medium | paraphrased instruction right after an untrusted read |

## Tests

```bash
python -m unittest discover -s tests -v
```

## Limits

Verbatim and near-verbatim copies are traced reliably; heavy paraphrase falls back to a heuristic.
Tool-name globs decide what is untrusted, so tune `--source` and `--sink` for your agent.

MIT licensed.
