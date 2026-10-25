"""Core analysis for memtaint.

A trace is normalized into an ordered list of events:
  {"kind": "user"|"assistant"|"call"|"result", "name": str, "id": str, "text": str, "args": dict, "idx": int}

Untrusted sources are tool results whose tool name matches a source pattern.
Memory sinks are tool calls whose name matches a sink pattern, or file writes
whose target path looks like a persistent agent memory / instruction file.
For every sink write we compute verbatim provenance against earlier untrusted
results and against what the user actually said, then raise findings.
"""
from __future__ import annotations

import fnmatch
import json
import re
import unicodedata
from dataclasses import dataclass, field, asdict

DEFAULT_SOURCES = [
    "*fetch*", "*browse*", "*http*", "*web*", "*search*", "*scrape*", "*crawl*",
    "*email*", "*mail*", "*inbox*", "*slack*", "*read_url*", "*download*",
    "*issue*", "*comment*", "*pdf*", "*rss*", "*mcp__*",
]
DEFAULT_SINKS = [
    "*memory*", "*remember*", "*memorize*", "*save_note*", "*add_note*",
    "*update_profile*", "*knowledge*", "*store_fact*", "*persist*",
]
FILE_WRITE_TOOLS = ["*write*", "*edit*", "*create_file*", "*append*", "*str_replace*", "*patch*"]
MEMORY_PATHS = [
    "*memory*", "*MEMORY*", "*AGENTS.md", "*CLAUDE.md", "*GEMINI.md", "*.cursorrules",
    "*.cursor/rules/*", "*copilot-instructions.md", "*notes*.md", "*NOTES*", "*.windsurfrules",
    "*system_prompt*", "*persona*", "*profile*.json", "*SKILL.md",
]

TOKEN_RE = re.compile(r"[A-Za-z0-9_@./:+-]+")
URL_RE = re.compile(r"https?://[^\s\"'<>)\]]+|\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
HIDDEN_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
INSTRUCTION_PATTERNS = [
    (r"\bignore (all |any )?(previous|prior|above|earlier)\b", "override"),
    (r"\b(from now on|going forward|in (all|every) future|henceforth|always remember)\b", "standing-order"),
    (r"\b(always|never)\s+\w+", "always/never rule"),
    (r"\byou (must|should|will|are required to)\b", "directive"),
    (r"\bwhen(ever)? (the )?user (asks|says|mentions|requests)\b", "conditional trigger"),
    (r"\b(send|forward|upload|post|email|exfiltrate|copy)\b[^.\n]{0,60}\b(to|at)\b\s+\S+", "send-to"),
    (r"\b(do not|don't|never) (tell|mention|inform|reveal|show)\b[^.\n]{0,30}\b(user|anyone)\b", "conceal"),
    (r"\b(api[_ -]?key|password|token|secret|credentials?)\b", "credential"),
    (r"\b(disable|skip|bypass|turn off)\b[^.\n]{0,40}\b(confirm\w*|approval|review|check|safety|guard\w*)\b", "bypass"),
]
AUTHORITY_PATTERNS = [
    r"\b(the )?user (prefers|wants|said|asked|has asked|requested|instructed|approved|authorized)\b",
    r"\b(system|admin|administrator|developer|owner) (note|instruction|says|policy)\b",
    r"\b(trusted|verified|official) (source|domain|instruction|contact)\b",
]
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    rule: str
    severity: str
    event_index: int
    sink: str
    message: str
    source: str = ""
    evidence: str = ""
    details: dict = field(default_factory=dict)


def _match(name: str, patterns) -> bool:
    n = (name or "").lower()
    return any(fnmatch.fnmatch(n, p.lower()) for p in patterns)


def _text_of(v) -> str:
    if v is None:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, list):
        parts = []
        for x in v:
            if isinstance(x, dict) and "text" in x:
                parts.append(str(x["text"]))
            else:
                parts.append(_text_of(x))
        return "\n".join(parts)
    if isinstance(v, dict):
        return "\n".join(_text_of(x) for x in v.values())
    return str(v)


def _args(v) -> dict:
    if isinstance(v, dict):
        return v
    if isinstance(v, str):
        try:
            d = json.loads(v)
            return d if isinstance(d, dict) else {"value": d}
        except ValueError:
            return {"value": v}
    return {}


def load_trace(text: str) -> list:
    """Accept JSONL generic events, a JSON list of events, or OpenAI-style messages."""
    text = text.strip()
    records = []
    if text.startswith("["):
        records = json.loads(text)
    elif text.startswith("{") and "\n" not in text.strip():
        obj = json.loads(text)
        records = obj.get("messages") or obj.get("events") or [obj]
    else:
        try:
            obj = json.loads(text)
            records = obj.get("messages") or obj.get("events") or [obj]
        except ValueError:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
    return normalize(records)


def normalize(records) -> list:
    events = []
    call_names = {}

    def add(kind, name="", id_="", text="", args=None):
        events.append({"kind": kind, "name": name or "", "id": id_ or "", "text": text or "",
                       "args": args or {}, "idx": len(events)})

    for r in records:
        if not isinstance(r, dict):
            continue
        role = r.get("role")
        typ = r.get("type")
        if role in ("user", "system", "developer"):
            add("user" if role == "user" else "system", text=_text_of(r.get("content")))
        elif role == "assistant":
            if r.get("content"):
                add("assistant", text=_text_of(r.get("content")))
            for tc in r.get("tool_calls") or []:
                fn = tc.get("function", tc)
                a = _args(fn.get("arguments", fn.get("input")))
                call_names[tc.get("id", "")] = fn.get("name", "")
                add("call", fn.get("name"), tc.get("id"), json.dumps(a, ensure_ascii=False), a)
        elif role == "tool":
            cid = r.get("tool_call_id", "")
            add("result", r.get("name") or call_names.get(cid, ""), cid, _text_of(r.get("content")))
        elif typ in ("user", "user_message"):
            add("user", text=_text_of(r.get("content", r.get("text"))))
        elif typ in ("assistant", "assistant_message", "message"):
            add("assistant", text=_text_of(r.get("content", r.get("text"))))
        elif typ in ("tool_call", "call", "function_call", "tool_use"):
            a = _args(r.get("args", r.get("arguments", r.get("input"))))
            cid = r.get("id") or r.get("call_id", "")
            call_names[cid] = r.get("name", "")
            add("call", r.get("name"), cid, json.dumps(a, ensure_ascii=False), a)
        elif typ in ("tool_result", "result", "function_call_output", "observation"):
            cid = r.get("call_id") or r.get("tool_call_id") or r.get("id", "")
            add("result", r.get("name") or call_names.get(cid, ""), cid,
                _text_of(r.get("content", r.get("output", r.get("text")))))
    return events


def tokens(s: str) -> list:
    s = unicodedata.normalize("NFKC", HIDDEN_RE.sub("", s or "")).lower()
    return TOKEN_RE.findall(s)


def ngram_index(toks, n):
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


def copied_spans(write_toks, src_toks, n=6):
    """Return (coverage fraction, longest run, list of copied spans as strings)."""
    if len(write_toks) < n or len(src_toks) < n:
        return 0.0, 0, []
    idx = ngram_index(src_toks, n)
    covered = [False] * len(write_toks)
    for i in range(len(write_toks) - n + 1):
        if tuple(write_toks[i:i + n]) in idx:
            for j in range(i, i + n):
                covered[j] = True
    spans, longest, i = [], 0, 0
    while i < len(covered):
        if covered[i]:
            j = i
            while j < len(covered) and covered[j]:
                j += 1
            spans.append(" ".join(write_toks[i:j]))
            longest = max(longest, j - i)
            i = j
        else:
            i += 1
    return sum(covered) / len(covered), longest, spans


def sink_payload(ev, sinks, write_tools, mem_paths):
    """Return (sink label, text written) if event is a memory write, else None."""
    if ev["kind"] != "call":
        return None
    name, a = ev["name"], ev["args"]
    if _match(name, sinks):
        return name, _text_of({k: v for k, v in a.items() if k not in ("id", "key_id")})
    if _match(name, write_tools):
        path = str(a.get("path") or a.get("file_path") or a.get("filename") or a.get("target_file") or "")
        if path and _match(path, mem_paths):
            body = a.get("content") or a.get("new_string") or a.get("new_str") or a.get("text") \
                or a.get("contents") or a.get("diff") or a.get("patch") or ""
            return f"{name}:{path}", _text_of(body)
    return None


def analyze(events, sources=None, sinks=None, write_tools=None, mem_paths=None,
            ngram=6, min_run=8, min_cov=0.3):
    sources = sources or DEFAULT_SOURCES
    sinks = sinks or DEFAULT_SINKS
    write_tools = write_tools or FILE_WRITE_TOOLS
    mem_paths = mem_paths or MEMORY_PATHS
    findings = []
    untrusted = []  # (idx, name, raw text, tokens)
    user_toks = []
    user_urls = set()
    writes = 0
    for ev in events:
        if ev["kind"] in ("user", "system"):
            user_toks.extend(tokens(ev["text"]) + ["\x00"])
            user_urls.update(u.lower().rstrip(".,") for u in URL_RE.findall(ev["text"]))
            continue
        if ev["kind"] == "result" and _match(ev["name"], sources) and not _match(ev["name"], sinks):
            untrusted.append((ev["idx"], ev["name"], ev["text"], tokens(ev["text"])))
            continue
        sp = sink_payload(ev, sinks, write_tools, mem_paths)
        if not sp:
            continue
        writes += 1
        sink, body = sp
        wt = tokens(body)
        best = None
        for (sidx, sname, raw, st) in untrusted:
            cov, run, spans = copied_spans(wt, st, ngram)
            if run >= min_run or (cov >= min_cov and run >= ngram):
                if best is None or run > best[1]:
                    best = (cov, run, spans, sidx, sname, raw)
        ucov, urun, _ = copied_spans(wt, user_toks, ngram)
        src_label = f"{best[4]}@{best[3]}" if best else ""
        if best:
            cov, run, spans, sidx, sname, raw = best
            ev_text = max(spans, key=len)[:200]
            sev = "medium" if ucov < 0.5 else "low"
            findings.append(Finding("TAINTED_PERSIST", sev, ev["idx"], sink,
                                    f"memory write copies {run} consecutive tokens ({cov:.0%} of the write) "
                                    f"from untrusted {sname} output at event {sidx}",
                                    src_label, ev_text,
                                    {"coverage": round(cov, 3), "longest_run": run,
                                     "user_coverage": round(ucov, 3)}))
            tainted_text = " ".join(spans)
            hits = sorted({label for pat, label in INSTRUCTION_PATTERNS
                           if re.search(pat, tainted_text, re.I)})
            if hits:
                sev = "critical" if any(h in hits for h in ("override", "send-to", "conceal", "bypass")) else "high"
                findings.append(Finding("INSTRUCTION_PERSIST", sev, ev["idx"], sink,
                                        "instruction-like text from untrusted output is being saved "
                                        "where future sessions will read it: " + ", ".join(hits),
                                        src_label, ev_text, {"patterns": hits}))
            for pat in AUTHORITY_PATTERNS:
                m = re.search(pat, tainted_text, re.I)
                if m:
                    findings.append(Finding("FORGED_AUTHORITY", "high", ev["idx"], sink,
                                            f"saved text claims authority ('{m.group(0)}') but it was "
                                            f"copied from {sname} output, not said by the user",
                                            src_label, ev_text))
                    break
        # destinations persisted that only an untrusted source introduced
        w_urls = {u.lower().rstrip(".,") for u in URL_RE.findall(body)}
        for u in sorted(w_urls - user_urls):
            origin = next((f"{n}@{i}" for (i, n, raw, _) in untrusted if u in raw.lower()), "")
            if origin:
                findings.append(Finding("UNTRUSTED_DESTINATION", "high", ev["idx"], sink,
                                        f"persists a URL or address the user never gave, introduced by {origin}",
                                        origin, u))
        hidden = HIDDEN_RE.findall(body)
        if hidden:
            decoded = "".join(chr(ord(c) - 0xE0000) for c in hidden if 0xE0020 <= ord(c) <= 0xE007E)
            findings.append(Finding("HIDDEN_TEXT_PERSIST", "critical" if decoded else "high", ev["idx"], sink,
                                    f"memory write contains {len(hidden)} invisible characters"
                                    + (f" encoding: {decoded!r}" if decoded else ""),
                                    src_label, decoded[:200], {"count": len(hidden)}))
        if not best and not hidden:
            # paraphrase heuristic: instruction text written right after untrusted read, user never said it
            hits = sorted({label for pat, label in INSTRUCTION_PATTERNS if re.search(pat, body, re.I)}
                          - {"always/never rule", "credential"})
            recent = [u for u in untrusted if ev["idx"] - u[0] <= 6]
            if hits and recent and ucov < 0.3:
                findings.append(Finding("UNSOURCED_INSTRUCTION", "medium", ev["idx"], sink,
                                        "memory write adds instruction-like text (" + ", ".join(hits) +
                                        ") shortly after reading untrusted "
                                        f"{recent[-1][1]} output, and the user never said it",
                                        f"{recent[-1][1]}@{recent[-1][0]}", body[:200], {"patterns": hits}))
    return findings, {"events": len(events), "untrusted_results": len(untrusted), "memory_writes": writes}


def max_severity(findings):
    return max((SEVERITY_ORDER[f.severity] for f in findings), default=-1)


def to_dict(findings, stats):
    return {"stats": stats, "findings": [asdict(f) for f in findings]}
