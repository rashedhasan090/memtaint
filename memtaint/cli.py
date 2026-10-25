import argparse
import json
import sys

from . import __version__
from .core import (analyze, load_trace, to_dict, max_severity, SEVERITY_ORDER,
                   DEFAULT_SOURCES, DEFAULT_SINKS, MEMORY_PATHS)


def render_text(path, findings, stats):
    out = [f"{path}: {stats['events']} events, {stats['untrusted_results']} untrusted results, "
           f"{stats['memory_writes']} memory writes, {len(findings)} findings"]
    for f in sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.event_index)):
        out.append(f"  [{f.severity.upper()}] {f.rule} at event {f.event_index} ({f.sink})")
        out.append(f"      {f.message}")
        if f.evidence:
            out.append(f"      evidence: {f.evidence[:160]}")
    return "\n".join(out)


def render_md(path, findings, stats):
    out = [f"### memtaint: `{path}`", "",
           f"{stats['memory_writes']} memory writes, {stats['untrusted_results']} untrusted results, "
           f"{len(findings)} findings", ""]
    if findings:
        out += ["| Severity | Rule | Event | Sink | Source | Message |", "|---|---|---|---|---|---|"]
        for f in sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.event_index)):
            msg = f.message.replace("|", "\\|")
            out.append(f"| {f.severity} | {f.rule} | {f.event_index} | `{f.sink}` | {f.source} | {msg} |")
    return "\n".join(out)


def main(argv=None):
    p = argparse.ArgumentParser(prog="memtaint", description=
        "Find agent memory writes that persist text from untrusted tool output "
        "(persistent prompt injection / memory poisoning).")
    p.add_argument("traces", nargs="+", help="trace files: JSONL events, JSON list, or OpenAI messages")
    p.add_argument("--source", action="append", help="glob for untrusted tool names (repeatable; replaces defaults)")
    p.add_argument("--sink", action="append", help="glob for memory-write tool names (repeatable; replaces defaults)")
    p.add_argument("--memory-path", action="append", help="glob for persistent memory file paths (replaces defaults)")
    p.add_argument("--ngram", type=int, default=6, help="n-gram size for verbatim matching (default 6)")
    p.add_argument("--min-run", type=int, default=8, help="min consecutive copied tokens to call a write tainted")
    p.add_argument("--format", choices=["text", "json", "md"], default="text")
    p.add_argument("--fail-on", choices=list(SEVERITY_ORDER), help="exit 1 if any finding at or above this severity")
    p.add_argument("--list-defaults", action="store_true", help="print default source/sink/path globs and exit")
    p.add_argument("--version", action="version", version=f"memtaint {__version__}")
    if argv is None:
        argv = sys.argv[1:]
    if "--list-defaults" in argv:
        print(json.dumps({"sources": DEFAULT_SOURCES, "sinks": DEFAULT_SINKS, "memory_paths": MEMORY_PATHS}, indent=2))
        return 0
    a = p.parse_args(argv)
    worst, reports = -1, []
    for path in a.traces:
        with open(path, encoding="utf-8") as fh:
            events = load_trace(fh.read())
        findings, stats = analyze(events, a.source, a.sink, None, a.memory_path, a.ngram, a.min_run)
        worst = max(worst, max_severity(findings))
        if a.format == "json":
            d = to_dict(findings, stats)
            d["trace"] = path
            reports.append(d)
        elif a.format == "md":
            reports.append(render_md(path, findings, stats))
        else:
            reports.append(render_text(path, findings, stats))
    if a.format == "json":
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2, ensure_ascii=False))
    else:
        print("\n\n".join(reports))
    if a.fail_on and worst >= SEVERITY_ORDER[a.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
