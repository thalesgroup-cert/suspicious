#!/usr/bin/env python3
"""Summarise gunicorn access-log durations per endpoint. Usage:
   docker logs suspicious 2>&1 | python3 slow_endpoints.py [--top 15]"""
import re, sys, collections
LINE = re.compile(r'"(?P<m>[A-Z]+) (?P<p>\S+) HTTP[^"]*" (?P<s>\d{3}) .*? (?P<us>\d+)µs\s*$')
top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 15
rows = collections.defaultdict(list)
for line in sys.stdin:
    m = LINE.search(line)
    if not m: continue
    path = re.sub(r"\d+", "{n}", m["p"].split("?")[0])
    rows[(m["m"], path)].append(int(m["us"]) / 1e6)
def pct(v, q): v = sorted(v); return v[min(len(v) - 1, int(len(v) * q))]
print("%-6s %-48s %6s %7s %7s %7s %8s" % ("verb", "endpoint", "n", "p50", "p95", "max", "total_s"))
for (m, p), v in sorted(rows.items(), key=lambda kv: -sum(kv[1]))[:top]:
    print("%-6s %-48s %6d %6.2fs %6.2fs %6.2fs %8.1f" % (m, p[:48], len(v), pct(v, .5), pct(v, .95), max(v), sum(v)))
