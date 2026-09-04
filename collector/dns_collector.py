#!/usr/bin/env python3
"""
SOC Pipeline - Technitium DNS collector (Phase 3.1).

Read-only, incremental pull of DNS query logs from one or more Technitium servers
via the Query Logs (Sqlite) app API. Normalizes each query to a flat JSON event
and writes JSON-lines for the GELF emitter / Wazuh, plus a per-server high-water
mark (last timestamp seen) so each run only pulls NEW records.

This does NOT write to Technitium. logs/query (read) + dashboard/stats (read) only.
Never changes DNS config, zones, or app settings.

Design notes:
- DNS is high-volume telemetry. FULL query volume is meant for Graylog (retention/
  hunting). The subset that should reach Wazuh as detections is decided by rules,
  not here; this collector emits normalized events and a few cheap enrichments
  (label stats, entropy) so rules can gate on them without re-parsing.
- Incremental by timestamp: the API supports start=<ISO> ascending. We keep the
  last timestamp per server in a state file and pull start=that on the next run.

Env (from ~/.config/soc-pipeline/env): TECHNITIUM_TOKEN, TECHNITIUM_SERVERS (comma-separated
host or host:port; default port 5380).

Usage:
  dns_collector.py --out <dir> [--state <file>] [--max-pages N] [--lookback-min M]
"""
import argparse, json, os, sys, math, datetime, urllib.parse, urllib.request, collections

APP_NAME = "Query Logs (Sqlite)"
APP_CLASS = "QueryLogsSqlite.App"
DEFAULT_PORT = 5380
STATE_DEFAULT = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".dns_state.json")


def load_env(path=None):
    path = path or os.environ.get(
        "SOC_ENV_FILE", os.path.expanduser("~/.config/soc-pipeline/env")
    )
    e = {}
    if os.path.exists(path):
        for line in open(path):
            if "=" in line and not line.strip().startswith("#"):
                k, v = line.strip().split("=", 1)
                e[k] = v
    return e


def http_get_json(url, timeout=20):
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = collections.Counter(s)
    n = len(s)
    return round(-sum((c / n) * math.log2(c / n) for c in counts.values()), 3)


def normalize(entry, server):
    """One Technitium query-log entry -> flat normalized DNS event."""
    qname = (entry.get("qname") or "").rstrip(".")
    labels = [l for l in qname.split(".") if l]
    # longest label + entropy of the leftmost label feed tunneling/DGA rules
    longest = max((len(l) for l in labels), default=0)
    leftmost = labels[0] if labels else ""
    rtype = entry.get("responseType")
    # Technitium blocks come in two flavors: local blocklist ("Blocked") and
    # upstream forwarder ("UpstreamBlocked"). Capture BOTH. block_type carries
    # which; blocked is the boolean either-way for simple rule gating.
    block_type = rtype if rtype in ("Blocked", "UpstreamBlocked") else "none"
    ev = {
        "event_type": "dns_query",
        "source": "technitium",
        "server": server,
        "timestamp": entry.get("timestamp"),
        "client": entry.get("clientIpAddress"),
        "dns_protocol": entry.get("protocol"),         # 'protocol' is reserved in Wazuh's mapping; use dns_protocol
        "response_type": rtype,                        # Cached/Recursive/Blocked/UpstreamBlocked/Authoritative
        "rcode": entry.get("rcode"),                   # NoError/NxDomain/Refused/ServerFailure
        "qname": qname,
        "qtype": entry.get("qtype"),
        "qclass": entry.get("qclass"),
        "answer": entry.get("answer"),
        # cheap enrichments for detection rules (computed once, here)
        "qname_len": len(qname),
        "label_count": len(labels),
        "longest_label": longest,
        "leftmost_label_entropy": shannon_entropy(leftmost),
        "blocked": block_type != "none",
        "block_type": block_type,                      # Blocked | UpstreamBlocked | none
    }
    return ev


def pull_server(server, token, start_iso, max_pages, per_page=1000):
    """Incrementally pull entries with timestamp >= start_iso (ascending)."""
    host = server if ":" in server else f"{server}:{DEFAULT_PORT}"
    base = f"http://{host}/api/logs/query"
    events, last_ts, pages = [], start_iso, 0
    page = 1
    while page <= max_pages:
        params = {
            "token": token, "name": APP_NAME, "classPath": APP_CLASS,
            "pageNumber": page, "entriesPerPage": per_page,
            "descendingOrder": "false",
        }
        if start_iso:
            params["start"] = start_iso
        url = base + "?" + urllib.parse.urlencode(params)
        try:
            d = http_get_json(url)
        except Exception as e:
            print(f"WARN {server}: query failed page {page}: {e}", file=sys.stderr)
            break
        if d.get("status") != "ok":
            print(f"WARN {server}: API status {d.get('status')}: {d.get('errorMessage','')[:120]}",
                  file=sys.stderr)
            break
        r = d.get("response", {})
        ents = r.get("entries", [])
        if not ents:
            break
        for e in ents:
            events.append(normalize(e, server))
            ts = e.get("timestamp")
            if ts and ts > last_ts:
                last_ts = ts
        pages += 1
        total_pages = r.get("totalPages", page)
        if page >= total_pages:
            break
        page += 1
    return events, last_ts, pages


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="./dns_out")
    ap.add_argument("--state", default=STATE_DEFAULT)
    ap.add_argument("--max-pages", type=int, default=200,
                    help="safety cap on pages per server per run")
    ap.add_argument("--lookback-min", type=int, default=10,
                    help="on first run (no state), how far back to seed the window")
    ap.add_argument("--dry-run", action="store_true", help="print summary, write nothing")
    args = ap.parse_args()

    env = load_env()
    token = os.environ.get("TECHNITIUM_TOKEN") or env.get("TECHNITIUM_TOKEN")
    servers_raw = os.environ.get("TECHNITIUM_SERVERS") or env.get("TECHNITIUM_SERVERS", "")
    servers = [s.strip() for s in servers_raw.split(",") if s.strip()]
    if not token or not servers:
        sys.exit("TECHNITIUM_TOKEN / TECHNITIUM_SERVERS not set in env or ~/.config/soc-pipeline/env")

    state = {}
    if os.path.exists(args.state):
        state = json.load(open(args.state)).get("last_ts", {})

    seed = (datetime.datetime.now(datetime.UTC) -
            datetime.timedelta(minutes=args.lookback_min)).strftime("%Y-%m-%dT%H:%M:%S")

    all_events, new_state, summary = [], dict(state), []
    for srv in servers:
        start_iso = state.get(srv, seed)
        evs, last_ts, pages = pull_server(srv, token, start_iso, args.max_pages)
        all_events.extend(evs)
        new_state[srv] = last_ts
        summary.append({"server": srv, "pulled": len(evs), "pages": pages,
                        "from": start_iso, "to": last_ts})

    # aggregate stats for the run summary (what detection would key on)
    rc = collections.Counter(e["rcode"] for e in all_events)
    blocked = sum(1 for e in all_events if e["blocked"])
    block_types = collections.Counter(e["block_type"] for e in all_events if e["blocked"])
    high_entropy = sum(1 for e in all_events if e["leftmost_label_entropy"] >= 3.5)
    long_label = sum(1 for e in all_events if e["longest_label"] >= 40)

    if args.dry_run:
        print(json.dumps({"dry_run": True, "servers": summary,
                          "total": len(all_events), "rcode": dict(rc),
                          "blocked": blocked, "block_types": dict(block_types),
                          "high_entropy_labels": high_entropy,
                          "long_labels": long_label}, indent=1))
        return

    os.makedirs(args.out, exist_ok=True)
    ts = datetime.datetime.now(datetime.UTC).strftime("%Y%m%dT%H%M%SZ")
    outpath = os.path.join(args.out, f"dns-events-{ts}.jsonl")
    with open(outpath, "w") as f:
        for e in all_events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")

    os.makedirs(os.path.dirname(os.path.abspath(args.state)), exist_ok=True)
    json.dump({"last_ts": new_state}, open(args.state, "w"), indent=1)

    print(f"collected {len(all_events)} DNS events from {len(servers)} servers -> {outpath}")
    print("rcode:", json.dumps(dict(rc)))
    print(f"blocked={blocked} block_types={dict(block_types)} "
          f"high_entropy_labels={high_entropy} long_labels={long_label}")
    for s in summary:
        print(f"  {s['server']}: {s['pulled']} events ({s['pages']} pages)")


if __name__ == "__main__":
    main()
