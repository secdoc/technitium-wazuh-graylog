#!/usr/bin/env python3
"""
SOC Pipeline - DNS pipeline runner (Phase 3.1).

One cycle:
  1. collector: read-only incremental pull from Technitium (dns_collector.py),
     writing normalized DNS events + advancing the per-server high-water state.
  2. deliver each NEW event to BOTH consumers (parallel-consumer model):
       - GELF/TCP -> Graylog DNS input (retention/hunting)
       - append to the Wazuh manager DNS localfile (detection)

No dedupe layer here: the collector's per-server timestamp state already yields
only new events per run. Read-only against Technitium. Safe to cron (15 min).

Env (from /opt/soc/.env): TECHNITIUM_TOKEN, TECHNITIUM_SERVERS, GRAYLOG_HOST,
  WAZUH_SSH_USER, WAZUH_SSH_HOST, WAZUH_SSH_KEY.
"""
import argparse, json, os, socket, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))


def load_env(path="/opt/soc/.env"):
    e = {}
    if os.path.exists(path):
        for l in open(path):
            if "=" in l and not l.strip().startswith("#"):
                k, v = l.strip().split("=", 1); e[k] = v
    return e


def to_gelf(ev, source_host):
    """Normalized DNS event -> GELF 1.1 message. Non-detection fields are
    underscore-prefixed custom fields (searchable in Graylog)."""
    qname = ev.get("qname", "")
    short = f"DNS {ev.get('qtype','?')} {qname or '?'} from {ev.get('client','?')} [{ev.get('rcode','?')}]"
    epoch = time.time()
    ts = ev.get("timestamp") or ""
    if ts:
        # Technitium ISO8601 with fractional secs + Z
        try:
            epoch = time.mktime(time.strptime(ts[:19], "%Y-%m-%dT%H:%M:%S"))
        except ValueError:
            pass
    # low syslog level for normal, elevate blocked/NXDOMAIN slightly for Graylog routing
    level = 6
    if ev.get("blocked"):
        level = 4
    elif ev.get("rcode") == "NxDomain":
        level = 5
    g = {
        "version": "1.1",
        "host": source_host,
        "short_message": short[:250],
        "timestamp": round(epoch, 3),
        "level": level,
        "_event_type": ev.get("event_type", "dns_query"),
        "_source": ev.get("source", "technitium"),
        "_dns_server": ev.get("server", ""),
        "_client": ev.get("client", ""),
        "_dns_protocol": ev.get("dns_protocol", ""),
        "_response_type": ev.get("response_type", ""),
        "_rcode": ev.get("rcode", ""),
        "_qname": qname,
        "_qtype": ev.get("qtype", ""),
        "_qclass": ev.get("qclass", ""),
        "_answer": ev.get("answer") or "",
        "_qname_len": ev.get("qname_len", 0),
        "_label_count": ev.get("label_count", 0),
        "_longest_label": ev.get("longest_label", 0),
        "_leftmost_label_entropy": ev.get("leftmost_label_entropy", 0.0),
        "_blocked": bool(ev.get("blocked")),
        "_block_type": ev.get("block_type", "none"),
    }
    return g


def send_graylog_tcp(events, host, port, source_host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    s.connect((host, port))
    n = 0
    for ev in events:
        s.sendall(json.dumps(to_gelf(ev, source_host)).encode() + b"\x00")  # GELF TCP null-delimited
        n += 1
    s.close()
    return n


def append_wazuh(events, env, wazuh_path):
    key = env["WAZUH_SSH_KEY"].replace("~/.ssh", os.path.expanduser("~/.ssh"))
    if not os.path.exists(key):
        key = os.path.expanduser("~/.ssh/wazuh_hermes")
    data = "".join(json.dumps(ev, ensure_ascii=False) + "\n" for ev in events)
    r = subprocess.run(["ssh", "-i", key, "-o", "StrictHostKeyChecking=accept-new",
                        "-o", "BatchMode=yes", f"{env['WAZUH_SSH_USER']}@{env['WAZUH_SSH_HOST']}",
                        f"cat >> {wazuh_path}"], input=data, capture_output=True, text=True)
    return r.returncode, r.stderr[:200]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=os.path.join(HERE, ".dns_state.json"))
    ap.add_argument("--graylog-port", type=int, default=12202)
    ap.add_argument("--wazuh-path", default="/var/ossec/logs/dns/queries.jsonl")
    ap.add_argument("--source-host", default="technitium-dns")
    ap.add_argument("--lookback-min", type=int, default=20)
    ap.add_argument("--max-pages", type=int, default=200)
    ap.add_argument("--no-graylog", action="store_true")
    ap.add_argument("--no-wazuh", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    env = load_env()
    workdir = tempfile.mkdtemp(prefix="dnspipe_")

    # 1. collect (read-only, advances state unless dry-run handled inside collector)
    cmd = [sys.executable, os.path.join(HERE, "dns_collector.py"),
           "--out", workdir, "--state", args.state,
           "--lookback-min", str(args.lookback_min), "--max-pages", str(args.max_pages)]
    if args.dry_run:
        cmd.append("--dry-run")
    r = subprocess.run(cmd, capture_output=True, text=True)
    sys.stdout.write(r.stdout)
    if r.returncode != 0:
        print("collector failed:", r.stderr[:300]); sys.exit(1)
    if args.dry_run:
        print("dry-run: no delivery"); return

    jl = sorted(f for f in os.listdir(workdir) if f.endswith(".jsonl"))
    if not jl:
        print("no events file produced"); return
    events = [json.loads(l) for l in open(os.path.join(workdir, jl[-1])) if l.strip()]
    if not events:
        print("no new DNS events to deliver"); return

    delivered = {}
    if not args.no_graylog:
        try:
            n = send_graylog_tcp(events, env["GRAYLOG_HOST"], args.graylog_port, args.source_host)
            delivered["graylog"] = n
        except Exception as e:
            print("WARN: graylog delivery failed:", str(e)[:200])
            delivered["graylog"] = f"ERROR: {e}"
    if not args.no_wazuh:
        rc, err = append_wazuh(events, env, args.wazuh_path)
        delivered["wazuh"] = "ok" if rc == 0 else f"ERROR: {err}"

    print(f"delivered {len(events)} DNS events:", json.dumps(delivered))


if __name__ == "__main__":
    main()
