# technitium-wazuh-graylog

Wire a **[Technitium DNS](https://technitium.com/dns/)** server (or cluster) into a SIEM as a
first-class lane: a read-only collector pulls the Query Logs API, normalizes each query, computes
cheap detection enrichments (label stats, entropy), and delivers to **both Graylog** (retention/
hunting, full volume) and **Wazuh** (detection, rule-gated), with Wazuh rules for DNS blocking,
NXDOMAIN, DGA, and tunneling signals.

> Sanitized, adaptable reference. Placeholders (`<TECHNITIUM_HOST>`, `<GRAYLOG_HOST>`,
> `<WAZUH_HOST>`, RFC5737 example networks, `example.com` domains) stand in for real values.
> Carries no real environment data. Part of a modular SIEM-pipeline set:
> [soc-pipeline](https://github.com/secdoc/soc-pipeline-public) (umbrella) ·
> [socfortress-waf-siem](https://github.com/secdoc/socfortress-waf-siem) ·
> [greenbone-wazuh-graylog](https://github.com/secdoc/greenbone-wazuh-graylog).

## Why this exists

DNS is one of the highest-signal, highest-volume telemetry sources on any network: C2 domains,
data exfil over DNS tunneling, DGA beaconing, and newly-registered-domain contact all show up
here first. But raw query volume (100k+/day) drowns an analyst. This treats DNS as one source in
your pipeline: **full volume to Graylog** for hunting/retention, a **rule-gated subset to Wazuh**
so single odd queries stay queryable-but-quiet and only patterns page.

## Architecture (parallel consumers, not a chain)

```
  Technitium (Query Logs API, read-only)  -->  dns_collector.py (incremental per-server)
                                                   |  normalize + enrich once
                        +--------------------------+--------------------------+
                        v                                                     v
             Graylog (GELF/TCP)                                  Wazuh manager localfile
             full volume, retention/hunting                      detection (rules 116xxx)
```

Do **not** chain source -> Graylog -> Wazuh: Graylog reformats and breaks Wazuh decoders. Both
consumers get the normalized event independently. Multi-server: the collector keeps a per-server
high-water timestamp so each run ships only new records, from one or many Technitium nodes.

## Alert discipline (the point of the design)

DNS is ~100k-200k queries/day. Full volume lives in Graylog. In Wazuh:

- Base rule (116000, **level 0**): every DNS event recorded, not alerted.
- Single-event anomalies (long label, high entropy, NXDOMAIN, blocked) fire at **low levels (3-6)**:
  queryable, do **not** page. One odd query is not an incident.
- **Frequency rules escalate to paging (10-12)** only when a client crosses a rate threshold
  (e.g. many NXDOMAINs or high-entropy lookups in a window) - that's the real signal.

## Detection enrichments (computed once, in the collector)

Each normalized event carries fields the rules gate on without re-parsing: `qname_len`,
`label_count`, `longest_label` (tunneling), `leftmost_label_entropy` (DGA/exfil),
`blocked`/`block_type` (local `Blocked` vs `UpstreamBlocked`), `response_type`, `rcode`. See
`samples/dns-events-sample.jsonl`.

## Wazuh rules (`wazuh/rules/dns_rules.xml`)

Rule IDs `116000-116999`, chained under stock rule 86600. Parsing uses Wazuh's built-in **json
decoder** (no custom decoder). Gotchas baked in: `<field>` is OS_Regex not PCRE (numeric ranges
use `type="pcre2"`); `protocol` is reserved in the Wazuh mapping so the collector emits
`dns_protocol`; first-match-wins ordering puts higher-value detections first.

## Quick start

```bash
cp .env.example .env      # TECHNITIUM_SERVERS/TOKEN, GRAYLOG_HOST, WAZUH_* (never commit real .env)
python3 collector/dns_pipeline.py --dry-run     # pull + normalize, no delivery
python3 collector/dns_pipeline.py               # deliver new events to Graylog + Wazuh
# deploy scripts/dns-pull.sh on a ~15-min cron
```

Full walkthrough (Technitium API, GELF, Wazuh rules + install) in
[`docs/dns-lane-deployment.md`](docs/dns-lane-deployment.md) and
[`docs/technitium-api-reference.md`](docs/technitium-api-reference.md).

## Repo layout

```
collector/   dns_collector.py (pull+normalize+enrich), dns_pipeline.py (fan-out to Graylog+Wazuh)
wazuh/rules/ dns_rules.xml (116xxx: blocked/NXDOMAIN/DGA/tunneling + frequency escalation)
scripts/     dns-pull.sh (cron wrapper), scrub_check.py (public gate)
docs/        dns-lane-deployment.md, technitium-api-reference.md, SANITIZATION.md
samples/     dns-events-sample.jsonl (SYNTHETIC)
```

## License

Dual-licensed: code under Apache-2.0 (`LICENSE`), docs/diagrams under CC BY 4.0
(`LICENSE-docs`). Attribution required under both. See `LICENSING.md` and `NOTICE`.

*Technitium, Wazuh, and Graylog are their respective projects' trademarks; this is an independent
integration.*
