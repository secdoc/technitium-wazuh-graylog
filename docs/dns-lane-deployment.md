# DNS lane deployment record (Phase 3.1)

Live objects created 2026-08-17 when the Technitium DNS lane went into production. Kept for reproducibility and rollback.

## Graylog (<GRAYLOG_HOST>)

| Object | ID | Notes |
|--------|----|-------|
| GELF TCP input "SOC Pipeline - DNS GELF TCP" | `6a832d9c1ebdc2c72b1be2a5` | port 12202, global, null-delimited |
| Index set "SOC Pipeline - DNS" | `6a832d8f1ebdc2c72b1be292` | prefix `dns`, daily rotation, 30-day deletion retention, 1 shard / 0 replica |
| Stream "SOC Pipeline - DNS" | `6a832dcb1ebdc2c72b1be2d6` | rule: `event_type == dns_query`; routes to the dns index set; removes matches from Default |

**Rollback:** delete the stream, then the index set (deletes indices), then the input. Order matters (stream references the index set).

### Pitfall (fixed during deploy)
The GELF `host` field becomes Graylog's `source`. The emitter sets host = `technitium-dns` (via `--source-host`), so a stream rule matching `source == technitium` does NOT match and messages fall through to the Default stream. The rule matches the custom field `event_type == dns_query` instead, which is present and exact on every DNS event regardless of source-host naming.

## Wazuh manager (<WAZUH_HOST>)

| Change | Detail |
|--------|--------|
| Rules | `/var/ossec/etc/rules/dns_rules.xml` (range 116000-116999) |
| Localfile | `/var/ossec/logs/dns/queries.jsonl` (log_format json) added to ossec.conf |
| Backup | `ossec.conf.bak-20260817T155103Z` on the manager |

**Rollback:** remove the localfile block from ossec.conf (restore the backup), delete `dns_rules.xml`, `analysisd -t`, restart.

## Cron (Hermes host)

| Job | ID | Schedule |
|-----|----|---------| 
| DNS 15-min pull -> Wazuh/Graylog | `62b5eb0df0df` | `*/15 * * * *`, no_agent, deliver=local |

Wrapper: `/opt/soc/scripts/dns-pull.sh` (source: `scripts/dns-pull.sh`). Status log: `/var/log/dns-pull.log`.

## Ingestion cadence & latency (pull model)

**This lane is a scheduled PULL, not a live push.** Every 15 minutes the cron job
polls each Technitium server's query-log API for records newer than the last run
(incremental, by timestamp), then ships that batch to Graylog (GELF/TCP :12202) and
appends it to the Wazuh localfile. Between ticks, nothing flows; at each tick, one
burst of everything since the previous run lands at once.

- **Cadence:** every 15 min (`*/15 * * * *`).
- **Worst-case latency:** ~15 min. A query logged at 09:01 is not in Graylog/Wazuh
  until the 09:15 run. Average latency ~7.5 min.
- **Batch size scales with volume:** observed ~2,100 events per 15-min window
  (~205k/day across the 4 servers), consistent with the design estimate. Fine for
  Graylog retention; DNS query volume is high by nature.

### Why pull, not push
Technitium's **Log Exporter** app (installed on all 4 servers, currently disabled)
*can* stream every query to syslog/GELF in real time. We deliberately chose the API
pull model for the initial deployment because it needs **zero configuration change on
the 4 production DNS servers** (read-only API token only), matches the vuln lane's
proven collector pattern, and keeps the DNS servers untouched. The trade-off accepted:
up to 15-min ingest latency instead of real-time.

### Levers to change latency (not yet applied)
| Option | Effect | Cost |
|--------|--------|------|
| Tighten cron to `*/5 * * * *` | worst-case latency ~5 min, smaller batches | 3x pull frequency against the Technitium API + manager; trivial cron edit |
| Enable Technitium **Log Exporter** (syslog/GELF push) | near-real-time, no polling | config change on all 4 DNS servers (out of the read-only pull model); syslog UDP can drop under load |

For detection this cadence is adequate — DNS tunneling and DGA beaconing play out over
windows longer than 15 min. Latency would only matter for DNS-triggered *fast
containment*, which is not wired (Phase 4, blocked on Shuffle). Revisit if that changes.

*Source of truth: `secdoc/soc-pipeline`. Deployed 2026-08-17.*

---

## Phase 4.1 — Wazuh -> Shuffle enrichment interconnect (2026-08-17)

Wazuh `<integration>` (stock `shuffle` script) POSTs matching alerts to the
SOC-Enrich-Triage workflow hook, which enriches (AbuseIPDB) + briefs + posts to Discord.

- **Config:** `<integration>` block in `/var/ossec/etc/ossec.conf` (backup
  `ossec.conf.bak-20260817T175747Z`). hook_url = reachable form
  `http://<SHUFFLE_HOST>:3001/api/v1/hooks/webhook_75dbfb15-...` (Shuffle stores it as
  `localhost:3001`, but the manager needs the routable IP — verified reachable http=200).
- **Webhook trigger** must be STARTED in the Shuffle UI (API activation 404s on this build).
- **Deliver target:** Discord (`DISCORD_SOC_WEBHOOK` in .env). Slack Workflow Builder
  triggers need a paid plan (`workflow_not_published` on free) — not used.

### PITFALL (caught live): `<level>10</level>` alone floods the workflow
First cut used only `<level>10</level>`. A greenbone localfile re-read fired ~80 High
`vulnerability_high` findings at once -> 82 workflow executions -> Discord flood. Greenbone
findings also have NO srcip, so enrichment is pointless for them.
**Fix:** scope with `<group>` to IOC-bearing alerts only:
`<group>authentication_failures,attacks,ids,intrusion_prevention,dns_anomaly,web_attack</group>`
plus `<level>10</level>`. Vulnerability findings are intentionally excluded (they belong on
the dashboard, not the per-alert enrichment pager). Mirrors the "only High/Crit pages" rule.

---

## Phase 4.1 — Anti-flood redesign: per-alert integration -> aggregated digest (2026-08-17)

The per-alert Wazuh `<integration>` was a self-DoS: one greenbone re-read fired ~80
workflow runs and flooded Discord (which also hard rate-limits ~30 req/min). Replaced
with a pull-based aggregating digest.

### Why not aggregate inside Shuffle
On-prem/unlicensed Shuffle has **no working schedule trigger** (endpoints 404, flagged
cloud/"hybrid" in getinfo) and **`list_cache` returns empty**, so a datastore digest
queue drained by a Shuffle schedule is not buildable here. Aggregation moved to the
Hermes host where the scheduler + full query control already live.

### Design (live)
- **Per-alert integration REMOVED** from ossec.conf (backup `ossec.conf.bak-<ts>`).
  integratord no longer POSTs per alert.
- `scripts/soc_digest_drain.py` (Hermes host): every 15 min, queries the Wazuh indexer
  (`wazuh-alerts-*`, `rule.level>=10`, IOC-bearing `rule.groups`, `now-15m`), aggregates
  by `data.srcip`, enriches each DISTINCT ip ONCE via AbuseIPDB, posts ONE Discord digest
  (criticals first by score). **Silent when nothing matches** (watchdog pattern, no empty posts).
- Cron `473ce9d2486d` `*/15 * * * *`, no_agent, deliver=local, wrapper `/opt/soc/scripts/soc-digest.sh`,
  log `/var/log/soc-digest.log`.
- The SOC-Enrich-Triage Shuffle workflow remains as the **on-demand single-IOC deep-enrich**
  tool (webhook/execute), not the bulk pager.

### Flood math
N alerts in a window -> 1 Discord message (deduped by source IP). AbuseIPDB calls =
distinct IPs, not alert count. Well under Discord's ~30/min limit regardless of alert volume.

### PITFALL: Discord 403 from urllib
Direct `urllib` POST to a Discord webhook returns **403** without a real `User-Agent`
header (Cloudflare blocks the default python UA). Fix: set `User-Agent: SOC-Digest-Bot/1.0`.
(Shuffle's http app sets its own UA, so the workflow path never hit this.)
