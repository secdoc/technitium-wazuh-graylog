# Reference: Technitium DNS API

*Last verified live: 2026-08-17 (200). Source of truth: `secdoc/dns-config`.*

HTTP API for the Technitium DNS cluster (4 nodes, the deployed example.local resolvers + the DNS SIEM lane source).

| Item | Value |
|------|-------|
| Nodes | technitium1 `<TECHNITIUM_HOST>` (hub/primary), technitium2 `<TECHNITIUM_HOST>`, technitium3 `<TECHNITIUM_HOST>`, silversurfer `<TECHNITIUM_HOST>` |
| API port | `5380` (HTTP) |
| Base | `http://<node>:5380/api` |
| Auth | `?token=<token>` query param on every call |
| Env | `.env` → `TECHNITIUM_SERVERS` (comma list), `TECHNITIUM_TOKEN` |

```bash
T=$(echo $TECHNITIUM_SERVERS | cut -d, -f1)
curl -s "http://$T:5380/api/user/session/get?token=$TECHNITIUM_TOKEN"
```

## Endpoints used

| Purpose | Endpoint |
|---------|----------|
| Session check | `/api/user/session/get?token=` |
| Query log (SIEM pull) | `/api/logs/query?token=&start=<ISO>&end=<ISO>&...&ascending=true` |
| Zones list | `/api/zones/list?token=` |
| Zone options (catalog) | `/api/zones/options/get?token=&zone=`, `/api/zones/options/set?...&catalog=` |
| Records | `/api/zones/records/get?token=&zone=` |
| DHCP scopes | `/api/dhcp/scopes/list?token=` |

## Query-log fields (SIEM lane)

`timestamp, clientIpAddress, protocol, responseType (Cached/Recursive/Blocked/UpstreamBlocked), rcode (NoError/NxDomain/Refused), qname, qtype, qclass, answer`. Supports `start`/`end` ISO + `ascending` for incremental pull.

## Gotchas

- **Blocks come in TWO types:** `Blocked` (local blocklist) and `UpstreamBlocked` (upstream). A collector capturing only `Blocked` silently drops upstream blocks — capture both, tag `block_type`.
- Query log does **not** name which blocklist/category matched (needs EDNS extended-error logging, a production config change).
- **Cluster HA = catalog zones** on the hub (.226) replicating to the 3 secondaries. A zone with `catalog=None` is Primary-only = a hub SPOF (this was the DNS design finding fixed 2026-08-17).
- ~200–205k queries/day fleet-wide → high-volume; the SIEM lane pulls every 15 min and routes to Graylog retention, only anomalies to Wazuh alerts.

Cluster design + deployment: [Technitium cluster](/network/dns/technitium-cluster), [DNS lane deployment](/siem/soc-pipeline/dns-lane-deployment).
