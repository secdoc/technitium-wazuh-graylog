# DNS lane deployment example

This public reference intentionally omits real object IDs, scheduler identifiers,
host counts, internal paths, account names, and deployment dates.

## Deployment sequence

1. Copy `.env.example` to an untracked environment file and populate the required
   Technitium, Graylog, and Wazuh settings.
2. Run `python3 collector/dns_pipeline.py --dry-run` and confirm that no state or
   downstream data changes occur.
3. Install `scripts/dns-pull.sh` under a neutral service path such as
   `<INSTALL_ROOT>`, then set `SOC_ENV_FILE`, `SOC_PIPELINE_ROOT`, and
   `DNS_PULL_LOG` for that host.
4. Schedule the wrapper at the required cadence. Start with a long interval and
   measure API load, batch size, and end-to-end latency before tightening it.
5. Verify Graylog input state, stream routing, Wazuh decoding, rule matches, and
   duplicate suppression with synthetic events.

## Rollback

Disable the scheduler, preserve the state file for investigation, remove the
Wazuh localfile configuration and custom rules if they were installed, then
remove the Graylog stream and input after confirming no other source uses them.
