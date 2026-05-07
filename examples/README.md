# mole / examples

Drop-in observability assets for a mole deployment. Both files are validated
against live data on a real netns-isolated install; the dashboard parses
through `prometheus_client.parser` and the alerts pass `promtool check rules`.

## Files

- **`grafana-dashboard.json`** — 22-panel Grafana dashboard organised in
  five rows: at-a-glance KPI strip, VPN renewal lifecycle, handshake +
  port-forward keepalives, DNS throughput / latency / errors, and cache
  + blocklist health. Annotations mark VPN reconnects, renewal successes,
  and renewal failures on every time-series.

- **`prometheus-alerts.yml`** — 10 alert rules across two groups
  (`mole.tunnel` and `mole.dns`), each annotated with a one-line summary
  and a multi-line description that explains the failure mode and the
  first thing to check.

## Wire it up

### Prometheus scrape config

Mole's `/metrics` endpoint goes through the same auth gate as the rest
of the API. With `HTTP_API_KEY` set in `/etc/mole/config`, point
Prometheus at it with `authorization: { type: Bearer }`:

```yaml
scrape_configs:
  - job_name: mole
    metrics_path: /metrics
    scheme: http
    static_configs:
      - targets: ['mole.internal:8080']
    authorization:
      type: Bearer
      credentials_file: /etc/prometheus/secrets/mole-api-key
```

The `credentials_file` should contain just the token on a single line,
mounted read-only into the Prometheus container if you're running in
Docker. Inline `credentials: <key>` works too but ties the secret to
prometheus.yml's filesystem permissions.

### Alert rules

Add the rules file to Prometheus's `rule_files:` directive and reload:

```yaml
rule_files:
  - /etc/prometheus/rules/mole-alerts.yml
```

Then either send `SIGHUP` to Prometheus, hit `POST /-/reload`, or
restart the container. `promtool check rules` is the canonical way to
validate before reloading:

```sh
promtool check rules examples/prometheus-alerts.yml
```

### Grafana dashboard

If your Grafana is provisioned (recommended), drop the dashboard JSON
into the dashboards provider directory. With a typical config like:

```yaml
# /etc/grafana/provisioning/dashboards/default.yaml
apiVersion: 1
providers:
  - name: mole
    folder: mole
    type: file
    options:
      path: /etc/grafana/provisioning/dashboards/json
```

…copy `grafana-dashboard.json` to that path. Grafana picks up changes
within `updateIntervalSeconds` (default 30s).

If you import via the UI instead: **Dashboards → New → Import → Upload
JSON file**. The dashboard expects a Prometheus datasource with
`uid: prometheus`; if yours has a different UID, the import dialog lets
you remap it.

## Tuning

The alert thresholds reflect mole's stock defaults
(`RENEWAL_INTERVAL=7d`, NAT-PMP keepalive every 45s on Proton). If
you've tuned those, the threshold expressions in
`prometheus-alerts.yml` should be adjusted in step:

| Alert | Threshold expression | Tuning hint |
|---|---|---|
| `MoleRenewalLagging` | `time() - …last_success > 1209600` | Set to ~2× your `RENEWAL_INTERVAL` |
| `MolePortForwardStale` | `…age_seconds > 600` | Set to ~10× your `KEEPALIVE_INTERVAL` |
| `MoleBlocklistStale` | `time() - …last_update > 172800` | Set to ~2× your `DOT_UPDATE_PERIOD` |
| `MoleHighDnsLatency` | `…p99_seconds > 1` | Tighten if your upstream is normally fast (e.g. local AdGuard); loosen if you're routing through a tunnel |
| `MoleHighDnsErrorRate` | `rate(…) > 0.5` | Loosen if you have a bursty workload that legitimately produces errors |

The dashboard's threshold colour bands (handshake age 120s/180s,
latency 50ms/200ms for p50, etc.) are visual rather than alertable, so
they don't need to match the alert thresholds; tune them via the
Grafana panel-edit UI to match your environment's healthy baseline.

## Validation

Both files were checked against a real mole install:

- `prometheus_client.parser.text_string_to_metric_families` parses all
  metric families on the `/metrics` endpoint cleanly (24 families, 10
  counters + 14 gauges).
- `promtool check rules examples/prometheus-alerts.yml` returns
  `SUCCESS: 10 rules found`.
- Every alert expression returns `status=success` when issued against
  a live Prometheus instance scraping mole.
