"""
Tests for mole_pkg.services.api_main — currently focused on the Prometheus
metrics formatter, which is a pure function and so testable without spinning
up the asyncio HTTP server.
"""

import re
import unittest

from mole_pkg.services.api_main import (
    format_prometheus_metrics,
    _prom_escape_label,
)


# ---------- _prom_escape_label ----------

class TestPromEscapeLabel(unittest.TestCase):
    def test_passthrough_simple(self):
        self.assertEqual(_prom_escape_label("custom"), "custom")

    def test_escapes_backslash_first(self):
        # backslash MUST be escaped before the others, otherwise their
        # escapes get re-escaped.
        self.assertEqual(_prom_escape_label('a\\b'), 'a\\\\b')

    def test_escapes_double_quote(self):
        self.assertEqual(_prom_escape_label('a"b'), 'a\\"b')

    def test_escapes_newline(self):
        self.assertEqual(_prom_escape_label('a\nb'), 'a\\nb')

    def test_none_renders_empty(self):
        self.assertEqual(_prom_escape_label(None), "")

    def test_non_string_coerced(self):
        self.assertEqual(_prom_escape_label(42), "42")


# ---------- format_prometheus_metrics ----------

# A representative dns_stats blob shaped like dns_main writes to
# /var/lib/mole/dns_stats.json. Numbers chosen to be easy to spot.
SAMPLE_DNS_STATS = {
    "enabled": True,
    "upstream": "custom",
    "blocked_domains": 90087,
    "in_flight": 0,
    "last_blocklist_update": 1778163652,
    "cache_entries": 28,
    "cache_size_bytes": 1492,
    "counters": {
        "queries_total": 40,
        "cache_hits": 4,
        "cache_misses": 36,
        "in_flight_peak": 1,
        "singleflight_collapses": 2,
        "blocked": 7,
        "upstream_queries": 36,
        "upstream_errors": 1,
        "retries": 3,
        "failovers": 0,
        "resolve_errors": 0,
    },
    "upstreams": [
        {
            "name": "custom",
            "host": "10.0.0.1",
            "port": 853,
            "pool_size": 2,
            "open_connections": 1,
            "primary": True,
            "query_p50_ms": 54.8,
            "query_p95_ms": 116.9,
            "query_p99_ms": 132.8,
            "query_samples": 36,
            "counters": {
                "queries": 36,
                "errors": 1,
                "retries": 3,
                "failovers_out": 0,
            },
        }
    ],
}


class TestFormatPrometheusMetricsEmpty(unittest.TestCase):
    """Behavior when no data is available (cold start, dns disabled)."""

    def setUp(self):
        self.text = format_prometheus_metrics({}, {}, version="0.4.0")

    def test_emits_build_info_when_version_provided(self):
        self.assertIn('mole_build_info{version="0.4.0"} 1', self.text)

    def test_skips_build_info_when_version_empty(self):
        text = format_prometheus_metrics({}, {}, version="")
        self.assertNotIn("mole_build_info", text)

    def test_vpn_connected_zero(self):
        self.assertIn("mole_vpn_connected 0", self.text)

    def test_vpn_forwarded_port_zero(self):
        self.assertIn("mole_vpn_forwarded_port 0", self.text)

    def test_aggregate_counters_present_at_zero(self):
        for name in [
            "mole_dns_queries_total",
            "mole_dns_cache_hits_total",
            "mole_dns_cache_misses_total",
            "mole_dns_blocked_total",
            "mole_dns_resolve_errors_total",
            "mole_dns_singleflight_collapses_total",
        ]:
            with self.subTest(name=name):
                # Use multiline regex so we can anchor at line boundaries
                # within the multi-line exposition output.
                self.assertRegex(
                    self.text,
                    rf"(?m)^{re.escape(name)} 0$",
                )
                self.assertIn(f"# HELP {name} ", self.text)
                self.assertIn(f"# TYPE {name} counter", self.text)

    def test_no_per_upstream_rows_when_no_upstreams(self):
        # Per-upstream metric names should not appear at all.
        self.assertNotIn("mole_dns_upstream_queries_total", self.text)
        self.assertNotIn("mole_dns_upstream_errors_total", self.text)
        self.assertNotIn("mole_dns_upstream_query_latency_p50_seconds", self.text)


class TestFormatPrometheusMetricsFull(unittest.TestCase):
    """All metrics rendered correctly when given a populated dns_stats blob."""

    def setUp(self):
        self.text = format_prometheus_metrics(
            dns_stats=SAMPLE_DNS_STATS,
            vpn_status={"connected": True, "port": 47387},
            version="0.4.0",
        )

    def test_vpn_connected_one(self):
        self.assertIn("mole_vpn_connected 1", self.text)

    def test_vpn_forwarded_port(self):
        self.assertIn("mole_vpn_forwarded_port 47387", self.text)

    def test_aggregate_counters_pass_through(self):
        self.assertIn("mole_dns_queries_total 40", self.text)
        self.assertIn("mole_dns_cache_hits_total 4", self.text)
        self.assertIn("mole_dns_cache_misses_total 36", self.text)
        self.assertIn("mole_dns_blocked_total 7", self.text)
        self.assertIn("mole_dns_resolve_errors_total 0", self.text)
        self.assertIn("mole_dns_singleflight_collapses_total 2", self.text)

    def test_state_gauges_pass_through(self):
        self.assertIn("mole_dns_in_flight_peak 1", self.text)
        self.assertIn("mole_dns_cache_entries 28", self.text)
        self.assertIn("mole_dns_cache_size_bytes 1492", self.text)
        self.assertIn("mole_dns_blocked_domains 90087", self.text)
        self.assertIn("mole_dns_blocklist_last_update_seconds 1778163652", self.text)

    def test_per_upstream_counters(self):
        self.assertIn(
            'mole_dns_upstream_queries_total{upstream="custom"} 36', self.text
        )
        self.assertIn(
            'mole_dns_upstream_errors_total{upstream="custom"} 1', self.text
        )
        self.assertIn(
            'mole_dns_upstream_retries_total{upstream="custom"} 3', self.text
        )
        self.assertIn(
            'mole_dns_upstream_failovers_total{upstream="custom"} 0', self.text
        )

    def test_per_upstream_gauges(self):
        self.assertIn(
            'mole_dns_upstream_open_connections{upstream="custom"} 1', self.text
        )
        self.assertIn(
            'mole_dns_upstream_pool_size{upstream="custom"} 2', self.text
        )
        self.assertIn(
            'mole_dns_upstream_query_latency_samples{upstream="custom"} 36', self.text
        )

    def test_latency_percentiles_in_seconds(self):
        # 54.8 ms → 0.0548 s
        self.assertRegex(
            self.text,
            r'mole_dns_upstream_query_latency_p50_seconds\{upstream="custom"\} 0\.0548\b',
        )
        self.assertRegex(
            self.text,
            r'mole_dns_upstream_query_latency_p95_seconds\{upstream="custom"\} 0\.1169\b',
        )
        self.assertRegex(
            self.text,
            r'mole_dns_upstream_query_latency_p99_seconds\{upstream="custom"\} 0\.1328\b',
        )


class TestFormatPrometheusMetricsEdgeCases(unittest.TestCase):

    def test_disconnected_vpn(self):
        text = format_prometheus_metrics(
            {}, {"connected": False, "port": 0}, version="0.4.0"
        )
        self.assertIn("mole_vpn_connected 0", text)

    def test_multiple_upstreams_label_isolation(self):
        stats = {
            "counters": {},
            "upstreams": [
                {
                    "name": "cloudflare",
                    "open_connections": 2,
                    "pool_size": 2,
                    "query_p50_ms": 10.0,
                    "query_p95_ms": 50.0,
                    "query_p99_ms": 80.0,
                    "query_samples": 100,
                    "counters": {"queries": 100, "errors": 1, "retries": 0, "failovers_out": 0},
                },
                {
                    "name": "quad9",
                    "open_connections": 0,
                    "pool_size": 2,
                    "query_p50_ms": 12.0,
                    "query_p95_ms": 60.0,
                    "query_p99_ms": 90.0,
                    "query_samples": 50,
                    "counters": {"queries": 50, "errors": 0, "retries": 0, "failovers_out": 1},
                },
            ],
        }
        text = format_prometheus_metrics(stats, {"connected": True}, version="")
        # Each upstream's counters come out under its own label.
        self.assertIn(
            'mole_dns_upstream_queries_total{upstream="cloudflare"} 100', text
        )
        self.assertIn(
            'mole_dns_upstream_queries_total{upstream="quad9"} 50', text
        )
        self.assertIn(
            'mole_dns_upstream_failovers_total{upstream="quad9"} 1', text
        )
        # HELP/TYPE for each metric appears exactly once even with two
        # upstreams sharing the metric.
        self.assertEqual(
            text.count("# HELP mole_dns_upstream_queries_total "), 1
        )
        self.assertEqual(
            text.count("# TYPE mole_dns_upstream_queries_total counter"), 1
        )

    def test_upstream_with_no_latency_samples_skipped(self):
        # An upstream that hasn't recorded any successful queries yet has
        # query_p50_ms/p95/p99 == None — we must not emit "None" as a metric value.
        stats = {
            "counters": {},
            "upstreams": [
                {
                    "name": "fresh",
                    "open_connections": 0,
                    "pool_size": 1,
                    "query_p50_ms": None,
                    "query_p95_ms": None,
                    "query_p99_ms": None,
                    "query_samples": 0,
                    "counters": {"queries": 0, "errors": 0, "retries": 0, "failovers_out": 0},
                },
            ],
        }
        text = format_prometheus_metrics(stats, {"connected": True}, version="")
        # Latency metrics are entirely omitted when no samples exist for any upstream.
        self.assertNotIn("mole_dns_upstream_query_latency_p50_seconds", text)
        self.assertNotIn("None", text)
        # Sample-count gauge should still emit (with 0).
        self.assertIn(
            'mole_dns_upstream_query_latency_samples{upstream="fresh"} 0', text
        )

    def test_label_value_escaping_in_upstream_name(self):
        # Defensive — a hostile or odd upstream name shouldn't break parse.
        stats = {
            "counters": {},
            "upstreams": [
                {
                    "name": 'has"quote\\and\nnewline',
                    "open_connections": 0,
                    "pool_size": 1,
                    "query_samples": 0,
                    "counters": {"queries": 1},
                }
            ],
        }
        text = format_prometheus_metrics(stats, {}, version="")
        self.assertIn(
            'mole_dns_upstream_queries_total{upstream="has\\"quote\\\\and\\nnewline"} 1',
            text,
        )

    def test_junk_counter_values_default_to_zero(self):
        # If dns_stats.json is corrupt and a counter is a string or None,
        # we default to 0 rather than raising.
        stats = {
            "counters": {
                "queries_total": "not a number",
                "cache_hits": None,
                "cache_misses": 5,
            }
        }
        text = format_prometheus_metrics(stats, {}, version="")
        self.assertIn("mole_dns_queries_total 0", text)
        self.assertIn("mole_dns_cache_hits_total 0", text)
        self.assertIn("mole_dns_cache_misses_total 5", text)


# ---------- output is parseable Prometheus text ----------

# Approximate Prometheus exposition format per
# https://prometheus.io/docs/instrumenting/exposition_formats/
_LINE_RE = re.compile(
    r"^("
    r"#\s*(HELP|TYPE)\s+\w+(\s.*)?"  # comment lines
    r"|"
    r"\w+(\{[^}]*\})?\s+-?[0-9.eE+-]+(\s+\d+)?"  # metric line
    r"|"
    r""  # blank line
    r")$"
)


# ---------- New operational metric groups ----------

class TestVpnHandshakeAge(unittest.TestCase):
    """mole_vpn_handshake_age_seconds is opt-in: only emitted when the
    api_main handler successfully parsed `wg show mole latest-handshakes`."""

    def test_emitted_when_present(self):
        text = format_prometheus_metrics(
            {}, {"connected": True, "handshake_age_seconds": 42.5}, version=""
        )
        self.assertIn("mole_vpn_handshake_age_seconds 42.5", text)
        self.assertIn("# TYPE mole_vpn_handshake_age_seconds gauge", text)

    def test_omitted_when_absent(self):
        text = format_prometheus_metrics({}, {"connected": True}, version="")
        self.assertNotIn("mole_vpn_handshake_age_seconds", text)

    def test_zero_age_still_emitted(self):
        # 0.0 is a valid value (just-handshook). Don't accidentally drop it.
        text = format_prometheus_metrics(
            {}, {"connected": True, "handshake_age_seconds": 0.0}, version=""
        )
        self.assertRegex(text, r"(?m)^mole_vpn_handshake_age_seconds 0(\.0)?$")


class TestVpnByteCounters(unittest.TestCase):
    """mole_vpn_{receive,transmit}_bytes_total — opt-in counters that
    surface the WireGuard interface's RX/TX byte totals so dashboards
    can derive throughput via rate(). The interface is recreated on
    every renewal, which resets the kernel counters to zero; Prometheus
    handles counter resets internally, so a `counter` TYPE is correct."""

    def test_emitted_when_present(self):
        text = format_prometheus_metrics(
            {},
            {
                "connected": True,
                "receive_bytes_total": 123456789,
                "transmit_bytes_total": 987654321,
            },
            version="",
        )
        self.assertIn("mole_vpn_receive_bytes_total 123456789", text)
        self.assertIn("mole_vpn_transmit_bytes_total 987654321", text)
        self.assertIn("# TYPE mole_vpn_receive_bytes_total counter", text)
        self.assertIn("# TYPE mole_vpn_transmit_bytes_total counter", text)

    def test_omitted_when_absent(self):
        text = format_prometheus_metrics({}, {"connected": True}, version="")
        self.assertNotIn("mole_vpn_receive_bytes_total", text)
        self.assertNotIn("mole_vpn_transmit_bytes_total", text)

    def test_zero_values_still_emitted(self):
        # 0 is a valid fresh-interface value (renewal just happened).
        # Don't accidentally drop it.
        text = format_prometheus_metrics(
            {},
            {
                "connected": True,
                "receive_bytes_total": 0,
                "transmit_bytes_total": 0,
            },
            version="",
        )
        self.assertRegex(text, r"(?m)^mole_vpn_receive_bytes_total 0$")
        self.assertRegex(text, r"(?m)^mole_vpn_transmit_bytes_total 0$")

    def test_emitted_independently(self):
        # If only one direction was successfully parsed (partial wg-tool
        # output), the other shouldn't be invented.
        text = format_prometheus_metrics(
            {},
            {"connected": True, "receive_bytes_total": 42},
            version="",
        )
        self.assertIn("mole_vpn_receive_bytes_total 42", text)
        self.assertNotIn("mole_vpn_transmit_bytes_total", text)

    def test_large_values_as_integers(self):
        # 64-bit counters can comfortably exceed 2^32. Prometheus accepts
        # decimal integers; we must not drift into scientific notation.
        big = 5 * 10**12  # 5 TB
        text = format_prometheus_metrics(
            {},
            {
                "connected": True,
                "receive_bytes_total": big,
                "transmit_bytes_total": big,
            },
            version="",
        )
        self.assertIn(f"mole_vpn_receive_bytes_total {big}", text)
        self.assertIn(f"mole_vpn_transmit_bytes_total {big}", text)
        self.assertNotIn("e+", text.lower().split("mole_vpn_receive_bytes_total")[1].split("\n")[0])


class TestVpnEndpointInfo(unittest.TestCase):
    """mole_vpn_endpoint_info{server, country, endpoint_ip} 1 — labelled
    gauge for joins. Emitted iff at least one of the labels has content."""

    def test_emitted_with_full_metadata(self):
        text = format_prometheus_metrics(
            {},
            {
                "connected": True,
                "hostname": "node-nl-47",
                "server_ip": "138.199.7.129",
                "country": "NL",
            },
            version="",
        )
        self.assertIn(
            'mole_vpn_endpoint_info{server="node-nl-47",country="NL",endpoint_ip="138.199.7.129"} 1',
            text,
        )

    def test_omitted_when_all_labels_empty(self):
        text = format_prometheus_metrics({}, {"connected": True}, version="")
        self.assertNotIn("mole_vpn_endpoint_info", text)

    def test_emitted_with_partial_metadata(self):
        # Cold-start case: hostname known, country/IP not yet.
        text = format_prometheus_metrics(
            {},
            {"connected": True, "hostname": "node-nl-47"},
            version="",
        )
        self.assertIn(
            'mole_vpn_endpoint_info{server="node-nl-47",country="",endpoint_ip=""} 1',
            text,
        )


class TestRenewalState(unittest.TestCase):

    def test_emitted_when_state_provided(self):
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            renewal_state={
                "success_total": 12,
                "failure_total": 1,
                "last_success_ts": 1778163652,
                "last_duration_seconds": 7.234,
            },
            version="",
        )
        self.assertIn('mole_vpn_renewals_total{result="success"} 12', text)
        self.assertIn('mole_vpn_renewals_total{result="failure"} 1', text)
        self.assertIn(
            "mole_vpn_renewal_last_duration_seconds 7.234", text
        )
        self.assertIn(
            "mole_vpn_renewal_last_success_timestamp_seconds 1778163652", text
        )

    def test_omitted_when_state_absent(self):
        text = format_prometheus_metrics(
            {}, {"connected": True}, renewal_state=None, version=""
        )
        self.assertNotIn("mole_vpn_renewals_total", text)
        self.assertNotIn("mole_vpn_renewal_last_", text)

    def test_zero_success_zero_failure_still_emits(self):
        # First-ever startup: counters at 0, last_success_ts still 0. We
        # emit the counters anyway so Prometheus has a baseline; alerts
        # that look for "success counter increased in the last day" then
        # work from day one.
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            renewal_state={
                "success_total": 0,
                "failure_total": 0,
                "last_success_ts": 0,
                "last_duration_seconds": 0,
            },
            version="",
        )
        self.assertIn('mole_vpn_renewals_total{result="success"} 0', text)
        self.assertIn('mole_vpn_renewals_total{result="failure"} 0', text)


class TestPortForwardState(unittest.TestCase):

    def test_emitted_with_age(self):
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "age_seconds": 30.5,
                "success_total": 100,
                "failure_total": 2,
            },
            version="",
        )
        self.assertIn("mole_vpn_port_forward_age_seconds 30.5", text)
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{result="success"} 100', text
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{result="failure"} 2', text
        )

    def test_age_omitted_when_no_success_yet(self):
        # If a port-forward keepalive has never succeeded, age is undefined
        # — emitting "0" would say "we just succeeded" which is wrong, and
        # emitting "infinity" doesn't render. The handler omits the gauge
        # entirely (consistent with handshake_age behaviour).
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={"success_total": 0, "failure_total": 0},
            version="",
        )
        self.assertNotIn("mole_vpn_port_forward_age_seconds", text)
        # Counters still present though.
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{result="success"} 0', text
        )

    def test_omitted_when_state_absent(self):
        text = format_prometheus_metrics(
            {}, {"connected": True}, port_forward_state=None, version=""
        )
        self.assertNotIn("mole_vpn_port_forward_", text)


class TestPortForwardCountryBreakdown(unittest.TestCase):
    """When the keepalive loop has written per-country buckets, the metric
    is emitted with both a `country` and `result` label. The fallback to
    the unlabelled aggregate covers the upgrade-window case where pre-PR
    mole is still running but the api server has been restarted on the
    new code path."""

    def test_breakdown_emits_labelled_samples(self):
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "age_seconds": 5.0,
                "success_total": 25,
                "failure_total": 3,
                "breakdown": {
                    "NL": {"success": 20, "failure": 3},
                    "US": {"success": 5, "failure": 0},
                },
            },
            version="",
        )
        # Each (country, result) tuple is a separate sample.
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="NL",result="success"} 20',
            text,
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="NL",result="failure"} 3',
            text,
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="US",result="success"} 5',
            text,
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="US",result="failure"} 0',
            text,
        )
        # HELP/TYPE block emitted exactly once for the labelled form.
        self.assertEqual(
            text.count("# TYPE mole_vpn_port_forward_renewals_total counter"), 1
        )
        # No unlabelled emission alongside the labelled one.
        self.assertNotIn(
            'mole_vpn_port_forward_renewals_total{result="success"} ', text
        )

    def test_falls_back_to_aggregate_when_breakdown_empty(self):
        # Pre-upgrade or post-fresh-install: breakdown JSON not yet written.
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "success_total": 100,
                "failure_total": 2,
                "breakdown": {},
            },
            version="",
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{result="success"} 100', text
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{result="failure"} 2', text
        )
        # No country-labelled samples appear.
        self.assertNotIn('country="', text)

    def test_unknown_country_bucket(self):
        # Connection came up before server_country was populated → still
        # accounted under "unknown" rather than silently dropped.
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "success_total": 1,
                "failure_total": 0,
                "breakdown": {"unknown": {"success": 1, "failure": 0}},
            },
            version="",
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="unknown",result="success"} 1',
            text,
        )

    def test_non_dict_bucket_skipped_gracefully(self):
        # Defensive: malformed JSON state (e.g. partial write or hand-edit)
        # shouldn't crash the scrape — just skip the bad entry.
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "success_total": 0,
                "failure_total": 0,
                "breakdown": {
                    "NL": {"success": 5, "failure": 1},
                    "BROKEN": "not-a-dict",
                },
            },
            version="",
        )
        self.assertIn(
            'mole_vpn_port_forward_renewals_total{country="NL",result="success"} 5',
            text,
        )
        self.assertNotIn('country="BROKEN"', text)

    def test_breakdown_country_keys_sorted(self):
        # Stable output ordering matters for diff-friendly scrape responses
        # and predictable Prometheus series identity.
        text = format_prometheus_metrics(
            {},
            {"connected": True},
            port_forward_state={
                "success_total": 0,
                "failure_total": 0,
                "breakdown": {
                    "US": {"success": 1, "failure": 0},
                    "DE": {"success": 1, "failure": 0},
                    "NL": {"success": 1, "failure": 0},
                },
            },
            version="",
        )
        # Find the order in which the country labels appear.
        order = []
        for line in text.splitlines():
            if line.startswith("mole_vpn_port_forward_renewals_total{country="):
                country = line.split('country="', 1)[1].split('"', 1)[0]
                if country not in order:
                    order.append(country)
        self.assertEqual(order, ["DE", "NL", "US"])


class TestBlocklistUpdateHealth(unittest.TestCase):

    def test_full_input(self):
        text = format_prometheus_metrics(
            {
                "last_blocklist_update": 1778163652,
                "last_blocklist_update_duration": 1.234567,
                "blocklist_update_failures_total": 3,
            },
            {"connected": True},
            version="",
        )
        # Duration emitted with 6-decimal rounding (matches latency convention).
        self.assertRegex(
            text,
            r"(?m)^mole_dns_blocklist_update_last_duration_seconds 1\.234567$",
        )
        self.assertIn("mole_dns_blocklist_update_failures_total 3", text)

    def test_defaults_when_dns_stats_empty(self):
        text = format_prometheus_metrics({}, {"connected": True}, version="")
        # Both metrics still emit at 0, so a fresh deployment has the
        # series present from the first scrape.
        self.assertIn("mole_dns_blocklist_update_last_duration_seconds 0", text)
        self.assertIn("mole_dns_blocklist_update_failures_total 0", text)


# ---------- Existing "output is parseable" check (kept) ----------

class TestPrometheusOutputParseable(unittest.TestCase):
    """Spot-check that every non-blank line matches the exposition grammar.

    Not a full parser — pulls in a regex sufficient to catch obvious bugs
    like un-escaped chars in label values, stray words in metric values, etc.
    """

    def _assert_lines_well_formed(self, text):
        for i, line in enumerate(text.splitlines()):
            with self.subTest(line_no=i, line=line):
                self.assertRegex(line, _LINE_RE)

    def test_empty_input_well_formed(self):
        self._assert_lines_well_formed(
            format_prometheus_metrics({}, {}, version="0.4.0")
        )

    def test_full_input_well_formed(self):
        self._assert_lines_well_formed(
            format_prometheus_metrics(
                SAMPLE_DNS_STATS,
                {"connected": True, "port": 47387},
                version="0.4.0",
            )
        )

    def test_help_and_type_balanced(self):
        # Every metric series should have a matching HELP and TYPE.
        text = format_prometheus_metrics(
            SAMPLE_DNS_STATS,
            {"connected": True, "port": 47387},
            version="0.4.0",
        )
        help_names = re.findall(r"^# HELP (\S+)", text, re.MULTILINE)
        type_names = re.findall(r"^# TYPE (\S+)", text, re.MULTILINE)
        self.assertEqual(set(help_names), set(type_names))
        # And each HELP appears exactly once per metric (Prometheus rejects
        # duplicates within a single exposition response).
        self.assertEqual(len(help_names), len(set(help_names)))


if __name__ == "__main__":
    unittest.main()
