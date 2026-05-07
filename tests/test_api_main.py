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
