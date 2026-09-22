"""Suricata EVE parsing and alert triage.

The reduction is the point. An IDS that emits 11,000 alerts has not told an
analyst anything they can act on, and the tests below assert that the flood
collapses without the intrusion collapsing with it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import polars as pl
import pytest

from voidai.analyzers import (
    AlertTriageAnalyzer,
    AlertTriageConfig,
    AnalysisContext,
    score_alert_cluster,
)
from voidai.analyzers.alerts import category_weight
from voidai.ingest import read_eve
from voidai.ingest.schema import ALERT_SCHEMA, conform
from voidai.lexicon import EntityType, Predicate, Severity


def event(
    ts: float,
    src: str,
    signature: str,
    signature_id: int,
    category: str = "A Network Trojan was detected",
    severity: int = 1,
    dst: str = "203.0.113.7",
    event_type: str = "alert",
) -> str:
    stamp = datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000"
    payload: dict[str, object] = {
        "timestamp": stamp,
        "event_type": event_type,
        "src_ip": src,
        "dest_ip": dst,
        "dest_port": 443,
        "proto": "TCP",
    }
    if event_type == "alert":
        payload["alert"] = {
            "signature_id": signature_id,
            "signature": signature,
            "category": category,
            "severity": severity,
        }
    return json.dumps(payload)


@pytest.fixture
def eve(tmp_path: Path) -> Path:
    lines = [
        event(1_750_000_000.0 + i, "10.0.0.5", "ET TROJAN Foo", 2018000) for i in range(5)
    ]
    lines.append(event(1_750_000_100.0, "10.0.0.6", "ET POLICY Bar", 2013000,
                       category="Not Suspicious Traffic", severity=3))
    # Non-alert events make up most of a real EVE stream and must be ignored.
    lines += [event(1_750_000_200.0, "10.0.0.7", "", 0, event_type="flow") for _ in range(20)]
    path = tmp_path / "eve.json"
    path.write_text("\n".join(lines))
    return path


class TestEveParsing:
    def test_reads_only_alert_events(self, eve: Path) -> None:
        frame = read_eve(eve)
        assert frame.height == 6  # 20 flow events dropped

    def test_conforms_to_the_alert_schema(self, eve: Path) -> None:
        assert set(read_eve(eve).columns) == set(ALERT_SCHEMA)

    def test_unpacks_the_nested_alert_object(self, eve: Path) -> None:
        row = read_eve(eve).sort("ts").row(0, named=True)
        assert row["signature"] == "ET TROJAN Foo"
        assert row["signature_id"] == 2018000
        assert row["severity"] == 1

    def test_renames_dest_ip_to_dst_ip(self, eve: Path) -> None:
        assert read_eve(eve).sort("ts")["dst_ip"][0] == "203.0.113.7"

    def test_parses_the_timestamp_with_offset(self, eve: Path) -> None:
        assert read_eve(eve).sort("ts")["ts"][0] == pytest.approx(1_750_000_000.0, abs=0.01)

    def test_records_source_line_numbers(self, eve: Path) -> None:
        assert read_eve(eve).sort("ts")["source_line"][0] == 1

    def test_missing_file(self, tmp_path: Path) -> None:
        assert read_eve(tmp_path / "absent.json").height == 0

    def test_stream_with_no_alerts_at_all(self, tmp_path: Path) -> None:
        path = tmp_path / "eve.json"
        path.write_text("\n".join(event(1.0, "10.0.0.1", "", 0, event_type="flow") for _ in range(5)))
        assert read_eve(path).height == 0

    def test_malformed_lines_are_skipped(self, tmp_path: Path) -> None:
        path = tmp_path / "eve.json"
        path.write_text(event(1_750_000_000.0, "10.0.0.5", "ET TROJAN Foo", 1) + "\nnot json\n")
        assert read_eve(path).height >= 1

    @pytest.mark.parametrize("absent", ["signature_id", "category", "severity"])
    def test_alert_object_missing_a_field_still_parses(
        self, tmp_path: Path, absent: str
    ) -> None:
        """Not every producer of `eve.json` is Suricata itself, and the ones
        that reshape it — a shipper, a trimmed template, an older release —
        drop keys. Asking a struct for a field it lacks throws, so a single
        missing key used to cost the entire log."""
        record = json.loads(event(1_750_000_000.0, "10.0.0.5", "ET TROJAN Foo", 1))
        del record["alert"][absent]
        (tmp_path / "eve.json").write_text(json.dumps(record) + "\n")

        frame = read_eve(tmp_path / "eve.json")
        assert frame.height == 1
        assert frame["signature"].to_list() == ["ET TROJAN Foo"]
        assert frame[absent].to_list() == [None]

    def test_alert_object_carrying_only_a_signature(self, tmp_path: Path) -> None:
        """The floor of the same rule: everything optional gone at once. The
        signature is what the analyzer needs, and it survives alone."""
        record = json.loads(event(1_750_000_000.0, "10.0.0.5", "ET TROJAN Foo", 1))
        record["alert"] = {"signature": "ET TROJAN Foo"}
        (tmp_path / "eve.json").write_text(json.dumps(record) + "\n")

        frame = read_eve(tmp_path / "eve.json")
        assert frame.height == 1
        assert frame["signature"].to_list() == ["ET TROJAN Foo"]

    def test_alert_that_is_not_an_object_yields_no_alerts(self, tmp_path: Path) -> None:
        """`alert` present but not a struct leaves no fields to read. That is a
        file with nothing in it for us, not a reason to abandon the run."""
        record = json.loads(event(1_750_000_000.0, "10.0.0.5", "ET TROJAN Foo", 1))
        record["alert"] = "ET TROJAN Foo"
        (tmp_path / "eve.json").write_text(json.dumps(record) + "\n")

        assert read_eve(tmp_path / "eve.json").height == 0


class TestCategoryWeight:
    @pytest.mark.parametrize(
        ("category", "floor"),
        [
            ("A Network Trojan was detected", 0.9),
            ("Attempted Administrator Privilege Gain", 0.8),
            ("Web Application Attack", 0.8),
        ],
    )
    def test_serious_categories_score_high(self, category: str, floor: float) -> None:
        assert category_weight(category) >= floor

    @pytest.mark.parametrize(
        "category", ["Not Suspicious Traffic", "Misc activity", "Potential Corporate Policy Violation"]
    )
    def test_noise_categories_score_low(self, category: str) -> None:
        assert category_weight(category) <= 0.5

    def test_unknown_and_missing(self) -> None:
        assert 0.0 < category_weight(None) < 1.0
        assert 0.0 < category_weight("Some Novel Category") < 1.0


class TestScoreAlertCluster:
    def test_rare_severe_alert_scores_high(self) -> None:
        score = score_alert_cluster(
            alerts=12,
            hosts_with_signature=1,
            stated_severity=1,
            category="A Network Trojan was detected",
            config=AlertTriageConfig(),
        )
        assert score is not None
        assert score.score >= AlertTriageConfig().high_threshold

    def test_estate_wide_signature_is_suppressed(self) -> None:
        """Sixty machines on one rule is a policy, not an incident."""
        score = score_alert_cluster(
            alerts=5000,
            hosts_with_signature=60,
            stated_severity=1,
            category="A Network Trojan was detected",
            config=AlertTriageConfig(),
        )
        assert score is not None
        assert score.score < AlertTriageConfig().score_threshold

    def test_volume_alone_does_not_raise_the_score(self) -> None:
        """Ten thousand copies of one alert is one fact, not ten thousand."""
        config = AlertTriageConfig()
        few = score_alert_cluster(5, 1, 1, "A Network Trojan was detected", config)
        many = score_alert_cluster(10_000, 1, 1, "A Network Trojan was detected", config)
        assert few is not None and many is not None
        assert few.score == pytest.approx(many.score)

    def test_low_severity_noise_category_scores_low(self) -> None:
        score = score_alert_cluster(50, 3, 3, "Not Suspicious Traffic", AlertTriageConfig())
        assert score is not None
        assert score.score < AlertTriageConfig().score_threshold

    def test_too_few_alerts_returns_none(self) -> None:
        assert score_alert_cluster(1, 1, 1, "A Network Trojan was detected",
                                   AlertTriageConfig()) is None

    def test_missing_severity_is_scored_neutrally(self) -> None:
        score = score_alert_cluster(10, 1, None, "A Network Trojan was detected",
                                    AlertTriageConfig())
        assert score is not None
        assert 0.0 < score.components["stated_severity"] < 1.0

    def test_basis_names_every_component(self) -> None:
        score = score_alert_cluster(10, 1, 1, "A Network Trojan was detected",
                                    AlertTriageConfig())
        assert score is not None
        for component in score.components:
            assert component in score.basis()


def _stream(rows: list[dict[str, object]]) -> pl.DataFrame:
    return conform(pl.DataFrame(rows), ALERT_SCHEMA)


def _alerts(src: str, signature: str, sid: int, count: int, severity: int, category: str,
            start: float = 1_750_000_000.0) -> list[dict[str, object]]:
    return [
        {
            "ts": start + i * 7,
            "src_ip": src,
            "dst_ip": "203.0.113.7",
            "dst_port": 443,
            "proto": "tcp",
            "signature": signature,
            "signature_id": sid,
            "category": category,
            "severity": severity,
            "source_file": "<synthetic>",
            "source_line": i + 1,
        }
        for i in range(count)
    ]


@pytest.fixture(scope="module")
def flood() -> pl.DataFrame:
    """A realistic stream: estate-wide noise plus one compromised host."""
    rows: list[dict[str, object]] = []
    for host in range(60):
        rows += _alerts(f"10.0.2.{host + 1}", "ET POLICY curl User-Agent", 2013028,
                        60, 3, "Not Suspicious Traffic")
        rows += _alerts(f"10.0.2.{host + 1}", "ET SCAN Unusual Port 445", 2001569,
                        40, 3, "Misc activity")
    rows += _alerts("10.0.2.99", "ET TROJAN Observed Malicious SSL Cert", 2018000,
                    12, 1, "A Network Trojan was detected")
    return _stream(rows)


class TestAlertTriageAnalyzer:
    def test_collapses_the_flood(self, flood: pl.DataFrame) -> None:
        findings = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood))
        assert flood.height > 5000
        assert len(findings) <= 3

    def test_surfaces_the_compromised_host(self, flood: pl.DataFrame) -> None:
        findings = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood))
        assert {f.subject.value for f in findings} == {"10.0.2.99"}

    def test_uses_the_triggered_signature_predicate(self, flood: pl.DataFrame) -> None:
        findings = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood))
        assert all(f.predicate is Predicate.TRIGGERED_SIGNATURE for f in findings)
        assert all(f.object is not None and f.object.type is EntityType.SIGNATURE
                   for f in findings)

    def test_severity_is_capped_at_medium(self, flood: pl.DataFrame) -> None:
        """A ruleset's opinion must not outrank VoidLexicon's own measurements."""
        findings = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood))
        assert findings
        assert all(f.severity.rank <= Severity.MEDIUM.rank for f in findings)

    def test_carries_resolvable_evidence(self, flood: pl.DataFrame) -> None:
        for finding in AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood)):
            for evidence in finding.evidence:
                assert evidence.artifacts
                for artifact in evidence.artifacts:
                    assert artifact.source and artifact.locator

    def test_is_deterministic(self, flood: pl.DataFrame) -> None:
        ctx = AnalysisContext(alerts=flood)
        assert [f.id for f in AlertTriageAnalyzer().analyze(ctx)] == [
            f.id for f in AlertTriageAnalyzer().analyze(ctx)
        ]

    def test_lazy_and_eager_agree(self, flood: pl.DataFrame) -> None:
        eager = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood))
        lazy = AlertTriageAnalyzer().analyze(AnalysisContext(alerts=flood.lazy()))
        assert [f.id for f in eager] == [f.id for f in lazy]

    def test_empty_input(self) -> None:
        assert AlertTriageAnalyzer().analyze(AnalysisContext(alerts=_stream([]))) == []

    def test_no_alert_source_at_all(self) -> None:
        assert AlertTriageAnalyzer().analyze(AnalysisContext()) == []
