"""The offline guarantee.

The README states that VoidLexicon runs correctly with the network interface down
and that the test suite asserts it. This is that assertion.

Sockets are severed at the module level for the duration of each test, so any
attempt to open a connection — by VoidLexicon, or by anything it imports and calls
— raises instead of silently succeeding on a developer machine that happens to
have connectivity.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from voidai.analyzers import (
    AnalysisContext,
    BeaconingAnalyzer,
    ThreatIntelAnalyzer,
    TlsDgaAnalyzer,
)
from voidai.eval.benchmark import run_benchmark
from voidai.eval.synth import CorpusGenerator, DgaCorpusGenerator, TlsCorpusGenerator
from voidai.ingest.ioc import load_indicators
from voidai.ingest.zeek import read_conn_log


class NetworkAccessError(AssertionError):
    """Raised when code under test reaches for the network."""


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise NetworkAccessError(
            "VoidLexicon attempted a network connection. Nothing in the detection "
            "path may leave the machine."
        )

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)


@pytest.mark.usefixtures("no_network")
class TestPipelineRunsOffline:
    def test_corpus_generation_is_offline(self) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=6.0)
        assert corpus.connections.height > 0

    def test_parsing_is_offline(self, tmp_path: Path) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=6.0)
        log = corpus.write_zeek_conn_log(tmp_path / "conn.log")
        assert read_conn_log(log).height > 0

    def test_detection_is_offline(self) -> None:
        corpus = CorpusGenerator(seed=1337).generate(hours=24.0)
        findings = BeaconingAnalyzer().analyze(AnalysisContext(connections=corpus.connections))
        assert findings, "detection produced nothing — the test would be vacuous"

    def test_tls_and_dga_detection_is_offline(self) -> None:
        """The cluster most likely to tempt a lookup.

        Both halves of this analyzer describe things a network tool would
        normally resolve — a domain's registration status, a fingerprint's
        reputation. Neither is looked up. The public-suffix reduction is a
        table in the source, and every measurement comes from the capture.
        """
        dga = DgaCorpusGenerator(seed=1337).generate()
        tls = TlsCorpusGenerator(seed=1337).generate()
        findings = TlsDgaAnalyzer().analyze(
            AnalysisContext(dns=dga.queries, ssl=tls.sessions)
        )
        assert findings, "detection produced nothing — the test would be vacuous"

    def test_threat_intel_is_offline(self, tmp_path: Path) -> None:
        """The cluster most likely to tempt someone into fetching a feed.

        Threat intel is one HTTP call away from being much easier to build,
        and the whole architecture rests on it not being built that way. IOC
        sets are files the operator places on disk; VoidLexicon reads them and
        never retrieves them.
        """
        corpus = CorpusGenerator(seed=1337).generate(hours=6.0)
        destination = corpus.connections["dst_ip"][0]
        # Dated just before the generated corpus, which starts 2025-06-15, so
        # the age path is exercised rather than sidestepped by an undated feed.
        (tmp_path / "operator.ioc").write_text(
            "# name: offline-fixture\n"
            "# confidence: 0.9\n"
            "# updated: 2025-06-01\n"
            f"{destination}\n"
        )

        indicators = load_indicators(tmp_path)
        assert len(indicators) == 1, "the fixture must actually load, or the test is vacuous"

        findings = ThreatIntelAnalyzer().analyze(
            AnalysisContext(connections=corpus.connections, indicators=indicators)
        )
        assert findings, "detection produced nothing — the test would be vacuous"

    def test_full_benchmark_is_offline(self) -> None:
        """The end-to-end path: generate, write, parse, detect, score, meter."""
        result = run_benchmark(seed=1337, hours=24.0)
        # Precision is the property that must hold absolutely: no false alarms.
        assert result.detection.precision == 1.0
        assert result.detection.recall >= 0.8


@pytest.mark.usefixtures("no_network")
def test_the_guard_itself_works() -> None:
    """Confirms the fixture would actually catch a violation."""
    with pytest.raises(NetworkAccessError):
        socket.socket()
