"""Tests for hunt query generation.

Two properties matter here, and they are different in kind.

The first is *correctness*: a generated query must actually match the thing
the finding was about. This is easy to get wrong invisibly — an equality test
against a tunnelling zone parses fine, runs fine, and returns nothing forever,
which reads as a clean estate. So the Zeek pipelines are not merely inspected;
they are executed against a log file with known contents and their output is
compared to the answer.

The second is *safety*. Indicator values are copied out of logs, and logs hold
whatever an attacker wrote into them. A generated query is a string an analyst
pastes into a console that holds production credentials. The escaping tests
below use values crafted to break out of each dialect's quoting, and assert
that the executed pipeline still returns the right rows — proving the value
was treated as data rather than as syntax.
"""

from __future__ import annotations

import re
import subprocess
import uuid
from pathlib import Path

import pytest
import yaml

from voidai.correlate import build_queue
from voidai.hunt import Dialect, escape, pivot_entities, queries_for, queries_for_incident
from voidai.lexicon import (
    Artifact,
    Entity,
    EntityType,
    Evidence,
    Finding,
    Incident,
    Predicate,
)

_SIGMA_LEVELS = {"informational", "low", "medium", "high", "critical"}


def _evidence(kind: str = "interval_regularity") -> Evidence:
    return Evidence(
        kind=kind,
        summary="synthetic evidence",
        artifacts=[Artifact(source="conn.log", locator="line:1")],
    )


def finding(
    predicate: Predicate,
    subject: Entity,
    target: Entity | None,
    confidence: float = 0.9,
) -> Finding:
    return Finding(
        predicate=predicate,
        subject=subject,
        object=target,
        evidence=[_evidence(predicate.value)],
        confidence=confidence,
        basis="synthetic",
        analyzer="test@0",
    )


def beacon(host: str = "10.0.1.14", target: str = "45.83.220.17") -> Finding:
    return finding(
        Predicate.BEACONS_TO,
        Entity(type=EntityType.IP, value=host),
        Entity(type=EntityType.IP, value=target),
    )


def tunnel(host: str = "10.0.1.14", zone: str = "tunnel.example.com") -> Finding:
    return finding(
        Predicate.TUNNELS_DNS_OVER,
        Entity(type=EntityType.IP, value=host),
        Entity(type=EntityType.DOMAIN, value=zone),
        confidence=0.8,
    )


def scan(host: str = "10.0.1.14", port: str = "445") -> Finding:
    return finding(
        Predicate.SCANS,
        Entity(type=EntityType.IP, value=host),
        Entity(type=EntityType.PORT, value=port),
        confidence=0.7,
    )


def signature(host: str = "10.0.1.14", name: str = "ET TROJAN Beacon") -> Finding:
    return finding(
        Predicate.TRIGGERED_SIGNATURE,
        Entity(type=EntityType.IP, value=host),
        Entity(type=EntityType.SIGNATURE, value=name),
        confidence=0.6,
    )


def fingerprint(
    host: str = "10.0.1.14",
    ja3: str = "9f1a7c4be2d3084f5a6b7c8d9e0f1a2b",
) -> Finding:
    return finding(
        Predicate.PRESENTS_RARE_TLS_FINGERPRINT,
        Entity(type=EntityType.IP, value=host),
        Entity(type=EntityType.TLS_FINGERPRINT, value=ja3),
        confidence=0.83,
    )


def rare_process(
    host: str = "FINANCE-WS04",
    image: str = "svchost-update.exe",
) -> Finding:
    return finding(
        Predicate.EXECUTES_RARE_PROCESS,
        Entity(type=EntityType.HOST, value=host),
        Entity(type=EntityType.PROCESS, value=image),
        confidence=0.98,
    )


def lineage(host: str = "FINANCE-WS04", image: str = "cmd.exe") -> Finding:
    return finding(
        Predicate.EXHIBITS_ANOMALOUS_LINEAGE,
        Entity(type=EntityType.HOST, value=host),
        Entity(type=EntityType.PROCESS, value=image),
        confidence=0.97,
    )


class TestProcessPivot:
    """A process finding pivots on the image and asks about other machines.

    Three things differ from every pivot above it, and each is a way the
    generated query returns nothing forever while looking like a clean estate.
    """

    def test_the_image_is_matched_as_a_path_suffix(self) -> None:
        r"""The proposition names a basename; the log column holds a full path.

        `Image: "powershell.exe"` compares `powershell.exe` against
        `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` and
        matches nothing. The suffix separator is a path separator here and a
        dot for a DNS zone, which is why it is a field rather than a constant.
        """
        rule = yaml.safe_load(queries_for(rare_process(), (Dialect.SIGMA,))[0].query)
        selection = rule["detection"]["selection"]
        assert "Image|endswith" in selection
        assert selection["Image|endswith"] == "\\svchost-update.exe"

    def test_the_subject_column_is_the_hostname(self) -> None:
        """Network telemetry answers "which other addresses". This answers
        "which other machines", and those are different columns."""
        rule = yaml.safe_load(queries_for(rare_process(), (Dialect.SIGMA,))[0].query)
        assert rule["detection"]["filter_known"] == {"Computer": "FINANCE-WS04"}
        assert "src_ip" not in rule["detection"]["filter_known"]

    def test_the_log_source_is_process_creation(self) -> None:
        rule = yaml.safe_load(queries_for(rare_process(), (Dialect.SIGMA,))[0].query)
        assert rule["logsource"]["category"] == "process_creation"

    def test_no_zeek_pipeline_is_generated(self) -> None:
        """Zeek writes no process log, and a zeek-cut over a file that does
        not exist returns nothing forever — the reason `matches_threat_intel`
        declines to pivot on a hash rather than emitting a query for one."""
        dialects = {q.dialect for q in queries_for(rare_process())}
        assert Dialect.ZEEK not in dialects
        assert dialects == {Dialect.SIGMA, Dialect.KQL, Dialect.SPL}

    def test_an_explicit_zeek_request_yields_nothing_rather_than_a_bad_query(self) -> None:
        assert queries_for(rare_process(), (Dialect.ZEEK,)) == []

    def test_both_host_predicates_pivot(self) -> None:
        for query in queries_for(lineage(), (Dialect.KQL,)):
            assert "DeviceProcessEvents" in query.query
            assert 'DeviceName != "FINANCE-WS04"' in query.query

    def test_the_indicator_is_offered_for_hunting(self) -> None:
        incident = Incident(findings=[rare_process(), lineage()])
        assert [e.value for e in pivot_entities(incident)] == [
            "svchost-update.exe",
            "cmd.exe",
        ]


class TestTlsFingerprintPivot:
    """A JA3 is an indicator, but not one of the kinds already templated.

    It is not a destination and not a name — it identifies the *client*, so
    the hunt asks which other hosts run that client. Getting the field wrong
    here is the failure mode this whole module exists to avoid: a query that
    returns nothing forever while looking like a clean estate.
    """

    def test_pivots_on_the_fingerprint_and_excludes_the_known_host(self) -> None:
        queries = queries_for(fingerprint())
        assert queries
        for query in queries:
            assert "9f1a7c4be2d3084f5a6b7c8d9e0f1a2b" in query.query
            assert "10.0.1.14" in query.query
            assert query.pivot.startswith("ja3=")

    def test_every_dialect_reads_from_its_tls_source(self) -> None:
        """A JA3 does not live in the connection or DNS table."""
        expected = {
            Dialect.SIGMA: "service: tls",
            Dialect.KQL: "TlsEvents",
            Dialect.SPL: "index=tls",
            Dialect.ZEEK: "ssl.log",
        }
        for query in queries_for(fingerprint()):
            assert expected[query.dialect] in query.query

    def test_the_fingerprint_is_matched_exactly(self) -> None:
        """Unlike a tunnelling zone, a JA3 is the whole value, not a suffix."""
        for query in queries_for(fingerprint()):
            if query.dialect is Dialect.SIGMA:
                assert "endswith" not in query.query


class TestAlgorithmicDomainPivot:
    def test_pivots_on_the_generated_name(self) -> None:
        generated = finding(
            Predicate.RESOLVES_ALGORITHMIC_DOMAIN,
            Entity(type=EntityType.IP, value="10.0.2.31"),
            Entity(type=EntityType.DOMAIN, value="uqnqxhhqz.biz"),
        )
        queries = queries_for(generated)
        assert queries
        for query in queries:
            assert "uqnqxhhqz.biz" in query.query
            assert "10.0.2.31" in query.query


class TestPivotSelection:
    def test_every_dialect_is_emitted(self) -> None:
        queries = queries_for(beacon())
        assert {q.dialect for q in queries} == set(Dialect)

    def test_a_subset_of_dialects_can_be_requested(self) -> None:
        queries = queries_for(beacon(), dialects=(Dialect.SIGMA,))
        assert [q.dialect for q in queries] == [Dialect.SIGMA]

    def test_relational_predicates_yield_nothing(self) -> None:
        """`precedes` describes VoidLexicon's own reasoning, not an indicator.

        There is no field in any SIEM that holds "came before". Inventing a
        query for it would mean inventing an indicator, which is exactly the
        failure mode the Lexicon exists to prevent.
        """
        pair = finding(
            Predicate.PRECEDES,
            Entity(type=EntityType.IP, value="10.0.1.14"),
            Entity(type=EntityType.IP, value="10.0.1.23"),
        )
        assert queries_for(pair) == []

    def test_an_intel_match_pivots_on_its_subject(self) -> None:
        """The one unary predicate that carries a real indicator.

        `matches_threat_intel` has no object — the address *is* the claim — so
        the pivot has to come from the subject. This test previously asserted
        that objectless findings yield nothing, which was true only while no
        analyzer emitted the predicate; the invariant it was actually guarding
        is the one below it, that a finding carrying no SIEM-queryable
        indicator stays silent.
        """
        intel = finding(
            Predicate.MATCHES_THREAT_INTEL,
            Entity(type=EntityType.IP, value="45.83.220.17"),
            None,
        )
        queries = queries_for(intel)
        assert queries, "an intel match on an address is the most pivotable finding there is"
        for query in queries:
            assert "45.83.220.17" in query.query
            assert query.pivot == "dst=45.83.220.17"

    def test_an_intel_match_hunts_every_host_including_the_known_one(self) -> None:
        """No exclusion, unlike every other pivot.

        Elsewhere the known subject is excluded because re-finding the traffic
        that produced the finding tells an analyst nothing. Here the subject
        *is* the indicator, and every host that touched it — the one already
        seen included — is what the query is for.
        """
        intel = finding(
            Predicate.MATCHES_THREAT_INTEL,
            Entity(type=EntityType.DOMAIN, value="c2.evil.example"),
            None,
        )
        sigma = queries_for(intel, dialects=(Dialect.SIGMA,))[0]
        assert "c2.evil.example" in sigma.query
        assert "filter" not in sigma.query.lower(), "an intel hunt excludes nothing"

    def test_unqueryable_intel_subjects_yield_nothing(self) -> None:
        """A hash is not a field in any log source this generator templates.

        A query for one would return nothing forever while looking like a
        clean estate, which is worse than no query at all.
        """
        digest = finding(
            Predicate.MATCHES_THREAT_INTEL,
            Entity(type=EntityType.FILE_HASH, value="d41d8cd98f00b204e9800998ecf8427e"),
            None,
        )
        assert queries_for(digest) == []

    def test_the_pivot_is_the_object_not_the_subject(self) -> None:
        """The point of a hunt is to find hosts you do not already know about."""
        for query in queries_for(beacon()):
            assert "45.83.220.17" in query.query
            assert query.pivot == "dst=45.83.220.17"

    def test_the_known_subject_is_excluded(self) -> None:
        for query in queries_for(beacon()):
            assert "10.0.1.14" in query.query, "the subject must appear, as an exclusion"
        sigma = queries_for(beacon(), dialects=(Dialect.SIGMA,))[0]
        assert "condition: selection and not filter_known" in sigma.query

    def test_every_query_carries_its_finding(self) -> None:
        source = beacon()
        for query in queries_for(source):
            assert query.finding_id == source.id
            assert source.id in query.query, "provenance must survive a copy-paste"


class TestSigma:
    @pytest.mark.parametrize(
        "produce", [beacon, tunnel, scan, signature], ids=lambda f: f.__name__
    )
    def test_output_is_valid_yaml_with_the_required_keys(self, produce) -> None:  # type: ignore[no-untyped-def]
        rule = yaml.safe_load(queries_for(produce(), dialects=(Dialect.SIGMA,))[0].query)
        assert {"title", "id", "logsource", "detection", "level"} <= rule.keys()
        assert rule["detection"]["condition"]
        assert rule["level"] in _SIGMA_LEVELS

    def test_the_rule_id_is_a_uuid(self) -> None:
        """Sigma requires a UUID; VoidLexicon IDs are not one.

        A v5 derivation satisfies the schema without giving up reproducibility.
        """
        rule = yaml.safe_load(queries_for(beacon(), dialects=(Dialect.SIGMA,))[0].query)
        assert uuid.UUID(rule["id"]).version == 5

    def test_the_rule_id_is_reproducible(self) -> None:
        first = queries_for(beacon(), dialects=(Dialect.SIGMA,))[0].query
        second = queries_for(beacon(), dialects=(Dialect.SIGMA,))[0].query
        assert first == second

    def test_distinct_findings_get_distinct_rule_ids(self) -> None:
        a = yaml.safe_load(queries_for(beacon(), dialects=(Dialect.SIGMA,))[0].query)
        b = yaml.safe_load(
            queries_for(beacon(target="203.0.113.9"), dialects=(Dialect.SIGMA,))[0].query
        )
        assert a["id"] != b["id"]

    def test_attack_techniques_carry_through(self) -> None:
        rule = yaml.safe_load(queries_for(beacon(), dialects=(Dialect.SIGMA,))[0].query)
        assert "attack.t1071" in rule["tags"]

    def test_a_port_is_numeric_not_a_string(self) -> None:
        """`dst_port: "445"` does not match a numeric column."""
        rule = yaml.safe_load(queries_for(scan(), dialects=(Dialect.SIGMA,))[0].query)
        assert rule["detection"]["selection"]["dst_port"] == 445

    def test_a_dns_zone_is_matched_as_a_suffix(self) -> None:
        rule = yaml.safe_load(queries_for(tunnel(), dialects=(Dialect.SIGMA,))[0].query)
        selection = rule["detection"]["selection"]
        assert "query" not in selection, "an equality test on a zone apex matches nothing"
        assert selection["query|endswith"] == ".tunnel.example.com"

    def test_a_crafted_signature_name_cannot_forge_yaml_structure(self) -> None:
        """The classic YAML break-out, as a signature name in an alert file."""
        hostile = 'X"\ncondition: selection\nlevel: critical\nx: "'
        rule = yaml.safe_load(
            queries_for(signature(name=hostile), dialects=(Dialect.SIGMA,))[0].query
        )
        # informational is this finding's own severity; critical is what the
        # crafted name tried to assert.
        assert rule["level"] == "informational"
        assert "x" not in rule
        # The newlines are gone, so the value is one scalar rather than a
        # document fragment. What survives is inert text.
        assert "\n" not in rule["detection"]["selection"]["signature"]


class TestKqlAndSpl:
    def test_kql_pivots_on_the_right_table(self) -> None:
        assert "DnsEvents" in queries_for(tunnel(), dialects=(Dialect.KQL,))[0].query
        assert "SecurityAlert" in queries_for(signature(), dialects=(Dialect.KQL,))[0].query
        assert "NetworkEvents" in queries_for(beacon(), dialects=(Dialect.KQL,))[0].query

    def test_kql_uses_endswith_for_a_zone(self) -> None:
        query = queries_for(tunnel(), dialects=(Dialect.KQL,))[0].query
        assert 'QueryName endswith ".tunnel.example.com"' in query

    def test_spl_wildcards_a_zone_but_escapes_one_in_a_value(self) -> None:
        """Splunk treats `*` as a wildcard even inside quotes.

        The wildcard we add ourselves must survive; one arriving from a log
        must not, or the hunt silently widens to match everything.
        """
        zone = queries_for(tunnel(), dialects=(Dialect.SPL,))[0].query
        assert 'query="*.tunnel.example.com"' in zone

        hostile = queries_for(signature(name="A*"), dialects=(Dialect.SPL,))[0].query
        assert 'signature="A\\*"' in hostile

    def test_a_port_is_unquoted_in_both(self) -> None:
        assert "DestinationPort == 445" in queries_for(scan(), dialects=(Dialect.KQL,))[0].query
        assert "dest_port=445" in queries_for(scan(), dialects=(Dialect.SPL,))[0].query

    @pytest.mark.parametrize("dialect", [Dialect.KQL, Dialect.SPL])
    def test_a_crafted_value_cannot_close_the_string(self, dialect: Dialect) -> None:
        hostile = 'X" or 1==1 or AlertName == "'
        query = queries_for(signature(name=hostile), dialects=(dialect,))[0].query
        # Every quote originating in the value is escaped, so the number of
        # unescaped quotes is even and the injected clause stays inside one.
        assert len(re.findall(r'(?<!\\)"', query)) % 2 == 0
        assert '\\" or 1==1' in query


def _write_conn_log(directory: Path, rows: list[tuple[str, str]], name: str) -> Path:
    """A minimal zeek-cut-shaped file: tab-separated, no header."""
    path = directory / name
    path.write_text("".join(f"{src}\t{dst}\n" for src, dst in rows), encoding="utf-8")
    return path


def _run_pipeline(query: str, directory: Path) -> list[str]:
    """Execute a generated Zeek hunt, with `cat` standing in for `zeek-cut`.

    zeek-cut is not installed in CI, and its job here — project two columns
    from a log — is exactly what the fixture files already contain. Swapping
    it for `cat` leaves the part under test, the awk filter, untouched.
    """
    body = query.split("\n", 1)[1]  # drop the comment line
    body = re.sub(r"cat (\S+) \| zeek-cut [^\\]*", r"cat \1 ", body)
    completed = subprocess.run(
        ["sh", "-c", body],
        cwd=directory,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return [line.split()[-1] for line in completed.stdout.splitlines() if line.strip()]


class TestZeekPipelineExecutes:
    """The generated shell must run, and return the right hosts.

    A query that parses but matches nothing is the failure this class exists
    to catch: it looks identical to a clean estate.
    """

    def test_it_finds_the_other_hosts_and_omits_the_known_one(self, tmp_path: Path) -> None:
        _write_conn_log(
            tmp_path,
            [
                ("10.0.1.14", "45.83.220.17"),  # the host we already know about
                ("10.0.1.99", "45.83.220.17"),  # the answer
                ("10.0.1.99", "45.83.220.17"),
                ("10.0.2.7", "45.83.220.17"),  # also the answer
                ("10.0.1.50", "93.184.216.34"),  # unrelated
            ],
            "conn.log",
        )
        query = queries_for(beacon(), dialects=(Dialect.ZEEK,))[0].query
        assert sorted(_run_pipeline(query, tmp_path)) == ["10.0.1.99", "10.0.2.7"]

    def test_a_zone_hunt_matches_subdomains_and_not_the_apex(self, tmp_path: Path) -> None:
        """The bug this test was written for.

        Every tunnelled query is `<chunk>.zone`; none is `zone`. An equality
        test against the zone returns nothing and reads as an all-clear.
        """
        _write_conn_log(
            tmp_path,
            [
                ("10.0.1.99", "aGVsbG8.tunnel.example.com"),
                ("10.0.1.99", "d29ybGQ.tunnel.example.com"),
                ("10.0.2.7", "eDE.deep.tunnel.example.com"),
                ("10.0.1.14", "abc.tunnel.example.com"),  # known subject
                ("10.0.1.50", "tunnel.example.com"),  # apex only: not a tunnel
                ("10.0.1.50", "nottunnel.example.com"),  # must not match
                ("10.0.1.50", "tunnel.example.com.evil.net"),  # must not match
            ],
            "dns.log",
        )
        query = queries_for(tunnel(), dialects=(Dialect.ZEEK,))[0].query
        assert sorted(_run_pipeline(query, tmp_path)) == ["10.0.1.99", "10.0.2.7"]

    def test_an_indicator_containing_spaces_still_matches(self, tmp_path: Path) -> None:
        """Regression: awk's default separator is whitespace, not tab.

        zeek-cut emits tab-separated columns and every Suricata signature name
        contains spaces. Without an explicit `-F'\\t'`, `ET TROJAN Beacon`
        parses as three fields and the comparison is against "TROJAN".
        """
        _write_conn_log(
            tmp_path,
            [
                ("10.0.1.99", "ET TROJAN Beacon"),
                ("10.0.1.14", "ET TROJAN Beacon"),
                ("10.0.1.50", "ET TROJAN Something Else"),
            ],
            "notice.log",
        )
        query = queries_for(signature(), dialects=(Dialect.ZEEK,))[0].query
        assert _run_pipeline(query, tmp_path) == ["10.0.1.99"]

    def test_a_crafted_indicator_cannot_execute_a_command(self, tmp_path: Path) -> None:
        """A signature name written by whoever generated the traffic.

        `awk -v` keeps the value out of the program text, and shell single
        quoting keeps it out of the command line. If either failed, the marker
        file below would exist.
        """
        marker = tmp_path / "pwned"
        hostile = f"'; touch {marker}; echo '"
        _write_conn_log(
            tmp_path,
            [("10.0.1.99", hostile), ("10.0.1.14", hostile), ("10.0.1.50", "benign")],
            "notice.log",
        )
        query = queries_for(signature(name=hostile), dialects=(Dialect.ZEEK,))[0].query
        found = _run_pipeline(query, tmp_path)
        assert not marker.exists(), "the indicator escaped into the shell"
        assert found == ["10.0.1.99"], "and it still matched the right row"

    def test_a_backslash_in_an_indicator_survives_awk(self, tmp_path: Path) -> None:
        r"""`awk -v` expands escapes in the assigned value: `\t` becomes a tab."""
        hostile = r"ET\tTROJAN\x41"
        _write_conn_log(
            tmp_path,
            [("10.0.1.99", hostile), ("10.0.1.50", "ET\tTROJANA")],
            "notice.log",
        )
        query = queries_for(signature(name=hostile), dialects=(Dialect.ZEEK,))[0].query
        assert _run_pipeline(query, tmp_path) == ["10.0.1.99"]


class TestEscaping:
    @pytest.mark.parametrize("dialect", list(Dialect))
    def test_control_characters_are_stripped(self, dialect: Dialect) -> None:
        assert "\n" not in escape("a\nb", dialect)
        assert "\x00" not in escape("a\x00b", dialect)
        assert "\r" not in escape("a\rb", dialect)

    @pytest.mark.parametrize("dialect", list(Dialect))
    def test_ordinary_indicators_pass_through_unchanged(self, dialect: Dialect) -> None:
        for value in ("45.83.220.17", "tunnel.example.com", "445", "ET TROJAN Beacon"):
            assert escape(value, dialect) == value

    @pytest.mark.parametrize("dialect", list(Dialect))
    def test_no_query_contains_a_control_character(self, dialect: Dialect) -> None:
        hostile = "evil\r\n\x07\x00.example.com"
        query = queries_for(tunnel(zone=hostile), dialects=(dialect,))[0].query
        assert not any(character in query for character in "\r\x07\x00")


class TestIncidents:
    def _incident(self) -> Incident:
        return Incident(findings=[beacon(), tunnel(), scan(), signature()])

    def test_every_pivotable_finding_contributes(self) -> None:
        queries = queries_for_incident(self._incident(), dialects=(Dialect.SIGMA,))
        assert len(queries) == 4

    def test_identical_pivots_are_deduplicated(self) -> None:
        """Two findings naming one destination are two views of one indicator."""
        incident = Incident(findings=[beacon(), beacon(host="10.0.1.23")])
        queries = queries_for_incident(incident, dialects=(Dialect.SIGMA,))
        assert len(queries) == 1

    def test_the_strongest_finding_supplies_the_surviving_query(self) -> None:
        weak = finding(
            Predicate.CONTACTS_RARE_DESTINATION,
            Entity(type=EntityType.IP, value="10.0.1.23"),
            Entity(type=EntityType.IP, value="45.83.220.17"),
            confidence=0.3,
        )
        incident = Incident(findings=[weak, beacon()])
        query = queries_for_incident(incident, dialects=(Dialect.SIGMA,))[0]
        assert query.finding_id == beacon().id

    def test_pivot_entities_are_ordered_by_confidence(self) -> None:
        entities = pivot_entities(self._incident())
        assert [entity.value for entity in entities] == [
            "45.83.220.17",
            "tunnel.example.com",
            "445",
            "ET TROJAN Beacon",
        ]

    def test_an_incident_with_no_indicators_yields_nothing(self) -> None:
        pair = finding(
            Predicate.PRECEDES,
            Entity(type=EntityType.IP, value="10.0.1.14"),
            Entity(type=EntityType.IP, value="10.0.1.23"),
        )
        assert queries_for_incident(Incident(findings=[pair])) == []
        assert pivot_entities(Incident(findings=[pair])) == []


class TestAgainstThePipeline:
    """Generated from real analyzer output rather than hand-built findings."""

    def test_the_demo_incident_produces_runnable_hunts(self, tmp_path: Path) -> None:
        from voidai.analyzers import DEFAULT_ANALYZERS, AnalysisContext
        from voidai.eval.synth import build_demo_capture
        from voidai.ingest.passivedns import load_passivedns
        from voidai.ingest.suricata import load_alerts
        from voidai.ingest.zeek import load_connections, load_dns

        build_demo_capture(tmp_path)
        dns = load_dns(tmp_path)
        if dns.is_empty():
            dns = load_passivedns(tmp_path)
        ctx = AnalysisContext(
            connections=load_connections(tmp_path),
            dns=dns,
            alerts=load_alerts(tmp_path),
        )
        findings: list[Finding] = []
        for analyzer in DEFAULT_ANALYZERS:
            findings += analyzer().analyze(ctx)

        top = build_queue(findings).incidents[0].incident
        queries = queries_for_incident(top)
        assert queries, "the top-ranked incident must be actionable elsewhere"

        index = {f.id for f in top.findings}
        for query in queries:
            assert query.finding_id in index, "no query without a finding behind it"

        for query in queries:
            if query.dialect is Dialect.SIGMA:
                rule = yaml.safe_load(query.query)
                assert rule["level"] in _SIGMA_LEVELS


@pytest.fixture(scope="module")
def capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """One generated capture, shared by the command-line tests."""
    from voidai.eval.synth import build_demo_capture

    directory = tmp_path_factory.mktemp("hunt-capture")
    build_demo_capture(directory)
    return directory


class TestCommand:
    """`voidai hunt` end to end, over a generated capture."""

    def _invoke(self, *args: str) -> str:
        from typer.testing import CliRunner

        from voidai.cli import app

        result = CliRunner().invoke(app, list(args))
        assert result.exit_code == 0, result.output
        return result.output

    def test_stdout_queries_are_not_wrapped(self, capture: Path) -> None:
        """A YAML rule wrapped at terminal width is no longer a YAML rule.

        Rich wraps by default, and the damage is quiet: the output still looks
        like a Sigma rule, but `description:` continuation lines lose their
        indentation and the document no longer parses. An analyst discovers
        this after pasting it into a console.
        """
        output = self._invoke("hunt", str(capture), "--top", "1", "--no-receipt")
        rules = [block for block in output.split("\n\n") if block.startswith("title:")]
        assert rules, "no Sigma rules in the output"
        for rule in rules:
            assert yaml.safe_load(rule)["detection"]["condition"]

    def test_files_are_written_and_parse(self, capture: Path, tmp_path: Path) -> None:
        out = tmp_path / "rules"
        self._invoke("hunt", str(capture), "--out", str(out), "--no-receipt")
        written = sorted(out.glob("*.yml"))
        assert written, "nothing written"
        for path in written:
            rule = yaml.safe_load(path.read_text())
            assert rule["level"] in _SIGMA_LEVELS
            # The filename is the finding ID, so a rule found in a repository
            # months later still points back at its evidence.
            assert path.stem in rule["description"]

    @pytest.mark.parametrize("dialect", [d.value for d in Dialect])
    def test_every_dialect_runs_from_the_command_line(
        self, capture: Path, dialect: str
    ) -> None:
        output = self._invoke("hunt", str(capture), "-d", dialect, "--top", "1", "--no-receipt")
        assert "fnd_" in output, "every emitted query cites its finding"

    def test_a_missing_path_exits_nonzero(self, tmp_path: Path) -> None:
        from typer.testing import CliRunner

        from voidai.cli import app

        result = CliRunner().invoke(app, ["hunt", str(tmp_path / "nope")])
        assert result.exit_code == 2
