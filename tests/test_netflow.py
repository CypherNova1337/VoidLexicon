"""Parser tests for the labelled NetFlow dialect.

The fixture reproduces the exact quirks of the real CTU-13 files: a header
line that does not use tab separators throughout, the direction arrow as its
own column, and the Windows XP ephemeral source ports that broke the first
attempt at flow orientation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from voidai.ingest.netflow import (
    LABEL_BACKGROUND,
    LABEL_BOTNET,
    LABEL_NORMAL,
    read_labelled_netflow,
    scan_labelled_netflow,
)

HEADER = (
    "Date flow start         Durat   Prot    Src IP Addr:Port"
    "                Dst IP Addr:Port\tFlags   Tos     Packets Bytes   Flows   Label Labels\n"
)


def row(ts: str, src: str, dst: str, *, proto="TCP", flags="PA_", pkts=4, size=512, label="Background") -> str:
    return f"{ts}\t0.512\t{proto}\t{src}\t->\t{dst}\t{flags}\t0\t{pkts}\t{size}\t1\t{label}\n"


CAPTURE = HEADER + "".join(
    [
        # A genuine C2 channel: high server port, legacy-range source port.
        row("2011-08-16 10:00:00.100", "147.32.84.165:1027", "91.212.135.158:5678", label="Botnet"),
        row("2011-08-16 10:00:33.400", "147.32.84.165:1031", "91.212.135.158:5678", label="Botnet"),
        # Ordinary browsing, and its reply half.
        row("2011-08-16 10:00:01.000", "147.32.84.59:52431", "93.184.216.34:443", label="Normal"),
        row("2011-08-16 10:00:01.200", "93.184.216.34:443", "147.32.84.59:52431", label="Normal"),
        # ICMP: no ports at all.
        row("2011-08-16 10:00:02.000", "147.32.84.59", "8.8.8.8", proto="ICMP", flags="INT"),
        # A malformed line that must be skipped rather than crash the parse.
        "not a flow record at all\n",
    ]
)


@pytest.fixture
def capture(tmp_path: Path) -> Path:
    path = tmp_path / "capture.netflow.labeled"
    path.write_text(CAPTURE)
    return path


class TestParsing:
    def test_reads_the_expected_records(self, capture: Path) -> None:
        frame = read_labelled_netflow(capture, orient=False)
        assert frame.height == 5  # the malformed line is dropped

    def test_destination_comes_from_index_five_not_four(self, capture: Path) -> None:
        """The direction arrow occupies its own column."""
        frame = read_labelled_netflow(capture, orient=False).sort("ts")
        assert frame["dst_ip"][0] == "91.212.135.158"
        assert frame["dst_port"][0] == 5678

    def test_parses_timestamps_as_utc_epoch(self, capture: Path) -> None:
        frame = read_labelled_netflow(capture, orient=False).sort("ts")
        # 2011-08-16 10:00:00.100 UTC
        assert frame["ts"][0] == pytest.approx(1313488800.1, abs=0.01)

    def test_endpoints_split_on_the_rightmost_colon(self, capture: Path) -> None:
        frame = read_labelled_netflow(capture, orient=False).sort("ts")
        assert frame["src_ip"][0] == "147.32.84.165"
        assert frame["src_port"][0] == 1027

    def test_missing_ports_yield_null_not_a_dropped_row(self, capture: Path) -> None:
        frame = read_labelled_netflow(capture, orient=False)
        icmp = frame.filter(frame["proto"] == "icmp")
        assert icmp.height == 1
        assert icmp["dst_port"][0] is None
        assert icmp["dst_ip"][0] == "8.8.8.8"

    def test_records_true_source_line_numbers(self, capture: Path) -> None:
        frame = read_labelled_netflow(capture, orient=False).sort("ts")
        assert frame["source_line"][0] == 2  # first record follows the header

    def test_empty_file(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.labeled"
        path.write_text(HEADER)
        assert read_labelled_netflow(path).height == 0


#: Verbatim from CTU-13 scenario 6. The files pad a short field with an extra
#: tab so the columns line up in a terminal; these are the infected host's own
#: DNS lookup and its reply, one padded after the destination and one after
#: the source.
PADDED_AFTER_DESTINATION = (
    "2011-08-16 10:02:08.703\t0.000\tUDP\t147.32.84.165:1025\t->\t147.32.80.9:53\t\tINT"
    "\t0\t1\t78\t1\tBotnet\n"
)
PADDED_AFTER_SOURCE = (
    "2011-08-16 10:02:08.871\t0.000\tUDP\t147.32.80.9:53\t\t->\t147.32.84.165:1025\tINT"
    "\t0\t1\t427\t1\tBotnet\n"
)
PADDED_TWICE = (
    "2011-08-16 10:01:47.788\t0.000\tARP\t147.32.87.78\t\t->\t147.32.87.78\t\tINT"
    "\t0\t1\t60\t1\tBackground\n"
)


class TestPaddedColumns:
    """A run of tabs is one separator.

    Read positionally, a padded row shifts every column after the pad. The
    first parser did that to 29% of scenario 6 and 41% of scenario 3 — a
    number landed in every one's label column, and in about half the arrow
    landed in the destination column too — and reported success. Newer
    Polars refuses the file instead.
    """

    @pytest.fixture
    def padded(self, tmp_path: Path) -> Path:
        path = tmp_path / "padded.netflow.labeled"
        path.write_text(HEADER + PADDED_AFTER_DESTINATION + PADDED_AFTER_SOURCE + PADDED_TWICE)
        return path

    def test_every_padded_row_parses(self, padded: Path) -> None:
        assert read_labelled_netflow(padded, orient=False).height == 3

    def test_a_pad_after_the_source_does_not_move_the_arrow_into_the_destination(
        self, padded: Path
    ) -> None:
        frame = read_labelled_netflow(padded, orient=False).sort("source_line")
        assert "->" not in frame["dst_ip"].to_list()
        assert frame["dst_ip"].to_list() == ["147.32.80.9", "147.32.84.165", "147.32.87.78"]
        assert frame["dst_port"].to_list() == [53, 1025, None]

    def test_a_pad_after_the_destination_keeps_the_label_and_the_volume(
        self, padded: Path
    ) -> None:
        """The case that cost ground truth: shifted, the flow count `1` is
        read as the label, and a botnet row is scored as background."""
        frame = read_labelled_netflow(padded, orient=False).sort("source_line")
        assert frame["label"].to_list() == [LABEL_BOTNET, LABEL_BOTNET, LABEL_BACKGROUND]
        assert frame["orig_bytes"].to_list() == [78, 427, 60]
        assert frame["orig_pkts"].to_list() == [1, 1, 1]
        assert frame["conn_state"].to_list() == ["INT", "INT", "INT"]

    def test_padded_and_unpadded_rows_mix_in_one_file(self, tmp_path: Path) -> None:
        """Real captures interleave both shapes line by line."""
        path = tmp_path / "mixed.netflow.labeled"
        path.write_text(
            HEADER
            + row("2011-08-16 10:00:00.100", "147.32.84.165:1027", "91.212.135.158:5678", label="Botnet")
            + PADDED_AFTER_DESTINATION
            + row("2011-08-16 10:00:01.000", "147.32.84.59:52431", "93.184.216.34:443", label="Normal")
            + PADDED_AFTER_SOURCE
        )
        frame = read_labelled_netflow(path, orient=False).sort("source_line")
        assert frame.height == 4
        assert frame["source_line"].to_list() == [2, 3, 4, 5]
        assert frame["dst_ip"].to_list() == [
            "91.212.135.158",
            "147.32.80.9",
            "93.184.216.34",
            "147.32.84.165",
        ]


class TestLabels:
    def test_normalises_the_three_classes(self, capture: Path) -> None:
        labels = set(read_labelled_netflow(capture, orient=False)["label"].to_list())
        assert labels == {LABEL_BOTNET, LABEL_NORMAL, LABEL_BACKGROUND}

    def test_matches_verbose_label_dialects(self, tmp_path: Path) -> None:
        path = tmp_path / "verbose.labeled"
        path.write_text(
            HEADER
            + row("2011-08-16 10:00:00.000", "1.1.1.1:1027", "2.2.2.2:5678",
                  label="flow=From-Botnet-V50-TCP-CC")
        )
        assert read_labelled_netflow(path)["label"].to_list() == [LABEL_BOTNET]

    def test_label_is_absent_from_the_connection_schema(self, capture: Path) -> None:
        """Ground truth must never reach an analyzer as telemetry."""
        from voidai.ingest.schema import CONNECTION_SCHEMA

        assert "label" not in CONNECTION_SCHEMA


class TestOrientation:
    def test_drops_the_reply_half_of_a_conversation(self, capture: Path) -> None:
        oriented = read_labelled_netflow(capture, orient=True)
        pairs = set(zip(oriented["src_ip"].to_list(), oriented["dst_port"].to_list(), strict=True))
        assert ("93.184.216.34", 52431) not in pairs  # the reply
        assert ("147.32.84.59", 443) in pairs  # the request

    def test_keeps_c2_sourced_from_a_legacy_ephemeral_port(self, capture: Path) -> None:
        """The regression CTU-13 exposed.

        The scenario 6 bot sources from ports 1027-4985 to a controller on
        5678. A "server has the lower port" rule deletes exactly that channel.
        """
        oriented = read_labelled_netflow(capture, orient=True)
        c2 = oriented.filter(oriented["dst_ip"] == "91.212.135.158")
        assert c2.height == 2

    def test_keeps_flows_without_ports(self, capture: Path) -> None:
        oriented = read_labelled_netflow(capture, orient=True)
        assert oriented.filter(oriented["proto"] == "icmp").height == 1

    def test_orientation_can_be_disabled(self, capture: Path) -> None:
        assert read_labelled_netflow(capture, orient=False).height > read_labelled_netflow(
            capture, orient=True
        ).height


class TestLaziness:
    def test_scan_returns_a_lazyframe(self, capture: Path) -> None:
        """Projection must be pushed down, not applied after materialising."""
        import polars as pl

        assert isinstance(scan_labelled_netflow(capture), pl.LazyFrame)
