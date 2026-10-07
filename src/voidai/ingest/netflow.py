"""Labelled NetFlow parser (nfdump / Stratosphere dialect).

The CTU-13 corpus and the wider Stratosphere malware captures publish
bidirectional NetFlow exported by nfdump, with a ground-truth `Label` column
appended. That makes them the most useful public source of *real* botnet
command-and-control traffic carrying per-flow labels, and this parser is what
lets VoidLexicon's benchmark run against them rather than only against its own
synthetic corpus.

The format is tab-separated, with two quirks worth knowing. The flow direction
arrow occupies its own column, so the destination endpoint sits at index 5
rather than 4:

    Date flow start   Durat  Prot  Src IP Addr:Port  ->  Dst IP Addr:Port  ...
    2011-08-16 10:01:46.972  4.933  TCP  88.176.79.163:49213  ->  147.32.84.172:18250 ...

And the files were written to line up in a terminal, so a *short* field is
followed by an extra tab: `147.32.80.13:80\t\t->` where a long endpoint gets
one. A run of tabs is therefore one separator. Read positionally, the padded
rows shift every column after the pad — the arrow lands in the destination
column, or the flow count lands in the label column — and the first version of
this parser did exactly that: 29% of scenario 6's rows and 41% of scenario 3's
were misread, including 43% of scenario 6's botnet rows, which lost their
label. Collapsing the runs gives every one of the 17.8 million rows in both
captures exactly twelve fields with the arrow in its column.

Parsing is fully vectorised through Polars — no per-row Python. A row loop
costs about 37k flows/second, which turns the 66-hour CTU-13 scenario into a
ten-minute wait on a desktop and something far worse on a Pi. The columnar
path is roughly twenty times quicker and holds memory flat, which is the
difference between this benchmark being runnable on the target hardware and
being a desktop-only exercise.
"""

from __future__ import annotations

from pathlib import Path

import polars as pl

from voidai.ingest.schema import CONNECTION_SCHEMA, conform, empty

#: Raw column names, positional. The arrow column is read and discarded.
_RAW_COLUMNS = [
    "ts_raw",
    "duration",
    "proto",
    "src_raw",
    "arrow",
    "dst_raw",
    "flags",
    "tos",
    "packets",
    "bytes",
    "flows",
    "label_raw",
]

#: Rightmost colon only — IPv6 endpoints carry colons of their own, and
#: splitting on the first would mangle every one of them.
_ENDPOINT = r"^(.*):([0-9]+)$"

_TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S%.f"

#: IANA-registered start of the modern ephemeral range.
_EPHEMERAL_FLOOR = 32768

LABEL_BOTNET = "botnet"
LABEL_NORMAL = "normal"
LABEL_BACKGROUND = "background"


def normalise_label(column: str) -> pl.Expr:
    """Collapse label dialects to botnet / normal / background.

    Captures in the collection write the same ground truth several ways — a
    bare `Botnet`, or `flow=From-Botnet-V50-TCP-CC`. Matching on the substring
    covers both without a per-capture special case.
    """
    lowered = pl.col(column).str.to_lowercase()
    return (
        pl.when(lowered.str.contains("botnet"))
        .then(pl.lit(LABEL_BOTNET))
        .when(lowered.str.contains("normal"))
        .then(pl.lit(LABEL_NORMAL))
        .otherwise(pl.lit(LABEL_BACKGROUND))
        .alias("label")
    )


def _endpoint(column: str, address_alias: str, port_alias: str) -> list[pl.Expr]:
    """Split `1.2.3.4:443` into address and port columns.

    An endpoint with no port (ICMP flows appear this way) yields the whole
    field as the address and a null port, rather than dropping the record.
    """
    return [
        pl.coalesce(
            pl.col(column).str.extract(_ENDPOINT, 1),
            pl.col(column),
        )
        .str.strip_chars()
        .alias(address_alias),
        pl.col(column)
        .str.extract(_ENDPOINT, 2)
        .cast(pl.Int32, strict=False)
        .alias(port_alias),
    ]


def _client_to_server() -> pl.Expr:
    """Keep only the initiating direction of each conversation.

    NetFlow exports both halves of every connection: `client:52431 -> web:443`
    is followed by `web:443 -> client:52431`. Analysed naively, the response
    half becomes a separate source→destination pair whose "destination port"
    is the client's ephemeral port — and since a client holds that port for the
    life of the conversation, the reverse records form a regular series that
    scores as a textbook beacon. On CTU-13 scenario 6 this manufactured tens of
    false detections on ports like 49375 and 49397.

    A record is dropped only when its destination port is in the modern
    ephemeral range *and* the source port is lower — that is, when it looks
    like a reply to a conversation some other record already describes.

    The obvious rule, "the server is whichever endpoint has the lower port",
    is wrong, and CTU-13 proves it. The scenario 6 bot sources its C2
    connections from ports 1027-4985 — the Windows XP ephemeral range — while
    its controller listens on 5678. Under the lower-port rule the genuine
    command-and-control channel is classified as a reply and silently deleted,
    taking the only true positive in the capture with it. The narrow rule
    below leaves anything below 32768 alone and so cannot make that mistake.

    What it cannot catch is a real service listening above 32768 contacted
    from a lower source port. Those survive as spurious pairs; that is the
    accepted cost of never discarding a real channel.

    Zeek needs none of this: it orients connections at capture time. The
    correction belongs to the parser with the problem, not to the analyzers,
    which should never have to know which sensor produced a record.
    """
    return ~(
        pl.col("dst_port").is_not_null()
        & pl.col("src_port").is_not_null()
        & (pl.col("dst_port") >= _EPHEMERAL_FLOOR)
        & (pl.col("src_port") < pl.col("dst_port"))
    )


def scan_labelled_netflow(path: str | Path, orient: bool = True) -> pl.LazyFrame:
    """Lazily scan a labelled NetFlow capture into the connection schema.

    Returned lazily so callers can project and filter before anything is
    materialised. On the 1.4GB scenario that is the difference between a few
    hundred megabytes of working set and several gigabytes.

    The frame carries an extra `label` column holding ground truth. It is not
    part of CONNECTION_SCHEMA, because it is evaluation metadata rather than
    telemetry: keeping analyzers from ever seeing it is the benchmark's job,
    and `voidai.eval.ctu13` strips it before analysis.

    `orient` drops the response half of each conversation — see
    `_client_to_server`. Disable it only to inspect raw bidirectional records.
    """
    path = Path(path)

    # Each line is read whole and split here rather than by the CSV reader,
    # because a run of tabs is one separator in this format — see the module
    # docstring. `\x1f` never occurs in the files, so it keeps the reader from
    # splitting at all.
    scan = (
        pl.scan_csv(
            path,
            separator="\x1f",
            has_header=False,
            skip_rows=1,  # the header line does not use tab separators throughout
            new_columns=["line"],
            schema_overrides={"line": pl.Utf8},
            quote_char=None,  # log text is not quoted; treating " as a quote breaks rows
            low_memory=True,
        )
        .with_row_index("source_line", offset=2)  # offset past the skipped header
        .with_columns(
            pl.col("line")
            .str.replace_all(r"\t+", "\t")
            .str.splitn("\t", len(_RAW_COLUMNS))
            .struct.rename_fields(_RAW_COLUMNS)
            .alias("fields")
        )
        .unnest("fields")
    )

    parsed = scan.select(
        pl.col("ts_raw")
        .str.strip_chars()
        .str.to_datetime(format=_TIMESTAMP_FORMAT, strict=False)
        .dt.replace_time_zone("UTC")
        .dt.epoch(time_unit="ms")
        .cast(pl.Float64)
        .truediv(1000.0)
        .alias("ts"),
        *_endpoint("src_raw", "src_ip", "src_port"),
        *_endpoint("dst_raw", "dst_ip", "dst_port"),
        pl.col("proto").str.strip_chars().str.to_lowercase().alias("proto"),
        pl.col("duration").cast(pl.Float64, strict=False).alias("duration"),
        # NetFlow reports total bytes for the flow rather than the
        # originator's share. Recorded as orig_bytes because it is the only
        # volume figure available; docs/benchmarks.md records how that
        # weakens the payload-uniformity signal.
        pl.col("bytes").cast(pl.Int64, strict=False).alias("orig_bytes"),
        pl.col("packets").cast(pl.Int64, strict=False).alias("orig_pkts"),
        pl.col("flags").str.strip_chars().alias("conn_state"),
        pl.lit(str(path)).alias("source_file"),
        pl.col("source_line").cast(pl.Int64),
        normalise_label("label_raw"),
    ).filter(pl.col("ts").is_not_null() & pl.col("src_ip").is_not_null())

    if orient:
        parsed = parsed.filter(_client_to_server())

    return parsed


def read_labelled_netflow(path: str | Path, orient: bool = True) -> pl.DataFrame:
    """Read a labelled NetFlow capture in full, conformed to the schema."""
    empty_result = empty(CONNECTION_SCHEMA).with_columns(
        pl.lit(None, dtype=pl.Utf8).alias("label")
    )
    try:
        frame = scan_labelled_netflow(path, orient=orient).collect(engine="streaming")
    except pl.exceptions.NoDataError:
        # A capture with a header and no records. A sensor that produced
        # nothing is a normal condition, not a parse failure.
        return empty_result
    if frame.is_empty():
        return empty_result
    return conform(frame, CONNECTION_SCHEMA).with_columns(frame["label"]).sort("ts")
