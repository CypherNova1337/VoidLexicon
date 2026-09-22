"""Synthetic telemetry with ground truth.

Public labelled beaconing corpora barely exist, and the ones that do are
small, stale, and mostly unencrypted. So VoidLexicon generates its own: a
reproducible network of benign traffic with implants planted in known places,
seeded so that any reviewer can regenerate the exact corpus a benchmark ran on.

The generator is deliberately adversarial toward VoidLexicon. Benign traffic
includes the categories that produce false positives in every published
beaconing detector:

  * monitoring agents polling on a fixed schedule with variable payloads
  * software update checks — periodic, low-volume, long-lived
  * chatty API clients whose arrivals are regular but bursty

and the implants include a low-and-slow profile with 50% jitter that any
naive MAD threshold will miss. A detector that scores well here has earned it.

Synthetic data proves the mathematics, not the product. It is a floor under
the benchmark, and `docs/benchmarks.md` reports real-capture results
alongside it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import ClassVar

import numpy as np
import polars as pl

from voidai.ingest.schema import (
    CONNECTION_SCHEMA,
    DNS_SCHEMA,
    PROCESS_SCHEMA,
    SSL_SCHEMA,
    conform,
)

_ZEEK_CONN_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "proto",
    "service",
    "duration",
    "orig_bytes",
    "resp_bytes",
    "conn_state",
]


@dataclass(frozen=True)
class Implant:
    """A planted beacon, and the label a detector is scored against."""

    src_ip: str
    dst_ip: str
    dst_port: int
    period_seconds: float
    jitter_fraction: float
    payload_bytes: int
    label: str
    #: "symmetric" for uniform jitter either side of the period; "scheduled"
    #: for the hard-floor, right-tailed shape real captures exhibit.
    jitter_model: str = "symmetric"

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.src_ip, self.dst_ip, self.dst_port)


@dataclass
class Corpus:
    """Generated telemetry plus the ground truth needed to score against it."""

    connections: pl.DataFrame
    implants: list[Implant]
    benign_pairs: set[tuple[str, str, int]] = field(default_factory=set)

    @property
    def implant_keys(self) -> set[tuple[str, str, int]]:
        return {i.key for i in self.implants}

    def write_zeek_conn_log(self, path: str | Path) -> Path:
        """Serialise to Zeek TSV so the real parser is exercised end to end.

        Tests that build a DataFrame directly would never catch a parser
        regression, so the benchmark writes a genuine log and reads it back.
        """
        return write_zeek_conn_log(self.connections, path)


def write_zeek_conn_log(connections: pl.DataFrame, path: str | Path) -> Path:
    """Write a connection frame as a Zeek `conn.log`.

    A free function because more than one corpus needs it and none of them
    should own it. Every generated corpus goes to disk in the sensor's real
    format and comes back through the production parser, so a benchmark
    cannot pass over data the parser could not have produced.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    frame = connections.sort("ts")
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tconn",
        "#fields\t" + "\t".join(_ZEEK_CONN_FIELDS),
        "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tinterval\tcount\tcount\tstring",
    ]

    rows = []
    for r in frame.iter_rows(named=True):
        rows.append(
            "\t".join(
                [
                    f"{r['ts']:.6f}",
                    r["uid"] or "-",
                    r["src_ip"],
                    str(r["src_port"]),
                    r["dst_ip"],
                    str(r["dst_port"]),
                    r["proto"] or "tcp",
                    r["service"] or "-",
                    f"{r['duration']:.6f}" if r["duration"] is not None else "-",
                    str(r["orig_bytes"]) if r["orig_bytes"] is not None else "-",
                    str(r["resp_bytes"]) if r["resp_bytes"] is not None else "-",
                    r["conn_state"] or "SF",
                ]
            )
        )

    path.write_text("\n".join(header + rows) + "\n")
    return path


class CorpusGenerator:
    """Builds a labelled network capture from a seed."""

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)
        self._uid = 0

    def _next_uid(self) -> str:
        self._uid += 1
        return f"C{self._uid:08x}"

    def _browsing(self, duration: float, sessions: int) -> np.ndarray:
        """Bursty human browsing: idle gaps punctuated by clusters of requests."""
        starts = self.rng.uniform(0, duration, size=sessions)
        timestamps: list[np.ndarray] = []
        for start in starts:
            count = int(self.rng.integers(4, 40))
            # Within a session, arrivals are exponential with a short mean.
            offsets = np.cumsum(self.rng.exponential(2.5, size=count))
            timestamps.append(start + offsets)
        if not timestamps:
            return np.array([])
        return np.sort(np.concatenate(timestamps))

    def _scheduled(
        self,
        duration: float,
        period: float,
        jitter: float,
        miss_rate: float = 0.03,
    ) -> np.ndarray:
        """Arrivals from a real implant: a hard floor with a right tail.

        Modelled on the CTU-13 Menti channel, whose observed intervals sit at
        q1=33.0s, q2=33.3s, q3=42.4s — an extremely tight lower edge with a
        long tail running out to five times the base period.

        The shape follows from how implants actually work. A beacon told to
        sleep thirty seconds cannot wake in twenty; scheduler slack, network
        latency and a dropped check-in only ever push the next arrival later.
        The symmetric `uniform(+/-jitter)` model in `_periodic` cannot produce
        that asymmetry, and a detector validated only against it learns a
        property of the generator rather than a property of malware.
        """
        timestamps: list[float] = []
        t = 0.0
        while t < duration:
            timestamps.append(t)
            t += period * (1.0 + abs(self.rng.normal(0.0, jitter)))
            if self.rng.random() < miss_rate:
                t += period  # a missed check-in doubles the gap
        return np.array(timestamps)

    def _periodic(self, duration: float, period: float, jitter: float) -> np.ndarray:
        """Regular arrivals with symmetric uniform jitter.

        Kept alongside `_scheduled` deliberately: some implant families do
        jitter symmetrically, and the detector has to handle both shapes.
        """
        count = max(int(duration / period), 1)
        base = np.arange(count) * period
        if jitter > 0:
            base = base + self.rng.uniform(-jitter * period, jitter * period, size=count)
        base = base[(base >= 0) & (base < duration)]
        return np.sort(base)

    def _rows(
        self,
        timestamps: np.ndarray,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        sizes: np.ndarray,
        service: str,
        start_epoch: float,
    ) -> list[dict[str, object]]:
        rows = []
        for ts, size in zip(timestamps, sizes, strict=True):
            rows.append(
                {
                    "ts": start_epoch + float(ts),
                    "uid": self._next_uid(),
                    "src_ip": src_ip,
                    "src_port": int(self.rng.integers(32768, 60999)),
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "proto": "tcp",
                    "service": service,
                    "duration": float(abs(self.rng.normal(0.4, 0.2))),
                    "orig_bytes": int(max(size, 0)),
                    "resp_bytes": int(max(size * self.rng.uniform(1.5, 8.0), 0)),
                    "orig_pkts": int(max(size // 500 + 2, 2)),
                    "resp_pkts": int(max(size // 300 + 2, 2)),
                    "conn_state": "SF",
                    "source_file": "<synthetic>",
                    "source_line": 0,
                }
            )
        return rows

    def generate(
        self,
        hours: float = 24.0,
        benign_hosts: int = 12,
        start_epoch: float = 1_750_000_000.0,
    ) -> Corpus:
        duration = hours * 3600
        rows: list[dict[str, object]] = []
        benign_pairs: set[tuple[str, str, int]] = set()

        # Benign: human browsing
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            for site_index in range(int(self.rng.integers(3, 8))):
                dst = f"93.184.{site_index}.{self.rng.integers(1, 250)}"
                timestamps = self._browsing(duration, sessions=int(self.rng.integers(6, 25)))
                if timestamps.size == 0:
                    continue
                # Heavy-tailed request sizes — the opposite of a beacon.
                sizes = self.rng.lognormal(6.2, 1.4, size=timestamps.size)
                rows += self._rows(timestamps, src, dst, 443, sizes, "ssl", start_epoch)
                benign_pairs.add((src, dst, 443))

        # Benign: monitoring agent (periodic, variable payload)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "10.0.0.50"
            timestamps = self._periodic(duration, period=60.0, jitter=0.05)
            # Regular schedule, but the payload carries live metrics and varies
            # widely. This is the classic beaconing false positive.
            sizes = self.rng.lognormal(7.0, 0.9, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 9100, sizes, "http", start_epoch)
            benign_pairs.add((src, dst, 9100))

        # Benign: software update check (periodic, uniform, sparse)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "151.101.1.55"
            timestamps = self._periodic(duration, period=3600.0, jitter=0.35)
            sizes = self.rng.normal(820, 120, size=timestamps.size)
            rows += self._rows(timestamps, src, dst, 443, sizes, "ssl", start_epoch)
            benign_pairs.add((src, dst, 443))

        # Benign: NTP (regular, uniform — suppressed by port)
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            dst = "216.239.35.0"
            timestamps = self._periodic(duration, period=64.0, jitter=0.02)
            sizes = np.full(timestamps.size, 76.0)
            rows += self._rows(timestamps, src, dst, 123, sizes, "ntp", start_epoch)
            benign_pairs.add((src, dst, 123))

        # Malicious: implants
        implants = [
            Implant("10.0.1.14", "45.83.220.17", 443, 60.0, 0.00, 512, "textbook-60s"),
            Implant("10.0.1.17", "185.220.101.9", 8443, 300.0, 0.10, 1024, "jittered-5m"),
            Implant("10.0.1.11", "141.98.11.4", 443, 900.0, 0.25, 380, "jittered-15m"),
            Implant("10.0.1.19", "194.26.29.87", 80, 1800.0, 0.50, 256, "low-and-slow-30m"),
            Implant(
                "10.0.1.13", "45.129.14.22", 443, 33.0, 0.18, 640,
                "scheduled-33s-menti-like", jitter_model="scheduled",
            ),
            Implant(
                "10.0.1.16", "179.43.160.8", 8080, 600.0, 0.30, 900,
                "scheduled-10m", jitter_model="scheduled",
            ),
        ]
        for implant in implants:
            timestamps = (
                self._scheduled(duration, implant.period_seconds, implant.jitter_fraction)
                if implant.jitter_model == "scheduled"
                else self._periodic(
                    duration, implant.period_seconds, implant.jitter_fraction
                )
            )
            # Check-in payloads vary only slightly: a task poll plus framing.
            sizes = self.rng.normal(implant.payload_bytes, implant.payload_bytes * 0.06, size=timestamps.size)
            rows += self._rows(
                timestamps,
                implant.src_ip,
                implant.dst_ip,
                implant.dst_port,
                sizes,
                "ssl" if implant.dst_port != 80 else "http",
                start_epoch,
            )

        frame = conform(pl.DataFrame(rows), CONNECTION_SCHEMA).sort("ts")
        # Assign line numbers matching the order they will be written out in.
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return Corpus(connections=frame, implants=implants, benign_pairs=benign_pairs)




@dataclass(frozen=True)
class Transfer:
    """A planted exfiltration, and the label a detector is scored against."""

    src_ip: str
    dst_ip: str
    dst_port: int
    total_bytes: int
    flows: int
    #: Fraction of the capture elapsed before the first flow to this
    #: destination. The novelty signal is measured against exactly this.
    starts_at: float
    label: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.dst_ip)


@dataclass
class EgressCorpus:
    """Generated transfer telemetry plus the ground truth needed to score it."""

    connections: pl.DataFrame
    transfers: list[Transfer]
    #: Benign destinations that are *meant* to be hard, keyed the same way, so
    #: a scoring run can name which decoy it fell for rather than reporting an
    #: anonymous false positive.
    decoys: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def transfer_keys(self) -> set[tuple[str, str]]:
        return {t.key for t in self.transfers}

    def write_zeek_conn_log(self, path: str | Path) -> Path:
        return write_zeek_conn_log(self.connections, path)


class EgressCorpusGenerator:
    """Builds labelled bulk-transfer traffic from a seed.

    Separate from `CorpusGenerator` rather than folded into it. That generator
    and its seed back the published beaconing figures in `docs/benchmarks.md`,
    and quietly adding traffic to it would invalidate results the same
    document calls reproducible. `DnsCorpusGenerator` set the precedent.

    Adversarial by design. The benign traffic here is not filler — it is the
    four categories that break volume detectors, and three of them are
    *indistinguishable from exfiltration* on volume and direction alone:

      * a nightly backup: enormous, almost entirely outbound, on a schedule
      * a cloud sync: large, outbound, and reached by the whole estate
      * a software mirror: large, but inbound, which is the one thing
        exfiltration never is
      * a lone backup target used by exactly one host, which is the case
        estate-wide rarity cannot help with and which is left in deliberately

    A detector that clears the first three has separated *where the bytes went
    and to whom* from *how many there were*, which is the whole difficulty.
    The fourth is here to be reported, not to be passed — see
    `docs/benchmarks.md`.
    """

    #: Reached by every host in the estate, and reached from the first hour.
    _BACKUP = "10.0.2.60"
    _CLOUD_SYNC = "52.216.10.5"
    _MIRROR = "151.101.1.55"
    _MAIL = "10.0.2.25"
    #: Reached by one host only. Rarity says "unique", novelty says "always
    #: been there", and only the second is right.
    _LONE_BACKUP = "10.0.2.61"

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)
        self._uid = 0

    def _next_uid(self) -> str:
        self._uid += 1
        return f"E{self._uid:08x}"

    def _flows(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamps: np.ndarray,
        orig_bytes: np.ndarray,
        resp_bytes: np.ndarray,
        service: str,
        start_epoch: float,
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + float(ts),
                "uid": self._next_uid(),
                "src_ip": src_ip,
                "src_port": int(self.rng.integers(32768, 60999)),
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": "tcp",
                "service": service,
                "duration": float(abs(self.rng.normal(2.0, 0.8))),
                "orig_bytes": int(max(out, 0)),
                "resp_bytes": int(max(back, 0)),
                "orig_pkts": int(max(out // 1400 + 2, 2)),
                "resp_pkts": int(max(back // 1400 + 2, 2)),
                "conn_state": "SF",
                "source_file": "<synthetic>",
                "source_line": 0,
            }
            for ts, out, back in zip(timestamps, orig_bytes, resp_bytes, strict=True)
        ]

    def _spread(self, duration: float, count: int, start: float = 0.0) -> np.ndarray:
        """`count` arrivals scattered over the window from `start` onward."""
        span = max(duration * (1.0 - start), 1.0)
        return np.sort(duration * start + self.rng.uniform(0.0, span, size=count))

    def _regular(self, duration: float, count: int, start: float) -> np.ndarray:
        """`count` arrivals on a fixed cadence, the first at `start` exactly.

        Backups, syncs and mirror pulls run on a timer, and where the first
        one lands is not a coin toss. It matters because it is precisely what
        the novelty signal measures: a scheduled job is already running when
        the sensor starts recording, and scattering its first arrival
        somewhere random inside the window would hand the detector a
        different — and easier — problem on every seed.
        """
        first = duration * start
        return np.linspace(first, duration, num=count, endpoint=False)

    def generate(
        self,
        hours: float = 24.0,
        benign_hosts: int = 12,
        start_epoch: float = 1_760_000_000.0,
    ) -> EgressCorpus:
        duration = hours * 3600
        rows: list[dict[str, object]] = []
        decoys: dict[tuple[str, str], str] = {}
        hosts = [f"10.0.2.{index + 10}" for index in range(benign_hosts)]

        for host in hosts:
            # Browsing: many small conversations, and inbound-heavy, because
            # a page is pulled. Six of them, so every host has a baseline
            # wide enough for a robust deviation to mean something.
            for site in range(6):
                dst = f"93.184.{site}.{self.rng.integers(1, 250)}"
                count = int(self.rng.integers(60, 200))
                timestamps = self._spread(duration, count)
                out = self.rng.lognormal(6.6, 0.8, size=count)
                rows += self._flows(
                    host, dst, 443, timestamps, out, out * self.rng.uniform(6.0, 30.0, size=count),
                    "ssl", start_epoch,
                )

            # Nightly backup: the hardest benign case on volume and direction.
            timestamps = self._regular(duration, 24, start=0.02)
            out = self.rng.normal(90_000_000, 6_000_000, size=24)
            rows += self._flows(
                host, self._BACKUP, 22, timestamps, out, out * 0.002, "ssh", start_epoch
            )
            decoys[(host, self._BACKUP)] = "nightly-backup"

            # Cloud sync: outbound, large, and reached by the whole estate.
            timestamps = self._regular(duration, 140, start=0.015)
            out = self.rng.lognormal(14.4, 0.7, size=140)
            rows += self._flows(
                host, self._CLOUD_SYNC, 443, timestamps, out, out * 0.01, "ssl", start_epoch
            )
            decoys[(host, self._CLOUD_SYNC)] = "cloud-sync"

            # Software mirror: just as much volume, travelling the other way.
            timestamps = self._regular(duration, 20, start=0.03)
            back = self.rng.normal(120_000_000, 20_000_000, size=20)
            rows += self._flows(
                host, self._MIRROR, 443, timestamps, back * 0.002, back, "ssl", start_epoch
            )
            decoys[(host, self._MIRROR)] = "software-mirror"

            # Mail: modest, outbound, unremarkable.
            timestamps = self._spread(duration, 90)
            out = self.rng.lognormal(11.0, 0.9, size=90)
            rows += self._flows(
                host, self._MAIL, 25, timestamps, out, out * 0.01, "smtp", start_epoch
            )

        # One host keeps its own backup target. Nothing else in the estate
        # touches it, so estate-wide rarity scores it 1.0 — the one benign
        # shape rarity cannot defend against.
        lone = hosts[3]
        timestamps = self._regular(duration, 24, start=0.02)
        out = self.rng.normal(70_000_000, 5_000_000, size=24)
        rows += self._flows(
            lone, self._LONE_BACKUP, 22, timestamps, out, out * 0.002, "ssh", start_epoch
        )
        decoys[(lone, self._LONE_BACKUP)] = "lone-host-backup"

        # Planted exfiltration. Each is on a host that also browses, backs up
        # and syncs, so its baseline and its observation window are those of
        # an ordinary machine rather than of a machine that only exfiltrates.
        transfers = [
            Transfer(hosts[0], "45.83.220.17", 443, 800_000_000, 3, 0.70, "bulk-single-archive"),
            Transfer(hosts[5], "185.220.101.9", 8443, 600_000_000, 120, 0.40, "staged-chunked"),
            Transfer(hosts[9], "141.98.11.4", 443, 12_000_000, 40, 0.55, "slow-and-small"),
            # Below the byte floor for a volume claim, so the strongest thing
            # sayable about it is that something went somewhere rare. It is
            # here to exercise that band, and to prove the band is reachable
            # by something other than noise.
            Transfer(hosts[2], "179.43.160.8", 443, 600_000, 25, 0.62, "trickle-upload"),
        ]
        for transfer in transfers:
            timestamps = self._spread(duration, transfer.flows, start=transfer.starts_at)
            share = self.rng.dirichlet(np.full(transfer.flows, 6.0))
            out = share * transfer.total_bytes
            rows += self._flows(
                transfer.src_ip,
                transfer.dst_ip,
                transfer.dst_port,
                timestamps,
                out,
                out * self.rng.uniform(0.004, 0.02, size=transfer.flows),
                "ssl",
                start_epoch,
            )

        frame = conform(pl.DataFrame(rows), CONNECTION_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return EgressCorpus(connections=frame, transfers=transfers, decoys=decoys)


_BASE32 = "abcdefghijklmnopqrstuvwxyz234567"
_WORDS = ["www", "api", "cdn", "static", "assets", "mail", "smtp", "imap", "login", "auth", "account", "portal", "shop", "news", "blog", "media", "images", "video", "docs", "help", "support", "status", "admin", "dev", "stage", "prod", "eu", "us", "asia", "edge", "node", "cluster", "db", "cache", "queue", "search", "maps", "drive"]


@dataclass(frozen=True)
class DnsTunnel:
    """A planted DNS tunnel, and the label a detector is scored against."""

    src_ip: str
    zone: str
    label: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.zone)


@dataclass
class DnsCorpus:
    """Generated DNS telemetry plus its ground truth."""

    queries: pl.DataFrame
    tunnels: list[DnsTunnel]
    benign_zones: set[tuple[str, str]] = field(default_factory=set)

    @property
    def tunnel_keys(self) -> set[tuple[str, str]]:
        return {t.key for t in self.tunnels}


class DnsCorpusGenerator:
    """Builds labelled DNS traffic from a seed.

    Adversarial by design. The benign traffic includes the two categories that
    break naive entropy detectors:

      * content delivery networks, which mint thousands of subdomains
      * reputation and blocklist lookups, which encode hashes and reversed
        addresses into subdomains and are tunnel-shaped by every measure
        except entropy

    A detector that clears this corpus has separated encoding from mere
    cardinality, which is the whole difficulty.
    """

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)

    def _encoded(self, length: int) -> str:
        return "".join(self.rng.choice(list(_BASE32), size=length))

    def _hexed(self, length: int) -> str:
        return "".join(self.rng.choice(list("0123456789abcdef"), size=length))

    def _rows(
        self,
        src_ip: str,
        names: list[str],
        qtype: str,
        start_epoch: float,
        interval: float,
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + index * interval,
                "uid": f"D{index:08x}",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.53",
                "query": name,
                "qtype": qtype,
                "rcode": "NOERROR",
                "answers": "",
                "source_file": "<synthetic>",
                "source_line": index + 1,
            }
            for index, name in enumerate(names)
        ]

    def generate(
        self,
        hours: float = 6.0,
        benign_hosts: int = 10,
        start_epoch: float = 1_750_000_000.0,
    ) -> DnsCorpus:
        rows: list[dict[str, object]] = []
        benign: set[tuple[str, str]] = set()

        # Benign: ordinary lookups, low cardinality, natural names
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"{self.rng.choice(_WORDS)}.{self.rng.choice(['example', 'acme', 'globex'])}.com"
                for _ in range(int(self.rng.integers(80, 200)))
            ]
            rows += self._rows(src, names, "A", start_epoch, 11.0)
            benign.add((src, "example.com"))

        # Benign: a CDN — very high cardinality, structured names
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                f"e{self.rng.integers(1000, 99999)}-{self.rng.integers(1, 40)}"
                f".dscx.akamaiedge.net"
                for _ in range(300)
            ]
            rows += self._rows(src, names, "A", start_epoch, 7.0)
            benign.add((src, "akamaiedge.net"))

        # Benign: reputation lookups — encoded, but hex, not base32
        # The hardest benign case: high cardinality, long names, structured
        # payload in the subdomain. Only entropy separates it from a tunnel.
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [f"{self._hexed(32)}.avqs.reputation-example.net" for _ in range(250)]
            rows += self._rows(src, names, "A", start_epoch, 9.0)
            benign.add((src, "reputation-example.net"))

        # Benign: DNSBL — reversed addresses, numeric, long
        for host_index in range(benign_hosts):
            src = f"10.0.1.{host_index + 10}"
            names = [
                ".".join(str(self.rng.integers(1, 254)) for _ in range(4)) + ".zen.blocklist-example.org"
                for _ in range(200)
            ]
            rows += self._rows(src, names, "A", start_epoch, 13.0)
            benign.add((src, "blocklist-example.org"))

        # Malicious: tunnels
        tunnels = [
            DnsTunnel("10.0.1.21", "tunnel-example.com", "iodine-like-long-txt"),
            DnsTunnel("10.0.1.22", "c2-example.net", "dnscat2-like-a-records"),
            DnsTunnel("10.0.1.23", "exfil-example.org", "chunked-multi-label"),
        ]

        # iodine: long single label, TXT for return capacity
        rows += self._rows(
            tunnels[0].src_ip,
            [f"{self._encoded(58)}.{tunnels[0].zone}" for _ in range(600)],
            "TXT",
            start_epoch,
            3.0,
        )
        # dnscat2 in A-record mode: no qtype tell at all
        rows += self._rows(
            tunnels[1].src_ip,
            [f"{self._encoded(40)}.{tunnels[1].zone}" for _ in range(450)],
            "A",
            start_epoch,
            4.0,
        )
        # payload chunked across several labels
        rows += self._rows(
            tunnels[2].src_ip,
            [
                f"{self._encoded(20)}.{self._encoded(20)}.{self._encoded(18)}.{tunnels[2].zone}"
                for _ in range(380)
            ],
            "CNAME",
            start_epoch,
            5.0,
        )

        frame = conform(pl.DataFrame(rows), DNS_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return DnsCorpus(queries=frame, tunnels=tunnels, benign_zones=benign)



#: Brand-shaped second-level labels for benign DNS. Written independently of
#: `analyzers/ngrams.WORDS`, and only partly overlapping it: a benign corpus
#: built entirely from the character model's own vocabulary would be scored by
#: that model as trivially natural, and the resulting specificity figure would
#: describe the overlap rather than the detector.
_BENIGN_LABELS = (
    "northwind", "brightpath", "quicksilver", "cedarline", "harborview",
    "silverleaf", "ironbridge", "bluewater", "stonegate", "redwoodhill",
    "lightfield", "thornbury", "greenmeadow", "whitestone", "amberglass",
    "copperfield", "marblearch", "willowbrook", "foxglove", "hazelwood",
    "clearsprings", "eastgate", "fairhaven", "goldencrest", "highpoint",
    "junipertree", "kingsferry", "lakeshore", "maplegrove", "oakhollow",
    "pinecrest", "riverbend", "sandpiper", "tallgrass", "underhill",
    "valleyforge", "westbrook", "yellowstone", "ashgrove", "bellhaven",
)

#: Consonant-heavy, abbreviation-shaped labels that are entirely legitimate.
#: The decoy class the real fixture supplied — `crwdcntrl`, `msftncsi` — and
#: the one a structure signal alone will fall for.
_ABBREVIATED_LABELS = (
    "cdnmtrcs", "trckngsvc", "wbmtrx", "sftwrdst", "ntwrkstat",
    "clddstrb", "ndpntsvc", "prtlgtwy", "sysmntrng", "tlmtrysvc",
    "dgtlcrtfy", "scrtygwy", "bckpstrge", "mnthstsvc", "prfmnctrk",
)

_PATIENT_ZERO = "10.0.1.14"

#: The same machine, named. Host telemetry has no IP to key on — Sysmon event
#: ID 1 records a computer name and nothing else — so without an inventory the
#: demo's compromised host appears in the queue twice: once as `ip:10.0.1.14`
#: for everything the network sensors saw, and once as `host:FINANCE-WS04` for
#: what the endpoint agent saw. The capture ships the one mapping that joins
#: them; see `_write_demo_inventory` below and `docs/inventory.md`.
_PATIENT_ZERO_HOST = "FINANCE-WS04"


@dataclass(frozen=True)
class DgaFamily:
    """A planted domain-generation family, and the label it is scored against."""

    src_ip: str
    suffix: str
    #: Every registered domain the family minted. Scoring matches on any of
    #: them: a detector that names three of two hundred generated domains has
    #: found the family, and demanding a particular one would measure which
    #: exemplars the cap happened to keep.
    domains: frozenset[str]
    label: str
    #: Whether this family is expected to be found. `suppobox`-style
    #: dictionary generators are planted deliberately and are a known miss —
    #: see `analyzers/ngrams.py`. Recording the expectation in the corpus
    #: keeps it a *measured* limitation rather than a surprise.
    detectable: bool = True


@dataclass
class DgaCorpus:
    """Generated DNS telemetry with domain-generation families planted in it."""

    queries: pl.DataFrame
    families: list[DgaFamily]
    #: (src_ip, registered domain) -> what the decoy is, for naming a false
    #: positive rather than merely counting it.
    decoys: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def detectable_families(self) -> list[DgaFamily]:
        return [f for f in self.families if f.detectable]

    def family_of(self, src_ip: str, domain: str) -> DgaFamily | None:
        for family in self.families:
            if family.src_ip == src_ip and domain in family.domains:
                return family
        return None


class DgaCorpusGenerator:
    """Builds labelled DNS traffic containing domain-generation families.

    Adversarial in three directions, each of which defeats one of the three
    components on its own:

      * **a host with a broken search suffix** — a high NXDOMAIN rate over
        entirely ordinary names. Defeats `nxdomain_rate` alone.
      * **consonant-heavy abbreviations** — `crwdcntrl`-shaped names that
        resolve perfectly well. Defeats `structure` alone, and is the class
        the real fixture actually contains.
      * **a dictionary generator** — a real DGA family whose names are more
        English than English. Defeats `bigram_improbability`, and is planted
        as an expected miss rather than quietly omitted.

    And one that defeats the *grouping*: the alphanumeric family generates
    under `.com`, the same suffix its host browses, so its NXDOMAIN rate is
    diluted by ordinary traffic exactly as it would be in a real estate.
    """

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)

    def _pick(self, alphabet: str, length: int) -> str:
        return "".join(self.rng.choice(list(alphabet), size=length))

    def _rows(
        self,
        src_ip: str,
        names: list[str],
        start_epoch: float,
        interval: float,
        rcodes: list[str] | None = None,
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + index * interval,
                "uid": f"G{index:08x}",
                "src_ip": src_ip,
                "dst_ip": "10.0.0.53",
                "query": name,
                "qtype": "A",
                "rcode": "NOERROR" if rcodes is None else rcodes[index],
                "answers": "",
                "source_file": "<synthetic>",
                "source_line": index + 1,
            }
            for index, name in enumerate(names)
        ]

    def _browsing(self, src_ip: str, count: int, suffix: str = "com") -> list[str]:
        """Ordinary lookups: brand-shaped labels, repeated as a person repeats."""
        labels = self.rng.choice(_BENIGN_LABELS, size=min(count, len(_BENIGN_LABELS)), replace=False)
        names = [f"{label}.{suffix}" for label in labels]
        # Revisits: browsing returns to the same names, generation does not.
        return names + [str(self.rng.choice(names)) for _ in range(count)]

    def generate(
        self,
        hours: float = 6.0,
        benign_hosts: int = 8,
        start_epoch: float = 1_750_000_000.0,
    ) -> DgaCorpus:
        rows: list[dict[str, object]] = []
        decoys: dict[tuple[str, str], str] = {}

        # Benign: ordinary browsing, almost everything resolving.
        for index in range(benign_hosts):
            src = f"10.0.2.{index + 10}"
            names = self._browsing(src, 40)
            codes = ["NOERROR"] * len(names)
            # A few typos, as any real host produces.
            for position in self.rng.choice(len(names), size=3, replace=False):
                codes[int(position)] = "NXDOMAIN"
            rows += self._rows(src, names, start_epoch, 9.0, codes)
            for name in set(names):
                decoys[(src, name)] = "ordinary browsing"

        # Decoy: a host with a misconfigured DNS search suffix. Every name is
        # ordinary; two thirds of them fail. High NXDOMAIN, natural labels.
        broken = "10.0.2.90"
        names = self._browsing(broken, 40, suffix="net")
        codes = ["NXDOMAIN" if self.rng.random() < 0.66 else "NOERROR" for _ in names]
        rows += self._rows(broken, names, start_epoch, 7.0, codes)
        for name in set(names):
            decoys[(broken, name)] = "broken search suffix"

        # Decoy: consonant-heavy service abbreviations, all resolving.
        abbreviated = "10.0.2.91"
        names = [f"{label}.{tld}" for label in _ABBREVIATED_LABELS for tld in ("com", "net")]
        names += [str(self.rng.choice(names)) for _ in range(60)]
        rows += self._rows(abbreviated, names, start_epoch, 11.0, ["NOERROR"] * len(names))
        for name in set(names):
            decoys[(abbreviated, name)] = "consonant-heavy abbreviation"

        families: list[DgaFamily] = []

        # Conficker-shaped: random lowercase, minority resolving.
        alpha_host = "10.0.2.31"
        alpha = [f"{self._pick('abcdefghijklmnopqrstuvwxyz', int(self.rng.integers(9, 13)))}.biz"
                 for _ in range(180)]
        codes = ["NXDOMAIN"] * len(alpha)
        codes[42] = "NOERROR"  # the one the operator registered
        rows += self._rows(alpha_host, alpha, start_epoch, 5.0, codes)
        families.append(DgaFamily(alpha_host, "biz", frozenset(alpha), "random-alphabetic"))

        # Alphanumeric, generating under the suffix its host also browses, so
        # the family's NXDOMAIN rate is diluted by ordinary traffic.
        mixed_host = "10.0.2.32"
        benign_names = self._browsing(mixed_host, 40)
        rows += self._rows(mixed_host, benign_names, start_epoch, 13.0, ["NOERROR"] * len(benign_names))
        for name in set(benign_names):
            decoys[(mixed_host, name)] = "ordinary browsing beside a DGA"
        mixed = [f"{self._pick('abcdefghijklmnopqrstuvwxyz0123456789', int(self.rng.integers(12, 18)))}.com"
                 for _ in range(200)]
        codes = ["NXDOMAIN"] * len(mixed)
        codes[7] = "NOERROR"
        rows += self._rows(mixed_host, mixed, start_epoch + 1.0, 6.0, codes)
        families.append(DgaFamily(mixed_host, "com", frozenset(mixed), "alphanumeric-under-browsed-suffix"))

        # Hex-encoded: the shape per-character entropy scores as *more*
        # natural than English, and the character model scores highest.
        hex_host = "10.0.2.33"
        hexed = [f"{self._pick('0123456789abcdef', 16)}.net" for _ in range(150)]
        codes = ["NXDOMAIN"] * len(hexed)
        codes[91] = "NOERROR"
        rows += self._rows(hex_host, hexed, start_epoch, 8.0, codes)
        families.append(DgaFamily(hex_host, "net", frozenset(hexed), "hex-encoded"))

        # Dictionary generator: a real family, and an expected miss.
        word_host = "10.0.2.34"
        worded = [
            f"{self.rng.choice(_BENIGN_LABELS)}{self.rng.choice(_BENIGN_LABELS)}.org"
            for _ in range(160)
        ]
        codes = ["NXDOMAIN"] * len(worded)
        codes[3] = "NOERROR"
        rows += self._rows(word_host, worded, start_epoch, 10.0, codes)
        families.append(
            DgaFamily(word_host, "org", frozenset(worded), "dictionary-concatenation", detectable=False)
        )

        frame = conform(pl.DataFrame(rows), DNS_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return DgaCorpus(queries=frame, families=families, decoys=decoys)


@dataclass(frozen=True)
class RareClient:
    """A planted TLS client whose fingerprint nothing else in the estate uses."""

    src_ip: str
    ja3: str
    label: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.src_ip, self.ja3)


@dataclass
class TlsCorpus:
    """Generated TLS session telemetry plus its ground truth."""

    sessions: pl.DataFrame
    clients: list[RareClient]
    decoys: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def client_keys(self) -> set[tuple[str, str]]:
        return {c.key for c in self.clients}


class TlsCorpusGenerator:
    """Builds labelled TLS sessions from a seed.

    The decoys are the two ways a prevalence measure goes wrong. A fingerprint
    seen **once** is a truncated handshake rather than a client the host runs,
    and a fingerprint shared by a **handful** of hosts is a minority browser
    build rather than an implant. Both are rare by the raw measure and neither
    should reach the queue on its own.
    """

    #: Fingerprint-shaped hex, fixed rather than generated: a JA3 is an MD5 of
    #: the ClientHello and the analyzer never parses it, so a stable literal
    #: keeps the corpus readable in a failure message.
    COMMON = (
        "e7d705a3286e19ea42f587b344ee6865",
        "6734f37431670b3ab4292b8f60f29984",
        "a0e9f5d64349fb13191bc781f81f42e1",
    )

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)

    def _sessions(
        self,
        src_ip: str,
        ja3: str,
        count: int,
        start_epoch: float,
        servers: list[str],
    ) -> list[dict[str, object]]:
        return [
            {
                "ts": start_epoch + index * float(self.rng.integers(20, 400)),
                "uid": f"T{self.rng.integers(0, 2**31):08x}",
                "src_ip": src_ip,
                "src_port": int(self.rng.integers(1024, 60000)),
                "dst_ip": servers[index % len(servers)],
                "dst_port": 443,
                "version": "TLSv12",
                "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "server_name": f"host{index % len(servers)}.example.com",
                "ja3": ja3,
                "ja3s": "ec74a5c51106f0419184d0dd08fb05bc",
                "established": True,
                "source_file": "<synthetic>",
                "source_line": 0,
            }
            for index in range(count)
        ]

    def generate(
        self,
        benign_hosts: int = 40,
        start_epoch: float = 1_750_000_000.0,
    ) -> TlsCorpus:
        rows: list[dict[str, object]] = []
        decoys: dict[tuple[str, str], str] = {}
        servers = [f"93.184.216.{n}" for n in range(1, 12)]

        # Benign estate: three browser builds spread across every host.
        for index in range(benign_hosts):
            src = f"10.0.3.{index + 10}"
            ja3 = self.COMMON[index % len(self.COMMON)]
            rows += self._sessions(src, ja3, int(self.rng.integers(8, 30)), start_epoch, servers)
            decoys[(src, ja3)] = "common browser build"

        # Decoy: a minority build shared by two hosts. Rare, but not one host.
        minority = "1b2c3d4e5f60718293a4b5c6d7e8f900"
        for src in ("10.0.3.70", "10.0.3.71"):
            rows += self._sessions(src, minority, 12, start_epoch, servers)
            decoys[(src, minority)] = "minority browser build, two hosts"

        # Decoy: a unique fingerprint seen exactly once. A truncated handshake.
        single = "ffee0011223344556677889900aabbcc"
        rows += self._sessions("10.0.3.80", single, 1, start_epoch, servers)
        decoys[("10.0.3.80", single)] = "single truncated handshake"

        clients = [
            RareClient("10.0.3.51", "9f1a7c4be2d3084f5a6b7c8d9e0f1a2b", "bespoke-implant-stack"),
            RareClient("10.0.3.52", "3c5e7a9b1d2f4068a1b3c5d7e9f0a2b4", "modified-openssl-client"),
        ]
        for client in clients:
            rows += self._sessions(
                client.src_ip, client.ja3, int(self.rng.integers(6, 20)), start_epoch, servers[:2]
            )

        frame = conform(pl.DataFrame(rows), SSL_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return TlsCorpus(sessions=frame, clients=clients, decoys=decoys)


_ZEEK_SSL_FIELDS = [
    "ts",
    "uid",
    "id.orig_h",
    "id.orig_p",
    "id.resp_h",
    "id.resp_p",
    "version",
    "cipher",
    "server_name",
    "established",
    "ja3",
    "ja3s",
]



@dataclass(frozen=True)
class PlantedExecution:
    """One execution the generator planted, and which predicate should see it."""

    host: str
    parent: str
    image: str
    label: str
    #: The predicate this execution is planted for. A lineage plant whose
    #: image is ordinary (`cmd.exe` under `winword.exe`) is deliberately
    #: invisible to the rarity half, and scoring it as a rarity miss would
    #: measure the corpus rather than the detector.
    predicate: str

    @property
    def image_name(self) -> str:
        return self.image.rsplit("\\", 1)[-1].lower()

    @property
    def parent_name(self) -> str:
        return self.parent.rsplit("\\", 1)[-1].lower()

    @property
    def process_key(self) -> tuple[str, str]:
        return (self.host, self.image_name)

    @property
    def lineage_key(self) -> tuple[str, str, str]:
        return (self.host, self.parent_name, self.image_name)


@dataclass
class HostCorpus:
    """Generated process-creation telemetry plus its ground truth."""

    events: pl.DataFrame
    implants: list[PlantedExecution]
    decoys: dict[tuple[str, str], str] = field(default_factory=dict)

    @property
    def process_keys(self) -> set[tuple[str, str]]:
        return {p.process_key for p in self.implants if p.predicate == "executes_rare_process"}

    @property
    def lineage_keys(self) -> set[tuple[str, str, str]]:
        return {p.lineage_key for p in self.implants if p.predicate == "exhibits_anomalous_lineage"}


class HostCorpusGenerator:
    """Builds a labelled Windows estate from a seed.

    The estate has to be an estate. Both host predicates are prevalence
    claims, and a generator that produced one machine would produce a corpus
    on which the analyzer correctly refuses to speak — which is what the real
    corpus in `tests/data` already demonstrates and does not need a second
    demonstration of. So forty workstations run the same twenty binaries, and
    the interesting rows are the ones that do not.

    The decoys are the ways a prevalence measure goes wrong on host telemetry,
    and they are not the ones that catch a network detector:

      * **a toolchain only one machine runs.** A developer's `msbuild.exe` and
        `node.exe` are on exactly one host out of forty and score a perfect
        rarity — but they live under `Program Files` and run hundreds of
        times, which is what `path_anomaly` and `execution_prevalence` are for.
      * **an administrator's tool on two machines.** Rare, run twice, and in
        `System32` where the operating system's own binaries live.
      * **a legitimate installer in a user's Downloads folder, run once.**
        Rare image, writable path, single execution. This one is *expected to
        fire*: it is indistinguishable from a dropped payload by anything this
        analyzer measures, and pretending otherwise by tuning it away would be
        the section 9 mistake. It is counted as a false positive and reported.
      * **a rare but ordinary lineage.** `explorer.exe` spawning an installer
        on one host is an edge seen nowhere else in the estate.

    The implants are three shapes rather than three instances of one:

      * a dropped binary in a user's temp directory — rare *and* anomalously
        parented, which is what the subsumption rule in `analyzers/host.py`
        exists to handle;
      * `winword.exe -> cmd.exe -> powershell.exe`, where every image is
        commonplace and only the *relationship* is wrong. Invisible to the
        rarity half by construction;
      * a service binary masquerading under `ProgramData`, parented by
        `svchost.exe`.
    """

    #: The estate's ordinary software. Each entry is (parent, image), and
    #: every host runs all of them, which is what makes prevalence mean
    #: something. Paths are the real ones because `path_anomaly` reads them.
    BASELINE: tuple[tuple[str, str], ...] = (
        ("C:\\Windows\\System32\\wininit.exe", "C:\\Windows\\System32\\services.exe"),
        ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\svchost.exe"),
        ("C:\\Windows\\System32\\services.exe", "C:\\Windows\\System32\\spoolsv.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\taskhostw.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\RuntimeBroker.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\dllhost.exe"),
        ("C:\\Windows\\System32\\winlogon.exe", "C:\\Windows\\explorer.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Google\\Chrome\\chrome.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"),
        ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
        ("C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft\\Teams\\Teams.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\notepad.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\cmd.exe"),
        ("C:\\Windows\\explorer.exe", "C:\\Windows\\System32\\mmc.exe"),
        ("C:\\Windows\\System32\\cmd.exe", "C:\\Windows\\System32\\conhost.exe"),
        ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
         "C:\\Windows\\System32\\conhost.exe"),
        ("C:\\Windows\\explorer.exe",
         "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\SearchIndexer.exe"),
        ("C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\System32\\sihost.exe"),
    )

    COMMANDS: ClassVar[dict[str, str]] = {
        "svchost.exe": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
        "conhost.exe": "\\??\\C:\\Windows\\system32\\conhost.exe 0xffffffff -ForceV1",
        "chrome.exe": '"C:\\Program Files\\Google\\Chrome\\chrome.exe" --type=renderer',
        "cmd.exe": '"C:\\Windows\\system32\\cmd.exe" /c dir',
        "powershell.exe": '"powershell.exe" -NoProfile -File C:\\ops\\inventory.ps1',
    }

    def __init__(self, seed: int = 1337) -> None:
        self.rng = np.random.default_rng(seed)
        self._sequence = 0

    def _guid(self) -> str:
        self._sequence += 1
        return f"{{aaaaaaaa-0000-0000-0000-{self._sequence:012d}}}"

    def _event(
        self,
        host: str,
        parent: str,
        image: str,
        ts: float,
        parent_guid: str | None = None,
        command_line: str | None = None,
        user: str = "CONTOSO\\jsmith",
    ) -> dict[str, object]:
        name = image.rsplit("\\", 1)[-1].lower()
        return {
            "ts": ts,
            "host": host,
            "user": user,
            "image": image,
            "command_line": command_line or self.COMMANDS.get(name, f'"{image}"'),
            "current_directory": "C:\\Windows\\system32\\",
            "integrity_level": "Medium",
            "process_guid": self._guid(),
            "process_id": int(self.rng.integers(400, 30000)),
            "parent_image": parent,
            "parent_command_line": f'"{parent}"' if parent else None,
            "parent_guid": parent_guid,
            "parent_process_id": int(self.rng.integers(400, 30000)),
            "sha256": f"{self.rng.integers(0, 2**63):064x}"[:64],
            "source_file": "<synthetic>",
            "source_line": 0,
        }

    def generate(
        self,
        hosts: int = 40,
        hours: float = 8.0,
        start_epoch: float = 1_750_000_000.0,
    ) -> HostCorpus:
        rows: list[dict[str, object]] = []
        decoys: dict[tuple[str, str], str] = {}
        span = hours * 3600.0

        # The estate: every workstation runs every baseline binary, which is
        # what stops prevalence from measuring the corpus's size.
        guids: dict[tuple[str, str], str] = {}
        for index in range(hosts):
            host = f"WS{index + 1:03d}.contoso.local"
            for parent, image in self.BASELINE:
                for _ in range(int(self.rng.integers(2, 7))):
                    event = self._event(
                        host, parent, image, start_epoch + float(self.rng.random()) * span,
                        parent_guid=guids.get((host, parent.rsplit("\\", 1)[-1].lower())),
                    )
                    guids.setdefault((host, image.rsplit("\\", 1)[-1].lower()),
                                     str(event["process_guid"]))
                    rows.append(event)

        # Decoy: a developer's toolchain, on one host and only one host.
        for image in (
            "C:\\Program Files\\Microsoft Visual Studio\\MSBuild\\Current\\Bin\\MSBuild.exe",
            "C:\\Program Files\\nodejs\\node.exe",
        ):
            for _ in range(120):
                rows.append(
                    self._event(
                        "WS007.contoso.local", "C:\\Windows\\System32\\cmd.exe", image,
                        start_epoch + float(self.rng.random()) * span,
                        parent_guid=guids.get(("WS007.contoso.local", "cmd.exe")),
                    )
                )
            decoys[("WS007.contoso.local", image.rsplit("\\", 1)[-1].lower())] = (
                "developer toolchain, one host, hundreds of executions"
            )

        # Decoy: an administrator's tool, twice, on two machines, in System32.
        for host in ("WS011.contoso.local", "WS012.contoso.local"):
            for _ in range(2):
                rows.append(
                    self._event(
                        host, "C:\\Windows\\System32\\cmd.exe",
                        "C:\\Windows\\System32\\PsExec64.exe",
                        start_epoch + float(self.rng.random()) * span,
                        parent_guid=guids.get((host, "cmd.exe")),
                    )
                )
            decoys[(host, "psexec64.exe")] = "administrator tool, two hosts, System32"

        # Decoy: a legitimate installer in a user's Downloads folder, run once.
        # Expected to fire. See the class docstring.
        rows.append(
            self._event(
                "WS019.contoso.local", "C:\\Windows\\explorer.exe",
                "C:\\Users\\dpatel\\Downloads\\7z2301-x64.exe",
                start_epoch + 0.42 * span,
                parent_guid=guids.get(("WS019.contoso.local", "explorer.exe")),
            )
        )
        decoys[("WS019.contoso.local", "7z2301-x64.exe")] = (
            "legitimate installer, user Downloads, single execution — expected false positive"
        )

        implants = [
            # Rare-process plants: a binary the estate has never run. The
            # parent edge is novel too, and deliberately so — that is the
            # overlap `_subsume` resolves, and a corpus with no instance of it
            # would not test the resolution.
            PlantedExecution(
                host="WS023.contoso.local",
                parent="C:\\Windows\\explorer.exe",
                image="C:\\Users\\mrivera\\AppData\\Local\\Temp\\svchost-update.exe",
                label="dropped binary in a user temp directory",
                predicate="executes_rare_process",
            ),
            PlantedExecution(
                host="WS038.contoso.local",
                parent="C:\\Windows\\System32\\svchost.exe",
                image="C:\\ProgramData\\svcnet\\netsvc.exe",
                label="service binary masquerading under ProgramData",
                predicate="executes_rare_process",
            ),
            PlantedExecution(
                host="WS027.contoso.local",
                parent="C:\\Windows\\System32\\cmd.exe",
                image="C:\\Users\\Public\\rclone.exe",
                label="staging tool in a world-writable directory",
                predicate="executes_rare_process",
            ),
            # Lineage plants: every image is commonplace and runs on every
            # host in the estate. Invisible to the rarity half by
            # construction, which is the point — if these were also rare the
            # corpus would not show that the two predicates measure different
            # things.
            PlantedExecution(
                host="WS031.contoso.local",
                parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
                image="C:\\Windows\\System32\\cmd.exe",
                label="office application spawning a shell",
                predicate="exhibits_anomalous_lineage",
            ),
            PlantedExecution(
                host="WS033.contoso.local",
                parent="C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
                image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                label="mail client spawning a shell",
                predicate="exhibits_anomalous_lineage",
            ),
        ]
        for implant in implants:
            parent_guid = guids.get((implant.host, implant.parent_name))
            event = self._event(
                implant.host, implant.parent, implant.image,
                start_epoch + 0.63 * span, parent_guid=parent_guid,
                command_line=f'"{implant.image}"',
            )
            rows.append(event)
            # The macro chain continues: the shell then launches PowerShell,
            # so the ancestry an analyst reads is the whole chain rather than
            # one edge. Labelled too — it is a second execution, not a second
            # view of the first.
            if implant.image_name == "cmd.exe":
                child = self._event(
                    implant.host, implant.image,
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    start_epoch + 0.63 * span + 2.0,
                    parent_guid=str(event["process_guid"]),
                    command_line='"powershell.exe" -nop -w hidden -enc SQBFAFgAIA==',
                )
                rows.append(child)
                implants.append(
                    PlantedExecution(
                        host=implant.host,
                        parent=implant.image,
                        image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                        label="shell spawned by a macro then launching PowerShell",
                        predicate="exhibits_anomalous_lineage",
                    )
                )

        frame = conform(pl.DataFrame(rows), PROCESS_SCHEMA).sort("ts")
        frame = frame.with_columns(
            pl.int_range(1, frame.height + 1, dtype=pl.Int64).alias("source_line")
        )
        return HostCorpus(events=frame, implants=implants, decoys=decoys)


def write_zeek_ssl_log(
    sessions: pl.DataFrame,
    path: str | Path,
    with_ja3: bool = True,
) -> Path:
    """Write a TLS frame as a Zeek `ssl.log`.

    `with_ja3=False` writes the log a **stock Zeek** produces: every column
    except the fingerprints, because those come from a package that is not
    loaded. That is not a corner case to be tolerated, it is the common
    deployment, and the analyzer's behaviour on it is asserted rather than
    assumed.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fields = [f for f in _ZEEK_SSL_FIELDS if with_ja3 or not f.startswith("ja3")]
    types = {
        "ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
        "id.resp_h": "addr", "id.resp_p": "port", "version": "string",
        "cipher": "string", "server_name": "string", "established": "bool",
        "ja3": "string", "ja3s": "string",
    }
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tssl",
        "#fields\t" + "\t".join(fields),
        "#types\t" + "\t".join(types[f] for f in fields),
    ]

    column = {
        "ts": lambda r: f"{r['ts']:.6f}",
        "uid": lambda r: r["uid"] or "-",
        "id.orig_h": lambda r: r["src_ip"],
        "id.orig_p": lambda r: str(r["src_port"]),
        "id.resp_h": lambda r: r["dst_ip"],
        "id.resp_p": lambda r: str(r["dst_port"]),
        "version": lambda r: r["version"] or "-",
        "cipher": lambda r: r["cipher"] or "-",
        "server_name": lambda r: r["server_name"] or "-",
        # Zeek's TSV boolean, which casts to null rather than False unless the
        # parser maps it — the reason `read_ssl_log` maps it.
        "established": lambda r: "T" if r["established"] else "F",
        "ja3": lambda r: r["ja3"] or "-",
        "ja3s": lambda r: r["ja3s"] or "-",
    }
    rows = [
        "\t".join(column[f](r) for f in fields)
        for r in sessions.sort("ts").iter_rows(named=True)
    ]
    path.write_text("\n".join(header + rows) + "\n")
    return path


def write_sysmon_jsonl(path: str | Path, events: pl.DataFrame) -> Path:
    """Write process records as Sysmon JSON lines, the way a collector would.

    Field names are Sysmon's own rather than the normalised schema's, so the
    demo exercises `ingest/sysmon.py` end to end instead of handing the
    analyzer a frame the parser never saw. `UtcTime` is written and
    `@timestamp` deliberately is not: the parser prefers the sensor's clock,
    and a corpus that only carried the shipper's would let that preference
    rot untested.
    """
    path = Path(path)
    lines: list[str] = []
    for row in events.iter_rows(named=True):
        moment = datetime.fromtimestamp(float(row["ts"]), tz=timezone.utc)
        record = {
            "EventID": 1,
            "SourceName": "Microsoft-Windows-Sysmon",
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "UtcTime": moment.strftime("%Y-%m-%d %H:%M:%S.") + f"{moment.microsecond // 1000:03d}",
            "Hostname": row["host"],
            "User": row["user"],
            "ProcessGuid": row["process_guid"],
            "ProcessId": row["process_id"],
            "Image": row["image"],
            "CommandLine": row["command_line"],
            "CurrentDirectory": row["current_directory"],
            "IntegrityLevel": row["integrity_level"],
            "Hashes": f"SHA1=0000000000000000000000000000000000000000,SHA256={row['sha256']}",
            "ParentProcessGuid": row["parent_guid"],
            "ParentProcessId": row["parent_process_id"],
            "ParentImage": row["parent_image"],
            "ParentCommandLine": row["parent_command_line"],
        }
        lines.append(json.dumps({k: v for k, v in record.items() if v is not None}))
    path.write_text("\n".join(lines) + "\n")
    return path


def write_eve_json(path: str | Path, alerts: list[dict[str, object]]) -> Path:
    """Serialise alert records as Suricata EVE JSON."""
    import json
    from datetime import datetime, timezone

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for alert in sorted(alerts, key=lambda a: a["ts"]):
        stamp = datetime.fromtimestamp(float(alert["ts"]), tz=timezone.utc)
        lines.append(
            json.dumps(
                {
                    "timestamp": stamp.strftime("%Y-%m-%dT%H:%M:%S.%f") + "+0000",
                    "event_type": "alert",
                    "src_ip": alert["src_ip"],
                    "dest_ip": alert["dst_ip"],
                    "dest_port": alert.get("dst_port", 443),
                    "proto": "TCP",
                    "alert": {
                        "signature_id": alert["signature_id"],
                        "signature": alert["signature"],
                        "category": alert["category"],
                        "severity": alert["severity"],
                    },
                }
            )
        )
    path.write_text("\n".join(lines) + "\n")
    return path


_ZEEK_DNS_FIELDS = ["ts", "uid", "id.orig_h", "id.resp_h", "query", "qtype_name", "rcode_name"]


def write_zeek_dns_log(queries: pl.DataFrame, path: str | Path) -> Path:
    """Write a DNS frame as a Zeek `dns.log`.

    Zeek names the columns `qtype_name` and `rcode_name`, which is why
    `read_dns_log` accepts either spelling — and why this writes the Zeek
    ones rather than the normalised ones. A generator that emitted the
    internal names would test the schema against itself.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = [
        "#separator \\x09",
        "#set_separator\t,",
        "#empty_field\t(empty)",
        "#unset_field\t-",
        "#path\tdns",
        "#fields\t" + "\t".join(_ZEEK_DNS_FIELDS),
        "#types\ttime\tstring\taddr\taddr\tstring\tstring\tstring",
    ]
    rows = [
        "\t".join(
            [
                f"{r['ts']:.6f}",
                r["uid"] or "-",
                r["src_ip"],
                r["dst_ip"] or "10.0.0.53",
                r["query"],
                r["qtype"] or "A",
                r["rcode"] or "-",
            ]
        )
        for r in queries.sort("ts").iter_rows(named=True)
    ]
    path.write_text("\n".join(header + rows) + "\n")
    return path


def write_passivedns(path: str | Path, queries: pl.DataFrame) -> Path:
    """Serialise DNS queries in passivedns' pipe-delimited format."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = ["[*] PassiveDNS 1.2.0", "[*] Synthetic capture generated by voidai demo"]
    base = float(queries["ts"].min()) if queries.height else 0.0
    rows = [
        "||".join(
            [
                f"{float(r['ts']) - base:.6f}",
                r["src_ip"],
                r["dst_ip"] or "10.0.0.53",
                "IN",
                f"{r['query']}.",
                r["qtype"] or "A",
                "203.0.113.1",
                "300",
                "1",
            ]
        )
        for r in queries.sort("ts").iter_rows(named=True)
    ]
    path.write_text("\n".join(header + rows) + "\n")
    return path


def build_demo_capture(directory: str | Path, seed: int = 1337) -> Path:
    """Write a complete multi-source capture: connections, DNS, TLS and alerts.

    One host — `10.0.1.14` — beacons, sweeps a port, tunnels over DNS, runs a
    domain generation algorithm, presents a TLS client fingerprint nothing
    else in the estate runs, and trips two severe signatures. Every one of
    those is hidden in benign traffic of the same kind. Nothing about the host
    is flagged in the data; it is distinguishable only by measuring it, which
    is the point of the demonstration.

    Written as real files in real sensor formats, so `voidai run` exercises
    the production parsers rather than a shortcut.
    """
    import numpy as np

    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(seed)

    # Connections: beaconing and fan-out
    corpus = CorpusGenerator(seed=seed).generate(hours=24.0)
    start = float(corpus.connections["ts"].min())

    # Patient zero also sweeps port 445 across the estate.
    sweep = []
    for index in range(420):
        sweep.append(
            {
                "ts": start + index * 4.0,
                "uid": f"S{index:08x}",
                "src_ip": _PATIENT_ZERO,
                "src_port": int(rng.integers(1024, 5000)),
                "dst_ip": f"10.0.{index // 250}.{index % 250 + 1}",
                "dst_port": 445,
                "proto": "tcp",
                "service": None,
                "duration": 0.05,
                "orig_bytes": 320,
                "resp_bytes": 0,
                "orig_pkts": 2,
                "resp_pkts": 0,
                "conn_state": "S0",
                "source_file": "<synthetic>",
                "source_line": 0,
            }
        )
    connections = pl.concat(
        [corpus.connections, conform(pl.DataFrame(sweep), CONNECTION_SCHEMA)],
        how="vertical",
    ).sort("ts")
    connections = connections.with_columns(
        pl.int_range(1, connections.height + 1, dtype=pl.Int64).alias("source_line")
    )
    Corpus(connections=connections, implants=corpus.implants).write_zeek_conn_log(
        directory / "conn.log"
    )

    # DNS: a tunnel on the same host, among benign lookups
    dns = DnsCorpusGenerator(seed=seed).generate(hours=6.0)
    tunnel = dns.queries.with_columns(
        pl.when(pl.col("src_ip") == dns.tunnels[0].src_ip)
        .then(pl.lit(_PATIENT_ZERO))
        .otherwise(pl.col("src_ip"))
        .alias("src_ip")
    )
    write_passivedns(directory / "capture.passivedns", tunnel)

    # The same queries again as a Zeek dns.log, with a generation family
    # added: patient zero also runs a DGA.
    #
    # Written as a second file rather than folded into the passivedns above
    # because passivedns records no response code, and the NXDOMAIN rate is
    # the signal that separates a generator from a host with unusual taste in
    # domain names. `_detect` prefers dns.log where both exist — so this file
    # is the one that drives the demo, and it carries the tunnel as well as
    # the family. The passivedns file stays because it is a format VoidLexicon
    # supports and the CTU-13 captures ship it, and dropping it would remove
    # the only demonstration of that parser.
    dga = DgaCorpusGenerator(seed=seed).generate(hours=6.0)
    # One family, on patient zero. The generator plants four, and the demo
    # keeps the first: the other three would appear as further infected hosts
    # and blunt the point being demonstrated, which is that *one* host doing
    # several unrelated things outranks a field of hosts each doing one. The
    # benign traffic and every decoy stay.
    generated = dga.queries.filter(
        ~pl.col("src_ip").is_in([f.src_ip for f in dga.families[1:]])
    ).with_columns(
        pl.when(pl.col("src_ip") == dga.families[0].src_ip)
        .then(pl.lit(_PATIENT_ZERO))
        .otherwise(pl.col("src_ip"))
        .alias("src_ip")
    )
    combined = pl.concat([tunnel, generated], how="vertical").sort("ts")
    write_zeek_dns_log(combined, directory / "dns.log")

    # TLS: patient zero presents a client fingerprint nothing else runs.
    tls = TlsCorpusGenerator(seed=seed).generate()
    sessions = tls.sessions.with_columns(
        pl.when(pl.col("src_ip") == tls.clients[0].src_ip)
        .then(pl.lit(_PATIENT_ZERO))
        .otherwise(pl.col("src_ip"))
        .alias("src_ip")
    )
    write_zeek_ssl_log(sessions, directory / "ssl.log")

    # Host telemetry: the same machine, seen from the endpoint. Patient zero
    # runs a binary the estate does not, and an Office application on it
    # spawns a shell — one rare execution and one anomalous lineage, which is
    # the conjunction this cluster was built for.
    #
    # The estate is forty workstations because it has to be. Both host
    # predicates are prevalence claims and the analyzer refuses to make one
    # over a handful of machines, so a demo with three would demonstrate the
    # gate rather than the detector — and `tests/data/real.sysmon.jsonl.gz`
    # already demonstrates the gate, on real telemetry.
    host_corpus = HostCorpusGenerator(seed=seed).generate(hours=6.0, start_epoch=start)
    carried = {"WS023.contoso.local", "WS031.contoso.local"}
    # The generator plants five executions across five machines. The demo
    # keeps two and drops the rest: the others would read as further infected
    # hosts and blunt the point, which is that *one* machine doing several
    # unrelated things outranks a field each doing one. Same reasoning as the
    # generation family above, and the decoys all stay.
    unwanted = pl.lit(False)
    for implant in host_corpus.implants:
        if implant.host in carried:
            continue
        unwanted = unwanted | (
            (pl.col("host") == implant.host)
            & (pl.col("image") == implant.image)
            & (pl.col("parent_image") == implant.parent)
        )
    events = host_corpus.events.filter(~unwanted).with_columns(
        pl.when(pl.col("host").is_in(list(carried)))
        .then(pl.lit(_PATIENT_ZERO_HOST))
        .otherwise(pl.col("host"))
        .alias("host")
    )
    write_sysmon_jsonl(directory / "sysmon.jsonl", events)

    # Alerts: estate-wide noise plus two rare severe rules
    alerts: list[dict[str, object]] = []
    noise = [
        (2013028, "ET POLICY curl User-Agent Outbound", "Not Suspicious Traffic", 3),
        (2001569, "ET SCAN Behavioral Unusual Port 445 traffic", "Misc activity", 3),
    ]
    for host in range(55):
        src = f"10.0.1.{host + 10}"
        for sid, signature, category, severity in noise:
            for index in range(int(rng.integers(30, 70))):
                alerts.append(
                    {
                        "ts": start + index * 11,
                        "src_ip": src,
                        "dst_ip": "93.184.216.34",
                        "signature_id": sid,
                        "signature": signature,
                        "category": category,
                        "severity": severity,
                    }
                )
    for sid, signature, category in (
        (2018000, "ET TROJAN Observed Malicious SSL Certificate", "A Network Trojan was detected"),
        (2022000, "ET EXPLOIT Possible CVE-2017-0144 SMB Exploit Attempt",
         "Attempted Administrator Privilege Gain"),
    ):
        for index in range(14):
            alerts.append(
                {
                    "ts": start + index * 420,
                    "src_ip": _PATIENT_ZERO,
                    "dst_ip": "45.83.220.17",
                    "signature_id": sid,
                    "signature": signature,
                    "category": category,
                    "severity": 1,
                }
            )
    write_eve_json(directory / "eve.json", alerts)

    _write_demo_inventory(directory, start)

    return directory


def _write_demo_inventory(directory: Path, start_epoch: float) -> Path:
    """Ship the one asset mapping that joins the two halves of patient zero.

    One line, and it is the whole demonstration: the network sensors report an
    address and the endpoint agent reports a computer name, and until something
    states that they are the same machine the queue carries two rows that do
    not corroborate each other. Nothing in this file is derived from the
    telemetry — an inventory is a statement an operator makes, and deriving one
    from observed traffic is a different piece of work with a different failure
    mode.

    Deliberately a *partial* inventory: forty-odd source addresses appear in
    the capture and exactly one of them is named, so `voidai run` reports a
    coverage in the low single figures. That is the honest number for an
    inventory of one line and it is the figure an operator needs to see, rather
    than a mapping count that would read like completeness.

    Dated four days before the capture starts, which is what a register
    reconciled the week before an incident looks like — recent enough that
    `docs/inventory.md`'s staleness ladder leaves it unflagged, and dated at
    all so the demo does not quietly exercise the undated path.
    """
    stated = datetime.fromtimestamp(start_epoch, tz=timezone.utc).date() - timedelta(days=4)
    path = directory / "assets.inv"
    path.write_text(
        "\n".join(
            (
                "# name: corp-asset-register",
                "# source: netbox export, finance floor",
                f"# updated: {stated.isoformat()}",
                "# tlp: amber",
                "",
                f"{_PATIENT_ZERO:<12} {_PATIENT_ZERO_HOST:<14} "
                f"stated={stated.isoformat()}  note=static lease, finance floor",
                "",
            )
        ),
        encoding="utf-8",
    )
    return path
