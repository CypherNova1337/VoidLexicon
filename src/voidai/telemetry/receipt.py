"""The run receipt.

Every VoidLexicon investigation ends with an itemised bill: what it cost in time,
in CPU, in memory, in tokens, and in joules. Printed by default, not hidden
behind a verbose flag.

The point is accountability. A tool that will not tell you what it consumes
is asking you to take its efficiency on faith, and this project's entire
argument is that you should not have to.
"""

from __future__ import annotations

import os
import platform
import resource
from dataclasses import dataclass, field
from datetime import datetime, timezone

from voidai.ingest.inventory import Coverage
from voidai.telemetry.power import EnergyReading


def _peak_rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    peak = max(usage.ru_maxrss, children.ru_maxrss)
    # Linux reports kilobytes; Darwin reports bytes.
    return peak / 1024 if platform.system() != "Darwin" else peak / (1024 * 1024)


@dataclass
class TokenUsage:
    """Language-layer consumption. All zero on a --no-llm run, by design."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    invocations: int = 0
    model: str | None = None

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def add(self, prompt: int, completion: int) -> None:
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        self.invocations += 1


@dataclass
class RunReceipt:
    """The itemised cost of one investigation."""

    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    energy: EnergyReading | None = None
    #: Cost of the language layer, metered separately. Folding it into
    #: `energy` would divide detection throughput by the time a model spent
    #: writing prose, understating detection by two orders of magnitude.
    reasoning: EnergyReading | None = None
    tokens: TokenUsage = field(default_factory=TokenUsage)

    records_ingested: int = 0
    findings_emitted: int = 0
    incidents_emitted: int = 0
    claims_struck: int = 0

    #: What the asset inventory reached, when one was loaded. A mapping count
    #: alone answers the wrong question — an inventory covering 3% of an
    #: estate is a rounding error dressed as an improvement — so the receipt
    #: carries the fraction of observed addresses it actually resolved.
    inventory: Coverage | None = None

    peak_rss_mb: float = 0.0
    host: str = field(default_factory=platform.node)
    machine: str = field(default_factory=lambda: platform.machine())
    cores: int = field(default_factory=lambda: os.cpu_count() or 1)

    def finalize(self, energy: EnergyReading | None) -> RunReceipt:
        self.energy = energy
        self.peak_rss_mb = _peak_rss_mb()
        return self

    @property
    def records_per_second(self) -> float:
        """Detection throughput. Excludes the language layer by design."""
        if not self.energy or self.energy.wall_seconds <= 0:
            return 0.0
        return self.records_ingested / self.energy.wall_seconds

    @property
    def total_joules(self) -> float:
        return (self.energy.joules if self.energy else 0.0) + (
            self.reasoning.joules if self.reasoning else 0.0
        )

    @property
    def total_wall_seconds(self) -> float:
        return (self.energy.wall_seconds if self.energy else 0.0) + (
            self.reasoning.wall_seconds if self.reasoning else 0.0
        )

    @property
    def joules_per_incident(self) -> float:
        if not self.energy or self.incidents_emitted == 0:
            return 0.0
        return self.energy.joules / self.incidents_emitted

    @property
    def watt_hours(self) -> float:
        return self.energy.joules / 3600 if self.energy else 0.0

    def as_dict(self) -> dict[str, object]:
        e = self.energy
        return {
            "started_at": self.started_at.isoformat(),
            "host": {"name": self.host, "machine": self.machine, "cores": self.cores},
            "energy": (
                {
                    "joules": round(e.joules, 3),
                    "watt_hours": round(self.watt_hours, 6),
                    "average_watts": round(e.average_watts, 2),
                    "fidelity": e.fidelity,
                    "method": e.method,
                }
                if e
                else None
            ),
            "time": {
                "detection_wall_seconds": round(e.wall_seconds, 3) if e else None,
                "detection_cpu_seconds": round(e.cpu_seconds, 3) if e else None,
                "reasoning_wall_seconds": (
                    round(self.reasoning.wall_seconds, 3) if self.reasoning else None
                ),
                "total_wall_seconds": round(self.total_wall_seconds, 3),
            },
            "memory": {"peak_rss_mb": round(self.peak_rss_mb, 1)},
            "tokens": {
                "prompt": self.tokens.prompt_tokens,
                "completion": self.tokens.completion_tokens,
                "total": self.tokens.total,
                "invocations": self.tokens.invocations,
                "model": self.tokens.model,
            },
            "inventory": (
                {
                    "mappings_loaded": self.inventory.loaded,
                    "mappings_applied": self.inventory.applied,
                    "mappings_dropped": self.inventory.dropped,
                    "addresses_observed": self.inventory.observed,
                    "addresses_resolved": self.inventory.matched,
                    "coverage": round(self.inventory.fraction, 4),
                }
                if self.inventory
                else None
            ),
            "work": {
                "records_ingested": self.records_ingested,
                "findings_emitted": self.findings_emitted,
                "incidents_emitted": self.incidents_emitted,
                "claims_struck": self.claims_struck,
                "records_per_second": round(self.records_per_second, 1),
                "joules_per_incident": round(self.joules_per_incident, 2),
            },
        }
