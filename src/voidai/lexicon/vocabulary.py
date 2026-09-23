"""The vocabulary: everything VoidLexicon is capable of saying.

    "The limits of my language mean the limits of my world."

This module is that limit, made executable. An analyzer or a language model
may only assert a proposition built from a `Predicate` defined here, applied
to entity types this grammar permits. There is no free-text assertion path
into a VoidLexicon report.

The practical consequence: a language model cannot invent a new kind of
accusation. It can rank, narrate, and connect propositions that the
deterministic layer already grounded in evidence, and nothing else. Novel
prose is confined to the `narrative` field of an Incident, which is presented
as commentary and never as a finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class EntityType(str, Enum):
    """The nouns."""

    HOST = "host"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    USER = "user"
    PROCESS = "process"
    FILE_HASH = "file_hash"
    SIGNATURE = "signature"
    PORT = "port"
    TLS_FINGERPRINT = "tls_fingerprint"


class Severity(str, Enum):
    """Analyst-facing triage bands.

    Deliberately coarse. A five-band scale that everyone reads as
    "high or not high" is more honest than a 0-100 score nobody can calibrate.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Predicate(str, Enum):
    """The verbs. This is the complete set of assertions VoidLexicon can make."""

    # Network behaviour
    BEACONS_TO = "beacons_to"
    TUNNELS_DNS_OVER = "tunnels_dns_over"
    EXFILTRATES_TO = "exfiltrates_to"
    SCANS = "scans"
    CONTACTS_RARE_DESTINATION = "contacts_rare_destination"
    TRANSFERS_ANOMALOUS_VOLUME = "transfers_anomalous_volume"
    PRESENTS_RARE_TLS_FINGERPRINT = "presents_rare_tls_fingerprint"
    RESOLVES_ALGORITHMIC_DOMAIN = "resolves_algorithmic_domain"

    # Web
    ATTACKS_WEB_ENDPOINT = "attacks_web_endpoint"
    ENUMERATES_WEB_PATHS = "enumerates_web_paths"

    # Host / identity
    EXECUTES_RARE_PROCESS = "executes_rare_process"
    EXHIBITS_ANOMALOUS_LINEAGE = "exhibits_anomalous_lineage"
    AUTHENTICATION_ANOMALY = "authentication_anomaly"
    ESTABLISHES_PERSISTENCE = "establishes_persistence"

    # Signature / intel derived
    TRIGGERED_SIGNATURE = "triggered_signature"
    MATCHES_THREAT_INTEL = "matches_threat_intel"

    # Relational (used by the correlator, not by primary analyzers)
    SHARES_INFRASTRUCTURE_WITH = "shares_infrastructure_with"
    PRECEDES = "precedes"

    @property
    def spec(self) -> PredicateSpec:
        return GRAMMAR[self]


@dataclass(frozen=True)
class PredicateSpec:
    """The grammar rule for one predicate.

    `object_types` of ``None`` marks a unary predicate — one that says
    something about a subject alone, with no target.
    """

    subject_types: frozenset[EntityType]
    object_types: frozenset[EntityType] | None
    description: str
    default_severity: Severity
    attack_techniques: tuple[str, ...] = ()

    def is_unary(self) -> bool:
        return self.object_types is None


def _t(*types: EntityType) -> frozenset[EntityType]:
    return frozenset(types)


_ACTOR = _t(EntityType.HOST, EntityType.IP)
_NET_TARGET = _t(EntityType.IP, EntityType.DOMAIN)


GRAMMAR: dict[Predicate, PredicateSpec] = {
    Predicate.BEACONS_TO: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_NET_TARGET,
        description="Subject contacts the target on a regular schedule consistent with automated check-in.",
        default_severity=Severity.HIGH,
        attack_techniques=("T1071", "T1573", "T1008"),
    ),
    Predicate.TUNNELS_DNS_OVER: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_t(EntityType.DOMAIN),
        description="Subject encodes non-resolution data into DNS queries under the target zone.",
        default_severity=Severity.HIGH,
        attack_techniques=("T1071.004", "T1048.003"),
    ),
    Predicate.EXFILTRATES_TO: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_NET_TARGET,
        description="Subject transfers an anomalous outbound volume to the target.",
        default_severity=Severity.CRITICAL,
        attack_techniques=("T1041", "T1030"),
    ),
    Predicate.SCANS: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_t(EntityType.HOST, EntityType.IP, EntityType.PORT),
        description="Subject probes many targets or ports in a short window.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1046", "T1595"),
    ),
    Predicate.CONTACTS_RARE_DESTINATION: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_NET_TARGET,
        description="Subject contacts a destination rarely seen across the observed estate.",
        default_severity=Severity.LOW,
        attack_techniques=("T1071",),
    ),
    Predicate.TRANSFERS_ANOMALOUS_VOLUME: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_NET_TARGET,
        description="Byte volume between subject and target deviates sharply from its own baseline.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1030",),
    ),
    Predicate.PRESENTS_RARE_TLS_FINGERPRINT: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_t(EntityType.TLS_FINGERPRINT),
        description="Subject negotiates TLS with a client fingerprint rare in this environment.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1071.001",),
    ),
    Predicate.RESOLVES_ALGORITHMIC_DOMAIN: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_t(EntityType.DOMAIN),
        description="Subject resolves a domain whose structure is consistent with algorithmic generation.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1568.002",),
    ),
    Predicate.ATTACKS_WEB_ENDPOINT: PredicateSpec(
        subject_types=_t(EntityType.IP),
        object_types=_t(EntityType.URL),
        description="Subject sends requests carrying recognised exploitation patterns to the endpoint.",
        default_severity=Severity.HIGH,
        attack_techniques=("T1190", "T1059"),
    ),
    Predicate.ENUMERATES_WEB_PATHS: PredicateSpec(
        subject_types=_t(EntityType.IP),
        object_types=_t(EntityType.HOST, EntityType.URL),
        description="Subject requests many non-existent paths, consistent with content discovery.",
        default_severity=Severity.LOW,
        attack_techniques=("T1595.003",),
    ),
    Predicate.EXECUTES_RARE_PROCESS: PredicateSpec(
        subject_types=_t(EntityType.HOST),
        object_types=_t(EntityType.PROCESS),
        description="Subject runs a process rare across the observed estate.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1059",),
    ),
    Predicate.EXHIBITS_ANOMALOUS_LINEAGE: PredicateSpec(
        subject_types=_t(EntityType.HOST),
        object_types=_t(EntityType.PROCESS),
        description="A parent/child process relationship inconsistent with normal system behaviour.",
        default_severity=Severity.HIGH,
        attack_techniques=("T1059", "T1055"),
    ),
    Predicate.AUTHENTICATION_ANOMALY: PredicateSpec(
        subject_types=_t(EntityType.USER),
        object_types=_t(EntityType.HOST),
        description="Authentication pattern deviates from the subject's established baseline.",
        default_severity=Severity.MEDIUM,
        attack_techniques=("T1078", "T1110"),
    ),
    Predicate.ESTABLISHES_PERSISTENCE: PredicateSpec(
        subject_types=_t(EntityType.HOST),
        object_types=_t(EntityType.PROCESS, EntityType.FILE_HASH),
        description="A mechanism granting execution across reboot was created.",
        default_severity=Severity.HIGH,
        attack_techniques=("T1547", "T1053"),
    ),
    Predicate.TRIGGERED_SIGNATURE: PredicateSpec(
        subject_types=_ACTOR,
        object_types=_t(EntityType.SIGNATURE),
        description="A detection signature fired on traffic or activity involving the subject.",
        default_severity=Severity.INFO,
    ),
    Predicate.MATCHES_THREAT_INTEL: PredicateSpec(
        subject_types=_t(EntityType.IP, EntityType.DOMAIN, EntityType.FILE_HASH, EntityType.URL),
        object_types=None,
        description="Subject appears in a configured local threat intelligence set.",
        default_severity=Severity.MEDIUM,
    ),
    Predicate.SHARES_INFRASTRUCTURE_WITH: PredicateSpec(
        subject_types=_NET_TARGET,
        object_types=_NET_TARGET,
        description="Two network entities are linked by shared resolution or hosting.",
        default_severity=Severity.INFO,
    ),
    Predicate.PRECEDES: PredicateSpec(
        subject_types=frozenset(EntityType),
        object_types=frozenset(EntityType),
        description="Subject activity was observed before target activity within one incident window.",
        default_severity=Severity.INFO,
    ),
}


class GrammarError(ValueError):
    """Raised when a proposition is not expressible in the Lexicon."""


def validate_proposition(
    predicate: Predicate,
    subject_type: EntityType,
    object_type: EntityType | None,
) -> None:
    """Enforce the grammar. Raise `GrammarError` if the sentence is malformed."""
    spec = GRAMMAR[predicate]

    if subject_type not in spec.subject_types:
        allowed = ", ".join(sorted(t.value for t in spec.subject_types))
        raise GrammarError(
            f"'{predicate.value}' cannot take a {subject_type.value} as subject "
            f"(allowed: {allowed})"
        )

    if spec.is_unary():
        if object_type is not None:
            raise GrammarError(f"'{predicate.value}' is unary and takes no object")
        return

    if object_type is None:
        raise GrammarError(f"'{predicate.value}' requires an object")

    assert spec.object_types is not None  # narrowed by is_unary() above
    if object_type not in spec.object_types:
        allowed = ", ".join(sorted(t.value for t in spec.object_types))
        raise GrammarError(
            f"'{predicate.value}' cannot take a {object_type.value} as object "
            f"(allowed: {allowed})"
        )
