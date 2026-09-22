"""The Lexicon: the typed language in which VoidLexicon is permitted to speak."""

from voidai.lexicon.models import (
    Artifact,
    Claim,
    Entity,
    Evidence,
    Finding,
    Incident,
)
from voidai.lexicon.vocabulary import (
    GRAMMAR,
    EntityType,
    GrammarError,
    Predicate,
    PredicateSpec,
    Severity,
    validate_proposition,
)

__all__ = [
    "GRAMMAR",
    "Artifact",
    "Claim",
    "Entity",
    "EntityType",
    "Evidence",
    "Finding",
    "GrammarError",
    "Incident",
    "Predicate",
    "PredicateSpec",
    "Severity",
    "validate_proposition",
]
