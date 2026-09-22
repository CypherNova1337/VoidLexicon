"""Turning findings into queries that run somewhere else.

VoidLexicon analyses one sensor's window. A SIEM holds the estate's history. The
handoff between them is the point of this package: a typed proposition
carries enough structure to be templated into a hunt without a model reading
it and guessing what the indicator was.
"""

from voidai.hunt.queries import (
    Dialect,
    HuntQuery,
    escape,
    pivot_entities,
    queries_for,
    queries_for_incident,
)

__all__ = [
    "Dialect",
    "HuntQuery",
    "escape",
    "pivot_entities",
    "queries_for",
    "queries_for_incident",
]
