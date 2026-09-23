"""Model backends, and the grammar that constrains what they may emit.

VoidLexicon targets open-weight models in the 1.7B-4B range, quantised to four
bits, running on CPU through llama.cpp. That tier is chosen on principle —
small enough to run on hardware an individual owns, not a data centre — and
the architecture is what makes it sufficient: the model is handed a few
hundred tokens of already-grounded findings and asked only to rank, connect
and explain them.

`llama-cpp-python` is an optional dependency. Everything above this module
works without it, and `voidai run --no-llm` is a first-class path rather than
a degraded one. A backend that is absent reports itself absent; it does not
silently substitute anything.

## Why a grammar rather than a prompt asking nicely for JSON

Constrained decoding rejects invalid tokens *during* sampling, so malformed
output is not possible rather than merely unlikely. On a 1.7B model that is
the difference between a parser that works and one that fails a few times an
hour. The GBNF below permits exactly one shape: an object with a narrative, a
list of claims each carrying an array of cited IDs, and a list of recommended
actions.

The grammar cannot force *correct* citations, only well-formed ones. Deciding
whether a cited ID actually exists is the verifier's job, and it is done after
generation against the brief's citable set.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

#: GBNF grammar pinning the response to the Lexicon's reporting schema.
#:
#: One rule per line: llama.cpp's GBNF parser terminates a rule at the
#: newline, so a rule wrapped across lines fails to parse rather than being
#: joined.
#: Every string is length-bounded and every list is count-bounded. Without
#: that a small model writes one enormous narrative paragraph, exhausts the
#: token budget, and is cut off mid-claim — leaving JSON that cannot be
#: parsed at all. Measured on Qwen2.5-1.5B: a 900-character narrative
#: followed by truncation, on the first attempt.
#:
#: Whitespace is capped at a single optional space. Left free, the model
#: emits pretty-printed JSON with newlines and indentation, and on a
#: 512-token budget that formatting is the difference between a complete
#: response and one truncated mid-claim.
#:
#: Citations are pinned to the shape of a real Finding ID. The grammar cannot
#: know *which* IDs are valid, but it can stop the model inventing
#: "finding-1", which is the most common fabrication. Deciding whether a
#: well-formed ID actually resolves is the verifier's job.
RESPONSE_GRAMMAR = r"""
root ::= "{" ws "\"narrative\":" ws narrative ws "," ws "\"claims\":" ws claims ws "," ws "\"actions\":" ws actions ws "}"
claims ::= "[" ws claim (ws "," ws claim){0,2} ws "]"
claim ::= "{" ws "\"text\":" ws sentence ws "," ws "\"cites\":" ws idlist ws "}"
idlist ::= "[" ws findingid (ws "," ws findingid){0,2} ws "]"
actions ::= "[" ws sentence (ws "," ws sentence){0,2} ws "]"
narrative ::= "\"" char{1,420} "\""
sentence ::= "\"" char{1,140} "\""
findingid ::= "\"fnd_" [0-9a-f]{16} "\""
char ::= [^"\\] | "\\" ["\\/bfnrt]
ws ::= " "?
"""

SYSTEM_PROMPT = """You are a cyber-defence analyst assistant.

You will be given a brief containing findings that have ALREADY been proven by
deterministic analysis. Your job is to interpret them, not to detect anything.

Rules:
- Every claim you make must cite at least one finding ID from the brief.
- Never state a fact the brief does not contain. If you are unsure, say less.
- Do not invent hostnames, IP addresses, malware families, or timestamps.
- Recommend investigative next steps only. You cannot block, kill, or change
  anything, and must never imply that you can.
Be concise and concrete."""

USER_TEMPLATE = """{brief}

Produce:
1. narrative: two or three sentences explaining what this host appears to be
   doing and why the findings fit together.
2. claims: individual assertions, each citing the finding IDs that support it.
3. actions: what an analyst should check next, in order.

Keep the narrative under 350 characters and finish your sentences.
"""


@dataclass
class Completion:
    """What a backend returns, with the cost of producing it."""

    text: str
    prompt_tokens: int
    completion_tokens: int
    model: str

    def parse(self) -> dict[str, Any]:
        """Decode the constrained JSON response.

        Returns an empty structure rather than raising: a malformed response
        should cost an incident its narrative, not abort the run. With the
        grammar applied this path should be unreachable, and it exists for
        backends that cannot constrain sampling.
        """
        try:
            payload = json.loads(self.text)
        except (json.JSONDecodeError, TypeError):
            return {"narrative": "", "claims": [], "actions": []}
        if not isinstance(payload, dict):
            return {"narrative": "", "claims": [], "actions": []}
        return payload


@runtime_checkable
class ReasoningBackend(Protocol):
    """Anything that can turn a prompt into constrained JSON."""

    name: str

    def available(self) -> bool: ...

    def complete(self, system: str, user: str, max_tokens: int = 512) -> Completion: ...


class UnavailableBackend:
    """The honest null object: reports absence rather than faking presence."""

    name = "unavailable"

    def __init__(self, reason: str) -> None:
        self.reason = reason

    def available(self) -> bool:
        return False

    def complete(self, system: str, user: str, max_tokens: int = 512) -> Completion:
        raise RuntimeError(f"No reasoning backend available: {self.reason}")


class LlamaCppBackend:
    """llama.cpp via `llama-cpp-python`, with grammar-constrained sampling."""

    name = "llama.cpp"

    def __init__(
        self,
        model_path: str | Path,
        context_size: int = 4096,
        threads: int | None = None,
        seed: int = 1337,
    ) -> None:
        self.model_path = Path(model_path)
        self.context_size = context_size
        self.threads = threads
        # Fixed seed by default. A security report that changes wording every
        # time it is regenerated is one an analyst cannot diff against
        # yesterday's.
        self.seed = seed
        self._llama: Any | None = None
        self._grammar: Any | None = None

    def available(self) -> bool:
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return False
        return self.model_path.is_file()

    def _load(self) -> Any:
        if self._llama is not None:
            return self._llama

        from llama_cpp import Llama, LlamaGrammar

        kwargs: dict[str, Any] = {
            "model_path": str(self.model_path),
            "n_ctx": self.context_size,
            "seed": self.seed,
            "verbose": False,
        }
        if self.threads is not None:
            kwargs["n_threads"] = self.threads

        self._llama = Llama(**kwargs)
        self._grammar = LlamaGrammar.from_string(RESPONSE_GRAMMAR, verbose=False)
        return self._llama

    def complete(self, system: str, user: str, max_tokens: int = 512) -> Completion:
        llama = self._load()
        response = llama.create_chat_completion(
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            grammar=self._grammar,
            max_tokens=max_tokens,
            temperature=0.2,  # interpretation, not creative writing
        )
        usage = response.get("usage", {})
        return Completion(
            text=response["choices"][0]["message"]["content"],
            prompt_tokens=int(usage.get("prompt_tokens", 0)),
            completion_tokens=int(usage.get("completion_tokens", 0)),
            model=self.model_path.name,
        )


class ScriptedBackend:
    """A backend that replays fixed responses. For tests only.

    Lets the brief, the verifier and the wiring be tested deterministically
    without a 2GB model file, including the responses a real small model
    actually produces — fabricated citations among them.
    """

    name = "scripted"

    def __init__(self, responses: list[str], model: str = "scripted") -> None:
        self.responses = list(responses)
        self.model = model
        self.calls: list[tuple[str, str]] = []

    def available(self) -> bool:
        return bool(self.responses)

    def complete(self, system: str, user: str, max_tokens: int = 512) -> Completion:
        self.calls.append((system, user))
        text = self.responses.pop(0) if self.responses else "{}"
        return Completion(
            text=text,
            prompt_tokens=len(user) // 4,
            completion_tokens=len(text) // 4,
            model=self.model,
        )


def default_backend(model_path: str | Path | None = None) -> ReasoningBackend:
    """Pick a backend, or return one that explains why there is none."""
    if model_path is None:
        return UnavailableBackend("no model path configured (see docs/models.md)")

    backend = LlamaCppBackend(model_path)
    if not backend.available():
        try:
            import llama_cpp  # noqa: F401
        except ImportError:
            return UnavailableBackend("llama-cpp-python is not installed (pip install -e '.[llm]')")
        return UnavailableBackend(f"model file not found: {model_path}")
    return backend
