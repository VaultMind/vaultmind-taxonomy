"""ClassSpec — the per-vuln-class contract, minus the parts that live elsewhere.

The taxonomy fields live here (the shared source of truth). The oracle package
supplies `oracle`, the prompt package supplies detection/exploit prompts; the API
joins them by `id` at assembly time.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

# Oracle: (RunResult-like, spec dict) -> bool. Duck-typed on RunResult.
OracleFn = Callable[[object, dict], bool]


@dataclass(frozen=True)
class ClassSpec:
    id: str  # "SOLANA-SEC-V01"
    name: str  # slug: "missing-signer-check"
    display_name: str
    description: str
    audit_question: str
    severity_default: str = "medium"
    category: str = "vulnerability"
    external_refs: dict = field(default_factory=lambda: {"cwe": None, "owasp_solana": None})
    related: dict = field(
        default_factory=lambda: {"mitigated_by": [], "violates": [], "threat_origin": []}
    )
    notable_exploits: list = field(default_factory=list)

    # Filled in by the OTHER packages, joined by id in the API:
    detection_prompt: str = ""  # <- prompt package
    exploit_prompt: str = ""  # <- prompt package
    oracle: OracleFn | None = None  # <- oracle package

    def taxonomy_entry(self) -> dict:
        return {
            "category": self.category,
            "name": self.name,
            "display_name": self.display_name,
            "description": self.description,
            "audit_question": self.audit_question,
            "severity_default": self.severity_default,
            "external_refs": self.external_refs,
            "related": self.related,
            "notable_exploits": self.notable_exploits,
        }
