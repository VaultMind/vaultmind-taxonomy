"""RunResult — the shared runtime-result contract the oracles judge.

Produced by the executor (API side), consumed by the oracles (oracle repo).
Both import THIS one definition so the interface can't drift. Chain-specific:
SVM today; an EvmRunResult would add storage/balances/events when EVM lands.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RunResult:
    """SVM runtime result. `accounts` is alias -> pubkey; `accounts_after`
    is alias -> {owner, data_hex, exists} captured after the exploit tx."""

    tx_succeeded: bool
    logs: list = field(default_factory=list)
    error: str | None = None
    accounts: dict = field(default_factory=dict)
    accounts_after: dict = field(default_factory=dict)
