"""RunResult — the shared runtime-result contract the oracles judge.

Produced by the executor (API side), consumed by the oracles (oracle repo).
Both import THIS one definition so the interface can't drift. Chain-specific:
SVM today; an EvmRunResult would add storage/balances/events when EVM lands.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class RunResult:
    """SVM runtime result — the evidence a PoE oracle judges. Fields past
    `tx_succeeded` are additive and default-empty (old result JSON still parses)."""

    # ── 1. Did the attack run? ───────────────────────────────────────────────
    tx_succeeded: bool
    error_code: int | None = None           # structured program error code (e.g. 3007)
    failed_program: str | None = None       # program that threw, if any
    error: str | None = None                # human-readable failure reason
    compute_units: int | None = None        # total compute units consumed
    signers: list = field(default_factory=list)  # pubkeys that signed the tx
    logs: list = field(default_factory=list)     # program log lines
    # Contextual metadata
    slot: int | None = None                 # Slot number the transaction was processed in
    unix_timestamp: int | None = None      
    # ── 2. What did it change? ───────────────────────────────────────────────
    accounts: dict = field(default_factory=dict)  # alias -> resolved pubkey
    # alias -> {program_id, seeds:[hex], bump} — how a PDA was derived (bump/seed bugs)
    pdas: dict = field(default_factory=dict)
    # before/after snapshots, alias -> {exists, owner, lamports, data_hex, data_len}
    accounts_before: dict = field(default_factory=dict)
    accounts_after: dict = field(default_factory=dict)
    # SPL token balances, each [{account, mint, owner, amount, decimals}]
    token_balances_before: list = field(default_factory=list)
    token_balances_after: list = field(default_factory=list)

    # ── 3. How did it happen? ────────────────────────────────────────────────
    # ordered, CPI-nested. node = {program_id, depth, parent_index, instruction,
    # data_hex, accounts:[{pubkey, is_signer, is_writable}]}
    trace: list = field(default_factory=list)
    return_data: dict | None = None         # {program_id, data_hex} from sol_set_return_data
    # prior per-tx results for multi-tx exploits (front-running, TOCTOU); [] if single-tx
    steps: list = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict, *, accounts: dict | None = None) -> "RunResult":
        """Build a RunResult from a raw result dict — the ONE deserializer shared
        by production (poe-harness stdout) and tests (fixture JSON), so the parse
        can't drift. `accounts` (alias -> pubkey) is supplied by the caller when
        the raw dict doesn't carry it."""
        return cls(
            tx_succeeded=bool(d.get("tx_succeeded")),
            error_code=d.get("error_code"),
            failed_program=d.get("failed_program"),
            error=d.get("error"),
            slot=d.get("slot"),               
            unix_timestamp=d.get("unix_timestamp"), 
            compute_units=d.get("compute_units"),
            signers=list(d.get("signers") or []),
            logs=list(d.get("logs") or []),
            accounts=accounts if accounts is not None else (d.get("accounts") or {}),
            pdas=d.get("pdas") or {},
            accounts_before=d.get("accounts_before") or {},
            accounts_after=d.get("accounts_after") or {},
            token_balances_before=list(d.get("token_balances_before") or []),
            token_balances_after=list(d.get("token_balances_after") or []),
            trace=list(d.get("trace") or []),
            return_data=d.get("return_data"),
            steps=list(d.get("steps") or []),
        )
