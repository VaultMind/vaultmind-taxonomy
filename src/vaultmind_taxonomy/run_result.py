"""RunResult — the shared runtime-result contract the oracles judge.

Produced by the executor (poe-harness stdout) and consumed by the oracles; both
import THIS one definition so the interface can't drift. Chain-specific: SVM
today; an EvmRunResult would add storage/balances/events when EVM lands.

Fully typed, nested: the pubkey-keyed account snapshots, trace nodes, token
balances and return-data are their own dataclasses (not bare dicts), so a
mistyped field fails loud instead of silently returning None — the right default
for a correctness judge. `RunResult.from_dict` is the ONE shared deserializer
(poe-harness JSON on the API side, fixture JSON in tests) so parse can't drift.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field


@dataclass
class AccountSnapshot:
    """One account's state at a point in time (pre- or post-tx). `exists=False`
    means the account was absent; the remaining fields are then defaults."""

    exists: bool = False
    owner: str | None = None
    lamports: int | None = None
    data_hex: str | None = None
    data_len: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "AccountSnapshot":
        return cls(
            exists=bool(d.get("exists", False)),
            owner=d.get("owner"),
            lamports=d.get("lamports"),
            data_hex=d.get("data_hex"),
            data_len=d.get("data_len"),
        )

    def data(self) -> bytes:
        """Raw account data decoded from data_hex (empty -> b'')."""
        return bytes.fromhex(self.data_hex) if self.data_hex else b""


@dataclass
class TraceAccount:
    """An account as it appeared on one instruction node in the trace."""

    pubkey: str | None = None
    is_signer: bool = False
    is_writable: bool = False

    @classmethod
    def from_dict(cls, d: dict) -> "TraceAccount":
        return cls(
            pubkey=d.get("pubkey"),
            is_signer=bool(d.get("is_signer")),
            is_writable=bool(d.get("is_writable")),
        )


@dataclass
class TraceNode:
    """One instruction in the executed tx — top-level (depth 0) or an inner CPI
    (depth 1+). `data_hex` is the raw instruction data (first byte(s) = the
    discriminator); `instruction` is the resolved name when known."""

    program_id: str | None = None
    depth: int = 0
    parent_index: int | None = None
    instruction: str | None = None
    data_hex: str | None = None
    accounts: list[TraceAccount] = field(default_factory=list)

    @classmethod
    def from_dict(cls, d: dict) -> "TraceNode":
        return cls(
            program_id=d.get("program_id"),
            depth=int(d.get("depth") or 0),
            parent_index=d.get("parent_index"),
            instruction=d.get("instruction"),
            data_hex=d.get("data_hex"),
            accounts=[TraceAccount.from_dict(a) for a in (d.get("accounts") or [])],
        )


@dataclass
class TokenBalance:
    """One SPL token account's decoded balance (mint/owner/amount)."""

    account: str | None = None
    mint: str | None = None
    owner: str | None = None
    amount: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "TokenBalance":
        return cls(
            account=d.get("account"),
            mint=d.get("mint"),
            owner=d.get("owner"),
            amount=d.get("amount"),
        )


@dataclass
class ReturnData:
    """Program return data set via sol_set_return_data."""

    program_id: str | None = None
    data_hex: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "ReturnData":
        return cls(program_id=d.get("program_id"), data_hex=d.get("data_hex"))


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
    slot: int | None = None                 # slot the tx was processed in
    unix_timestamp: int | None = None       # tx Clock sysvar (time-based oracles)
    signers: list[str] = field(default_factory=list)  # pubkeys that signed the tx
    logs: list[str] = field(default_factory=list)      # program log lines

    # ── 2. What did it change? ───────────────────────────────────────────────
    accounts: dict = field(default_factory=dict)   # alias -> resolved pubkey (a plain map)
    pdas: dict = field(default_factory=dict)        # alias -> {program_id, seeds:[hex], bump}
    # pubkey -> AccountSnapshot, before/after the tx
    accounts_before: dict[str, AccountSnapshot] = field(default_factory=dict)
    accounts_after: dict[str, AccountSnapshot] = field(default_factory=dict)
    token_balances_before: list[TokenBalance] = field(default_factory=list)
    token_balances_after: list[TokenBalance] = field(default_factory=list)

    # ── 3. How did it happen? ────────────────────────────────────────────────
    trace: list[TraceNode] = field(default_factory=list)   # ordered, CPI-nested
    return_data: ReturnData | None = None
    # prior per-tx results for multi-tx exploits (front-running, TOCTOU); [] if single-tx
    steps: list["RunResult"] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Recursively serialize to a plain dict (nested dataclasses included)."""
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict, *, accounts: dict | None = None) -> "RunResult":
        """Build a RunResult from a raw result dict — the ONE deserializer shared
        by production (poe-harness stdout) and tests (fixture JSON), so the parse
        can't drift. `accounts` (alias -> pubkey) is supplied by the caller when
        the raw dict doesn't carry it."""

        def snaps(m: dict | None) -> dict[str, AccountSnapshot]:
            return {k: AccountSnapshot.from_dict(v) for k, v in (m or {}).items()}

        rd = d.get("return_data")
        return cls(
            tx_succeeded=bool(d.get("tx_succeeded")),
            error_code=d.get("error_code"),
            failed_program=d.get("failed_program"),
            error=d.get("error"),
            compute_units=d.get("compute_units"),
            slot=d.get("slot"),
            unix_timestamp=d.get("unix_timestamp"),
            signers=list(d.get("signers") or []),
            logs=list(d.get("logs") or []),
            accounts=accounts if accounts is not None else (d.get("accounts") or {}),
            pdas=d.get("pdas") or {},
            accounts_before=snaps(d.get("accounts_before")),
            accounts_after=snaps(d.get("accounts_after")),
            token_balances_before=[TokenBalance.from_dict(t) for t in (d.get("token_balances_before") or [])],
            token_balances_after=[TokenBalance.from_dict(t) for t in (d.get("token_balances_after") or [])],
            trace=[TraceNode.from_dict(n) for n in (d.get("trace") or [])],
            return_data=ReturnData.from_dict(rd) if rd else None,
            steps=[cls.from_dict(s) for s in (d.get("steps") or [])],
        )
