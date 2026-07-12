"""IP-free descriptive taxonomy — the shared source of truth for vuln classes.

This module holds ONLY the descriptive taxonomy fields (id, name, display_name,
description, audit_question, severity_default, and — when a class sets them —
category / external_refs / related / notable_exploits). It deliberately carries
NO prompts and NO oracle: the API supplies the per-class detection/exploit
prompts and the deterministic PoE oracle, joining them to these entries by id.
"""
from __future__ import annotations

from vaultmind_taxonomy.schema import ClassSpec

TAXONOMY: dict[str, ClassSpec] = {
    "SOLANA-SEC-V01": ClassSpec(
        id="SOLANA-SEC-V01",
        name="missing-signer-check",
        display_name="Missing Signer Check",
        description=(
            "An account treated as authoritative by the handler is declared with a "
            "non-signing type (e.g. AccountInfo, UncheckedAccount) and is never verified "
            "to have signed the transaction. Because Solana lets a transaction reference "
            "any pubkey in its accounts list without a corresponding signature, an attacker "
            "can pass the legitimate authority's pubkey while signing only with their own "
            "key. The program then proceeds as if that authority approved the call, enabling "
            "impersonation of any role used by the handler (admin, owner, payer, etc.)."
        ),
        audit_question="Did the account claiming authority actually sign the transaction?",
        severity_default="high",
    ),
    "SOLANA-SEC-V02": ClassSpec(
        id="SOLANA-SEC-V02",
        name="missing-owner-check",
        display_name="Missing Owner Check",
        description=(
            "A handler deserializes an account's data into a known type (e.g. an SPL Token "
            "account) and trusts the resulting fields without verifying that the account is "
            "actually owned by the expected program. Because any program can write any bytes "
            "into accounts it owns, an attacker can craft a custom account whose data layout "
            "mimics the expected type and pass it to the handler — the unpack succeeds and "
            "the program acts on attacker-controlled values (balances, authorities, "
            "configuration, etc.). The fix is to check the account-header owner against the "
            "expected program ID before trusting the unpacked data, either imperatively "
            "(`account.owner != &expected_program::ID`) or declaratively via Anchor's "
            "`Account<'info, T>` wrapper (which validates ownership at deserialization)."
        ),
        audit_question="Did the bytes I'm about to trust actually come from the expected program?",
        severity_default="high",
    ),
    "SOLANA-SEC-V03": ClassSpec(
        id="SOLANA-SEC-V03",
        name="missing-discriminator-check",
        display_name="Missing Discriminator Check",
        description=(
            "A handler deserializes account data into a typed struct without verifying that "
            "the account is the *right type* among multiple types managed by the program. "
            "When two account types have byte-compatible layouts, deserialization succeeds "
            "even when the wrong type is supplied, and the program operates on "
            "attacker-controlled data interpreted as the expected type — a form of "
            "intra-program type confusion that the V02 owner check does not catch (the "
            "account can be legitimately owned by this program but be the wrong type within "
            "it). The fix is to embed a type discriminant (e.g. an enum prefix or hash tag) "
            "in each account's data and verify it after deserialization. Anchor's "
            "`Account<'info, T>` does this automatically via an 8-byte type discriminator; "
            "native Solana programs must add the check manually."
        ),
        audit_question=(
            "Are the bytes I'm parsing actually the type I think they are, among the types "
            "my program manages?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V04": ClassSpec(
        id="SOLANA-SEC-V04",
        name="pda-substitution",
        display_name="PDA Substitution",
        description=(
            "A handler derives a Program-Derived Address (PDA) — typically used as a signing "
            "authority for CPIs or as the address of a state account — from seeds that are "
            "not unique to the operation being authorized. When the same seeds derive the "
            "same PDA across distinct logical contexts (e.g. all pools sharing a mint produce "
            "the same authority), an attacker can stand up their own context (their own pool, "
            "vault, or state account) whose PDA collides with a victim's, and trick the "
            "program into signing or operating on the victim's resources as if they were the "
            "attacker's. The fix is to include in the seeds a value that uniquely identifies "
            "the operation (per-user pubkey, destination account, owner key, or other "
            "discriminator) so each logical context produces a distinct PDA. Anchor `seeds` "
            "constraints in `#[account(seeds = [...], bump)]` declarations make this "
            "enforceable at the type-check layer."
        ),
        audit_question=(
            "Is this PDA unique to the operation being authorized, or could another context "
            "produce the same one?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V05": ClassSpec(
        id="SOLANA-SEC-V05",
        name="unsafe-account-close",
        display_name="Unsafe Account Close",
        description=(
            "A handler closes an account by draining its lamports to refund rent but does "
            "not zero the account's data or mark it as closed. Solana garbage-collects an "
            "account only between transactions, so an attacker can re-fund the account "
            "(transfer lamports back into it) in the same transaction the close was triggered "
            "from, canceling the garbage collection and leaving the account fully alive — "
            "with its original data, original discriminator, original program ownership — but "
            "having paid no rent. The revived account can then be re-used as if it had never "
            "been closed, allowing replay of state, double-spending of one-time tokens, or "
            "hijacking of identity-bearing accounts. The fix is to zero the data, overwrite "
            "the discriminator with `CLOSED_ACCOUNT_DISCRIMINATOR` (so future "
            "deserializations as the original type fail), and provide a `force_defund` "
            "instruction that anyone can call to drain a revived-closed account. Anchor's "
            "`close = destination` constraint on a typed `Account<T>` field handles all of "
            "this automatically."
        ),
        audit_question=(
            "Does the close handler also invalidate the account's data, or could the account "
            "be revived in the same transaction with its state intact?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V06": ClassSpec(
        id="SOLANA-SEC-V06",
        name="account-reinitialization",
        display_name="Account Reinitialization",
        description=(
            "A handler initializes an account's state (authority, balances, configuration) "
            "without verifying whether the account has already been initialized. Because "
            "Solana accounts are just byte buffers — the program's create-account instruction "
            "allocates space and ownership, but data starts as zeros — any caller who can "
            "pass an existing account into the initialize handler can overwrite its state, "
            "hijacking authority fields or resetting cooldowns. The fix is to either (a) "
            "maintain an `is_initialized` discriminator field that the handler rejects when "
            "already true, or (b) use Anchor's `#[account(init, payer = ..., space = ...)]` "
            "constraint, which atomically creates the account and reverts if it already "
            "exists. The Anchor approach is preferred in modern code; manual discriminator "
            "checks remain relevant for native programs."
        ),
        audit_question=(
            "Does the initialize handler reject accounts that have already been initialized, "
            "or could a caller overwrite the state of an existing account?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V07": ClassSpec(
        id="SOLANA-SEC-V07",
        name="cpi-target-spoofing",
        display_name="CPI Target Spoofing",
        description=(
            "A handler invokes another program via cross-program invocation (CPI) but uses a "
            "caller-provided `AccountInfo` as the program identity without verifying it "
            "matches the expected program ID. Because `solana_program::program::invoke` "
            "dispatches to whichever program is at the address it's given, an attacker can "
            "pass a malicious program in that slot — the CPI runs the attacker's bytecode, "
            "which receives the program's accounts (sources, destinations, authorities) and "
            "can execute arbitrary logic on them while the calling program assumes it called "
            "a trusted target (SPL Token, system program, etc.). The fix is to verify the "
            "program account against the known-correct program ID before invoking, either "
            "imperatively (`account.key != &expected::ID`) or declaratively via Anchor's "
            "`Program<'info, T>` type (which validates the program identity at "
            "deserialization)."
        ),
        audit_question=(
            "Is the program being invoked actually the program I expect, or could the caller "
            "substitute a different one?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V08": ClassSpec(
        id="SOLANA-SEC-V08",
        name="missing-account-data-match",
        display_name="Missing Account Data Match",
        description=(
            "A handler unpacks an account's data into a known type and operates on the "
            "contents without verifying that the user calling the handler is the one recorded "
            "in those bytes. This differs from V02 (program-level owner check) by operating "
            "one layer higher: V02 ensures the account was written by the right program, V08 "
            "ensures the user invoking matches the user the account belongs to. A handler "
            "that passes V02 but skips V08 lets one user act on another user's "
            "legitimately-owned data. The fix compares the calling signer's pubkey to the "
            "relevant identity field stored inside the unpacked account (`token.owner`, "
            "`user.authority`, etc.)."
        ),
        audit_question="Does the data inside this account confirm the calling user is the one entitled to it?",
        severity_default="high",
    ),
    "SOLANA-SEC-V09": ClassSpec(
        id="SOLANA-SEC-V09",
        name="duplicate-mutable-accounts",
        display_name="Duplicate Mutable Accounts",
        description=(
            "A handler accepts two or more mutable account references in its accounts struct "
            "and operates on each as if they were distinct, but never checks the caller "
            "actually passed distinct accounts. Solana lets the caller put the same pubkey in "
            "multiple slots — when the handler writes to `account_a` and then `account_b`, "
            "the second write silently overwrites the first if both point to the same "
            "underlying account. The program acts as if two updates happened when only one "
            "did, breaking invariants that rely on multi-account state changes (paired "
            "transfers, swaps, escrow setups). The fix is to compare the keys of every pair "
            "of mutable account fields and reject duplicates, either imperatively (`if "
            "a.key() == b.key() { Err }`) or declaratively via Anchor's `#[account(constraint "
            "= a.key() != b.key())]`."
        ),
        audit_question=(
            "If the caller passes the same account in two slots, does the handler's behavior "
            "break invariants?"
        ),
        severity_default="medium",
    ),
    "SOLANA-SEC-V10": ClassSpec(
        id="SOLANA-SEC-V10",
        name="missing-sysvar-address-check",
        display_name="Missing Sysvar Address Check",
        description=(
            "A handler accepts a sysvar account (Rent, Clock, EpochSchedule, SlotHashes, "
            "etc.) as an `AccountInfo` and uses its data without verifying the account's "
            "address matches the well-known sysvar pubkey. Because sysvars live at fixed "
            "deterministic addresses, a caller can pass any other account claiming to be the "
            "sysvar and the handler will trust whatever bytes it reads — letting attackers "
            "fake clock readings, rent calculations, or slot-history checks. The fix verifies "
            "the passed account's pubkey against the known sysvar address (`sysvar::rent::ID`, "
            "`sysvar::clock::ID`, etc.), either imperatively (`require_eq!`) or declaratively "
            "via Anchor's typed `Sysvar<'info, Rent>` accessor."
        ),
        audit_question=(
            "Is this sysvar account actually the well-known sysvar, or could it be a fake "
            "account at a different address?"
        ),
        severity_default="medium",
    ),
    "SOLANA-SEC-V11": ClassSpec(
        id="SOLANA-SEC-V11",
        name="stale-account-after-cpi",
        display_name="Stale Account Data After CPI",
        description=(
            "After a cross-program invocation that mutates an account, the calling program's "
            "local `Account<T>` reference still holds the *pre-CPI* state because Anchor "
            "caches deserialized account data at handler entry. Any read of the account after "
            "the CPI returns stale data unless `account.reload()` is called to re-fetch the "
            "post-CPI bytes from the account's data buffer. Handlers that make decisions "
            "based on post-CPI account state (balance checks, role checks, status flags, "
            "computed deltas) will operate on the wrong values — silently bypassing "
            "invariants the post-CPI state was supposed to enforce, double-counting, or "
            "paying out twice. The fix is to call `account.reload()?` after every CPI that "
            "may have mutated the account, before any subsequent read."
        ),
        audit_question=(
            "After this CPI, does the handler read the account again — and if so, did it call "
            "`.reload()` to refresh the local copy?"
        ),
        severity_default="medium",
    ),
    "SOLANA-SEC-V12": ClassSpec(
        id="SOLANA-SEC-V12",
        name="initialization-frontrunning",
        display_name="Initialization Frontrunning",
        description=(
            "An initialization handler that creates a long-lived state account (global "
            "config, treasury, registry, admin record) is callable by anyone — whoever calls "
            "first writes themselves into the account's authority field and claims permanent "
            "control. An attacker who watches the mempool can submit their own initialize() "
            "before the legitimate deployer's transaction lands, taking ownership of the "
            "program's most privileged state for the lifetime of the deployment. Distinct "
            "from V06 (re-initialization, which is overwriting after init); V12 is racing TO "
            "be the first to init. The fix gates the initialize handler against a deploy-time "
            "identity — typically the program's own upgrade authority, read from the BPF "
            "loader's `ProgramData` account at the well-known program-data PDA — so only the "
            "deployer can perform the initial setup. Other valid gates: hardcoded admin "
            "pubkey, multi-sig key, or a deterministic seed tied to deployment."
        ),
        audit_question=(
            "Can anyone call this initialize handler, or is it gated to a deploy-time "
            "identity that an attacker can't impersonate?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V13": ClassSpec(
        id="SOLANA-SEC-V13",
        name="arithmetic-overflow",
        display_name="Arithmetic Overflow / Underflow",
        description=(
            "A handler performs arithmetic on numeric fields (lamport balances, token "
            "amounts, fees, supply tracking, accumulated rewards) using unchecked operators "
            "(`+`, `-`, `*`, `/`, `+=`, `-=`) on bounded integer types (u64, u32, etc.). "
            "Solana programs compile in release mode where Rust's overflow checks are off by "
            "default — `u64::MAX + 1` silently wraps to 0, `0u64 - 1` wraps to `u64::MAX` — "
            "letting an attacker craft inputs whose arithmetic underflows or overflows past "
            "invariant checks. The classic exploit subtracts more than the balance to make "
            "the balance grow, or accumulates additions past `u64::MAX` to reset a counter. "
            "The fix is to use checked operations (`checked_add`, `checked_sub`, "
            "`checked_mul`, `checked_div`) returning `Option`/`Result`, or saturating "
            "operations (`saturating_*`) where overflow should clamp rather than wrap. Anchor "
            "projects with `overflow-checks = true` in Cargo.toml are protected at the "
            "language level; native Solana programs and any code using `wrapping_*` "
            "operations remain vulnerable."
        ),
        audit_question=(
            "Could the arithmetic in this handler overflow or underflow for adversarial input "
            "values, and are checked operations used to prevent it?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V14": ClassSpec(
        id="SOLANA-SEC-V14",
        name="arithmetic-unit-mismatch",
        display_name="Arithmetic Unit Mismatch",
        description=(
            "A quantity is written to state in one unit but later combined with a value in a "
            "different unit. A handler scales or divides an input at write time (e.g. stores a "
            "duration as `window = slots / LEADER_SLOT_WINDOW`, a window count) and then, at "
            "read time, adds or compares that stored value against a raw quantity of the "
            "original unit (e.g. `deposit_slot + window <= current_slot`, mixing window counts "
            "with raw slots). The dimensional mismatch makes a threshold — a vesting/lockup/"
            "timeout boundary — fire at the wrong magnitude (e.g. 4x too early). An attacker "
            "acts on the premature boundary: withdrawing, claiming, or unlocking before the "
            "real deadline. The fix keeps every operand in the same unit domain (multiply back "
            "before storing, or store the raw value and scale consistently at every use)."
        ),
        audit_question=(
            "Is any stored quantity written in one unit (scaled/divided/normalized) but later "
            "added to or compared against a value in a different unit, so a threshold check "
            "(vesting/lockup/timeout) fires at the wrong magnitude?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V15": ClassSpec(
        id="SOLANA-SEC-V15",
        name="missing-state-update",
        display_name="Missing State Update",
        description=(
            "A per-account accounting value that MUST be refreshed before a balance/share "
            "change (a reward-factor snapshot, accrued fees, a checkpoint) is updated on one "
            "account but omitted on another involved in the same operation. A transfer, for "
            "example, preprocesses the source position but never the destination, so the "
            "destination keeps a stale snapshot and is then credited rewards/fees as if it had "
            "held its new balance for the whole prior period — value it never earned. An "
            "attacker cycles balances through the un-refreshed account repeatedly, fabricating "
            "a fresh unearned payout on each hop and draining the pool's accumulated fees. The "
            "fix refreshes EVERY account whose accounting depends on the change before applying "
            "it (cheap/no-op on an empty account, but it resets the snapshot to the present)."
        ),
        audit_question=(
            "Does any handler skip a required per-account state refresh (reward snapshot / fee "
            "accrual / checkpoint) on one account while performing it on another before "
            "changing balances, letting a stale value be reused to claim unearned value?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V16": ClassSpec(
        id="SOLANA-SEC-V16",
        name="incorrect-boundary-check",
        display_name="Incorrect Boundary Check",
        description=(
            "Two mutually-exclusive phases or time windows (deposit vs claim, open vs settle) "
            "are gated by inequalities that OVERLAP at the shared boundary — `<=` on one side "
            "and `>=` on the other against the same value — so at the exact boundary (e.g. "
            "`end_time == claim_time`) both phases are simultaneously active. In that one-slot "
            "overlap an attacker performs both actions atomically: deposit to inflate their "
            "share and immediately claim the disproportionate reward, typically with a flash "
            "loan, then withdraw and repay in the same transaction. The fix uses strict "
            "inequalities (`now < end_time`, `now >= claim_time`) so every value maps to "
            "exactly one active phase and the windows cannot overlap."
        ),
        audit_question=(
            "Do two exclusive phases or time windows use inequalities that overlap at the "
            "boundary (`<=` and `>=` against the same value), letting both be active in the "
            "same slot/timestamp and so in one transaction?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V17": ClassSpec(
        id="SOLANA-SEC-V17",
        name="missing-canonical-account-validation",
        display_name="Missing Canonical Account Validation",
        description=(
            "A handler trusts a supplied account by its OWNER (program) alone, without checking "
            "that it is the canonical, expected instance — and where it overwrites state from "
            "that account it enforces only freshness, not monotonicity/versioning. It accepts, "
            "for example, any price account owned by the oracle program instead of pinning the "
            "one canonical feed key, and updates a stored price whenever the source is recent "
            "rather than strictly newer. An attacker supplies their own program-owned account "
            "with forged contents (a self-published oracle) or replays an older-but-still-fresh "
            "update to roll the trusted value back or spoof it. The fix pins the canonical "
            "account key (or a PDA derived from fixed seeds) and adds a monotonicity/version "
            "guard before overwriting state."
        ),
        audit_question=(
            "Does any handler trust a supplied account based only on its owner (not a pinned "
            "canonical key/PDA), or overwrite state from it without a monotonicity/version "
            "check, so a substituted or stale-but-fresh account is accepted?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V18": ClassSpec(
        id="SOLANA-SEC-V18",
        name="missing-reference-count-validation",
        display_name="Missing Reference Count Validation",
        description=(
            "A parent account can be closed, reinitialized, or repurposed while child accounts "
            "still store a reference (its pubkey) to it, because the protocol tracks no active "
            "dependencies — no reference count, no outstanding-child check. The child is left "
            "holding a dangling reference to freed or reallocated memory; an attacker reuses the "
            "closed parent's address for a substituted account, or drives child handlers that "
            "follow the now-invalid reference to corrupt invariants or siphon value. The fix "
            "refuses to close a parent while any child still references it (a reference count "
            "or non-empty-dependents check), mirroring how Token-2022 forbids closing a mint "
            "whose token supply is non-zero."
        ),
        audit_question=(
            "Can a parent/owner account be closed or reinitialized while child accounts still "
            "store a reference to it, with no reference-count or outstanding-dependent check "
            "guarding the close?"
        ),
        severity_default="high",
    ),
    "SOLANA-SEC-V19": ClassSpec(
        id="SOLANA-SEC-V19",
        name="integer-truncation-inconsistency",
        display_name="Integer Truncation Inconsistency",
        description=(
            "A handler computes a proportional payout or accounting ratio (e.g. an LP's "
            "share of pool reserves) but downcasts one or more wide operands (u128) to a "
            "narrower type (u64) before the division, while performing the corresponding "
            "balance/position accounting at full width. When a legitimate value exceeds the "
            "narrow type's range (e.g. total liquidity > u64::MAX), the downcast wraps it to "
            "a small number, so the computed ratio no longer reflects the true proportion. An "
            "attacker engineers inputs so the truncated ratio is far larger than their real "
            "share, receiving far more value than they are entitled to while their position "
            "is debited only the true (full-width) amount — draining the protocol. The fix is "
            "to perform the whole computation at full width (no premature `as u64`), casting "
            "only the final result once it is provably in range, or to use checked conversions "
            "(`u64::try_from`) that error instead of wrapping."
        ),
        audit_question=(
            "Does any arithmetic downcast a wide operand (u128→u64) before a division or "
            "comparison, so a large legitimate value could wrap and distort the result?"
        ),
        severity_default="high",
    ),
}
