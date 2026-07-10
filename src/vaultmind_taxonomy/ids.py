"""Canonical class-ID list — the join key across oracle + prompt packages.

Naqib owns this. Adding a class here is what lets the oracle repo and prompt
repo contribute an `oracle` and prompts for it; the API's assembly fails CI if
any listed id is missing either.
"""
from __future__ import annotations

CLASS_IDS: list[str] = [
    "SOLANA-SEC-V01",  # missing-signer-check
    "SOLANA-SEC-V02",  # missing-owner-check
    "SOLANA-SEC-V03",  # missing-discriminator
    "SOLANA-SEC-V04",  # pda-substitution
    "SOLANA-SEC-V05",  # unsafe-account-close
    "SOLANA-SEC-V06",  # reinitialization
    "SOLANA-SEC-V07",  # cpi-target-spoofing
    "SOLANA-SEC-V08",  # account-data-match
    "SOLANA-SEC-V09",  # duplicate-mutable
    "SOLANA-SEC-V10",  # sysvar-address
    "SOLANA-SEC-V11",  # stale-after-cpi
    "SOLANA-SEC-V12",  # init-frontrunning
    "SOLANA-SEC-V13",  # arithmetic-overflow
    "SOLANA-SEC-V14",  # arithmetic-unit-mismatch
    "SOLANA-SEC-V15",  # missing-state-update
    "SOLANA-SEC-V16",  # incorrect-boundary-check
    "SOLANA-SEC-V17",  # missing-canonical-account-validation
    "SOLANA-SEC-V18",  # missing-reference-count-validation
    "SOLANA-SEC-V19",  # integer-truncation-inconsistency
]
