"""vaultmind-taxonomy — the shared, IP-free contract.

Exports the RunResult the oracles judge, the ClassSpec schema, and the canonical
class-ID list. The oracle package and prompt package both depend on this; the API
joins their contributions by id.
"""
from __future__ import annotations

from vaultmind_taxonomy.data import TAXONOMY
from vaultmind_taxonomy.exploit_spec import (
    ExploitSpec,
    ProgramSpec,
    PdaSpec,
    SetupAccount,
    SpecAccount,
    SpecInstruction,
    ROLES,
    tagged,
)
from vaultmind_taxonomy.ids import CLASS_IDS
from vaultmind_taxonomy.run_result import (
    AccountSnapshot,
    ReturnData,
    RunResult,
    TokenBalance,
    TraceAccount,
    TraceNode,
)
from vaultmind_taxonomy.schema import ClassSpec, OracleFn

__all__ = [
    # runtime result (the evidence)
    "RunResult", "AccountSnapshot", "TraceNode", "TraceAccount", "TokenBalance", "ReturnData",
    # exploit spec (the intent)
    "ExploitSpec", "SpecInstruction", "SpecAccount", "SetupAccount", "PdaSpec", "ProgramSpec",
    "ROLES", "tagged",
    # class registry
    "ClassSpec", "OracleFn", "CLASS_IDS", "TAXONOMY",
]
