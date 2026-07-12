"""vaultmind-taxonomy — the shared, IP-free contract.

Exports the RunResult the oracles judge, the ClassSpec schema, and the canonical
class-ID list. The oracle package and prompt package both depend on this; the API
joins their contributions by id.
"""
from __future__ import annotations

from vaultmind_taxonomy.data import TAXONOMY
from vaultmind_taxonomy.exploit_spec import ExploitSpec, tagged
from vaultmind_taxonomy.ids import CLASS_IDS
from vaultmind_taxonomy.run_result import RunResult
from vaultmind_taxonomy.schema import ClassSpec, OracleFn

__all__ = ["RunResult", "ExploitSpec", "tagged", "ClassSpec", "OracleFn", "CLASS_IDS", "TAXONOMY"]
