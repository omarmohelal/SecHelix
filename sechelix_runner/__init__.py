"""SecHelix Runner — the optional execution runtime for the SecHelix workflow.

The portable Agent Skill is the product. This package is not required to use it,
and nothing in ``sechelix_core`` imports anything from here. Install it when you
want SecHelix orchestrated by code instead of by an agent reading ``SKILL.md``;
skip it and the skill behaves exactly as it always has.

**The runner owns no definitions.** ``finding``, ``evidence``, ``verification``,
``report``, ``scope`` and the release decision are defined by the JSON Schema
contracts in ``schemas/`` and validated by ``sechelix_core.contracts``. This
package consumes them. If a runner module ever needs a field the contract does
not have, the contract is what changes -- a second, runner-shaped definition of a
finding would be two sources of truth, and the whole point of the evidence model
is that there is one.
"""

from __future__ import annotations

__all__ = ["RUNNER_VERSION"]

#: Version of the orchestration layer. Distinct from the SecHelix catalog/skill
#: version because the runner can ship fixes without the methodology changing.
RUNNER_VERSION = "0.1.0"
