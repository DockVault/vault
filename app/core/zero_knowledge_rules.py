"""Which vault types can be made: the deployment's plan, its allowed types and the administrators' two
zero-knowledge switches, decided in one place.

The inputs:
- the plan (environment, set by the operator): ``PLAN_ZERO_KNOWLEDGE`` (zero-knowledge vaults at all),
  ``PLAN_FORCE_ZERO_KNOWLEDGE`` (everyone must use them), ``PLAN_MAX_ZK_VAULTS`` (-1 no cap, 0 none, N at
  most N) and ``PLAN_ALLOWED_VAULT_TYPES`` (the types that may be made; empty means every type);
- the administrators' saved switches: ``zero_knowledge_enabled`` (never saved counts as on: a plan that
  grants zero-knowledge gets it without a click) and ``force_zero_knowledge`` (with the departments exempted
  from it in ``standard_vault_allowed_groups``).

The rules, so that no mix of them leaves a person with no vault type to make:
- The plan offers zero-knowledge when it includes it and its cap is not 0. A cap of 0 is a plan without
  zero-knowledge: the plan's force and the administrators' force do not hold, and the vault form is told
  zero-knowledge is not available.
- The allowed types never leave nothing: a list naming only zero-knowledge on a plan that does not offer it
  allows every type, as an empty or unrecognised list does.
- Zero-knowledge vaults may be made where the plan offers them and the plan forces them, or the allowed types
  leave only zero-knowledge (an administrator's off switch would leave nothing to make), or the
  administrators' switch is on.
- The administrators' force holds where the plan offers zero-knowledge and their zero-knowledge switch is on.
- The two switches change something only where the plan offers zero-knowledge without forcing it and both
  types are allowed. Elsewhere they are locked: GET /settings says why, the settings page shows them
  disabled and does not send them, and a save that tries to change one is refused with that reason. Their
  saved values are kept, and apply again when the plan or the allowed types change back: a save made while
  the plan lacked zero-knowledge no longer switches it off for good.

A zero-knowledge cap that is reached is not a lock: it is a quota, refused at create with its own message
(the plan's N vaults are in use), and lifted by deleting one or a larger plan.
"""
from typing import Iterable, Mapping, Optional, Set

from app.core.config import settings

ZK = "zero_knowledge"
SWITCHES = ("zero_knowledge_enabled", "force_zero_knowledge")


def plan_offers() -> bool:
    """Whether the plan lets zero-knowledge vaults be made at all: it includes them, and its cap is not 0."""
    cap = settings.plan_max_zk_vaults
    return bool(settings.plan_zero_knowledge) and (cap is None or cap != 0)


def plan_forces() -> bool:
    """Whether the plan's own force holds: only where the plan offers zero-knowledge."""
    return bool(settings.plan_force_zero_knowledge) and plan_offers()


def allowed_types(raw: Optional[str], all_types: Iterable[str]) -> Set[str]:
    """The vault types the operator's list allows. Never empty, and never only a type the plan does not
    offer: either would stop every vault from being made, so it allows every type instead."""
    every = set(all_types)
    wanted = {t.strip().lower() for t in (raw or "").split(",") if t.strip()}
    allowed = wanted & every
    if not allowed or (allowed == {ZK} and not plan_offers()):
        return every
    return allowed


def switch_on(stored: Mapping) -> bool:
    """The administrators' zero-knowledge switch as saved: never saved counts as on."""
    value = (stored or {}).get("zero_knowledge_enabled")
    return True if value is None else bool(value)


def force_on(stored: Mapping) -> bool:
    """The administrators' force as saved: never saved counts as off."""
    return bool((stored or {}).get("force_zero_knowledge"))


def enabled(stored: Mapping, allowed: Set[str]) -> bool:
    """Whether zero-knowledge vaults may be made (the cap aside)."""
    if not plan_offers():
        return False
    if plan_forces() or allowed == {ZK}:
        return True
    return switch_on(stored)


def admin_force_holds(stored: Mapping) -> bool:
    """Whether the administrators' force holds (before any department's exemption)."""
    return plan_offers() and force_on(stored) and switch_on(stored)


def force_in_effect(stored: Mapping, allowed: Set[str]) -> bool:
    """Whether a person in no department must make zero-knowledge vaults."""
    return plan_forces() or allowed == {ZK} or (ZK in allowed and admin_force_holds(stored))


def switch_lock(allowed: Set[str]) -> Optional[str]:
    """Why the two switches cannot change anything now, in words for the settings page; None when they can."""
    if not settings.plan_zero_knowledge:
        return "This deployment's plan does not include zero-knowledge vaults."
    if not plan_offers():
        return "This deployment's plan allows no zero-knowledge vaults."
    if plan_forces():
        return "This deployment's plan requires zero-knowledge vaults."
    if allowed == {ZK}:
        return "This deployment allows only zero-knowledge vaults, so they cannot be turned off."
    if ZK not in allowed:
        return "This deployment does not allow zero-knowledge vaults."
    return None


def settle_switches(payload: Mapping, stored: Mapping, allowed: Set[str]) -> dict:
    """The payload a settings save may store, as to the two switches. Where the switches are locked, a value
    equal to the saved one is taken out (nothing changes, and a switch never saved stays never saved); a
    different value is refused with the reason (ValueError). Where they are not locked, the payload is
    unchanged."""
    out = dict(payload or {})
    reason = switch_lock(allowed)
    if reason is None:
        return out
    saved = {"zero_knowledge_enabled": switch_on(stored), "force_zero_knowledge": force_on(stored)}
    for key in SWITCHES:
        if key not in out:
            continue
        if bool(out[key]) != saved[key]:
            raise ValueError(f"The zero-knowledge settings cannot be changed now: {reason} They are kept as "
                             "saved and apply again when that changes.")
        del out[key]
    return out
