"""The retention state the audit chain records, and the rules a ``policy`` seal must follow.

A ``policy`` seal holds the state the pruner acts on: one entry per setting of the settings registry that an
administrator may change and whose lowering deletes sooner (the chain's settings), and one for the reduction
delay. Each entry is

    {"value": v, "source": "env|default|setting|clamped|held", "setting": s|null, "request_seq": r|null,
     "set_by": seq}

``setting`` is the value an administrator set (null when none has); ``value`` is that setting, or the .env
input or default, resolved under the .env bounds of the same state (source ``clamped`` when a bound moved it).
``held`` is the first start's maximum kept at "for ever" while the server's request to apply a positive
AUDIT_LOG_RETENTION_DAYS waits. Only .env sets the delay: its entry always has source env or default, and no
request, change or veto may name it. ``inputs`` holds every .env input the state is built from, as the raw
text .env gives (null when unset), so a change of .env is told by its inputs, never by the values they give.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from types import SimpleNamespace
from typing import Any, Dict, Optional

from app.core import settings_registry as registry

DELAY_ENTRY = "reduction_delay_days"
DELAY_INPUT = "RETENTION_REDUCTION_DELAY_DAYS"
MAX_DAYS = "audit_max_days"
MAX_DAYS_INPUT = "AUDIT_LOG_RETENTION_DAYS"

SOURCES = ("env", "default", "setting", "clamped", "held")
CAUSES = ("genesis", "env", "request", "applies", "database", "restore")
FIELDS = ("value", "source", "setting", "request_seq")

_TRUE = {"1", "on", "t", "true", "y", "yes"}
_FALSE = {"0", "off", "f", "false", "n", "no"}


def chain_specs() -> list:
    """The registry settings the chain records: those an administrator may change and whose change in one
    direction deletes sooner."""
    return sorted((s for s in registry.all_specs() if s.editable == registry.ADMIN and s.reduction is not None),
                  key=lambda s: s.key)


def chain_setting_keys() -> tuple:
    return tuple(s.key for s in chain_specs())


def entry_names() -> tuple:
    return chain_setting_keys() + (DELAY_ENTRY,)


def _delay_spec():
    from app.core import setting_changes
    return registry.spec_for(setting_changes.DELAY_KEY)


def input_names() -> tuple:
    """The .env inputs the state is built from, upper case: each chain setting's own value, floor and
    ceiling, and the delay."""
    names = set()
    for spec in chain_specs():
        for attr in (spec.env, spec.floor, spec.ceiling):
            if isinstance(attr, str) and attr:
                names.add(attr.upper())
    names.add(DELAY_INPUT)
    return tuple(sorted(names))


def raw_inputs(environ=None) -> Dict[str, Optional[str]]:
    """Every input as the process environment gives it (names compared without case, as the app's
    configuration reads them), or None when unset."""
    environ = os.environ if environ is None else environ
    lowered = {k.lower(): v for k, v in environ.items()}
    return {name: lowered.get(name.lower()) for name in input_names()}


def _field_types() -> Dict[str, Any]:
    from app.core.config import Settings
    return {name: f for name, f in Settings.model_fields.items()}


def _parse(kind, raw: str):
    text = raw.strip()
    if kind is bool:
        if text.lower() in _TRUE:
            return True
        if text.lower() in _FALSE:
            return False
        raise ValueError(raw)
    if kind is int:
        return int(text)
    return text


def settings_from_inputs(inputs: Dict[str, Optional[str]]):
    """A settings object with every field at its default, and the given inputs parsed as the app's
    configuration parses them. An input that does not parse is kept as its raw text, which every check then
    refuses."""
    fields = _field_types()
    values = {}
    for name, field in fields.items():
        default = field.default
        if default.__class__.__name__ == "PydanticUndefinedType":
            default = None
        values[name] = default
    for name, raw in inputs.items():
        attr = name.lower()
        if raw is None or attr not in fields:
            continue
        annotation = fields[attr].annotation
        try:
            values[attr] = _parse(annotation if annotation in (int, bool) else str, raw)
        except ValueError:
            values[attr] = raw
    return SimpleNamespace(**values)


def contract_problems(inputs: Dict[str, Optional[str]]) -> list:
    """What the server's startup contract refuses in these inputs (the server never starts with them), and
    a delay under one day."""
    ns = settings_from_inputs(inputs)
    problems = list(registry.check_contract(ns))
    delay = getattr(ns, "retention_reduction_delay_days", None)
    if not isinstance(delay, int) or isinstance(delay, bool) or delay < 1:
        problems.append("the reduction delay is under one day")
    return problems


def _bounds(spec, ns):
    return registry.bounds(spec, ns)


def resolve_setting(spec, setting, ns) -> tuple:
    """(value, source) of an administrator's ``setting`` under the bounds of ``ns``."""
    floor, ceiling = _bounds(spec, ns)
    value = registry.clamp(spec, setting, floor, ceiling)
    return value, ("setting" if value == setting else "clamped")


def input_entry(spec, ns, inputs) -> dict:
    """The entry an .env input or the default gives, resolved under the bounds of the same state."""
    raw = registry._from_env(spec, getattr(ns, spec.env, spec.default)) if spec.env else spec.default
    if registry.check_value(spec, raw) is not None:
        raw = spec.default
    is_set = bool(spec.env) and inputs.get(spec.env.upper()) is not None
    floor, ceiling = _bounds(spec, ns)
    return {"value": registry.clamp(spec, raw, floor, ceiling), "source": "env" if is_set else "default",
            "setting": None, "request_seq": None}


def delay_entry(ns, inputs) -> dict:
    spec = _delay_spec()
    raw = getattr(ns, "retention_reduction_delay_days", spec.default)
    if registry.check_value(spec, raw) is not None:
        raw = spec.default
    return {"value": raw, "source": "env" if inputs.get(DELAY_INPUT) is not None else "default",
            "setting": None, "request_seq": None}


def genesis_state(inputs: Dict[str, Optional[str]], seq: int, *, hold_max_days: bool) -> dict:
    """The first policy seal's state: from .env and the defaults only. ``hold_max_days``: the first start's
    positive AUDIT_LOG_RETENTION_DAYS waits as a request, and the maximum is kept at "for ever" meanwhile."""
    ns = settings_from_inputs(inputs)
    state = {}
    for spec in chain_specs():
        entry = input_entry(spec, ns, inputs)
        if spec.key == MAX_DAYS and hold_max_days:
            value, source = resolve_setting(spec, 0, ns)
            entry = {"value": value, "source": "held" if source == "setting" else "clamped", "setting": 0,
                     "request_seq": None}
        state[spec.key] = {**entry, "set_by": seq}
    state[DELAY_ENTRY] = {**delay_entry(ns, inputs), "set_by": seq}
    return state


def env_state(previous: dict, inputs: Dict[str, Optional[str]], seq: int) -> dict:
    """The state after an .env change: entries of source env or default recomputed from the new inputs, the
    others clamped or released under the new bounds, the admin's setting always kept."""
    ns = settings_from_inputs(inputs)
    state = {}
    specs = {s.key: s for s in chain_specs()}
    for name, old in previous.items():
        new = dict(old)
        if name == DELAY_ENTRY:
            new.update(delay_entry(ns, inputs))
        elif name in specs:
            spec = specs[name]
            if old.get("source") in ("env", "default"):
                fields = input_entry(spec, ns, inputs)
                fields["request_seq"] = old.get("request_seq")
                new.update(fields)
            else:
                value, source = resolve_setting(spec, old.get("setting"), ns)
                if old.get("source") == "held":
                    new.update(value=value, source="held" if source == "setting" else "clamped")
                else:
                    new.update(value=value, source=source)
        changed = any(new.get(f) != old.get(f) for f in FIELDS)
        new["set_by"] = seq if changed else old.get("set_by")
        state[name] = new
    return state


def deletes_sooner(spec, a: dict, b: dict) -> bool:
    """Whether entry ``b`` deletes sooner than entry ``a``: in its value, or in its setting (an entry with no
    setting stands in with its value)."""
    if registry.is_reduction(spec, a.get("value"), b.get("value")):
        return True
    sa = a.get("setting") if a.get("setting") is not None else a.get("value")
    sb = b.get("setting") if b.get("setting") is not None else b.get("value")
    return registry.is_reduction(spec, sa, sb)


def delay_days(state: dict) -> int:
    entry = (state or {}).get(DELAY_ENTRY) or {}
    value = entry.get("value")
    return int(value) if isinstance(value, int) and not isinstance(value, bool) else int(_delay_spec().default)


def value_of(state: dict, key: str):
    entry = (state or {}).get(key) or {}
    if "value" in entry:
        return entry["value"]
    spec = registry.spec_for(key)
    return spec.default if spec is not None else None


GAP = timedelta(hours=12)


def gaps_after(sealed_at: list, seq: int, then: Optional[datetime] = None) -> timedelta:
    """The length of every gap of more than 12 hours in sealed_at between seal ``seq`` and the newest seal,
    and between the newest and ``then`` (the time of a seal about to be written, or now): the time sealing
    did not run, which no delay counts."""
    total = timedelta()
    for i in range(seq, len(sealed_at)):
        step = sealed_at[i] - sealed_at[i - 1]
        if step > GAP:
            total += step
    if then is not None and sealed_at and then - sealed_at[-1] > GAP:
        total += then - sealed_at[-1]
    return total

