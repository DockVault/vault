"""What the host's ``dockvault.py audit retention`` shows and checks (``python -m app.core.audit_integrity
retention``, run in the web container).

Shown: every setting of how long records are kept, as the server has it: the value in force (for a setting the
audit log's integrity chain records, the chain's honoured value, which the pruner acts on), where it comes from,
the .env line that sets the deployment's value and the lines that bound it; and the changes waiting.

Checked, for .env lines the operator gives (``--set NAME=VALUE``): that each names a line of these settings,
that the server would start with them (the settings registry's startup contract), what each value in force
becomes, and which of those changes delete records sooner. A change of .env takes effect when the deployment is
recreated with it, without the delay a change in the panel waits. Nothing is written here: the host tool
writes .env.
"""
from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Dict, List, Optional

from app.core import settings_registry as registry

GROUPS = ("audit_retention", "retention", "audit_integrity", "working_records")
_NAME = re.compile(r"^[A-Z][A-Z0-9_]*$")


class Refused(Exception):
    """A given line the check cannot take, in plain words."""


def specs() -> list:
    return [s for s in registry.all_specs() if s.group in GROUPS]


def env_lines() -> Dict[str, str]:
    """Every .env line these settings read, upper case -> the configuration's field: each setting's own line
    (none for a fixed one) and the lines of its floor and ceiling."""
    out = {}
    for spec in specs():
        if spec.env and spec.editable != registry.FIXED:
            out[spec.env.upper()] = spec.env
        for bound in (spec.floor, spec.ceiling):
            if isinstance(bound, str):
                out[bound.upper()] = bound
    return out


def _row(described: dict, chain: Optional[dict]) -> dict:
    row = {k: described.get(k) for k in ("key", "group", "label", "unit", "kind", "value", "source", "deployment",
                                 "deployment_source", "min", "max", "unlimited", "floor", "ceiling", "env",
                                 "floor_env", "ceiling_env", "editable", "locked", "reduction")}
    if chain is not None:
        # What the pruner acts on: the chain's honoured entry, whatever the database's copy says.
        row["database_value"] = row["value"]
        row["value"] = chain.get("value")
    return row


def _settings_now():
    current = registry._deployment_settings()
    fields = getattr(type(current), "model_fields", None) or vars(current)
    return SimpleNamespace(**{name: getattr(current, name, None) for name in fields})


def parse_lines(given: List[str]) -> Dict[str, str]:
    """``NAME=VALUE`` texts as {NAME: VALUE}; Refused for one that is not of that form, that names a line these
    settings do not read, or that repeats a name."""
    lines = env_lines()
    out: Dict[str, str] = {}
    for text in given:
        name, sep, value = (text or "").partition("=")
        name, value = name.strip(), value.strip()
        if not sep or not _NAME.match(name) or not value or "\n" in value or "\r" in value:
            raise Refused(f"{text!r} is not NAME=VALUE")
        if name not in lines:
            raise Refused(f"{name} is not a .env line of how long records are kept "
                          f"(these are: {', '.join(sorted(lines))})")
        if name in out:
            raise Refused(f"{name} is given twice")
        out[name] = value
    return out


def _parse(field_name: str, raw: str):
    """``raw`` as the app's configuration reads the .env line: validated by the configuration's own field (its
    type and its validators, as at startup), so a spelling the app would refuse to start with is refused here,
    and one it takes is read as it reads it ("+20" and "1_000" are 20 and 1000; digits other than 0-9 are
    refused). Raises Refused, in plain words, for a value the field refuses."""
    from pydantic import ValidationError
    from app.core.config import Settings, settings
    probe = settings.model_copy()
    try:
        Settings.__pydantic_validator__.validate_assignment(probe, field_name, raw)
    except ValidationError as exc:
        annotation = Settings.model_fields[field_name].annotation
        if annotation is bool:
            raise Refused(f"{field_name.upper()}={raw} is not true or false")
        if annotation is int:
            raise Refused(f"{field_name.upper()}={raw} is not a whole number")
        errors = exc.errors()
        raise Refused(f"{field_name.upper()}={raw} is refused by the configuration: "
                      f"{errors[0].get('msg') if errors else exc}")
    return getattr(probe, field_name)


def check(proposed: Dict[str, str], rows_before: List[dict]) -> dict:
    """What ``proposed`` (.env lines) would do: the startup contract's refusals, each value in force that
    changes, and which of those delete sooner."""
    lines = env_lines()
    ns = _settings_now()
    for name, raw in proposed.items():
        setattr(ns, lines[name], _parse(lines[name], raw))
    problems = registry.check_contract(ns)
    real = registry._deployment_settings
    registry._deployment_settings = lambda: ns
    try:
        after = {d["key"]: d for d in registry.describe([s.key for s in specs()])}
    finally:
        registry._deployment_settings = real
    changes, sooner = [], []
    for before in rows_before:
        new = after.get(before["key"])
        if new is None or new["value"] == before["value"]:
            continue
        spec = registry.spec_for(before["key"])
        changes.append({"key": before["key"], "label": before["label"], "unit": before["unit"],
                        "unlimited": before["unlimited"], "before": before["value"], "after": new["value"]})
        if registry.is_reduction(spec, before["value"], new["value"]):
            sooner.append(before["key"])
    return {"problems": problems, "changes": changes, "deletes_sooner": sooner}


def report(db, st, view, record, now, proposed: Optional[Dict[str, str]] = None) -> dict:
    """The answer of ``retention``: the settings, the changes waiting, and the check of ``proposed``."""
    from app.core import audit_chain_pending
    from app.core import audit_chain_policy_seals as chain_seals
    honoured = chain_seals.honoured_state(view, record, now) if view.newest_policy() is not None else {}
    rows = [_row(d, honoured.get(d["key"])) for d in registry.describe([s.key for s in specs()])]
    pending = [{k: e.get(k) for k in ("key", "label", "old", "new", "effective_at", "requested_by", "status")}
               for e in audit_chain_pending.entries(db, st=st, now=now)]
    out = {"settings": rows, "pending": pending, "chain_started": bool(honoured)}
    if proposed:
        before = [dict(row, value=row.get("database_value", row["value"])) for row in rows]
        out["check"] = check(proposed, before)
    return out
