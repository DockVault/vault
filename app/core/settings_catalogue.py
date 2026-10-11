"""What the Settings pages need to sort, mark and search every setting: the settings registry's entries of
every kind (app/core/settings_registry.py), each with its page, level and release, whether it is new to the
administrator looking, and whether the deployment has locked it.

A locked entry says what it is set to and why: the pages fold it into "Set by your provider (N)", read-only.
Its reason names the .env setting that gives the value and SETTINGS_LOCKED_KEYS, which locks it; the words
for whoever set it are "your provider" (a managing operator, or the person who runs the vault). A fixed
setting is the same on every install and a field is never covered by the lock, so neither is ever locked.

Nothing here reads the database: the values come from each process's copy of the managed settings and from
the deployment's settings, and the release this administrator last opened the pages at is passed in.
"""
from __future__ import annotations

from typing import Optional

from app.core import settings_registry as registry

# The preference that keeps, per administrator, the release at which they last opened the Settings pages.
SEEN_PREFERENCE = "settings_seen"


def reason(env: str = "") -> str:
    """Why a locked setting cannot be changed on the pages, and where it can be."""
    where = f" in the deployment's .env ({env})" if env else ""
    return (f"Set by your provider{where} and locked there with SETTINGS_LOCKED_KEYS, so it cannot be changed "
            f"here. Whoever runs the vault changes it there.")


def _row(key: str, entry, current: str, seen: Optional[str], kind: str) -> dict:
    return {"key": key, "kind": kind, "page": entry.page, "level": entry.level, "since": entry.since,
            "new": registry.is_new(entry.since, current, seen), "label": getattr(entry, "label", ""),
            "help": getattr(entry, "help", ""), "locked": False}


def _lock(row: dict, value: str, env: str) -> dict:
    row.update(locked=True, value=value, reason=reason(env))
    return row


def _spec_env(spec) -> str:
    return spec.env.upper() if spec.env else ""


def entries(*, current: str, seen: Optional[str] = None, settings=None) -> list[dict]:
    """One row per entry of the registry, in the order the pages list them: key, kind (setting, listed, group
    or field), page, level, since, new, label and help (empty for a field: its page holds them), locked, and
    for a locked one its value in words and the reason."""
    settings = settings if settings is not None else registry._deployment_settings()
    stored = registry._cache.rows
    rows = []
    for spec in registry.all_specs():
        row = _row(spec.key, spec, current, seen, "setting")
        if registry.is_locked(spec, settings):
            value = registry._resolve(spec, stored, settings)[0]
            _lock(row, registry.shown(spec, value), _spec_env(spec))
        rows.append(row)
    for listed in registry.all_listed():
        row = _row(listed.key, listed, current, seen, "listed")
        if registry.listed_locked(listed.key, settings):
            _lock(row, listed.shown() if listed.shown else "", listed.env)
        rows.append(row)
    for group in registry.all_lock_groups():
        row = _row(group.name, group, current, seen, "group")
        if registry.group_locked(group.name, settings):
            _lock(row, group.shown() if group.shown else "", group.env)
        rows.append(row)
    for field in registry.all_fields():
        rows.append(_row(field.key, field, current, seen, "field"))
    return rows
