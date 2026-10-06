"""Settings an administrator manages in the panel, within limits the deployment sets.

Each setting is described by a SettingSpec: its kind and bounds; whether an administrator may change it in
the panel (``editable``); whether the deployment may lock it (``lockable``); a floor and a ceiling the
deployment may set in .env; which direction of change deletes data sooner (``reduction``: the caller delays
such a change rather than applying it at once); and its labels. The value in force is resolved in this order:

1. the deployment's value: the .env setting the spec names (``env``), else the spec's default;
2. the administrator's value stored in ``managed_settings``, when the setting is editable in the panel, is
   not locked, and the stored value is valid for the spec (an invalid one is ignored, never trusted);
3. clamped between the floor and the ceiling the deployment sets, when it sets them;
4. a locked setting skips step 2: SETTINGS_LOCKED_KEYS names its key, its group, or ``*``, and the panel
   shows it as set by the deployment.

Stored values are read from memory. Each process keeps a copy of ``managed_settings``, stamped with the
highest version it has seen, and a thread refreshes the copy in the background every REFRESH_SECONDS. A
process that stores a change calls refresh() after its commit. A request never reads the table, and another
process sees a change within REFRESH_SECONDS. Before the first load, and while the table cannot be read, the
copy held last stands (empty at first, so every setting has the deployment's value).

Every change stores a new version, higher than any before it, and clearing a value stores None rather than
deleting the row, so the highest version moves whenever anything changes and a refresh that finds the same
stamp can skip the reload.

``PUT /settings`` refuses every key the registry holds, and every key in ENV_ONLY_KEYS, so the general
settings store cannot hold a second copy of them (refused_settings_keys, settings_refusal).

check_contract() lists what makes the specs impossible to honour with this deployment's .env: a floor above
a ceiling, a value of the wrong kind or out of bounds. start() refuses to start the process while there is
one, and says what it is.

Specs are registered with register(), by the modules listed in SPEC_MODULES, which are imported the first
time the registry is read.

Two more kinds of name may be locked, so that SETTINGS_LOCKED_KEYS covers every setting an administrator
changes in the panel, whatever store keeps it:

- a key another store keeps (register_listed): the rate limits stay in the general settings blob, so that
  a rollback reads them where it always did. The registry lists them, the lock names them, and their own
  resolving ignores an administrator's value while they are locked (listed_locked). PUT /settings still
  takes them, and refuses them while they are locked.
- a group whose settings keep a table of their own (register_lock_group), such as the recording levels:
  their module asks group_locked().

A module whose settings must agree with each other adds a check to the startup contract with
register_contract(): it is given the deployment's settings and returns what contradicts, in plain words.
"""
from __future__ import annotations

import importlib
import os
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Iterable, Mapping, Optional, Union

# What an administrator may do with a setting in the panel.
ADMIN = "admin"          # change it, within the bounds and the deployment's floor and ceiling
ENV_ONLY = "env_only"    # nothing: only .env sets it
FIXED = "fixed"          # nothing: the value is the spec's default, whatever .env says
_EDITABLE = (ADMIN, ENV_ONLY, FIXED)

KINDS = ("int", "bool", "enum", "list", "str")

# Which direction of change deletes data sooner (a reduction).
LOWER = "lower"
HIGHER = "higher"

# Where each value came from, as describe() reports it.
SOURCE_DEFAULT = "default"
SOURCE_ENV = "env"
SOURCE_ADMIN = "admin"
SOURCE_LOCKED = "locked"

# The modules that register specs, imported the first time the registry is read.
SPEC_MODULES: tuple[str, ...] = ("app.core.rate_limit_settings", "app.core.setting_changes", "app.core.retention",
                                 "app.core.audit_retention", "app.core.security_records",
                                 "app.core.audit_privacy")

# Keys that only .env sets and that no registry spec describes. PUT /settings refuses them too (settings_refusal),
# so a settings save can never look as if it had changed one: nothing reads them from the settings store.
#   ZK_KEY_PROOF_ENFORCE: whether a key change to a zero-knowledge vault must carry a key proof.
ENV_ONLY_KEYS: frozenset[str] = frozenset({"ZK_KEY_PROOF_ENFORCE"})

REFRESH_SECONDS = 5.0
# A bound on each read of the table, so a refresh can never hang on it.
_STATEMENT_TIMEOUT_MS = 5000

Bound = Union[str, Callable[[Any], Any], None]


class SettingRefused(ValueError):
    """A value, or a change, the registry will not take. The message says why, in plain words."""


class SettingsContractError(RuntimeError):
    """The specs cannot be honoured with this deployment's .env. The message lists every reason."""


@dataclass(frozen=True)
class SettingSpec:
    """One setting. ``env`` names the attribute of app.core.config.settings that holds the deployment's
    value; ``floor`` and ``ceiling`` name such an attribute, or are a function of those settings, and give
    None when the deployment sets no bound. ``unlimited`` is a value of an int setting that means "no
    limit" (keep for ever, no cap): it ranks above every number, so a ceiling replaces it. ``validate``
    returns a refusal in plain words, or None."""
    key: str
    kind: str
    default: Any
    env: Optional[str] = None
    minimum: Optional[int] = None
    maximum: Optional[int] = None
    choices: tuple = ()
    editable: str = ADMIN
    lockable: bool = True
    floor: Bound = None
    ceiling: Bound = None
    unlimited: Any = None
    reduction: Optional[str] = None
    validate: Optional[Callable[[Any], Optional[str]]] = None
    group: str = ""
    label: str = ""
    help: str = ""
    since: str = ""
    # What a number counts ("days", "MB"), for the text that names a value.
    unit: str = ""


@dataclass(frozen=True)
class ListedKey:
    """A setting another store keeps, listed so that SETTINGS_LOCKED_KEYS can name it."""
    key: str
    group: str
    label: str = ""


_SPECS: dict[str, SettingSpec] = {}
_LISTED: dict[str, ListedKey] = {}
_LOCK_GROUPS: dict[str, str] = {}
_CONTRACTS: list = []
_modules_loaded = False
_modules_lock = threading.Lock()


def register(spec: SettingSpec) -> SettingSpec:
    """Add a spec. A key is registered once; a spec that cannot be right is refused here."""
    if not spec.key or spec.key != spec.key.lower() or not spec.key.replace("_", "").isalnum():
        raise ValueError(f"a setting key is lower-case letters, digits and underscores: {spec.key!r}")
    if spec.key in _SPECS or spec.key in _LISTED:
        raise ValueError(f"{spec.key} is registered twice")
    if spec.kind not in KINDS:
        raise ValueError(f"{spec.key}: unknown kind {spec.kind!r}")
    if spec.editable not in _EDITABLE:
        raise ValueError(f"{spec.key}: unknown editable {spec.editable!r}")
    if spec.reduction not in (None, LOWER, HIGHER):
        raise ValueError(f"{spec.key}: unknown reduction {spec.reduction!r}")
    if spec.kind not in ("int", "bool") and (spec.floor is not None or spec.ceiling is not None
                                             or spec.reduction is not None):
        raise ValueError(f"{spec.key}: only a number or a switch has a floor, a ceiling or a reduction")
    if spec.kind == "enum" and not spec.choices:
        raise ValueError(f"{spec.key}: an enum needs its choices")
    _SPECS[spec.key] = spec
    return spec


def _name_is_valid(name: str) -> bool:
    return bool(name) and name == name.lower() and name.replace("_", "").isalnum()


def register_listed(key: str, *, group: str, label: str = "") -> ListedKey:
    """List a setting another store keeps, so that the lock can name it (and its group)."""
    if not _name_is_valid(key) or not _name_is_valid(group):
        raise ValueError(f"a listed key and its group are lower-case letters, digits and underscores: "
                         f"{key!r}, {group!r}")
    if key in _LISTED or key in _SPECS:
        raise ValueError(f"{key} is registered twice")
    entry = ListedKey(key=key, group=group, label=label)
    _LISTED[key] = entry
    return entry


def register_lock_group(name: str, label: str = "") -> str:
    """Name a group of settings that keep a table of their own, so that the lock can name it."""
    if not _name_is_valid(name):
        raise ValueError(f"a group is lower-case letters, digits and underscores: {name!r}")
    _LOCK_GROUPS[name] = label
    return name


def register_contract(check: Callable[[Any], list]) -> Callable[[Any], list]:
    """Add a check to the startup contract: ``check(settings)`` returns what contradicts, in plain words."""
    if check not in _CONTRACTS:
        _CONTRACTS.append(check)
    return check


def _load_spec_modules() -> None:
    global _modules_loaded
    if _modules_loaded:
        return
    with _modules_lock:
        if not _modules_loaded:
            for name in SPEC_MODULES:
                importlib.import_module(name)
            _modules_loaded = True


def all_specs() -> list[SettingSpec]:
    _load_spec_modules()
    return list(_SPECS.values())


def spec_for(key: str) -> Optional[SettingSpec]:
    _load_spec_modules()
    return _SPECS.get(key)


def all_listed() -> list[ListedKey]:
    _load_spec_modules()
    return list(_LISTED.values())


def refused_settings_keys() -> frozenset[str]:
    """The keys PUT /settings refuses, whatever their case: every registered key and ENV_ONLY_KEYS."""
    _load_spec_modules()
    return frozenset(_SPECS) | frozenset(k.lower() for k in ENV_ONLY_KEYS)


def settings_refusal(key) -> Optional[str]:
    """Why PUT /settings refuses ``key``, whatever its case, or None when it takes it. A key only .env sets
    is managed by the deployment environment; a registered key is a managed setting, saved by its own route."""
    if not isinstance(key, str):
        return None
    name = key.lower()
    if name in {k.lower() for k in ENV_ONLY_KEYS}:
        return f"{name} is managed by the deployment environment"
    if name in refused_settings_keys():
        return f"{name} is not saved here: it is a managed setting"
    return None


# --------------------------------------------------------------------------- values

def _deployment_settings():
    from app.core.config import settings
    return settings


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def check_value(spec: SettingSpec, value) -> Optional[str]:
    """Why ``value`` is not a valid value of ``spec``, in plain words, or None when it is."""
    if spec.kind == "int":
        if not _is_int(value):
            return f"{spec.key} must be a whole number"
        if spec.unlimited is not None and value == spec.unlimited:
            pass
        elif spec.minimum is not None and value < spec.minimum:
            return f"{spec.key} must be at least {spec.minimum}"
        elif spec.maximum is not None and value > spec.maximum:
            return f"{spec.key} must be at most {spec.maximum}"
    elif spec.kind == "bool":
        if not isinstance(value, bool):
            return f"{spec.key} must be true or false"
    elif spec.kind == "enum":
        if value not in spec.choices:
            return f"{spec.key} must be one of {', '.join(map(str, spec.choices))}"
    elif spec.kind == "list":
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            return f"{spec.key} must be a list of text values"
        if spec.choices and any(v not in spec.choices for v in value):
            return f"{spec.key} may hold only {', '.join(map(str, spec.choices))}"
    elif spec.kind == "str":
        if not isinstance(value, str):
            return f"{spec.key} must be text"
    if spec.validate is not None:
        return spec.validate(value)
    return None


def _from_env(spec: SettingSpec, raw):
    """A .env value as the spec's kind: a list is written comma-separated in .env."""
    if spec.kind == "list" and isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    return raw


def _env_is_set(name: str) -> bool:
    """Whether the process environment sets the .env setting ``name`` (compared without case, as
    app.core.config reads it)."""
    wanted = name.lower()
    return any(k.lower() == wanted for k in os.environ)


def deployment_value(spec: SettingSpec, settings=None):
    """(value, source): the .env value when the spec names one and it is valid, else the default. An invalid
    .env value falls back to the default here; check_contract() reports it, and start() refuses to run."""
    settings = settings if settings is not None else _deployment_settings()
    if spec.editable == FIXED or not spec.env:
        return spec.default, SOURCE_DEFAULT
    raw = _from_env(spec, getattr(settings, spec.env, spec.default))
    if check_value(spec, raw) is not None:
        return spec.default, SOURCE_DEFAULT
    return raw, (SOURCE_ENV if _env_is_set(spec.env) else SOURCE_DEFAULT)


def _bound(spec: SettingSpec, bound: Bound, settings):
    if bound is None:
        return None
    value = bound(settings) if callable(bound) else getattr(settings, bound, None)
    if spec.kind == "int" and not _is_int(value):
        return None
    if spec.kind == "int" and value < 0:
        return None          # -1, as for the PLAN_* limits: no bound
    if spec.kind == "bool" and not isinstance(value, bool):
        return None
    return value


def bounds(spec: SettingSpec, settings=None):
    """(floor, ceiling) the deployment sets for ``spec``; each None when it sets none. A negative number, as
    -1 is for the PLAN_* limits, sets none."""
    settings = settings if settings is not None else _deployment_settings()
    return _bound(spec, spec.floor, settings), _bound(spec, spec.ceiling, settings)


def _rank(spec: SettingSpec, value):
    """Order values for clamping and for telling a reduction: ``unlimited`` above every number."""
    if spec.unlimited is not None and value == spec.unlimited:
        return float("inf")
    return int(value)


def clamp(spec: SettingSpec, value, floor, ceiling):
    """``value`` moved into [floor, ceiling]. Only a number or a switch is clamped."""
    if spec.kind not in ("int", "bool"):
        return value
    if floor is not None and _rank(spec, value) < _rank(spec, floor):
        value = floor
    if ceiling is not None and _rank(spec, value) > _rank(spec, ceiling):
        value = ceiling
    return value


def shown(spec: SettingSpec, value) -> str:
    """``value`` of ``spec`` in words: "no limit", "on" or "off", or the number and its unit."""
    if spec.unlimited is not None and value == spec.unlimited:
        return "no limit"
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, list):
        return ", ".join(map(str, value)) or "none"
    return f"{value} {spec.unit}" if spec.unit else str(value)


_shown = shown


def check_bounds(spec: SettingSpec, value, settings=None) -> Optional[str]:
    """Why ``value`` lies outside the floor or the ceiling the deployment sets for ``spec``, in plain words
    naming the .env line that sets the bound, or None. A value inside them is one resolve() keeps as it is."""
    if spec.kind not in ("int", "bool") or value is None:
        return None
    floor, ceiling = bounds(spec, settings)
    if floor is not None and _rank(spec, value) < _rank(spec, floor):
        where = f" ({spec.floor.upper()} in .env)" if isinstance(spec.floor, str) else ""
        if spec.kind == "bool":
            return f"{spec.key} cannot be {_shown(spec, value)}: the deployment keeps it on{where}"
        return f"{spec.key} cannot be {_shown(spec, value)}: the deployment keeps it at least {_shown(spec, floor)}{where}"
    if ceiling is not None and _rank(spec, value) > _rank(spec, ceiling):
        where = f" ({spec.ceiling.upper()} in .env)" if isinstance(spec.ceiling, str) else ""
        return f"{spec.key} cannot be {_shown(spec, value)}: the deployment allows at most {_shown(spec, ceiling)}{where}"
    return None


def is_reduction(spec: SettingSpec, old, new) -> bool:
    """Whether changing ``old`` to ``new`` makes data be deleted sooner, by the spec's ``reduction``."""
    if spec.reduction is None or old is None or new is None:
        return False
    if spec.reduction == LOWER:
        return _rank(spec, new) < _rank(spec, old)
    return _rank(spec, new) > _rank(spec, old)


def locked_tokens(settings=None) -> frozenset[str]:
    """SETTINGS_LOCKED_KEYS as a set of lower-case keys and groups (``*`` for all)."""
    settings = settings if settings is not None else _deployment_settings()
    raw = getattr(settings, "settings_locked_keys", "") or ""
    return frozenset(t.strip().lower() for t in raw.replace(";", ",").replace(" ", ",").split(",") if t.strip())


def is_locked(spec: SettingSpec, settings=None) -> bool:
    """Whether the deployment has locked ``spec``: its key, its group or ``*`` is in SETTINGS_LOCKED_KEYS,
    and the spec may be locked."""
    if not spec.lockable:
        return False
    tokens = locked_tokens(settings)
    return "*" in tokens or spec.key in tokens or bool(spec.group and spec.group.lower() in tokens)


def _tokens_lock(tokens: frozenset, key: str, group: str) -> bool:
    return "*" in tokens or key in tokens or bool(group and group.lower() in tokens)


def listed_locked(key: str, settings=None) -> bool:
    """Whether the deployment has locked the listed setting ``key`` (by its key, its group or ``*``). A key
    nobody listed is never locked here."""
    _load_spec_modules()
    entry = _LISTED.get(key)
    return entry is not None and _tokens_lock(locked_tokens(settings), entry.key, entry.group)


def group_locked(name: str, settings=None) -> bool:
    """Whether the deployment has locked the group ``name`` (by its name or ``*``)."""
    tokens = locked_tokens(settings)
    return "*" in tokens or name.lower() in tokens


def unknown_locked_tokens(settings=None) -> list[str]:
    """Tokens of SETTINGS_LOCKED_KEYS that name no registered key or group."""
    known = ({"*"} | {s.key for s in all_specs()} | {s.group.lower() for s in all_specs() if s.group}
             | set(_LISTED) | {e.group for e in _LISTED.values()} | set(_LOCK_GROUPS))
    return sorted(locked_tokens(settings) - known)


def _stored_value(spec: SettingSpec, stored: Mapping):
    """The administrator's stored value for ``spec`` when it may apply and is valid, else None."""
    if spec.editable != ADMIN or spec.key not in stored:
        return None
    value = stored[spec.key][0]
    if value is None or check_value(spec, value) is not None:
        return None
    return value


def _resolve(spec: SettingSpec, stored: Mapping, settings):
    """(value, source, deployment value, deployment source, stored value, clamped)."""
    deployment, deployment_source = deployment_value(spec, settings)
    locked = is_locked(spec, settings)
    admin = None if locked else _stored_value(spec, stored)
    value, source = (admin, SOURCE_ADMIN) if admin is not None else (deployment, deployment_source)
    floor, ceiling = bounds(spec, settings)
    clamped_value = clamp(spec, value, floor, ceiling)
    if locked:
        source = SOURCE_LOCKED
    return clamped_value, source, deployment, deployment_source, admin, clamped_value != value


def resolve(key: str):
    """The value in force for ``key``, from memory only. Raises KeyError for a key nobody registered."""
    spec = spec_for(key)
    if spec is None:
        raise KeyError(key)
    return _resolve(spec, _cache.rows, _deployment_settings())[0]


def describe(keys: Optional[Iterable[str]] = None) -> list[dict]:
    """One row per setting, for the panel: the value in force and where it came from (``source``: default,
    env, admin or locked), the deployment's value, the stored value, the bounds, and the labels."""
    settings = _deployment_settings()
    stored = _cache.rows
    wanted = None if keys is None else set(keys)
    rows = []
    for spec in all_specs():
        if wanted is not None and spec.key not in wanted:
            continue
        value, source, deployment, deployment_source, admin, clamped = _resolve(spec, stored, settings)
        floor, ceiling = bounds(spec, settings)
        rows.append({
            "key": spec.key, "group": spec.group, "label": spec.label, "help": spec.help, "since": spec.since,
            "kind": spec.kind, "choices": list(spec.choices), "min": spec.minimum, "max": spec.maximum,
            "unlimited": spec.unlimited, "unit": spec.unit, "floor": floor, "ceiling": ceiling,
            "editable": spec.editable,
            "lockable": spec.lockable, "locked": is_locked(spec, settings), "reduction": spec.reduction,
            "value": value, "source": source, "clamped": clamped, "deployment": deployment,
            "deployment_source": deployment_source, "stored": admin,
            "stored_version": stored.get(spec.key, (None, None))[1],
            "env": spec.env.upper() if spec.env and spec.editable != FIXED else None,
            "floor_env": spec.floor.upper() if isinstance(spec.floor, str) else None,
            "ceiling_env": spec.ceiling.upper() if isinstance(spec.ceiling, str) else None,
        })
    return rows


def check_contract(settings=None) -> list[str]:
    """Everything that makes a spec impossible to honour with this deployment's .env, in plain words."""
    settings = settings if settings is not None else _deployment_settings()
    problems = []
    for spec in all_specs():
        why = check_value(spec, spec.default)
        if why is not None:
            problems.append(f"{spec.key}: its default is not valid ({why})")
        if spec.env and spec.editable != FIXED:
            raw = _from_env(spec, getattr(settings, spec.env, spec.default))
            why = check_value(spec, raw)
            if why is not None:
                problems.append(f"{spec.env.upper()} is not valid ({why})")
        floor, ceiling = bounds(spec, settings)
        for name, bound, value in (("floor", spec.floor, floor), ("ceiling", spec.ceiling, ceiling)):
            raw = getattr(settings, bound, None) if isinstance(bound, str) else None
            if raw is not None and value is None and not (spec.kind == "int" and _is_int(raw) and raw < 0):
                problems.append(f"{bound.upper()}, the {name} of {spec.key}, is not a valid value")
        if floor is not None and ceiling is not None and _rank(spec, floor) > _rank(spec, ceiling):
            problems.append(f"{spec.key}: the floor ({floor}) is above the ceiling ({ceiling})")
    for check in list(_CONTRACTS):
        problems.extend(check(settings))
    return problems


# --------------------------------------------------------------------------- the stored values

class _Cache:
    """The process's copy of managed_settings: key -> (value, version), and the highest version seen."""

    def __init__(self):
        self.rows: dict[str, tuple] = {}
        self.stamp: Optional[int] = None
        self.loaded_at: Optional[float] = None
        self._lock = threading.Lock()

    def refresh(self, session_factory) -> bool:
        """Read the table's stamp; reload the rows when it moved. True when the rows were reloaded."""
        from sqlalchemy import func, text
        from app.core.models import ManagedSetting
        with self._lock:
            db = session_factory()
            try:
                if db.bind is not None and db.bind.dialect.name == "postgresql":
                    db.execute(text(f"SET LOCAL statement_timeout = {_STATEMENT_TIMEOUT_MS}"))
                stamp = db.query(func.max(ManagedSetting.version)).scalar() or 0
                if stamp == self.stamp:
                    self.loaded_at = time.monotonic()
                    return False
                rows = {r.key: (r.value, r.version) for r in db.query(ManagedSetting).all()}
                db.rollback()
            finally:
                db.close()
            # One assignment, so a reader sees the old copy or the new one, never half of each.
            self.rows = rows
            self.stamp = stamp
            self.loaded_at = time.monotonic()
            return True


_cache = _Cache()
_refresher: Optional[threading.Thread] = None
_refresher_stop = threading.Event()


def _default_session_factory():
    # Never the call that initializes this process's runtime: the refresh runs on a thread of its own, and
    # initializing there would overwrite the settings object under the process (see started_session).
    from app.core.database import started_session
    return started_session()


def _say(message: str) -> None:
    """Print a line for the operator. Never raises: a console that cannot take it loses the line."""
    try:
        print(message, flush=True)
    except Exception:  # noqa: BLE001
        pass


def refresh(session_factory=None) -> bool:
    """Bring this process's copy up to date now. Never raises: a failure keeps the copy it had."""
    try:
        return _cache.refresh(session_factory or _default_session_factory)
    except Exception as exc:  # noqa: BLE001 -- the copy held last stands
        from app.core.config import RuntimeNotReady
        if isinstance(exc, RuntimeNotReady):
            return False  # the process has not started yet: the next turn asks again
        _say(f"Warning: managed settings were not refreshed ({type(exc).__name__}); the values held stay "
             "in force")
        return False


def stamp() -> Optional[int]:
    """The highest version this process's copy holds (None before the first load)."""
    return _cache.stamp


def start(session_factory=None, *, interval: float = REFRESH_SECONDS, load_now: bool = True) -> threading.Thread:
    """At a process's start: refuse to go on while the specs cannot be honoured, load the stored values,
    and keep them fresh on a daemon thread. Says which SETTINGS_LOCKED_KEYS entries name nothing.
    ``load_now=False`` leaves the first load to the thread, for a process whose start must not wait on the
    database (the SFTP server's)."""
    problems = check_contract()
    if problems:
        raise SettingsContractError("The settings in .env contradict each other: " + "; ".join(problems))
    unknown = unknown_locked_tokens()
    if unknown:
        _say(f"Warning: SETTINGS_LOCKED_KEYS names no setting or group: {', '.join(unknown)}")
    factory = session_factory or _default_session_factory
    if load_now:
        refresh(factory)
    global _refresher
    if _refresher is not None and _refresher.is_alive():
        return _refresher
    _refresher_stop.clear()

    def run():
        if not load_now:
            refresh(factory)
        while not _refresher_stop.wait(interval):
            refresh(factory)

    _refresher = threading.Thread(target=run, name="managed-settings-refresh", daemon=True)
    _refresher.start()
    return _refresher


def stop() -> None:
    """End the background refresh (tests, and a process on its way out)."""
    _refresher_stop.set()


def store(db, key: str, value, *, by_id=None, by_name: Optional[str] = None, now: Optional[datetime] = None) -> int:
    """Store an administrator's value for ``key`` in ``db``'s transaction and return its version. ``None``
    clears it, so the deployment's value applies again. It does not commit: the caller commits, with the
    audit row of the change, and then calls refresh(). Raises SettingRefused for a key nobody registered,
    a setting the panel may not change or the deployment has locked, and an invalid value."""
    from sqlalchemy import func, text
    from app.core.models import ManagedSetting
    spec = spec_for(key)
    if spec is None:
        raise SettingRefused(f"{key} is not a setting the panel manages")
    if spec.editable != ADMIN:
        raise SettingRefused(f"{key} is set by the deployment, not in the panel")
    if is_locked(spec):
        raise SettingRefused(f"{key} is locked by the deployment")
    if value is not None:
        why = check_value(spec, value)
        if why is not None:
            raise SettingRefused(why)
    if db.bind is not None and db.bind.dialect.name == "postgresql":
        # Versions are one sequence across the table, so that the highest one moves on every change. Two
        # stores at once would otherwise read the same highest version.
        db.execute(text("LOCK TABLE managed_settings IN SHARE ROW EXCLUSIVE MODE"))
    version = (db.query(func.max(ManagedSetting.version)).scalar() or 0) + 1
    row = db.get(ManagedSetting, key)
    when = now or datetime.utcnow()
    if row is None:
        db.add(ManagedSetting(key=key, value=value, version=version, updated_by=by_id,
                              updated_by_name=by_name, updated_at=when))
    else:
        row.value, row.version, row.updated_by, row.updated_by_name, row.updated_at = (
            value, version, by_id, by_name, when)
    db.flush()
    return version
