"""A provider's groups mapped to departments and roles, as an administrator keeps them (Settings, Sign-in, a
provider's Groups page). What a sign-in does with a mapping is in app/services/sso_groups.py; this module holds
what a save may hold and what the page is shown. Nothing here commits.

A mapping names one group **exactly as the provider sends it** (an id or a name, compared letter for letter), and
gives it a department, a role, or both:

* a department: a person in the group joins it at each sign-in through the provider, and leaves it at the first
  sign-in whose token no longer names any group mapped to it;
* the role ``user`` or ``external``: applied at the sign-in (an administrator is never demoted by it);
* the role ``admin``: never given by a sign-in. It opens a request another administrator decides. It can be saved
  only while the provider may raise such requests (its ``sso_admin_mapping``) and its people can hold a password,
  which an administrator needs: on a provider whose people hold none, no request would ever be raised, and the
  save says what to change instead of keeping a mapping that does nothing.

Removing a mapping changes nobody when it is removed, and a role it gave stays: an administrator approved through
its group keeps the role, whatever is mapped to the role later. A department follows the groups still mapped to
it. While another mapping of the provider names the department, a person in it stays only as long as their
sign-ins through the provider name one of those groups, and leaves it at the first that names none; once no
mapping names it, a sign-in no longer touches it, and its members stay until an administrator takes them out. The
same holds when a mapping is added to a department that has members already, and when a mapping's group or
department is changed. Each of the three writes says how many accounts linked to the provider are in such a
department (app/services/sso_groups.py, may_leave). A request for the administrator role that a mapping's group
opened is ended with the mapping: when it is removed, and when its group or its role is changed
(app/services/sso_groups.py, end_requests_of_group).

A route judges a write twice: before it asks the administrator for anything, and again once it holds the provider's
row. The second time it passes ``fresh=True``: the mappings are read again as they are committed, not as this
request loaded them before it waited for the row (a session keeps the values of a row it has loaded).
"""
from __future__ import annotations

import uuid
from typing import Optional

from app.core import sso_policy
from app.services.sso_providers import Conflict, Invalid

MAX_MAPPINGS = 200                   # for one provider
GROUP_MAX = 255
ROLES = ("user", "external", "admin")
FIELDS = ("provider_group", "department_id", "role")

GROUP_TAKEN = "group_mapped"
TOO_MANY = "too_many_mappings"
ADMIN_OFF = "admin_mapping_off"
HOLDS_NO_PASSWORDS = "provider_holds_no_passwords"
UNSET = object()


def _label(row) -> str:
    return (getattr(row, "label", None) or getattr(row, "name", None) or "the provider")


def admin_refusal(row) -> Optional[Conflict]:
    """Why a group of ``row`` cannot be mapped to the administrator role as the provider stands, or None. Asked
    of the provider's own rule for passwords, not of any account's flag: an account that signs in only through
    the provider because it was made at its first sign-in there can be given the role (the approval ends that
    and hands over a link to choose a password); one whose provider lets nobody hold a password cannot."""
    from app.core import sso_only
    if not sso_policy.effective(getattr(row, "policy", None))["sso_admin_mapping"]:
        return Conflict(ADMIN_OFF, (
            f"{_label(row)} may not raise administrator requests. Turn on “Administrator group” on its "
            "Access page first."))
    if sso_only.password_less(row):
        return Conflict(HOLDS_NO_PASSWORDS, (
            f"People of {_label(row)} hold no password, which an administrator needs, so a sign-in through it "
            "raises no administrator request. Allow password sign-in for it on its Access page first."))
    return None


def _group(value) -> str:
    """A group's name or id as a mapping keeps it: letter for letter as it was given, because that is how a
    sign-in compares it with what the provider sends. Nothing is trimmed and no character is refused but a
    control character: trimmed, a group the provider sends with a space around it was saved as a name that
    never matched, with no word of it; and a group whose name holds a no-break space or an invisible mark could
    not be mapped at all."""
    import unicodedata
    if not isinstance(value, str):
        raise Invalid("provider_group", "A text is expected.")
    if (not 1 <= len(value) <= GROUP_MAX or not value.strip()
            or any(unicodedata.category(ch) == "Cc" for ch in value)):
        raise Invalid("provider_group", f"Between 1 and {GROUP_MAX} characters, without control characters.")
    return value


def _department(db, value):
    """The department a mapping names, or None for none. ``value`` is its id, or None."""
    from app.core.models import Group
    if value is None or value == "":
        return None
    try:
        department_id = uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        raise Invalid("department_id", "Unknown department.")
    department = db.query(Group).filter(Group.id == department_id).first()
    if department is None:
        raise Invalid("department_id", "Unknown department.")
    return department


def _role(value) -> Optional[str]:
    if value is None or value == "":
        return None
    if not isinstance(value, str) or value not in ROLES:
        raise Invalid("role", "One of user, external or admin, or none.")
    return value


def of(db, row, *, fresh: bool = False) -> list:
    """The provider's mappings, in the order the page shows them: by the group's name."""
    from app.core.models import SsoGroupMapping
    query = db.query(SsoGroupMapping).filter(SsoGroupMapping.provider_id == row.id)
    if fresh:
        query = query.populate_existing()
    rows = query.all()
    return sorted(rows, key=lambda m: ((m.provider_group or "").lower(), m.provider_group or "", str(m.id)))


def naming(db, department_id) -> int:
    """How many mappings, of every provider, name the department. They go with it when it is deleted (the rows
    cascade), a role on the same mapping included: its page says so before, and its deletion says how many went."""
    from app.core.models import SsoGroupMapping
    return len(db.query(SsoGroupMapping).filter(SsoGroupMapping.department_id == department_id).all())


def one(db, row, mapping_id, *, fresh: bool = False):
    """The mapping ``mapping_id`` of ``row``, or None (an id of another provider's mapping is not this one's)."""
    from app.core.models import SsoGroupMapping
    try:
        mid = uuid.UUID(str(mapping_id))
    except (ValueError, AttributeError, TypeError):
        return None
    query = db.query(SsoGroupMapping).filter(SsoGroupMapping.id == mid, SsoGroupMapping.provider_id == row.id)
    if fresh:
        query = query.populate_existing()
    return query.first()


def judge(db, row, *, provider_group=UNSET, department_id=UNSET, role=UNSET, mapping=None,
          fresh: bool = False) -> tuple:
    """Judge a new mapping of ``row`` (``mapping`` None) or a change to ``mapping``, changing nothing: the group,
    the department (or None) and the role (or None) as they would be stored. A field left out of a change keeps
    what the mapping has."""
    from app.core.models import Group
    if mapping is None:
        group = _group(provider_group if provider_group is not UNSET else None)
        department = _department(db, None if department_id is UNSET else department_id)
        wanted = _role(None if role is UNSET else role)
    else:
        group = mapping.provider_group if provider_group is UNSET else _group(provider_group)
        if department_id is UNSET:
            department = (db.query(Group).filter(Group.id == mapping.department_id).first()
                          if mapping.department_id is not None else None)
        else:
            department = _department(db, department_id)
        wanted = mapping.role if role is UNSET else _role(role)
    if department is None and wanted is None:
        raise Invalid("role", "Choose a department, a role, or both: a mapping with neither does nothing.")
    others = [m for m in of(db, row, fresh=fresh) if mapping is None or m.id != mapping.id]
    if mapping is None and len(others) >= MAX_MAPPINGS:
        raise Conflict(TOO_MANY, f"A provider holds at most {MAX_MAPPINGS} group mappings. Remove one first.")
    if any(m.provider_group == group for m in others):
        raise Conflict(GROUP_TAKEN, "This group is mapped already. Change that mapping instead.")
    # The administrator role: judged when it is asked for, or kept on a mapping whose group changes. A mapping
    # that has it already and only changes its department is left alone, so it can still be edited while the
    # provider's setting is off (it raises nothing meanwhile, and the page says so).
    asks_admin = wanted == "admin" and (mapping is None or mapping.role != "admin" or group != mapping.provider_group)
    if asks_admin:
        refusal = admin_refusal(row)
        if refusal is not None:
            raise refusal
    return group, department, wanted


def create(db, row, *, provider_group, department_id=None, role=None, fresh: bool = False):
    """Add a mapping to ``row``. In the caller's transaction."""
    from app.core.models import SsoGroupMapping
    group, department, wanted = judge(db, row, provider_group=provider_group, department_id=department_id, role=role,
                                      fresh=fresh)
    mapping = SsoGroupMapping(id=uuid.uuid4(), provider_id=row.id, provider_group=group,
                              department_id=department.id if department is not None else None, role=wanted)
    db.add(mapping)
    return mapping


def fields_of(body, *, new: bool) -> dict:
    """The fields a request's body names, for :func:`judge`. A new mapping names its group; a change names any of
    :data:`FIELDS`, and at least one. Anything else in the body is refused by its name."""
    if not isinstance(body, dict):
        raise Invalid("provider_group", "A mapping is expected.")
    for key in body:
        if key not in FIELDS:
            raise Invalid(str(key)[:40], "Unknown field.")
    if new and "provider_group" not in body:
        raise Invalid("provider_group", "Name the provider's group.")
    if not new and not body:
        raise Invalid("provider_group", "Nothing to change.")
    return {key: body[key] for key in FIELDS if key in body}


def differences(db, row, mapping, fields: dict, *, fresh: bool = False) -> tuple:
    """What ``fields`` would change on ``mapping``, changing nothing: ``({field: {"old": ..., "new": ...}}, the
    values as they would be stored)``. A department is recorded by its name. Refused as :func:`judge` refuses."""
    from app.core.models import Group
    group, department, wanted = judge(db, row, mapping=mapping, fresh=fresh, **fields)
    was = (db.query(Group).filter(Group.id == mapping.department_id).first()
           if mapping.department_id is not None else None)
    new_id = department.id if department is not None else None
    changes = {}
    if group != mapping.provider_group:
        changes["provider_group"] = {"old": mapping.provider_group, "new": group}
    if new_id != mapping.department_id:
        changes["department"] = {"old": getattr(was, "name", None), "new": getattr(department, "name", None)}
    if wanted != mapping.role:
        changes["role"] = {"old": mapping.role, "new": wanted}
    return changes, (group, new_id, wanted)


def change(db, row, mapping, fields: dict, *, fresh: bool = False) -> dict:
    """Change ``mapping`` as ``fields`` say (a department or a role given as null is taken away). Returns what
    changed, as :func:`differences` gives it. In the caller's transaction."""
    changes, (group, department_id, wanted) = differences(db, row, mapping, fields, fresh=fresh)
    mapping.provider_group, mapping.department_id, mapping.role = group, department_id, wanted
    return changes


def public(db, row, mapping, *, refusal=UNSET) -> dict:
    """``mapping`` as the page is shown it. ``does_nothing`` says why an administrator mapping raises no request as
    the provider stands, or is None."""
    from app.core.models import Group
    department = (db.query(Group).filter(Group.id == mapping.department_id).first()
                  if mapping.department_id is not None else None)
    if refusal is UNSET:
        refusal = admin_refusal(row)
    idle = refusal if mapping.role == "admin" else None
    return {
        "id": str(mapping.id), "provider_group": mapping.provider_group,
        "department": ({"id": str(department.id), "name": department.name} if department is not None else None),
        "role": mapping.role,
        "does_nothing": ({"reason": idle.reason, "message": str(idle)} if idle is not None else None),
    }


def listing(db, row) -> dict:
    """What the Groups page of ``row`` draws: its mappings, the departments and roles to choose from, whether the
    administrator role can be mapped now (and why not), the name of the claim the groups are read from, and the
    groups the last test sign-in carried (the tester's own: none when the token named none; None when no test
    sign-in has passed)."""
    from app.core.models import Group
    from app.services import sso_sign_in
    refusal = admin_refusal(row)
    departments = sorted(db.query(Group).all(), key=lambda g: ((g.name or "").lower(), str(g.id)))
    last = row.last_test if isinstance(getattr(row, "last_test", None), dict) else {}
    seen = last.get("groups")
    return {
        "mappings": [public(db, row, m, refusal=refusal) for m in of(db, row)],
        "departments": [{"id": str(g.id), "name": g.name,
                         "parent_id": str(g.parent_id) if g.parent_id is not None else None} for g in departments],
        "roles": list(ROLES),
        "admin_role": {"allowed": refusal is None,
                       "why_not": ({"reason": refusal.reason, "message": str(refusal)} if refusal is not None else None)},
        "groups_claim": sso_sign_in.claim_name(row, "groups", "groups"),
        "seen_at_last_test": [str(g) for g in seen] if isinstance(seen, list) else None,
        "limit": MAX_MAPPINGS,
    }
