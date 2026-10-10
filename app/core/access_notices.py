"""Telling a vault's owner when someone else gives a person access to one of their vaults.

Every change that newly reaches another person's vault for someone tells that vault's owner, in the change's own
transaction (the change is not committed without its notice, and a notice that cannot be written fails the
change):

- a grant to a person (POST /vaults/{id}/permissions);
- a grant to a department (POST /vaults/{id}/group-access): its members;
- adding people to a department (POST /groups/{id}/members) that has access to vaults, or that a share of an item
  in a vault is addressed to (they can then claim it);
- removing someone's own member row on a vault (DELETE /vaults/{id}/permissions/{user}) when their departments
  hold more there than the row gave them.

"Newly reaches" is the question the self-access guard asks (api_server._gains_own_access), asked for another
person: a permission on the vault they did not hold before the change (read, write, delete or manage), as
PermissionService resolves it without share claims; for a share, a claim they could not make before on a vault
they cannot read.

The owner is told in the app always, and by email through the owners' outbox (app/core/owner_notices.py, kind
``access_granted``) when the person who made the change could not open that vault before it, such as an
administrator who is not one of its members. A change the owner makes tells nobody, and nobody is told of access
given to the owner. One notice per owner per change, however many people and vaults it reaches.

The notice names each person given access, how old their account is, who created it, and whether its password
was set by someone else (app/core/password_origin.py). It never names a vault (vault names are sealed at rest): it
says how many, and the app opens the vault when there is one.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable, List, Optional

from sqlalchemy import and_, select

KIND = "access_granted"
NOTICE_TYPE = "vault_access_granted"
EMAIL_ACTION = "vault_access_notice"
# Where the in-app notice opens: one vault reached opens it; several open nothing (the notice says how many).
TARGET_PREFIX = "#vault/"

GRANT = "grant"
DEPARTMENT = "department"
JOINED = "joined_department"
ROW_REMOVED = "member_row_removed"
SHARE = "department_share"
VIAS = (GRANT, DEPARTMENT, JOINED, ROW_REMOVED, SHARE)

LEVELS = ("read", "write", "delete", "manage")
NONE = {k: False for k in LEVELS}
# The most people a notice describes one by one; the rest are counted.
PEOPLE_SHOWN = 10
_CHUNK = 500


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


def _uuid(value) -> uuid.UUID:
    return value if isinstance(value, uuid.UUID) else uuid.UUID(str(value))


# --------------------------------------------------------------------------- what a person holds

def held_many(db, vault, user_ids: Iterable) -> dict:
    """What each of ``user_ids`` holds on ``vault`` now, {str(user id): {read, write, delete, manage}}, as
    PermissionService.get_vault_permissions resolves it without share claims: the owner everything, a member row
    what it says (it overrides departments), else the departments' grants (read, plus write when one grants
    write; never on a zero-knowledge vault), else nothing. Three queries for any number of people."""
    from app.core.models import user_groups, vault_group_access, vault_members
    ids = list(dict.fromkeys(_uuid(u) for u in user_ids if u))
    out = {str(u): dict(NONE) for u in ids}
    if not ids or vault is None:
        return out
    members, groups = {}, {}
    for start in range(0, len(ids), _CHUNK):
        part = ids[start:start + _CHUNK]
        for r in db.execute(select(vault_members).where(and_(vault_members.c.vault_id == vault.id,
                                                              vault_members.c.user_id.in_(part)))).fetchall():
            members[str(r.user_id)] = {"read": bool(r.read_permission), "write": bool(r.write_permission),
                                       "delete": bool(r.delete_permission),
                                       "manage": bool(getattr(r, "manage_permission", False))}
        if getattr(vault, "type", "standard") == "zero_knowledge":
            continue
        rows = db.execute(
            select(user_groups.c.user_id, vault_group_access.c.permission)
            .select_from(user_groups.join(vault_group_access,
                                          vault_group_access.c.group_id == user_groups.c.group_id))
            .where(and_(vault_group_access.c.vault_id == vault.id, user_groups.c.user_id.in_(part)))).fetchall()
        for uid, permission in rows:
            groups[str(uid)] = groups.get(str(uid), False) or permission == "write"
    for uid in ids:
        key = str(uid)
        if vault.owner_id is not None and str(vault.owner_id) == key:
            out[key] = {k: True for k in LEVELS}
        elif key in members:
            out[key] = members[key]
        elif key in groups:
            out[key] = {"read": True, "write": groups[key], "delete": False, "manage": False}
    return out


def level_of(perms: dict) -> Optional[str]:
    """The highest level ``perms`` carries, or None."""
    for k in reversed(LEVELS):
        if perms.get(k):
            return k
    return None


def gained(before: dict, after: dict) -> List[str]:
    return [k for k in LEVELS if after.get(k) and not before.get(k)]


# --------------------------------------------------------------------------- watching a change

@dataclass
class _VaultWatch:
    vault: object
    before: dict
    via: str
    department: Optional[str]


@dataclass
class _ShareWatch:
    share: object
    vault: object
    could_claim: dict
    could_read: dict
    department: Optional[str]


@dataclass
class _Entry:
    owner_id: str
    member_id: str
    vault_id: str
    via: str
    level: Optional[str]
    widened: bool
    department: Optional[str]
    granter_member: bool
    shares: int = 0


@dataclass
class Reach:
    """What one change gives people on other people's vaults. ``watch`` and ``watch_share`` before the change,
    ``tell`` after it is written (flushed) and before its commit, in the same session."""
    db: object
    granter: object
    vaults: List[_VaultWatch] = field(default_factory=list)
    shares: List[_ShareWatch] = field(default_factory=list)
    _granter_reads: dict = field(default_factory=dict)

    def _granter_member(self, vault) -> bool:
        key = str(vault.id)
        if key not in self._granter_reads:
            mine = held_many(self.db, vault, [self.granter.id]).get(str(self.granter.id)) or NONE
            self._granter_reads[key] = bool(mine.get("read"))
        return self._granter_reads[key]

    def _others(self, vault, user_ids) -> list:
        owner = str(vault.owner_id) if vault.owner_id is not None else None
        return [u for u in dict.fromkeys(str(x) for x in user_ids if x) if u != owner]

    def watch(self, vault, user_ids: Iterable, *, via: str, department: Optional[str] = None) -> None:
        """Before the change: what each of ``user_ids`` holds on ``vault``. The owner's own change, and the
        owner as the one given access, are left out."""
        if via not in VIAS:
            raise ValueError(f"unknown way in: {via}")
        if vault is None or vault.owner_id is None or str(vault.owner_id) == str(self.granter.id):
            return
        ids = self._others(vault, user_ids)
        if not ids:
            return
        self._granter_member(vault)
        self.vaults.append(_VaultWatch(vault, held_many(self.db, vault, ids), via, department))

    def watch_share(self, share, vault, user_ids: Iterable, *, department: Optional[str] = None) -> None:
        """Before the change: whether each of ``user_ids`` could claim ``share`` (on ``vault``) and read its
        vault. A share of a zero-knowledge vault is never claimed, so it is left out."""
        if vault is None or share is None or getattr(vault, "type", "standard") == "zero_knowledge":
            return
        if vault.owner_id is None or str(vault.owner_id) == str(self.granter.id):
            return
        ids = self._others(vault, user_ids)
        if not ids:
            return
        self._granter_member(vault)
        self.shares.append(_ShareWatch(share, vault, {u: _may_claim(self.db, share, u) for u in ids},
                                       {u: p["read"] for u, p in held_many(self.db, vault, ids).items()},
                                       department))

    def entries(self) -> List[_Entry]:
        """After the change (flushed, not committed): what it newly gave, one entry per person and vault."""
        if not self.vaults and not self.shares:
            return []
        self.db.flush()
        out = []
        for w in self.vaults:
            after = held_many(self.db, w.vault, list(w.before))
            for uid, before in w.before.items():
                if gained(before, after.get(uid, NONE)):
                    out.append(_Entry(str(w.vault.owner_id), uid, str(w.vault.id), w.via, level_of(after[uid]),
                                      bool(before.get("read")), w.department,
                                      self._granter_reads.get(str(w.vault.id), False)))
        for s in self.shares:
            reads = held_many(self.db, s.vault, list(s.could_claim))
            for uid, could in s.could_claim.items():
                if could or s.could_read.get(uid) or reads.get(uid, NONE).get("read"):
                    continue
                if _may_claim(self.db, s.share, uid):
                    out.append(_Entry(str(s.vault.owner_id), uid, str(s.vault.id), SHARE, None, False,
                                      s.department, self._granter_reads.get(str(s.vault.id), False), shares=1))
        return _merge(out)

    def tell(self, *, now: Optional[datetime] = None) -> int:
        """Tell each owner, in the caller's transaction, of what the change gave on their vaults: the in-app
        notice always, the outbox row (the email) when the one who made it was not a member of one of those
        vaults, and the audit row. Raises on a failure, which fails the change. Returns how many owners."""
        entries = self.entries()
        if not entries:
            return 0
        now = now or utcnow()
        by_owner = {}
        for e in entries:
            by_owner.setdefault(e.owner_id, []).append(e)
        event = uuid.uuid4().hex
        told = 0
        for owner_id, items in by_owner.items():
            if _tell_owner(self.db, owner_id, items, granter=self.granter, event=event, now=now):
                told += 1
        return told


def _may_claim(db, share, user_id) -> bool:
    from app.core import sharing_policy
    from app.core.models import user_groups
    if getattr(share, "status", None) != "active":
        return False
    expires = getattr(share, "expires_at", None)
    if expires is not None and expires <= utcnow():
        return False
    groups = [str(r[0]) for r in db.execute(select(user_groups.c.group_id).where(
        user_groups.c.user_id == _uuid(user_id))).fetchall()]
    return bool(sharing_policy.user_matches_claim_audience(
        share.claim_audience, share.audience_user_ids, share.audience_department_ids, user_id, groups))


def _merge(entries: List[_Entry]) -> List[_Entry]:
    """One entry per owner, person, vault and way in; shares on one vault counted together."""
    merged = {}
    for e in entries:
        key = (e.owner_id, e.member_id, e.vault_id, e.via)
        if key in merged:
            merged[key].shares += e.shares
        else:
            merged[key] = e
    return list(merged.values())


# --------------------------------------------------------------------------- the notice

def person_facts(db, user) -> dict:
    """What the notice says of a person given access: their username, when their account was created and by
    whom (None when not recorded), and whether its password was set by someone else, by whom and when."""
    from app.core import password_origin
    from app.core.models import User
    names = {}
    for uid in (user.created_by, user.password_set_by):
        if uid is not None and uid not in names:
            names[uid] = db.query(User.username).filter(User.id == uid).scalar()
    by_other = password_origin.is_set_by_other(user)
    return {"username": user.username, "created_at": _iso(user.created_at),
            "created_by": names.get(user.created_by) if user.created_by is not None else None,
            "password_set_by_other": by_other,
            "password_set_by": (names.get(user.password_set_by) if user.password_set_by is not None
                                else ("operator@host" if by_other else None)),
            "password_set_at": _iso(user.password_set_by_other_at)}


def details_for(db, items: List[_Entry], *, granter) -> dict:
    """The outbox row's details: who made the change, and for each person (at most PEOPLE_SHOWN) what they were
    given and where they came from; usernames, a department's name, levels, counts, dates and vault ids, never a
    vault's name."""
    from app.core.models import User
    people, order = {}, []
    for e in items:
        if e.member_id not in people:
            order.append(e.member_id)
            people[e.member_id] = []
        people[e.member_id].append(e)
    shown = []
    for uid in order[:PEOPLE_SHOWN]:
        user = db.get(User, _uuid(uid))
        if user is None:
            continue
        grants = people[uid]
        vault_ids = sorted({g.vault_id for g in grants if g.via != SHARE})
        share_vaults = sorted({g.vault_id for g in grants if g.via == SHARE})
        levels = [g.level for g in grants if g.level]
        top = max(levels, key=LEVELS.index) if levels else None
        main = next((g for g in grants if g.via != SHARE), grants[0])
        shown.append({**person_facts(db, user), "vaults": len(vault_ids), "level": top,
                      "widened": all(g.widened for g in grants if g.via != SHARE) and bool(vault_ids),
                      "via": main.via, "department": main.department,
                      "shares": sum(g.shares for g in grants if g.via == SHARE), "share_vaults": len(share_vaults)})
    return {"by": getattr(granter, "username", None), "people": shown, "more_people": max(0, len(order) - len(shown)),
            "vaults": len({e.vault_id for e in items}), "vault_ids": sorted({e.vault_id for e in items})}


_LEVEL_WORDS = {"read": "read", "write": "read and write", "delete": "read, write and delete",
                "manage": "full (manage: they can also give others access)"}


def _when(iso: Optional[str]) -> Optional[datetime]:
    if not iso:
        return None
    try:
        return datetime.fromisoformat(str(iso).rstrip("Z"))
    except ValueError:
        return None


def _age(created: Optional[datetime], now: datetime) -> str:
    if created is None:
        return "at a time not recorded"
    days = max(0, (now - created).days)
    if days == 0:
        hours = max(0, int((now - created).total_seconds() // 3600))
        ago = "less than an hour ago" if hours == 0 else (f"{hours} hour ago" if hours == 1 else f"{hours} hours ago")
    else:
        ago = "1 day ago" if days == 1 else f"{days} days ago"
    return f"on {created:%d %b %Y} ({ago})"


def _who(name: Optional[str]) -> str:
    if name in (None, ""):
        return "someone"
    return "the server's operator" if name == "operator@host" else name


def _vaults(n: int) -> str:
    return "one of your vaults" if n == 1 else f"{n} of your vaults"


def _person_lines(p: dict, *, by: str, now: datetime) -> List[str]:
    name = p.get("username") or "someone"
    dept = p.get("department")
    the_dept = f"the department “{dept}”" if dept else "a department"
    level = _LEVEL_WORDS.get(p.get("level") or "", "some")
    n = int(p.get("vaults") or 0)
    via = p.get("via")
    lines = []
    if n:
        if via == GRANT:
            lines.append(f"{by} widened {name}'s access to {_vaults(n)} to {level}." if p.get("widened")
                         else f"{by} gave {name} {level} access to {_vaults(n)}.")
        elif via == DEPARTMENT:
            lines.append(f"{by} gave {the_dept}, which {name} belongs to, {level} access to {_vaults(n)}.")
        elif via == JOINED:
            lines.append(f"{by} added {name} to {the_dept}, which has {level} access to {_vaults(n)}.")
        elif via == ROW_REMOVED:
            lines.append(f"{by} removed {name}'s own access row on {_vaults(n)}, so {name}'s departments now give "
                         f"{name} {level} access there.")
    shares = int(p.get("shares") or 0)
    if shares:
        lines.append(f"{by} added {name} to {the_dept}, that "
                     f"{'a share' if shares == 1 else str(shares) + ' shares'} of items in "
                     f"{_vaults(int(p.get('share_vaults') or 1))} {'is' if shares == 1 else 'are'} addressed to: "
                     f"{name} can now claim {'it' if shares == 1 else 'them'}.")
    created = _when(p.get("created_at"))
    maker = p.get("created_by")
    origin = (f"{name}'s account was created {_age(created, now)}"
              + (f" by {_who(maker)}" if maker else "; who created it is not recorded"))
    if p.get("password_set_by_other"):
        at = _when(p.get("password_set_at"))
        origin += (f"; its password was set by {_who(p.get('password_set_by'))}"
                   + (f" on {at:%d %b %Y}" if at else "") + ", not by them")
    else:
        origin += "; its password is their own"
    lines.append(origin + ".")
    return lines


def notice_text(details: dict, *, now: Optional[datetime] = None, contact: Optional[str] = None) -> tuple:
    """(title, sentences) of the notice: built from the outbox row's details alone; never a vault's name."""
    now = now or utcnow()
    people = details.get("people") or []
    more = int(details.get("more_people") or 0)
    total = len(people) + more
    vaults = int(details.get("vaults") or 0)
    by = _who(details.get("by"))
    if total <= 1:
        title = ("Someone was given access to your vault" if vaults <= 1
                 else f"Someone was given access to {vaults} of your vaults")
    else:
        title = f"{total} people were given access to {'your vault' if vaults <= 1 else f'{vaults} of your vaults'}"
    lines = []
    for p in people:
        lines += _person_lines(p, by=by, now=now)
    if more:
        lines.append(f"And {more} more {'person' if more == 1 else 'people'}.")
    lines.append("If you did not expect this, open the vault, check who has access, and ask your administrator."
                 if vaults <= 1 else
                 "If you did not expect this, check who has access to your vaults, and ask your administrator.")
    if contact:
        lines.append(f"Questions: {contact}.")
    return title, lines


def _tell_owner(db, owner_id, items: List[_Entry], *, granter, event: str, now: datetime) -> bool:
    from app.core import owner_notices as on
    from app.core.models import ComplianceNoticeOutbox, User
    from app.core.security import seal_case_field
    owner = db.get(User, _uuid(owner_id))
    if owner is None:
        return False
    details = details_for(db, items, granter=granter)
    title, lines = notice_text(details, now=now, contact=on.contact(db))
    target = TARGET_PREFIX + details["vault_ids"][0] if len(details["vault_ids"]) == 1 else None
    dedup = f"access:{event}"
    on.notify_in_transaction(db, [owner.id], title=title[:255], body=" ".join(lines), ntype=NOTICE_TYPE,
                             target=target, dedup=dedup)
    email = any(not e.granter_member for e in items)
    status = "in_app_only"
    if email:
        address, previous = on.destinations(db, owner)
        row_id = uuid.uuid4()
        row = ComplianceNoticeOutbox(
            id=row_id, case_id=None, user_id=owner.id, kind=KIND, dedup_key=f"{dedup}:{owner.id}",
            details=on._jsonable(details), status=on.PENDING if address or previous else on.NO_ADDRESS, attempts=0,
            next_attempt_at=now if address or previous else None, created_at=now, sent_to=[])
        row.address_enc = seal_case_field(row_id, address, "notice_address") if address else None
        row.previous_address_enc = (seal_case_field(row_id, previous, "notice_previous_address")
                                    if previous else None)
        db.add(row)
        status = row.status if row.status == on.NO_ADDRESS else on.CASE_QUEUED
        copy = previous is not None
    else:
        copy = False
    on._audit(db, "owner_notice_written", None, actor_name=on.SYSTEM, user_id=owner.id,
              details={"kind": KIND, "vaults": details["vaults"], "count": len(details["people"])
                       + details["more_people"], "email_status": status, "copy_to_previous": copy})
    db.flush()
    if email:
        from app.core import after_commit
        after_commit.later(db, on._WAKE, 1)
    return True
