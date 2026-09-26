"""Names for the Activity page's events, looked up when a page of events is shown and never stored.

Audit rows carry vault, file and folder ids only: names are encrypted at rest, and a name copied into
the log would sit in cleartext one table over. So the Events tab asks for the names of the rows it is
about to show, and gets only what the viewing administrator could see in the vault itself:
- a vault's name when they can read the vault (owner, member with read access, or through a
  department), the same rule the vault pages use;
- a file or folder name only when, in addition, the vault has no vault password (its file list needs
  that password, which being an administrator does not replace) and is not zero-knowledge.
Anything else reads as not shown, deleted, or hidden, and no name is decrypted before access is known.
"""
import uuid
from typing import Dict, List, Optional

NOT_SHOWN = "Not shown: you are not a member of this vault"
DELETED_VAULT = "Deleted vault"
DELETED_ITEM = "Deleted"
ZK_HIDDEN = "Zero-knowledge: name hidden"
PASSWORD_HIDDEN = "Name hidden: the vault has a password"


def _uuid(value) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def targets(event: dict):
    """(vault id, (kind, item id)) an event is about, either of them None."""
    details = event.get("details") if isinstance(event.get("details"), dict) else {}
    kind = event.get("resource_type")
    vault_id = _uuid(event.get("resource_id")) if kind == "vault" else _uuid(details.get("vault_id"))
    item = (kind, _uuid(event.get("resource_id"))) if kind in ("file", "folder") else (None, None)
    return vault_id, item


def readable_vault_ids(db, viewer, vault_ids) -> set:
    """Of these vaults, the ones the viewer may read, by the permission service's own rule (no share
    claims, no administrator override)."""
    from app.core.authorization import PermissionService
    perms = PermissionService(db)
    out = set()
    for vid in set(vault_ids):
        p = perms.get_vault_permissions(viewer, vid)
        if p and p.get("read"):
            out.add(vid)
    return out


def names_for(db, viewer, events: List[dict]) -> List[Dict[str, Optional[str]]]:
    """For each event, {"vault": ..., "item": ...}: a name, a reason it is not shown, or None when the
    event is not about a vault or an item."""
    from app.core.models import File, Folder, Vault
    wanted = [targets(e) for e in events]
    # An item row that did not record its vault: read the item's vault id (the column alone, so no
    # name is decrypted before access is known).
    for kind, model in (("file", File), ("folder", Folder)):
        loose = {i for v, (k, i) in wanted if v is None and k == kind and i}
        if loose:
            home = dict(db.query(model.id, model.vault_id).filter(model.id.in_(loose)).all())
            wanted = [(home.get(i), (k, i)) if v is None and k == kind and i in home else (v, (k, i))
                      for v, (k, i) in wanted]
    vault_ids = {v for v, _ in wanted if v}
    # Existence, type and password first, as plain columns; names only for readable vaults.
    facts = {r[0]: (r[1], bool(r[2])) for r in db.query(Vault.id, Vault.type, Vault.password_hash)
             .filter(Vault.id.in_(vault_ids)).all()} if vault_ids else {}
    readable = readable_vault_ids(db, viewer, facts)
    names = {v.id: v.name for v in db.query(Vault).filter(Vault.id.in_(readable)).all()} if readable else {}
    open_items = {v for v in readable if facts[v][0] != "zero_knowledge" and not facts[v][1]}
    items = {}
    for kind, model in (("file", File), ("folder", Folder)):
        ids = {i for v, (k, i) in wanted if k == kind and i and v in open_items}
        if ids:
            items.update({(kind, o.id): o for o in db.query(model).filter(model.id.in_(ids)).all()})

    out = []
    for vault_id, (kind, item_id) in wanted:
        fact = facts.get(vault_id) if vault_id else None
        zk = bool(fact and fact[0] == "zero_knowledge")
        if vault_id is None:
            vault_name = None
        elif fact is None:
            vault_name = DELETED_VAULT
        elif vault_id not in readable:
            vault_name = NOT_SHOWN
        else:
            # A zero-knowledge vault's `name` is the owner's label, shown while it is locked.
            vault_name = names.get(vault_id) or (ZK_HIDDEN if zk else None)
        if kind is None or item_id is None:
            item_name = None
        elif vault_id is None:
            item_name = DELETED_ITEM          # no vault recorded and the item is gone
        elif fact is None or vault_id not in readable:
            item_name = vault_name            # the same reason as the vault's
        elif zk:
            item_name = ZK_HIDDEN
        elif fact[1]:
            item_name = PASSWORD_HIDDEN
        else:
            obj = items.get((kind, item_id))
            item_name = (getattr(obj, "original_name", None) or getattr(obj, "name", None)) if obj else DELETED_ITEM
        out.append({"vault": vault_name, "item": item_name})
    return out
