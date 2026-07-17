"""Pure, dependency-free ID-based file/folder scoping for temporary-credential grants.

A per-(temp credential, vault) grant may carry a ``scope_ids`` restriction limiting which files and
folders the credential may act on WITHIN that vault:
  * ``{"files": [file_id, ...], "folders": [folder_id, ...]}``
  * a ``folders`` entry means that folder AND its whole subtree; a ``files`` entry means exactly
    that one file.

``scope_ids is None`` (absent) means the WHOLE VAULT -- the default, backward compatible. A
PROVIDED scope with both lists empty means "no files" (fail closed): a caller that means "whole
vault" must OMIT the scope, not send empty lists.

IDs, unlike names, are always visible server-side (even for zero-knowledge vaults, whose names are
never held in cleartext), and folder membership is a plain ``File.folder_id`` / ``Folder.parent_
folder_id`` ancestry -- so this model enforces universally with no name decryption. This module is
STDLIB-ONLY on purpose (it holds the security-critical matching logic); the DB ancestry walk lives
in app/services/vault_service.folder_ancestry(), and temp_scope.require_scope() ties them together.
"""
import uuid as _uuid
from typing import List, Optional


def _valid_id(x) -> Optional[str]:
    """Canonicalize one id to its lowercase UUID string form, or None if it isn't a UUID."""
    try:
        return str(_uuid.UUID(str(x)))
    except (ValueError, TypeError, AttributeError):
        return None


def normalize_id_scope(raw) -> Optional[dict]:
    """Normalize a per-vault ``scope_ids`` restriction. ``None`` or a non-dict => ``None`` (WHOLE
    VAULT). A PROVIDED dict => ``{"files": sorted-unique valid ids, "folders": ...}`` (either list
    MAY be empty; both empty = deny all, fail closed -- never "whole vault")."""
    if not isinstance(raw, dict):
        return None

    def _ids(v):
        return sorted({s for s in (_valid_id(x) for x in (v if isinstance(v, list) else [])) if s})

    return {"files": _ids(raw.get("files")), "folders": _ids(raw.get("folders"))}


def scope_is_empty(scope) -> bool:
    """True for a PROVIDED scope that grants nothing (deny all). False for None (whole vault)."""
    return scope is not None and not scope.get("files") and not scope.get("folders")


def id_in_scope(scope, target_id, ancestor_folder_ids) -> bool:
    """Is a target file/folder permitted by ``scope``?

    ``scope is None`` -> whole vault (always True). Otherwise the target is in scope iff:
      * its own id is a scoped FILE, OR
      * its own id, or any of its ancestor FOLDER ids, is a scoped FOLDER (it is, or lives inside, a
        granted folder subtree).

    ``ancestor_folder_ids`` is the target's containing-folder chain toward the root -- for a FILE
    that is ``folder_ancestry(file.folder_id)``; for a FOLDER that is ``folder_ancestry(folder.
    parent_folder_id)`` (its own id is passed as ``target_id``). An empty ``scope`` denies
    everything (fail closed). Read and write ops share this check; directory LISTING navigation is a
    separate concern (the listing filter also shows ancestor folders that merely lead to a scoped
    entry)."""
    if scope is None:
        return True
    t = _valid_id(target_id)
    if t is None:
        return False
    if t in set(scope.get("files") or []):
        return True
    folders = set(scope.get("folders") or [])
    chain = [t] + [c for c in (_valid_id(a) for a in (ancestor_folder_ids or [])) if c]
    return any(c in folders for c in chain)


def intersect_id_scope(parent_scope, child_scope, ancestry_of) -> Optional[dict]:
    """Clamp a delegated child's ``scope_ids`` to the parent's -- a child can never widen past its
    parent.
      * parent ``None`` (unrestricted)     -> child stands as requested.
      * child ``None`` (didn't narrow)      -> INHERIT the parent's scope (never becomes whole vault).
      * both restricted -> keep only child ids that fall WITHIN the parent: a child id survives iff
        it is a scoped parent file, or it/any of its ancestor folders is a scoped parent folder.
        Disjoint ids are dropped (an empty result denies all -- fail closed).

    ``ancestry_of(id_str) -> [id_str, parent_folder, ..., root]`` supplies each child id's own id +
    folder ancestry (the DB walk is injected so this stays pure/testable)."""
    if parent_scope is None:
        return child_scope
    if child_scope is None:
        return {"files": list(parent_scope.get("files") or []),
                "folders": list(parent_scope.get("folders") or [])}
    p_files = set(parent_scope.get("files") or [])
    p_folders = set(parent_scope.get("folders") or [])

    def within_parent(cid: str) -> bool:
        if cid in p_files:
            return True
        return any(a in p_folders for a in (ancestry_of(cid) or [cid]))

    return {
        "files": sorted({f for f in (child_scope.get("files") or []) if within_parent(f)}),
        "folders": sorted({d for d in (child_scope.get("folders") or []) if within_parent(d)}),
    }
