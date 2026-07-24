"""Unit matrix for the pure ID-based scope helpers (app/core/id_scope.py).

Covers normalization (dedup, invalid-id drop, deny-all), the file/folder membership check via
folder ancestry, and the delegation intersection (a child can never widen past its parent). No db /
framework needed -- the module is stdlib-only on purpose.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.id_scope import (  # noqa: E402
    normalize_id_scope, scope_is_empty, id_in_scope, intersect_id_scope,
)

# Fixed ids: D is a root folder, SUB is a subfolder of D, OTHER is an unrelated root folder.
FILE = "11111111-1111-1111-1111-111111111111"   # root-level file
X = "77777777-7777-7777-7777-777777777777"       # file inside D
Y = "66666666-6666-6666-6666-666666666666"       # file inside OTHER
D = "33333333-3333-3333-3333-333333333333"       # folder (root)
SUB = "44444444-4444-4444-4444-444444444444"     # folder, parent = D
OTHER = "55555555-5555-5555-5555-555555555555"   # folder (root), unrelated

# ancestry_of(id) = [id] + its containing-folder chain toward root (what intersect_id_scope needs).
_ANC = {FILE: [FILE], X: [X, D], Y: [Y, OTHER], D: [D], SUB: [SUB, D], OTHER: [OTHER]}
def _ancestry_of(cid):
    return _ANC.get(cid, [cid])


def test_normalize_id_scope():
    assert normalize_id_scope(None) is None                       # absent -> whole vault
    assert normalize_id_scope("nope") is None                     # non-dict -> whole vault
    assert normalize_id_scope({}) == {"files": [], "folders": []}  # provided-empty -> deny all
    got = normalize_id_scope({"files": [X, X, "bad"], "folders": [D]})
    assert got == {"files": [X], "folders": [D]}                   # dedup + drop invalid
    assert normalize_id_scope({"files": ["not-a-uuid"]}) == {"files": [], "folders": []}


def test_scope_is_empty():
    assert scope_is_empty(None) is False                          # whole vault, not "empty"
    assert scope_is_empty({"files": [], "folders": []}) is True   # deny all
    assert scope_is_empty({"files": [X], "folders": []}) is False


def test_id_in_scope_whole_vault_and_deny_all():
    assert id_in_scope(None, X, [D]) is True                      # whole vault
    assert id_in_scope({"files": [], "folders": []}, X, [D]) is False  # deny all


def test_id_in_scope_exact_file():
    assert id_in_scope({"files": [FILE], "folders": []}, FILE, []) is True
    assert id_in_scope({"files": [FILE], "folders": []}, X, [D]) is False  # different file


def test_id_in_scope_folder_subtree():
    scope = {"files": [], "folders": [D]}
    assert id_in_scope(scope, X, [D]) is True                     # file directly in D
    assert id_in_scope(scope, "aaaaaaaa-0000-0000-0000-000000000000", [SUB, D]) is True  # file deep under D
    assert id_in_scope(scope, D, []) is True                      # the folder D itself
    assert id_in_scope(scope, SUB, [D]) is True                   # a subfolder of D
    assert id_in_scope(scope, Y, [OTHER]) is False                # file in an unrelated folder
    assert id_in_scope(scope, OTHER, []) is False                 # an unrelated folder


def test_intersect_delegation():
    # parent unrestricted -> child stands
    assert intersect_id_scope(None, {"files": [X], "folders": []}, _ancestry_of) == {"files": [X], "folders": []}
    # child omits scope -> inherit parent (never whole vault)
    assert intersect_id_scope({"files": [], "folders": [D]}, None, _ancestry_of) == {"files": [], "folders": [D]}
    # child narrows to a file inside the parent folder -> kept
    assert intersect_id_scope({"files": [], "folders": [D]}, {"files": [X], "folders": []}, _ancestry_of) \
        == {"files": [X], "folders": []}
    # child narrows to a subfolder of the parent folder -> kept
    assert intersect_id_scope({"files": [], "folders": [D]}, {"files": [], "folders": [SUB]}, _ancestry_of) \
        == {"files": [], "folders": [SUB]}
    # child asks for a file OUTSIDE the parent folder -> dropped (deny)
    assert intersect_id_scope({"files": [], "folders": [D]}, {"files": [Y], "folders": []}, _ancestry_of) \
        == {"files": [], "folders": []}
    # a file-only parent cannot be widened to a folder by a child
    assert intersect_id_scope({"files": [X], "folders": []}, {"files": [], "folders": [D]}, _ancestry_of) \
        == {"files": [], "folders": []}


def test_intersect_cannot_widen_to_whole_vault():
    # a restricted parent + a child that omits scope must NOT yield whole-vault
    assert intersect_id_scope({"files": [FILE], "folders": []}, None, _ancestry_of) == {"files": [FILE], "folders": []}
