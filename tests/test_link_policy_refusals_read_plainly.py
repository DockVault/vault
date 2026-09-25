"""A link-type refusal is read by the person filling in the form, so it must use the form's words.

The refusals used to name the API field and the raw number ("max_file_bytes 209715200 exceeds this
tag's cap of 104857600"), which the upload-link form showed as-is. Each refusal a person can reach
from the note-link, file-link or upload-link form now names the field the way the form labels it,
shows a byte cap in MB (the unit the form takes), and never mentions a field name or a tag.
"""
import importlib.util
import os
import re

import pytest

_CORE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app", "core")


def _load(name):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_CORE, name + ".py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rp = _load("receiver_policy")
nlp = _load("note_link_policy")

pytestmark = pytest.mark.unit

MB = 1024 * 1024

# What a refusal must never say to a person: an API field name, or the admin's word for a link type.
_RAW = re.compile(r"max_file_bytes|max_total_bytes|max_uploads|max_uses|ttl_hours|token_len|"
                  r"retention_days|secret_kind|\btag\b")


def _refusal(module, resolve, tag, overrides):
    with pytest.raises(module.PolicyViolation) as caught:
        resolve(tag, overrides)
    message = str(caught.value)
    assert not _RAW.search(message), f"the refusal leaks a field name or 'tag': {message!r}"
    return message


def _receiver_tag(**over):
    t = {"min_token_len": 10, "require_secret": "none", "kind_floor": "standard"}
    t.update(over)
    return t


# --- upload links ----------------------------------------------------------------------------------
def test_the_size_per_file_is_refused_in_mb_with_the_form_label():
    """The reported case: a file size above the link type's cap."""
    msg = _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(max_file_bytes_cap=100 * MB),
                   {"max_file_bytes": 200 * MB})
    assert msg == "The size per file can be at most 100 MB for this link type."


def test_a_cap_that_is_not_a_whole_number_of_mb_keeps_one_decimal():
    msg = _refusal(rp, rp.resolve_receiver_policy,
                   _receiver_tag(max_total_bytes_cap=1536 * 1024), {"max_total_bytes": 2 * MB})
    assert msg == "The total upload budget can be at most 1.5 MB for this link type."


def test_an_unlimited_value_under_a_cap_says_why_in_the_form_words():
    msg = _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(max_total_bytes_cap=500 * MB),
                   {"max_total_bytes": None})
    assert msg == "The total upload budget can be at most 500 MB for this link type, so it cannot be unlimited."


def test_the_number_of_files_is_a_count_not_a_size():
    msg = _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(max_uploads_cap=5), {"max_uploads": 6})
    assert msg == "The number of files can be at most 5 for this link type."


def test_upload_link_expiry_retention_length_and_secret():
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(max_ttl_hours=24),
                    {"ttl_hours": 48}) == "The expiry can be at most 24 hours for this link type."
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(max_ttl_hours=24),
                    {"ttl_hours": None}) == (
        "This link type expires links within 24 hours, so a link cannot be set to never expire.")
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(retention_max_days=30),
                    {"retention_days": 31}) == "The retention period can be at most 30 days for this link type."
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(retention_max_days=30),
                    {"retention_days": None}) == (
        "This link type deletes uploads within 30 days, so they cannot be kept forever.")
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(min_token_len=20),
                    {"token_len": 12}) == "The link length must be at least 20 characters for this link type."
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(require_secret="password"),
                    {"secret_kind": "pin", "pin": "123456"}) == (
        "This link type requires at least a password; a PIN is not enough.")


def test_upload_link_pin_and_password_rules():
    assert _refusal(rp, rp.resolve_receiver_policy, _receiver_tag(require_secret="pin", min_pin_len=6),
                    {"pin": "1234"}) == "The PIN must be at least 6 digits for this link type."
    assert _refusal(rp, rp.resolve_receiver_policy,
                    _receiver_tag(require_secret="password", password_min_len=12),
                    {"password": "short1"}) == "The password must be at least 12 characters for this link type."
    assert _refusal(rp, rp.resolve_receiver_policy,
                    _receiver_tag(require_secret="password", password_min_len=8, password_require_alnum=True),
                    {"password": "lettersonly"}) == (
        "The password must contain both letters and numbers for this link type.")


def test_a_value_within_every_cap_is_still_accepted():
    """The rewording changed words only: a value inside the caps resolves exactly as before."""
    got = rp.resolve_receiver_policy(
        _receiver_tag(max_file_bytes_cap=100 * MB, max_total_bytes_cap=500 * MB, max_uploads_cap=5,
                      max_ttl_hours=24, retention_max_days=30),
        {"max_file_bytes": 100 * MB, "max_total_bytes": 200 * MB, "max_uploads": 5,
         "ttl_hours": 24, "retention_days": 30})
    assert (got["max_file_bytes"], got["max_total_bytes"], got["max_uploads"],
            got["ttl_hours"], got["retention_days"]) == (100 * MB, 200 * MB, 5, 24, 30)


# --- note links and file links (one policy) --------------------------------------------------------
def test_note_and_file_link_refusals():
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_uses_cap": 3}, {"max_uses": 4}) == (
        "This link type allows at most 3 views or downloads per link.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_uses_cap": 3}, {"max_uses": None}) == (
        "This link type allows at most 3 views or downloads per link, so it cannot be unlimited.")
    # The seeded Confidential link type allows exactly one: the refusal must not say "1 views".
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_uses_cap": 1}, {"max_uses": 2}) == (
        "This link type allows at most 1 view or download per link.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_uses_cap": 1}, {"max_uses": None}) == (
        "This link type allows at most 1 view or download per link, so it cannot be unlimited.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_ttl_hours": 24}, {"ttl_hours": 25}) == (
        "The expiry can be at most 24 hours for this link type.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"max_ttl_hours": 24}, {"ttl_hours": None}) == (
        "This link type expires links within 24 hours, so a link cannot be set to never expire.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"min_token_len": 20}, {"token_len": 12}) == (
        "The link length must be at least 20 characters for this link type.")
    assert _refusal(nlp, nlp.resolve_link_policy, {"require_secret": "pin"},
                    {"secret_kind": "none"}) == "This link type requires at least a PIN; no code is not enough."
