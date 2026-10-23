"""Settings levels, offline: every setting on the Settings pages is an entry of the settings registry with a
level (essential or advanced), the release it arrived in and its page, and the pages' markup names exactly
those settings.

  * the registry (app/core/settings_registry.py) refuses an entry of any kind without a level, a release
    written X.Y.Z or a known page, and every entry of the release has all three;
  * the settings the registry does not resolve are listed as fields (app/core/settings_pages.py): the lock never
    covers one and PUT /settings never refuses one; a fixed setting is never locked either;
  * static/index.html marks every setting of every Settings page with data-setting, each a registry entry on
    that page, every field is on the pages, and no control of a page is left outside a setting;
  * "New": a setting that arrived in the running release line or the one before it, or after the release this
    administrator last opened the pages at;
  * the catalogue the pages read (app/core/settings_catalogue.py): a locked entry carries its value and the
    reason, naming its .env setting and SETTINGS_LOCKED_KEYS, in public words;
  * the routes and the preference: test_settings_catalogue_routes.py.
"""
import re
from html.parser import HTMLParser
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import settings_catalogue as catalogue  # noqa: E402
from app.core import settings_pages as pages  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_TABLES = ("_SPECS", "_LISTED", "_LOCK_GROUPS", "_FIELDS")


# --------------------------------------------------------------------------- every entry is placed

def test_every_entry_of_every_kind_has_a_level_a_release_and_a_page():
    reg.all_entries()                                    # load every module that registers
    kinds = {name: list(getattr(reg, name).values()) for name in _TABLES}
    assert all(kinds.values()), {name: len(found) for name, found in kinds.items()}
    unplaced = []
    for name, found in kinds.items():
        for entry in found:
            key = reg.entry_key(entry)
            if entry.level not in reg.LEVELS:
                unplaced.append(f"{key}: no level")
            if reg.parse_version(entry.since) is None:
                unplaced.append(f"{key}: no release")
            if entry.page not in reg.PAGES:
                unplaced.append(f"{key}: no page")
    assert not unplaced, unplaced
    assert len(reg.all_entries()) == sum(len(found) for found in kinds.values())


def test_both_levels_are_used_and_most_settings_are_advanced():
    levels = [entry.level for entry in reg.all_entries()]
    assert levels.count(reg.ESSENTIAL) and levels.count(reg.ADVANCED) > levels.count(reg.ESSENTIAL)


def test_the_managed_settings_are_on_their_page_and_the_rate_limits_on_security():
    assert {spec.page for spec in reg.all_specs()} == {reg.MANAGED_PAGE} == {"records"}
    assert {listed.page for listed in reg.all_listed()} == {"security"}


def test_the_records_page_draws_every_group_of_its_settings():
    """The records page draws the managed settings group by group (static/js/settings-retention.js, GROUPS): a
    setting of a group it does not list would be on no page."""
    js = (ROOT / "static" / "js" / "settings-retention.js").read_text(encoding="utf-8")
    assert js.count("const GROUPS = [") == 1
    start = js.index("const GROUPS = [")
    drawn = set(re.findall(r"\['([a-z_]+)', '", js[start:js.index("];", start)]))
    missing = {spec.group for spec in reg.all_specs()} - drawn
    assert not missing, sorted(missing)


@pytest.fixture
def bare(monkeypatch):
    """Only what a test registers, with deployment settings the test controls."""
    reg.all_entries()
    saved = [(getattr(reg, name), dict(getattr(reg, name))) for name in _TABLES]
    for table, _ in saved:
        table.clear()
    env = SimpleNamespace(settings_locked_keys="")
    monkeypatch.setattr(reg, "_deployment_settings", lambda: env)
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    yield env
    for table, before in saved:
        table.clear()
        table.update(before)


_PLACE = dict(level=reg.ADVANCED, since="0.34.0", page="records")


def _spec(**kw):
    return reg.SettingSpec(**{**dict(key="keep_days", kind="int", default=9, minimum=1, maximum=99, **_PLACE),
                              **kw})


_UNPLACED = [
    (dict(level=""), "level"), (dict(level="basic"), "level"), (dict(level="Essential"), "level"),
    (dict(since=""), "release"), (dict(since="0.34"), "release"), (dict(since="v0.34.0"), "release"),
    (dict(since="0.34.0-rc1"), "release"), (dict(page=""), "page"), (dict(page="nowhere"), "page"),
]


@pytest.mark.parametrize("kw,why", _UNPLACED)
def test_a_setting_without_its_level_release_or_page_is_refused(bare, kw, why):
    with pytest.raises(ValueError, match=why):
        reg.register(_spec(**kw))
    assert not reg._SPECS


@pytest.mark.parametrize("kw,why", _UNPLACED)
def test_a_listed_key_without_its_level_release_or_page_is_refused(bare, kw, why):
    with pytest.raises(ValueError, match=why):
        reg.register_listed("some_limit", group="limits", **{**_PLACE, **kw})
    assert not reg._LISTED


@pytest.mark.parametrize("kw,why", _UNPLACED)
def test_a_lock_group_without_its_level_release_or_page_is_refused(bare, kw, why):
    with pytest.raises(ValueError, match=why):
        reg.register_lock_group("some_group", **{**_PLACE, **kw})
    assert not reg._LOCK_GROUPS


@pytest.mark.parametrize("kw,why", _UNPLACED)
def test_a_field_without_its_level_release_or_page_is_refused(bare, kw, why):
    with pytest.raises(ValueError, match=why):
        reg.register_field("app_name", **{**_PLACE, **kw})
    assert not reg._FIELDS


def test_every_kind_shares_one_name_space(bare):
    reg.register(_spec())
    reg.register_field("app_name", **_PLACE)
    reg.register_lock_group("audit_levels", **_PLACE)
    reg.register_listed("some_limit", group="limits", **_PLACE)
    for register in (lambda k: reg.register(_spec(key=k)), lambda k: reg.register_field(k, **_PLACE),
                     lambda k: reg.register_listed(k, group="limits", **_PLACE)):
        for taken in ("keep_days", "app_name", "audit_levels", "some_limit"):
            with pytest.raises(ValueError, match="twice"):
                register(taken)
    for taken in ("keep_days", "app_name", "some_limit"):
        with pytest.raises(ValueError, match="twice"):
            reg.register_lock_group(taken, **_PLACE)
    with pytest.raises(ValueError, match="lower-case"):
        reg.register_field("App-Name", **_PLACE)


# --------------------------------------------------------------------------- what the lock covers

def test_a_field_is_never_locked_nor_refused_by_put_settings(bare):
    reg.register_field("app_name", **_PLACE)
    for tokens in ("*", "app_name", "records"):
        bare.settings_locked_keys = tokens
        assert "app_name" not in reg.refused_settings_keys()
        rows = {r["key"]: r for r in catalogue.entries(current="0.34.0")}
        assert rows["app_name"]["locked"] is False, tokens
    bare.settings_locked_keys = "app_name"
    assert reg.unknown_locked_tokens() == ["app_name"]


def test_a_fixed_setting_is_never_locked(bare):
    reg.register(_spec(key="kept_days", editable=reg.FIXED, group="working_records"))
    bare.settings_locked_keys = "*"
    spec = reg.spec_for("kept_days")
    assert reg.is_locked(spec) is False
    assert reg.describe()[0]["source"] == reg.SOURCE_DEFAULT and reg.describe()[0]["locked"] is False
    assert catalogue.entries(current="0.34.0")[0]["locked"] is False
    reg.register(_spec(key="env_days", editable=reg.ENV_ONLY, env="env_days"))
    assert reg.is_locked(reg.spec_for("env_days")) is True


def test_describe_gives_each_setting_its_level_and_page(bare):
    reg.register(_spec(level=reg.ESSENTIAL))
    row = reg.describe()[0]
    assert (row["level"], row["page"], row["since"]) == (reg.ESSENTIAL, "records", "0.34.0")


# --------------------------------------------------------------------------- new

@pytest.mark.parametrize("since,current,seen,new", [
    ("0.34.0", "0.34.0", None, True),             # this release line
    ("0.34.2", "0.34.0", None, True),             # later than the running release (a branch before its bump)
    ("0.33.1", "0.34.0", None, True),             # the line before
    ("0.33.1", "0.34.5", None, True),
    ("0.32.6", "0.34.0", None, False),            # two lines back
    ("0.32.6", "0.34.0", "0.32.0", True),         # after the release this administrator last opened at
    ("0.32.6", "0.34.0", "0.32.6", False),        # opened at that release already
    ("0.32.6", "0.34.0", "0.33.0", False),
    ("0.6.0", "0.34.0", "0.5.9", True),
    ("0.9.0", "1.0.0", None, False),              # a X.0 line: only that line counts
    ("1.0.0", "1.0.3", None, True),
    ("0.9.0", "1.0.0", "0.8.0", True),
    ("0.33.0", "1.33.0", None, False),
    ("", "0.34.0", None, False), ("0.34", "0.34.0", None, False), ("0.34.0", "", None, False),
    ("0.34.0", "dev", None, False), ("0.30.0", "0.34.0", "x", False), ("0.30.0", "0.34.0", 34, False),
])
def test_a_setting_is_new_by_its_release_line_or_since_the_pages_were_last_opened(since, current, seen, new):
    assert reg.is_new(since, current, seen) is new


# --------------------------------------------------------------------------- the catalogue

def test_the_catalogue_lists_every_entry_once_with_its_place_and_whether_it_is_new():
    rows = catalogue.entries(current="0.34.0", seen="0.33.3")
    keys = [r["key"] for r in rows]
    assert len(keys) == len(set(keys)) == len(reg.all_entries())
    by_key = {r["key"]: r for r in rows}
    for entry in reg.all_entries():
        row = by_key[reg.entry_key(entry)]
        assert (row["page"], row["level"], row["since"]) == (entry.page, entry.level, entry.since)
        assert row["new"] is reg.is_new(entry.since, "0.34.0", "0.33.3")
    assert by_key["audit_hot_days"]["kind"] == "setting" and by_key["audit_levels"]["kind"] == "group"
    assert by_key["rate_limit_vault_attempts"]["kind"] == "listed" and by_key["app_name"]["kind"] == "field"
    assert by_key["audit_hot_days"]["label"] and by_key["rate_limit_vault_attempts"]["help"]
    assert by_key["app_name"]["label"] == "" and by_key["app_name"]["help"] == ""


def test_nothing_is_locked_without_the_lock(monkeypatch):
    monkeypatch.setattr(reg._deployment_settings(), "settings_locked_keys", "", raising=False)
    rows = catalogue.entries(current="0.34.0")
    assert not [r["key"] for r in rows if r["locked"]]
    assert not [r for r in rows if "value" in r or "reason" in r]


def test_a_locked_entry_says_its_value_and_why_in_public_words(monkeypatch):
    settings = reg._deployment_settings()
    monkeypatch.setattr(settings, "settings_locked_keys", "audit_hot_days, rate_limit_vault_attempts, audit_levels, "
                        "log_prune_batch_rows, session_records_days", raising=False)
    monkeypatch.setattr(settings, "audit_hot_days", 120, raising=False)
    rows = {r["key"]: r for r in catalogue.entries(current="0.34.0")}
    assert sorted(k for k, r in rows.items() if r["locked"]) == ["audit_hot_days", "audit_levels",
                                                                 "log_prune_batch_rows", "rate_limit_vault_attempts"]
    hot = rows["audit_hot_days"]
    assert hot["value"] == "120 days"
    assert "AUDIT_HOT_DAYS" in hot["reason"] and "SETTINGS_LOCKED_KEYS" in hot["reason"]
    from app.core import rate_limit_settings as rls
    vault = rows["rate_limit_vault_attempts"]
    assert vault["value"] == f"{rls.deployment_default('rate_limit_vault_attempts')} attempts"
    assert "RATE_LIMIT_VAULT_ATTEMPTS" in vault["reason"]
    from app.core import audit_privacy as ap
    levels = rows["audit_levels"]
    limits = ap.env_limits()
    assert levels["value"] == "; ".join(f"{ap.LABELS[k]}: {limits[k]}" for k in ap.POLICY_KEYS)
    assert all(ap.ENV_NAMES[k] in levels["reason"] for k in ap.POLICY_KEYS)
    for row in (hot, vault, levels, rows["log_prune_batch_rows"]):
        assert row["reason"].startswith("Set by your provider")
    assert rows["session_records_days"]["locked"] is False           # fixed: the lock does not reach it


# --------------------------------------------------------------------------- the pages' markup

_VOID = {"input", "img", "br", "hr", "meta", "link", "source", "area", "base", "col", "embed", "param", "track", "wbr"}


class _Pages(HTMLParser):
    """The Settings pages of index.html: where each data-setting is, and each control's settings around it."""

    def __init__(self):
        super().__init__()
        self.stack = []
        self.settings = []        # (key, page)
        self.controls = []        # (description, page, inside a setting, exempt)
        self.groups = []          # (page, settings inside)

    def _page(self):
        for _, attrs in reversed(self.stack):
            match = re.fullmatch(r"settings-tab-([a-z]+)", attrs.get("id") or "")
            if match:
                return match.group(1)
        return None

    def _open(self, tag, attrs):
        attrs = dict(attrs)
        page = self._page()
        if page and attrs.get("data-setting"):
            self.settings.append((attrs["data-setting"], page))
            for group in self.groups:
                if group[2]:
                    group[1].append(attrs["data-setting"])
        if page and tag in ("input", "select", "textarea") and attrs.get("type") != "hidden":
            around = [a for _, a in self.stack]
            self.controls.append((f"<{tag} id={attrs.get('id')!r}>", page,
                                  any(a.get("data-setting") for a in around),
                                  any("data-setting-exempt" in a or "modal" in (a.get("class") or "").split()
                                      for a in around)))
        return attrs

    def handle_starttag(self, tag, attrs):
        attrs = self._open(tag, attrs)
        if tag in _VOID:
            return
        if "data-setting-group" in attrs:
            self.groups.append([self._page(), [], True])
            attrs["_group"] = self.groups[-1]
        self.stack.append((tag, attrs))

    def handle_startendtag(self, tag, attrs):
        self._open(tag, attrs)

    def handle_endtag(self, tag):
        while self.stack:
            t, attrs = self.stack.pop()
            if "_group" in attrs:
                attrs["_group"][2] = False
            if t == tag:
                break


@pytest.fixture(scope="module")
def markup():
    parser = _Pages()
    parser.feed((ROOT / "static" / "index.html").read_text(encoding="utf-8"))
    return parser


def test_the_pages_are_the_tabs_of_the_settings_section(markup):
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    tabs = re.findall(r'<button class="tab-btn(?: active)?" data-tab="([a-z]+)">', html)
    assert tuple(tabs) == reg.PAGES
    assert {page for _, page in markup.settings} <= set(reg.PAGES)


def test_every_marked_setting_is_a_registry_entry_on_that_page(markup):
    entries = {reg.entry_key(e): e for e in reg.all_entries()}
    wrong = [(key, page) for key, page in markup.settings if key not in entries or entries[key].page != page]
    assert not wrong, wrong


def test_every_field_and_lock_group_is_on_its_page(markup):
    marked = {key for key, _ in markup.settings}
    static = {f.key for f in reg.all_fields()} | {g.name for g in reg.all_lock_groups()}
    assert static - marked == set()
    # The rows of the managed settings and the rate limits are drawn by the page's scripts, not the markup.
    assert not marked & ({s.key for s in reg.all_specs()} | {e.key for e in reg.all_listed()})
    assert marked == static


def test_no_control_of_a_settings_page_is_left_outside_a_setting(markup):
    assert len(markup.controls) > 100
    loose = [(control, page) for control, page, inside, exempt in markup.controls if not inside and not exempt]
    assert not loose, loose


def test_every_group_holds_settings(markup):
    assert len(markup.groups) >= 20
    empty = [page for page, inside, _ in markup.groups if not inside]
    # The rate limits' card is a group whose rows the page draws (#rate-limit-settings).
    assert empty == ["security"], empty


def test_the_pages_list_of_fields_is_the_registry_fields():
    assert {k for fields in pages.FIELDS.values() for k, _, _ in fields} == {f.key for f in reg.all_fields()}
    assert set(pages.FIELDS) <= set(reg.PAGES)
