"""What `dockvault.py audit retention` asks the server (app/core/retention_report.py), offline.

The server shows every setting of how long records are kept as it has them: for one the audit chain records, the
chain's value, which the pruner acts on, beside the database's. For .env lines the operator gives, it checks
that each is a line of these settings and of the right kind, names what the server would refuse to start with,
and says what each value in force becomes and which change deletes sooner; it writes nothing.
"""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_chain_cli as cli  # noqa: E402
from app.core import audit_chain_policy as pol  # noqa: E402
from app.core import audit_chain_policy_seals as chain_seals  # noqa: E402
from app.core import audit_integrity as ai  # noqa: E402
from app.core import retention_report as rr  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402

pytestmark = pytest.mark.unit

LINES = {"AUDIT_LOG_RETENTION_DAYS", "AUDIT_MIN_RETENTION_DAYS", "AUDIT_PROTECTED_MIN_DAYS", "AUDIT_LOG_MAX_MB",
         "PLAN_LOG_MAX_DAYS", "PLAN_LOG_MAX_MB", "RETENTION_HOLD", "RETENTION_REDUCTION_DELAY_DAYS",
         "LOG_PRUNE_INTERVAL_MINUTES", "LOG_PRUNE_BATCH_ROWS", "SECURITY_RECORD_DAYS", "SECURITY_RECORD_MIN_DAYS",
         "SECURITY_RECORD_MAX_DAYS", "SECURITY_ALERT_RETENTION_DAYS", "AUDIT_SEAL_LAG_MINUTES", "AUDIT_HOT_DAYS",
         "AUDIT_ARCHIVE_START_AFTER_DAYS", "ERASE_BLOCKED_BY_PROTECTED_MINIMUM", "NOTIFICATION_RETENTION_DAYS",
         "LOG_PULL_SINK_MAX_MB"}


@pytest.fixture(autouse=True)
def deployment(monkeypatch):
    """Every setting at its default, no stored value."""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    ns = pol.settings_from_inputs({})
    monkeypatch.setattr(reg, "_deployment_settings", lambda: ns)
    return ns


def _rows():
    return reg.describe([s.key for s in rr.specs()])


def _check(**lines):
    return rr.check({k: str(v) for k, v in lines.items()}, _rows())


def test_the_lines_checked_are_the_lines_of_how_long_records_are_kept():
    assert set(rr.env_lines()) == LINES
    assert {s.group for s in rr.specs()} == set(rr.GROUPS)


def test_the_host_tool_keeps_every_one_of_those_lines_across_a_fresh_volume_set():
    import dockvault as dv
    kept = {env for _cfg, env, _default in dv.RETENTION_ENV_KEYS}
    assert LINES <= kept
    # The rest it keeps are the recording levels' limits and the chain's head file.
    assert kept - LINES == {"AUDIT_MAX_NAMES", "AUDIT_MAX_SIGNIN_NAMES", "AUDIT_MAX_EMAILS", "AUDIT_MAX_IP",
                            "AUDIT_MAX_USER_AGENT", "AUDIT_CHAIN_HEAD_FILE"}


@pytest.mark.parametrize("given, ok", [
    (["AUDIT_LOG_RETENTION_DAYS=30"], {"AUDIT_LOG_RETENTION_DAYS": "30"}),
    (["RETENTION_HOLD = true", "AUDIT_HOT_DAYS=120"], {"RETENTION_HOLD": "true", "AUDIT_HOT_DAYS": "120"}),
    ([], {}),
])
def test_lines_of_these_settings_are_taken(given, ok):
    assert rr.parse_lines(given) == ok


@pytest.mark.parametrize("given, why", [
    (["ENCRYPTION_KEY=x"], "is not a .env line of how long records are kept"),
    (["AUDIT_MAX_IP=none"], "is not a .env line of how long records are kept"),
    (["AUDIT_LOG_RETENTION_DAYS"], "is not NAME=VALUE"),
    (["audit_log_retention_days=3"], "is not NAME=VALUE"),
    (["AUDIT_LOG_RETENTION_DAYS="], "is not NAME=VALUE"),
    (["AUDIT_LOG_RETENTION_DAYS=1\nX=2"], "is not NAME=VALUE"),
    (["AUDIT_HOT_DAYS=100", "AUDIT_HOT_DAYS=120"], "is given twice"),
])
def test_any_other_line_is_refused(given, why):
    with pytest.raises(rr.Refused, match=why):
        rr.parse_lines(given)


def test_the_check_says_what_changes_and_what_deletes_sooner():
    out = _check(AUDIT_LOG_RETENTION_DAYS=30)
    assert out["problems"] == [] and out["deletes_sooner"] == ["audit_max_days"]
    assert [(c["key"], c["before"], c["after"]) for c in out["changes"]] == [("audit_max_days", 0, 30)]
    out = _check(RETENTION_HOLD="true")
    assert [(c["key"], c["before"], c["after"]) for c in out["changes"]] == [("logs_hold", False, True)]
    assert out["deletes_sooner"] == []
    out = _check(NOTIFICATION_RETENTION_DAYS=60, SECURITY_RECORD_DAYS=90)
    assert {c["key"] for c in out["changes"]} == {"notification_retention_days", "security_record_days"}
    assert out["deletes_sooner"] == ["notification_retention_days"]
    # A floor raised keeps more; lowering the delay changes no value in force.
    out = _check(AUDIT_PROTECTED_MIN_DAYS=400)
    assert out["deletes_sooner"] == [] and [c["key"] for c in out["changes"]] == ["audit_admin_min_days"]
    assert _check(AUDIT_LOG_RETENTION_DAYS=0)["changes"] == []


def test_the_check_names_what_the_server_would_not_start_with():
    assert any("the floor (400) is above the ceiling (365)" in p for p in _check(SECURITY_RECORD_MIN_DAYS=400)["problems"])
    assert any("LOG_PULL_SINK_MAX_MB is not valid" in p for p in _check(LOG_PULL_SINK_MAX_MB=2)["problems"])
    assert any("AUDIT_PROTECTED_MIN_DAYS" in p
               for p in _check(AUDIT_PROTECTED_MIN_DAYS=400, PLAN_LOG_MAX_DAYS=365)["problems"])
    assert any("NOTIFICATION_RETENTION_DAYS is not valid" in p
               for p in _check(NOTIFICATION_RETENTION_DAYS=10)["problems"])


@pytest.mark.parametrize("line", [{"AUDIT_LOG_RETENTION_DAYS": "abc"}, {"RETENTION_HOLD": "maybe"},
                                  {"AUDIT_HOT_DAYS": "1.5"}])
def test_a_value_of_the_wrong_kind_is_refused(line):
    with pytest.raises(rr.Refused):
        rr.check(line, _rows())


# Digits other than 0-9 (full-width, Arabic-Indic, mathematical bold), which int() takes and the app's
# configuration refuses, and other spellings it refuses.
REFUSED_NUMBERS = ["\uff12\uff10", "\u0662\u0660", "\U0001d7d0\U0001d7ce", "0x14", "2e1", "1__000", "_20", "20 MB"]
# Spellings the configuration reads as a whole number.
TAKEN_NUMBERS = ["+20", "1_000", "020", "20.0"]


def _configured(field, raw):
    """What the app's configuration makes of ``raw`` for ``field`` at startup, or None when it refuses it."""
    from pydantic import ValidationError
    from app.core.config import Settings
    try:
        return getattr(Settings(**{field: raw}), field)
    except ValidationError:
        return None


@pytest.mark.parametrize("raw", REFUSED_NUMBERS)
@pytest.mark.parametrize("line", ["LOG_PULL_SINK_MAX_MB", "AUDIT_LOG_RETENTION_DAYS", "SECURITY_RECORD_DAYS"])
def test_a_number_the_configuration_refuses_is_refused(raw, line):
    """A line the app would refuse to start with is never checked as fine (and so never written)."""
    assert _configured(rr.env_lines()[line], raw) is None
    with pytest.raises(rr.Refused, match=f"{line}=.* is not a whole number"):
        rr.check({line: raw}, _rows())


@pytest.mark.parametrize("raw", TAKEN_NUMBERS)
def test_a_number_the_configuration_takes_is_read_as_it_reads_it(raw):
    want = _configured("audit_log_retention_days", raw)
    assert want in (20, 1000)
    out = rr.check({"AUDIT_LOG_RETENTION_DAYS": raw}, _rows())
    assert [(c["key"], c["after"]) for c in out["changes"]] == [("audit_max_days", want)]
    assert out["problems"] == []


@pytest.mark.parametrize("raw", ["yes", "On", "T", "1", "no", "OFF", "f", "0", "maybe", "2", "tru", "oui"])
def test_a_switch_is_read_as_the_configuration_reads_it(raw):
    want = _configured("retention_hold", raw)
    if want is None:
        with pytest.raises(rr.Refused, match="RETENTION_HOLD=.* is not true or false"):
            rr.check({"RETENTION_HOLD": raw}, _rows())
        return
    out = rr.check({"RETENTION_HOLD": raw}, _rows())
    assert [(c["key"], c["after"]) for c in out["changes"]] == ([("logs_hold", True)] if want else [])


@pytest.mark.parametrize("raw", REFUSED_NUMBERS + TAKEN_NUMBERS + ["3", "1000", "2", "1001", "15"])
def test_the_launcher_reads_the_log_access_size_as_the_configuration_does(raw):
    """Both writers of the log-access file read LOG_PULL_SINK_MAX_MB as the app's configuration does: a value it
    takes is that value (the default when outside the bounds, which the app refuses to start with), and one it
    refuses is the default."""
    from app.services import log_sink
    want = _configured("log_pull_sink_max_mb", raw)
    mb = want if want is not None and 3 <= want <= 1000 else 15
    assert log_sink.sink_limits({"LOG_PULL_SINK_MAX_MB": raw}) == (mb * 1024 * 1024 // 3, 2)
    if want is not None and 3 <= want <= 1000:
        out = rr.check({"LOG_PULL_SINK_MAX_MB": raw}, _rows())
        assert out["problems"] == [] and [c["after"] for c in out["changes"]] == ([want] if want != 15 else [])


def test_the_launcher_finds_the_line_as_the_configuration_does(monkeypatch):
    import os
    from app.core.config import Settings
    from app.services import log_sink
    monkeypatch.setenv("LOG_PULL_SINK_MAX_MB", "60")
    monkeypatch.setenv("log_pull_sink_max_mb", "30")
    want = Settings().log_pull_sink_max_mb
    assert log_sink.sink_limits() == (want * 1024 * 1024 // 3, 2)
    if os.name == "posix":                                  # two names there; one on Windows
        assert want == 30


def test_an_administrators_value_keeps_its_value_in_force():
    reg._cache.rows = {"security_record_days": (40, 1)}
    assert _check(SECURITY_RECORD_DAYS=60)["changes"] == []
    # A bound that moves past it still changes it: clamped to the new floor.
    out = _check(SECURITY_RECORD_MIN_DAYS=50)
    assert [(c["key"], c["before"], c["after"]) for c in out["changes"]] == [("security_record_days", 40, 50)]


def test_the_check_leaves_the_deployments_settings_as_they_were(deployment):
    _check(AUDIT_LOG_RETENTION_DAYS=30)
    assert reg._deployment_settings() is deployment and deployment.audit_log_retention_days == 0


def test_the_report_without_a_chain_is_the_registrys(monkeypatch):
    out = rr.report(None, ai.ChainState(), ai.View(), None, None, {"AUDIT_LOG_RETENTION_DAYS": "30"})
    assert out["chain_started"] is False and out["pending"] == []
    rows = {r["key"]: r for r in out["settings"]}
    assert set(rows) == {s.key for s in rr.specs()}
    assert (rows["audit_max_days"]["value"], rows["audit_max_days"]["env"]) == (0, "AUDIT_LOG_RETENTION_DAYS")
    assert "database_value" not in rows["audit_max_days"]
    assert out["check"]["deletes_sooner"] == ["audit_max_days"]


def test_the_report_shows_the_chains_value_and_checks_against_the_databases(monkeypatch):
    view = SimpleNamespace(newest_policy=lambda: (1, {"state": {}}), position=0)
    monkeypatch.setattr(chain_seals, "honoured_state", lambda v, r, n: {"audit_max_days": {"value": 90}})
    out = rr.report(None, ai.ChainState(), view, None, None, {"AUDIT_LOG_RETENTION_DAYS": "30"})
    row = {r["key"]: r for r in out["settings"]}["audit_max_days"]
    assert (row["value"], row["database_value"], out["chain_started"]) == (90, 0, True)
    assert [(c["before"], c["after"]) for c in out["check"]["changes"]] == [(0, 30)]


def test_the_command_takes_its_lines(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "_retention", lambda args: seen.append(args.set) or 0)
    assert cli.main(["retention", "--set", "AUDIT_HOT_DAYS=120", "--set", "RETENTION_HOLD=true"]) == 0
    assert cli.main(["retention"]) == 0
    assert seen == [["AUDIT_HOT_DAYS=120", "RETENTION_HOLD=true"], None]
