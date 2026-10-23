"""Where compliance access and the audit log's integrity chain meet, offline.

- The chain judges an env seal's inputs by the startup contract, but not by a check that reads settings the seal
  does not record: the compliance boundary reads COMPLIANCE_ACCESS and COMPLIANCE_RECORD_MIN_DAYS, so a
  deployment with compliance access off and a PLAN_LOG_MAX_DAYS under the records' floor writes env seals the
  chain accepts, while its start is still checked against the whole contract.
- The names the server writes for itself include compliance access's own steps ("system"): the check's
  user-unlinked does not take such a row for one a database writer unlinked from an account of that name, and an
  erase of that name is refused.
- The compliance settings are placed on the Settings pages like every registered setting.
"""
from datetime import timedelta
from types import SimpleNamespace

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_policy as pol
from app.core import compliance_settings as cs
from app.core import legal_holds
from app.core import person_erase as pe
from app.core import settings_registry as reg
from app.core.models import RoleEnum, User

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def test_an_env_seals_inputs_are_not_judged_by_the_compliance_boundary(env):
    inputs = {name: None for name in pol.input_names()}
    inputs["PLAN_LOG_MAX_DAYS"] = "400"
    inputs["RETENTION_REDUCTION_DELAY_DAYS"] = "7"
    assert pol.contract_problems(inputs) == []
    # The deployment's own start is checked against the whole contract: with compliance access on, refused.
    deployment = pol.settings_from_inputs(inputs)
    problems = reg.check_contract(deployment)
    assert any("COMPLIANCE_RECORD_MIN_DAYS" in p and "PLAN_LOG_MAX_DAYS" in p for p in problems), problems
    off = SimpleNamespace(**dict(vars(deployment), compliance_access=cs.DISABLED))
    assert not [p for p in reg.check_contract(off) if "COMPLIANCE" in p]
    assert reg.check_contract(deployment, chain_inputs_only=True) == [p for p in problems if "COMPLIANCE" not in p]


def test_a_chain_whose_env_seal_has_a_short_plan_ceiling_verifies(env, monkeypatch):
    """The server's own env seal for PLAN_LOG_MAX_DAYS=400 (a deployment with compliance access off, whose records'
    floor of 2190 days could not be kept under it) is accepted and verifies clean."""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    monkeypatch.setenv("PLAN_LOG_MAX_DAYS", "400")
    env.settings.plan_log_max_days = 400
    env.settings.compliance_access = cs.DISABLED
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    assert env.st.view.newest_policy() is not None
    assert failures(env.verify()) == []


def test_a_row_of_the_servers_own_steps_is_not_taken_for_one_unlinked_from_an_account_of_that_name(env):
    with env.session() as db:
        db.add(User(username=legal_holds.SYSTEM, password_hash="x", role=RoleEnum.USER,
                    created_at=T0 - timedelta(days=30)))
        db.commit()
    env.row(T0 - timedelta(hours=5), action="case_closed", username=legal_holds.SYSTEM)
    env.row(T0 - timedelta(hours=4), action="file_upload", username=legal_holds.SYSTEM)
    env.run_until_sealed()
    found = failures(env.verify())
    # The file upload's row is one an account of that name made and a database writer unlinked; the case's is the
    # server's own step.
    assert found.count("user-unlinked") == 1, found
    report = env.verify()
    assert [f.message for f in report.findings if f.kind == "user-unlinked"] == [
        "1 rows of an account that still exists were unlinked from it"]


def test_an_erase_of_the_name_of_the_servers_own_steps_is_refused():
    assert legal_holds.SYSTEM in pe.system_names()
    assert "writes for itself" in pe.name_problem(legal_holds.SYSTEM)


def test_the_compliance_settings_are_placed_like_every_registered_setting():
    for key in cs.KEYS:
        spec = reg.spec_for(key)
        assert (spec.level, spec.since, spec.page, spec.editable) == (reg.ADVANCED, "0.34.0", reg.MANAGED_PAGE,
                                                                      reg.ENV_ONLY), key
