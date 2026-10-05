"""The switch that postpones the key proof on zero-knowledge key changes: ZK_KEY_PROOF_ENFORCE.

On by default. Only the host operator can turn it off, in the environment; the settings page refuses it,
so an application administrator cannot. dockvault.py writes it only when it is off, so a normal install's
.env never mentions it and a postponement survives a fresh volume set. The web container says so at start
when it is off.
"""
import importlib.util
from pathlib import Path

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core.config import Settings, settings  # noqa: E402
from app.services import zk_key_proof as kp  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_zk_switch", ROOT / "dockvault.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_switch_defaults_on_and_reads_false_from_the_environment():
    assert Settings.model_fields["zk_key_proof_enforce"].default is True
    assert Settings.model_construct().zk_key_proof_enforce is True
    for raw in ("false", "0", "no", "off", "False"):
        assert Settings(zk_key_proof_enforce=raw).zk_key_proof_enforce is False
    assert Settings(zk_key_proof_enforce="true").zk_key_proof_enforce is True


def test_enforcement_follows_the_setting(monkeypatch):
    monkeypatch.setattr(settings, "zk_key_proof_enforce", True)
    assert kp.enforcement_enabled() is True
    monkeypatch.setattr(settings, "zk_key_proof_enforce", False)
    assert kp.enforcement_enabled() is False


def test_env_example_documents_the_switch_on():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\nZK_KEY_PROOF_ENFORCE=true\n") == 1


def test_a_fresh_volume_set_keeps_a_postponement(monkeypatch):
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"ZK_KEY_PROOF_ENFORCE": "false"}, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert "ZK_KEY_PROOF_ENFORCE=false" in lines
    written = dv.parse_env("\n".join(lines))["ZK_KEY_PROOF_ENFORCE"]
    assert Settings(zk_key_proof_enforce=written).zk_key_proof_enforce is False


@pytest.mark.parametrize("env", [{}, {"ZK_KEY_PROOF_ENFORCE": "true"}, {"ZK_KEY_PROOF_ENFORCE": "yes"}])
def test_an_enforcing_environment_writes_nothing(env):
    """The common case authors the .env it always did; the application's default applies."""
    dv = _dockvault()
    cfg = dv.new_set_config(env, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert not [line for line in lines if line.startswith("ZK_KEY_PROOF_ENFORCE")]


@pytest.mark.parametrize("key", ["zk_key_proof_enforce", "ZK_KEY_PROOF_ENFORCE", "Zk_Key_Proof_Enforce"])
@pytest.mark.parametrize("value", [False, True, "false", 0])
def test_the_settings_page_cannot_change_it(key, value):
    with pytest.raises(HTTPException) as refused:
        api._validate_settings_payload({key: value}, db=None)
    assert refused.value.status_code == 400
    assert "managed by the deployment environment" in refused.value.detail


def test_the_web_container_says_so_at_start_only_when_it_is_off(monkeypatch):
    printed = []
    monkeypatch.setattr(settings, "zk_key_proof_enforce", False)
    kp.report_at_startup(printed.append)
    assert len(printed) == 1 and "ZK_KEY_PROOF_ENFORCE=false" in printed[0]
    printed.clear()
    monkeypatch.setattr(settings, "zk_key_proof_enforce", True)
    kp.report_at_startup(printed.append)
    assert printed == []


def test_the_start_report_runs_in_the_web_process():
    src = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert src.count("async def lifespan(") == 1
    startup = src[src.index("async def lifespan("):]
    startup = startup[:startup.index("\n    yield\n")]
    assert startup.count("zk_key_proof.report_at_startup()") == 1, "report it before the app serves"
    assert src.count("zk_key_proof.report_at_startup()") == 1
