"""A test cannot leave application settings to the tests after it, and a deployment's .env does not
reach the test process.

The application keeps one settings object for the whole process, and its runtime's start writes every
setting over it from the environment. tests/conftest.py starts the runtime once for the run, keeps a
start in the test process from reading the .env in the working directory, and gives every test the
settings as that start left them (its section "Every test starts from the application settings the run
started with" says why).

Most of this file is pairs: a test that leaves something changed on purpose, the way a careless test or
a start in the middle of a run does, and the test after it, which must find nothing of it. The second
of a pair needs no help from the first: each compares with what this module saw when it was imported,
before any test ran.
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from app.core import config
from app.core.config import Settings, settings
from app.core.startup_security import credential_manager

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent


def _seen():
    """Everything of the process-wide settings that a later test could find changed: the object, every
    value with its type, the fields that count as set, whether the runtime is started, and the
    credentials the start read from the environment."""
    live = config.settings
    seen = {f"settings.{name}": (type(value).__name__, value) for name, value in vars(live).items()}
    seen.update({f"credentials.{name}": value for name, value in credential_manager.credentials.items()})
    seen["the settings object"] = id(live)
    seen["the fields that count as set"] = frozenset(live.__pydantic_fields_set__)
    seen["the runtime is started"] = config.runtime_is_initialized()
    seen["the credentials are unlocked"] = credential_manager.is_unlocked
    seen["the credentials' cipher"] = id(credential_manager._fernet_cipher)
    return seen


def _changed(before, after):
    """The names of what differs. Names only: a value here may be a key."""
    return sorted(name for name in before.keys() | after.keys()
                  if name not in before or name not in after or before[name] != after[name])


# What the run started with, as this module found it when it was imported.
AS_THE_RUN_STARTED = _seen()


def _left_behind():
    return _changed(AS_THE_RUN_STARTED, _seen())


def _start_again(monkeypatch, **environment):
    """Start the runtime in this process once more, from the environment plus these values: what the
    import of the server module or the first use of a key does when nothing has started the runtime.
    Every setting is read again and written over the process-wide object, and nothing here undoes it
    (only the environment is put back, by monkeypatch)."""
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    config._runtime_initialized = False
    config.initialize_runtime(interactive=False)


# ---- a start in the middle of a run ---------------------------------------------------------------

def test_a_start_in_one_test_writes_its_environment_over_the_settings_of_the_process(monkeypatch):
    assert _left_behind() == []
    assert settings.max_storage_gb != 64 and settings.rate_limit_login_attempts != 2000
    _start_again(monkeypatch, MAX_STORAGE_GB="64", RATE_LIMIT_LOGIN_ATTEMPTS="2000")
    # The control: the start did change the object every module reads, and nothing in this test puts
    # it back. Without the fixture the next test, and every test after it, would work under this limit.
    assert settings.max_storage_gb == 64 and settings.rate_limit_login_attempts == 2000
    assert "settings.max_storage_gb" in _left_behind()


def test_the_test_after_a_start_finds_the_settings_the_run_started_with():
    assert _left_behind() == []
    assert settings.max_storage_gb != 64 and settings.rate_limit_login_attempts != 2000


# ---- the object replaced --------------------------------------------------------------------------

def test_a_test_replaces_the_settings_object_with_another():
    replacement = Settings.model_construct(max_storage_gb=64)
    config.settings = replacement
    assert config.settings is replacement and config.settings is not settings


def test_the_test_after_it_finds_the_object_the_run_started_with():
    assert config.settings is settings
    assert _left_behind() == []


# ---- a credential changed where it is kept ---------------------------------------------------------
# Ahead of the pair that replaces the credentials with others: what is put back there is a copy, and
# this pair is about the credentials the start itself filled.

def test_a_test_changes_a_credential_in_the_place_the_start_filled():
    credential_manager.credentials["ENCRYPTION_KEY"] = "another"
    credential_manager.credentials["A_NAME_THE_START_DID_NOT_READ"] = "added"
    assert set(_left_behind()) == {"credentials.ENCRYPTION_KEY", "credentials.A_NAME_THE_START_DID_NOT_READ"}


def test_the_test_after_it_finds_the_credentials_the_start_read():
    assert _left_behind() == []
    assert "A_NAME_THE_START_DID_NOT_READ" not in credential_manager.credentials


# ---- a setting removed, one added, the latch, the credentials --------------------------------------

def test_a_test_removes_a_setting_adds_one_and_changes_the_latch_and_the_credentials():
    del settings.max_storage_gb
    object.__setattr__(settings, "not_a_setting", "added")
    settings.__pydantic_fields_set__.symmetric_difference_update({"log_level"})
    config._runtime_initialized = not config._runtime_initialized
    credential_manager.credentials = {"ENCRYPTION_KEY": "another"}
    credential_manager.is_unlocked = not credential_manager.is_unlocked
    credential_manager._fernet_cipher = object()
    assert not hasattr(settings, "max_storage_gb") and settings.not_a_setting == "added"
    assert set(_left_behind()) >= {
        "settings.max_storage_gb", "settings.not_a_setting", "the fields that count as set",
        "the runtime is started", "credentials.ENCRYPTION_KEY", "the credentials are unlocked",
        "the credentials' cipher"}


def test_the_test_after_it_finds_every_one_of_them_as_it_was():
    assert _left_behind() == []
    assert not hasattr(settings, "not_a_setting")


# ---- what a test sets for itself holds while it runs -----------------------------------------------

@pytest.fixture
def a_limit_of_five(monkeypatch):
    monkeypatch.setattr(settings, "max_storage_gb", 5)


def test_a_value_a_test_sets_for_itself_holds_while_the_test_runs(monkeypatch, a_limit_of_five):
    assert settings.max_storage_gb == 5                          # its own fixture's
    monkeypatch.setattr(settings, "rate_limit_login_attempts", 7)
    assert settings.rate_limit_login_attempts == 7               # its own monkeypatch's
    monkeypatch.setenv("MAX_STORAGE_GB", "9")
    config._runtime_initialized = False
    config.initialize_runtime(interactive=False)
    assert settings.max_storage_gb == 9                          # a start it asked for itself


def test_and_is_gone_when_the_test_has_ended():
    assert _left_behind() == []


# ---- nothing is left between two tests either ------------------------------------------------------

def test_a_test_patches_a_setting_after_it_started_the_runtime_again(monkeypatch):
    _start_again(monkeypatch, MAX_STORAGE_GB="64")
    # monkeypatch remembers 64 as the value to put back, not the run's.
    monkeypatch.setattr(settings, "max_storage_gb", 5)
    assert settings.max_storage_gb == 5


class TestWhatAnEndedTestLeaves:
    @pytest.fixture(scope="class")
    def left_by_the_test_before(self):
        # A class-scoped fixture is set up before the first test of its class is given anything of its
        # own, so it sees what the test before the class left when it ended: the settings must be back
        # by then, after monkeypatch has put its 64 back and not before.
        return _left_behind()

    def test_nothing(self, left_by_the_test_before):
        assert left_by_the_test_before == []


# ---- a wider fixture's change does not reach its tests ---------------------------------------------

class TestAChangeMadeByAWiderFixture:
    @pytest.fixture(scope="class")
    def a_limit_for_the_class(self):
        settings.max_storage_gb = 64
        yield
        settings.max_storage_gb = 64

    def test_does_not_reach_a_test_of_the_class(self, a_limit_for_the_class):
        """Each test starts from the run's settings, whatever was done before it was set up: a fixture
        that wants a value for its tests sets it once per test."""
        assert _left_behind() == []


def test_nor_the_test_after_the_class_once_the_fixture_is_torn_down():
    assert _left_behind() == []


# ---- the run's own start ----------------------------------------------------------------------------

def test_every_test_finds_the_runtime_started_from_the_minimal_environment():
    """Whichever modules were collected with this one: the run starts the runtime before any of them is
    imported, so a module needs no other module's start, and none of its own."""
    assert config.runtime_is_initialized()
    assert settings.database_url and settings.encryption_key and settings.jwt_secret_key
    assert credential_manager.is_unlocked


# ---- a deployment's .env ----------------------------------------------------------------------------

ONLY_IN_THE_DOTENV = "A_NAME_ONLY_THE_DOTENV_HAS"


@pytest.fixture
def dotenv(tmp_path, monkeypatch):
    """A .env in the working directory, as a deployment has beside its compose file, with a storage
    limit and a name nothing else sets. Neither name is in the environment when the test starts, and
    neither is when it ends."""
    for name in ("MAX_STORAGE_GB", ONLY_IN_THE_DOTENV):
        monkeypatch.setenv(name, "set aside")       # so that monkeypatch removes whatever a start adds
        monkeypatch.delenv(name)
    path = tmp_path / ".env"
    path.write_text(f"MAX_STORAGE_GB=64\n{ONLY_IN_THE_DOTENV}=1\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    return path


def test_a_start_in_the_test_process_does_not_read_the_dotenv_in_the_working_directory(monkeypatch, dotenv):
    _start_again(monkeypatch)
    assert ONLY_IN_THE_DOTENV not in os.environ and "MAX_STORAGE_GB" not in os.environ
    assert settings.max_storage_gb == -1


def test_a_start_given_that_file_by_name_reads_it(dotenv):
    """The control for the test above: the file is one a start can read, and naming it still works."""
    config._runtime_initialized = False
    config.initialize_runtime(dotenv_path=dotenv, interactive=False)
    assert os.environ[ONLY_IN_THE_DOTENV] == "1"
    assert settings.max_storage_gb == 64


# A unit module as many are: it imports the server module, which starts the runtime if nothing has, so
# the start happens while pytest collects the module, before any test and any fixture.
A_MODULE_THAT_IMPORTS_THE_SERVER = """
    import os

    import pytest

    from app.api import api_server  # noqa: F401
    from app.core import config
    from app.core.config import settings

    pytestmark = pytest.mark.unit

    settings.rate_limit_vault_attempts = 77     # a change made while the module is imported


    def test_the_settings_are_not_the_deployments():
        assert config.runtime_is_initialized()
        assert "A_NAME_ONLY_THE_DOTENV_HAS" not in os.environ
        assert (settings.max_storage_gb, settings.rate_limit_login_attempts) == (-1, 5)


    def test_nor_what_a_module_set_while_it_was_imported():
        assert settings.rate_limit_vault_attempts == 5


    def test_the_same_file_given_by_name_would_have_set_them():
        config._runtime_initialized = False
        config.initialize_runtime(dotenv_path=".env", interactive=False)
        assert os.environ["A_NAME_ONLY_THE_DOTENV_HAS"] == "1"
        assert (settings.max_storage_gb, settings.rate_limit_login_attempts) == (64, 2000)
"""


IN_THE_DOTENV = ("MAX_STORAGE_GB", "RATE_LIMIT_LOGIN_ATTEMPTS", ONLY_IN_THE_DOTENV)


def _a_run_of_its_own(directory, module, **environment):
    """Run `module` in a pytest process of its own, started in `directory` with tests/conftest.py loaded
    as it is, and with this process's environment plus `environment`, less the names the deployment's
    .env sets. Returns the finished process and everything it said."""
    (directory / "pytest.ini").write_text("[pytest]\nmarkers =\n    unit: runs without a stack\n", encoding="utf-8")
    (directory / "test_in_a_run_of_its_own.py").write_text(textwrap.dedent(module), encoding="utf-8")
    given = {name: value for name, value in os.environ.items()
             if not name.startswith("PYTEST_") and name not in IN_THE_DOTENV}
    given.update(environment, PYTHONPATH=os.pathsep.join([str(TESTS), str(TESTS.parent)]),
                 PYTEST_DISABLE_PLUGIN_AUTOLOAD="1")
    # Well under the deadline every test of the suite has, so that a run that hangs fails this test.
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "conftest", "-p", "no:cacheprovider", "-v",
         "test_in_a_run_of_its_own.py"],
        cwd=directory, env=given, capture_output=True, text=True, timeout=300)
    return done, done.stdout + done.stderr


def test_a_run_beside_a_deployment_does_not_work_under_the_deployments_dotenv(tmp_path):
    """The case as it happens: a run of its own, started in a directory that holds a deployment's .env,
    whose test module imports the server while it is collected. The run's settings are the defaults:
    they were taken when the run started, before any test module was imported, so neither the .env nor
    a change the module makes at import is in them. The last test of the module is the control: the
    same file, named, does carry the limits."""
    (tmp_path / ".env").write_text(
        f"MAX_STORAGE_GB=64\nRATE_LIMIT_LOGIN_ATTEMPTS=2000\n{ONLY_IN_THE_DOTENV}=1\n", encoding="utf-8")
    done, said = _a_run_of_its_own(tmp_path, A_MODULE_THAT_IMPORTS_THE_SERVER)
    assert "test_the_settings_are_not_the_deployments PASSED" in said, said[-3000:]
    assert "test_nor_what_a_module_set_while_it_was_imported PASSED" in said, said[-3000:]
    assert "test_the_same_file_given_by_name_would_have_set_them PASSED" in said, said[-3000:]
    assert done.returncode == 0, said[-3000:]


# ---- an environment the runtime refuses -------------------------------------------------------------

A_GOOD_SIGNING_SECRET = "s" * 32

IN_A_RUN_THAT_COULD_NOT_START_THE_RUNTIME = f"""
    import pytest

    from app.core import config

    pytestmark = pytest.mark.unit


    def test_the_runtime_is_not_started_and_a_test_can_start_it_for_itself(monkeypatch):
        assert not config.runtime_is_initialized()
        monkeypatch.setenv("JWT_SECRET_KEY", "{A_GOOD_SIGNING_SECRET}")
        config.initialize_runtime(interactive=False)
        assert config.runtime_is_initialized()
        assert config.settings.jwt_secret_key == "{A_GOOD_SIGNING_SECRET}"


    def test_the_test_after_it_starts_as_the_run_did():
        assert not config.runtime_is_initialized()
        assert config.settings.jwt_secret_key != "{A_GOOD_SIGNING_SECRET}"
"""


def test_a_run_whose_environment_the_runtime_refuses_still_runs_its_tests(tmp_path):
    """The run's own start is given an environment the runtime refuses: a signing secret too short to
    use. The run does not end there. Its tests start from the settings as they were, never started, a
    test that needs the runtime starts it from an environment of its own, and the test after that one
    finds it not started again."""
    done, said = _a_run_of_its_own(tmp_path, IN_A_RUN_THAT_COULD_NOT_START_THE_RUNTIME, JWT_SECRET_KEY="short")
    assert "test_the_runtime_is_not_started_and_a_test_can_start_it_for_itself PASSED" in said, said[-3000:]
    assert "test_the_test_after_it_starts_as_the_run_did PASSED" in said, said[-3000:]
    assert done.returncode == 0, said[-3000:]


# ---- what putting back by value relies on -----------------------------------------------------------

def test_every_setting_is_a_plain_value():
    """The settings are put back value by value. A setting that held a list or a dict could be changed
    in place, which putting the same list back would not undo: this refuses such a setting until the
    fixture copies it."""
    plain = (str, int, float, bool, type(None))
    odd = {name: type(value).__name__
           for model in (Settings.model_construct(), settings)
           for name, value in vars(model).items() if not isinstance(value, plain)}
    assert odd == {}
