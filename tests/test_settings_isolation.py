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

import pytest

from app.core import config
from app.core.config import Settings, settings
from app.core.startup_security import credential_manager

pytestmark = pytest.mark.unit


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
