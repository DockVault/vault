"""The image carries no SQLite: no sqlite-libs package, and no _sqlite3 module left without its library.

The vault keeps its data in PostgreSQL, and nothing that runs in the image imports Python's sqlite3. The
base image installs Alpine's sqlite-libs only for that module (its .python-rundeps virtual package lists
libsqlite3.so.0), so findings against the library were findings against the image with no use of it: in
November 2026 four High ones (CVE-2026-119586, CVE-2026-119374, CVE-2026-119379, CVE-2026-119373) had no
fixed package for the base's Alpine branch. The Dockerfile drops that one entry, apk removes the library,
and the module goes with it.

These checks run inside the running stack's web container, so they hold the image that was built, not the
Dockerfile's text:

- the package and the library file are gone, and the module is gone rather than broken: `import sqlite3`
  fails as it does on a Python built without SQLite (No module named '_sqlite3'), not on a missing library;
- every other extension module of the standard library still loads, so the removal took nothing else with
  it. _tkinter is the one that never loaded: the base ships it without the Tk library it needs.

Each check has its control in the same run: the package query finds a package that is installed, the module
lookup finds a module that is there, and the import of every module sees the one that fails.
"""
import json
import os
import subprocess

import pytest

from conftest import skip_if_container_absent

pytestmark = pytest.mark.unit

_CHECK = r"""
import importlib, importlib.util, json, pathlib, sysconfig
result = {"lookup": {name: importlib.util.find_spec(name) is not None for name in ("_sqlite3", "_ssl")}}
try:
    import sqlite3  # noqa: F401
    result["import"] = None
except ImportError as error:
    result["import"] = {"type": type(error).__name__, "name": error.name, "text": str(error)}
lib = pathlib.Path("/usr/lib")
result["library_files"] = sorted(p.name for p in lib.iterdir() if p.name.startswith("libsqlite3"))
dynload = pathlib.Path(sysconfig.get_path("platstdlib")) / "lib-dynload"
loaded, failed = [], {}
for path in sorted(dynload.glob("*.so")):
    name = path.name.split(".")[0]
    try:
        importlib.import_module(name)
        loaded.append(name)
    except Exception as error:  # noqa: BLE001
        failed[name] = f"{type(error).__name__}: {error}"
result["loaded"] = loaded
result["failed"] = failed
print(json.dumps(result))
"""


def _in_the_image(*args, stdin=None):
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    command = ["docker", "exec"] + (["-i"] if stdin is not None else []) + [container, *args]
    try:
        ran = subprocess.run(command, input=stdin, capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(ran, container)
    return ran


@pytest.fixture(scope="module")
def python_in_the_image():
    """What the check found in the web container's Python (one run for the module)."""
    ran = _in_the_image("python", "-", stdin=_CHECK)
    assert ran.returncode == 0, (ran.stderr or ran.stdout)[-1500:]
    return json.loads(ran.stdout.strip().splitlines()[-1])


@pytest.mark.docker
def test_the_image_has_no_sqlite_package():
    gone = _in_the_image("apk", "info", "-e", "sqlite-libs")
    # Control: the same query answers for a package the image does have.
    there = _in_the_image("apk", "info", "-e", "musl")
    assert there.returncode == 0 and there.stdout.strip() == "musl", there
    assert gone.returncode != 0 and gone.stdout.strip() == "", (
        f"sqlite-libs is installed in the image: {gone.stdout!r}")
    rundeps = _in_the_image("apk", "info", "-R", ".python-rundeps")
    assert rundeps.returncode == 0 and "so:libssl.so.3" in rundeps.stdout, rundeps
    assert "libsqlite3" not in rundeps.stdout, rundeps.stdout


@pytest.mark.docker
def test_sqlite3_is_absent_as_on_a_python_built_without_it(python_in_the_image):
    result = python_in_the_image
    assert result["lookup"]["_ssl"] is True, result  # control: the lookup finds a module that is there
    assert result["lookup"]["_sqlite3"] is False, result
    assert result["library_files"] == [], result
    assert "_sqlite3" not in result["loaded"] and "_sqlite3" not in result["failed"], result
    failure = result["import"]
    assert failure is not None, "import sqlite3 succeeded in the image"
    # The module is not there at all, as on a build without SQLite; a module left behind without its
    # library would fail differently (ImportError, "Error loading shared library libsqlite3.so.0").
    assert failure["type"] == "ModuleNotFoundError" and failure["name"] == "_sqlite3", failure


@pytest.mark.docker
def test_every_other_module_of_the_standard_library_still_loads(python_in_the_image):
    result = python_in_the_image
    assert set(result["failed"]) == {"_tkinter"}, result["failed"]
    assert "libtk" in result["failed"]["_tkinter"], result["failed"]
    # The libraries the base installs for Python, each through a module that loads it.
    for name in ("_bz2", "_ctypes", "_curses", "_curses_panel", "_dbm", "_gdbm", "_hashlib", "_lzma",
                 "_ssl", "_uuid", "_zstd", "readline", "zlib"):
        assert name in result["loaded"], (name, result["loaded"])
