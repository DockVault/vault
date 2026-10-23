"""Every place in the application that writes a file, and why each is safe over a power cut, offline.

Stored bytes reach the disk before a row or an answer says they exist (app/core/durable_write.py): every
writer of stored bytes syncs the file, its name in its directory, and each directory it makes, before
the commit. That holds only while no writer is added that skips it, so this lists every call in app/
that writes a file -- an open for writing, write_bytes and write_text, a rename or a replace into place,
a shutil copy or move, a temporary file that is kept, a log file handler, a directory made -- by the
function it is in, and requires each one to be either:

- a writer of stored bytes, synced through durable_write: the entry names the function that syncs it
  and the durable_write calls made there, and the test checks that they are; or
- named below, with the reason it holds no stored bytes: a log, a liveness file, the health check's
  write test, scratch no row ever points at, a hint that may be lost, an archive built in memory.

A writing call in no list fails the test, and so does a listed one that is no longer there, so the lists
cannot drift from the code. Making a directory through durable_write.make_directories is not a writer
here: that is the helper doing it. Which order the syncs come in, and that a failed sync fails the
upload, are tested by running the writers (test_stored_bytes_durability.py and its routes file).
"""
import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------- the classification

# (file, enclosing function) -> (the writing calls in it, by the callee's text; the function that syncs
# what they write; the durable_write calls that function makes).
SYNCED = {
    # A brand image: written to a temporary name, synced, renamed into place, its directory synced.
    ("app/api/api_server.py", "upload_brand_asset"): (
        ["open", "os.replace"], "upload_brand_asset", {"make_directories", "sync_file", "sync_directory"}),
    # A chunk sealed into its .part file (seal_stream_to_file syncs it), renamed into place, the directory
    # synced before the session row counts it.
    ("app/api/api_server.py", "receiver_upload_chunk"): (["os.replace"], "receiver_upload_chunk", {"sync_directory"}),
    ("app/api/api_server.py", "upload_chunk"): (["os.replace"], "upload_chunk", {"sync_directory"}),
    ("app/core/upload_chunk_crypto.py", "seal_stream_to_file"): (["open"], "seal_stream_to_file", {"sync_file"}),
    # A chunk received as it is (its caller renames it into place and syncs the directory).
    ("app/services/streaming_upload.py", "receive_bounded"): (["open"], "receive_bounded", {"sync_file"}),
    # Every stored file of a vault: opened here, synced (content, then its name) when the context closes.
    ("app/services/streaming_upload.py", "StreamingUploadContext.__enter__"): (
        ["open"], "StreamingUploadContext.__exit__", {"sync_file", "sync_directory"}),
    # Overwrites of a stored blob before its unlink: the overwrite is on the disk before the name goes.
    ("app/services/encrypted_file_storage.py", "EncryptedFileStorage.secure_delete"): (
        ["open"], "EncryptedFileStorage.secure_delete", {"sync_file"}),
    ("app/services/vault_service.py", "VaultService._destroy_blobs"): (
        ["open"], "VaultService._destroy_blobs", {"sync_file"}),
    # The SFTP host key: its directory made, the key synced, its name synced.
    ("app/sftp/host_key.py", "generate_ed25519_host_key"): (
        ["os.open"], "generate_ed25519_host_key", {"make_directories", "sync_file", "sync_directory"}),
    # The audit chain's head record and the restore mark: a temporary file in the record's directory (made with
    # its name synced), given its owner and synced, renamed over the old one, the directory synced.
    ("app/core/audit_head_record.py", "_write_file"): (
        ["tempfile.mkstemp", "os.fdopen", "os.replace"], "_write_file",
        {"make_directories", "sync_file", "sync_directory"}),
    # The seals a discard deletes, saved beside the head record: the copy and its name synced before the deletion
    # commits.
    ("app/core/audit_chain_recovery.py", "_save_discarded"): (
        ["open"], "_save_discarded", {"sync_file", "sync_directory"}),
}

HELPER = "durable_write itself: the directory make_directories creates, synced into its parent there"
LOG = "a log file: no stored bytes"
LIVENESS = "the SFTP server's liveness file, written again at every beat; the healthcheck reads its age"
WRITE_TEST = "the health check's write test: an empty file, removed in the same call"
SCRATCH = ("scratch no row ever points at: a buffered SFTP upload's plaintext, removed when its handle "
           "closes (and at start); the stored file is written through StreamingUploadContext")
RESUME_HINT = ("a chunk's digest, a hint for a resuming client: lost or emptied, the client sends the "
               "chunk again, which is slower and never wrong")
IN_MEMORY = "the case export's ZIP, built in memory as it streams to the client: never stored"
NOT_A_FILE = "not a file: an in-memory cache's replace()"
LOCK = "the head record's lock file: empty, it holds only the lock (its directory made through durable_write)"

# (file, enclosing function) -> (the writing calls in it that hold no stored bytes, and why).
NO_STORED_BYTES = {
    ("app/core/durable_write.py", "make_directories"): (["directory.mkdir"], HELPER),
    ("app/services/log_sink.py", "init_sink"): (["os.makedirs", "logging.handlers.RotatingFileHandler"], LOG),
    ("app/sftp/heartbeat.py", "beat"): (["os.open"], LIVENESS),
    ("app/core/health.py", "check_storage_status"): (["open"], WRITE_TEST),
    ("app/sftp/sftp_server.py", "SFTPServerInterface._open_write"): (
        ["_SFTP_TMP_DIR.mkdir", "tempfile.mkstemp", "open"], SCRATCH),
    ("app/api/api_server.py", "receiver_upload_chunk"): (["hash_path.write_text"], RESUME_HINT),
    ("app/api/api_server.py", "upload_chunk"): (["hash_path.write_text"], RESUME_HINT),
    ("app/core/case_export.py", "ExportStream._pieces"): (["zipfile.ZipFile", "archive.open"], IN_MEMORY),
    ("app/api/api_server.py", "update_settings"): (["_api_rate_limit_policy_cache.replace"], NOT_A_FILE),
    ("app/core/audit_head_record.py", "_file_lock"): (["os.open"], LOCK),
}

# --------------------------------------------------------------------------- the scan

_MODE = re.compile(r"^[rwxabtU+]{1,5}$")
# Functions that open a file by name, with the mode as their second argument.
_OPENERS = {"open", "io.open", "os.fdopen", "codecs.open", "gzip.open", "bz2.open", "lzma.open", "tarfile.open"}
_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL", "O_TMPFILE"}
# Functions that write, whatever their arguments.
_WRITERS = {
    "os.rename", "os.renames", "os.replace", "os.link", "os.symlink", "os.mkdir", "os.makedirs", "os.truncate",
    "os.mkfifo", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree", "shutil.copyfileobj",
    "shutil.move", "shutil.make_archive", "shutil.unpack_archive", "tempfile.mkstemp", "tempfile.mkdtemp",
    "logging.FileHandler", "logging.handlers.RotatingFileHandler", "logging.handlers.TimedRotatingFileHandler",
    "logging.handlers.WatchedFileHandler",
}
# Methods that write, on whatever object (a Path, as a rule).
_WRITING_METHODS = {"write_bytes", "write_text", "touch", "mkdir", "symlink_to", "hardlink_to"}


def _imports(tree) -> dict:
    """Local name -> what it names, for the modules and functions imported anywhere in the module."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _qualified(func, imports) -> str:
    text = ast.unparse(func)
    head, _, rest = text.partition(".")
    if head in imports:
        return imports[head] + ("." + rest if rest else "")
    return text


def _keyword(call, name):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _writes_in_mode(mode) -> bool:
    if mode is None:
        return False                                    # the default mode reads
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(c in mode.value for c in "wax+")
    return True                                         # a mode the scan cannot read counts as a write


def _flags_write(flags) -> bool:
    """os.open's flags: a write when they name a writing flag, or name none the scan can read."""
    named = {n.attr for n in ast.walk(flags) if isinstance(n, ast.Attribute)}
    named |= {n.id for n in ast.walk(flags) if isinstance(n, ast.Name)}
    named |= {n.value for n in ast.walk(flags) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    flags_named = {n for n in named if n.startswith("O_")}
    return bool(flags_named & _WRITE_FLAGS) or not flags_named


def is_writer(call: ast.Call, imports: dict) -> bool:
    func = call.func
    name = _qualified(func, imports)
    if name == "os.open":
        return len(call.args) < 2 or _flags_write(call.args[1])
    if name in _OPENERS:
        mode = _keyword(call, "mode")
        if mode is None and len(call.args) > 1:
            mode = call.args[1]
        return _writes_in_mode(mode)
    if name in _WRITERS:
        return True
    if name == "tempfile.NamedTemporaryFile":
        delete = _keyword(call, "delete")              # kept unless deleted on close (the default)
        return delete is not None and not (isinstance(delete, ast.Constant) and delete.value is True)
    if name == "zipfile.ZipFile":
        mode = _keyword(call, "mode") or (call.args[1] if len(call.args) > 1 else None)
        return _writes_in_mode(mode)
    if isinstance(func, ast.Attribute):
        if func.attr == "open":                         # Path.open, ZipFile.open, aiofiles.open, ...
            mode = _keyword(call, "mode")
            if mode is None:
                mode = next((a for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                             and _MODE.match(a.value)), None)
            return _writes_in_mode(mode)
        if func.attr in _WRITING_METHODS:
            return True
        # Path.rename(target) and Path.replace(target): one argument, where str.replace takes two and
        # datetime.replace keywords.
        if func.attr in ("rename", "replace") and len(call.args) == 1 and not call.keywords:
            return True
    return False


def writers(source: str) -> dict:
    """{enclosing function's dotted name: [callee text, ...]} of every call in ``source`` that writes a file."""
    tree = ast.parse(source)
    imports = _imports(tree)
    found = {}

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, scope + [child.name])
                continue
            if isinstance(child, ast.Call) and is_writer(child, imports):
                found.setdefault(".".join(scope) or "<module>", []).append(ast.unparse(child.func))
            visit(child, scope)

    visit(tree, [])
    return found


def _functions(source: str) -> dict:
    """{dotted name: node} of every function in ``source``."""
    out = {}

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = scope + [child.name]
                if not isinstance(child, ast.ClassDef):
                    out[".".join(name)] = child
                visit(child, name)

    visit(ast.parse(source), [])
    return out


def durable_calls(source: str, function: str) -> set:
    """The durable_write functions ``function`` in ``source`` calls, through the module or imported by name."""
    tree = ast.parse(source)
    imports = _imports(tree)
    node = _functions(source)[function]
    out = set()
    for call in ast.walk(node):
        if isinstance(call, ast.Call):
            name = _qualified(call.func, imports)
            if name.startswith("app.core.durable_write.") or name.startswith("durable_write."):
                out.add(name.rsplit(".", 1)[1])
    return out


def _all_writers() -> dict:
    out = {}
    for path in sorted((ROOT / "app").rglob("*.py")):
        rel = path.relative_to(ROOT).as_posix()
        for scope, calls in writers(path.read_text(encoding="utf-8")).items():
            out[(rel, scope)] = calls
    return out


def unclassified(found: dict) -> dict:
    """The writing calls in ``found`` that neither list names, and the listed ones no longer there."""
    problems = {}
    for key in set(found) | set(SYNCED) | set(NO_STORED_BYTES):
        listed = SYNCED.get(key, ([],))[0] + NO_STORED_BYTES.get(key, ([],))[0]
        if sorted(found.get(key, [])) != sorted(listed):
            problems[key] = {"found": sorted(found.get(key, [])), "listed": sorted(listed)}
    return problems


def missing_syncs(sources: dict) -> dict:
    """For each synced writer, the durable_write calls its syncing function no longer makes."""
    problems = {}
    for (rel, scope), (_calls, site, needed) in SYNCED.items():
        made = durable_calls(sources[rel], site)
        if not needed <= made:
            problems[(rel, scope)] = sorted(needed - made)
    return problems


# --------------------------------------------------------------------------- the scan, checked

def test_the_scan_finds_each_kind_of_writer():
    source = (
        "import io, os, shutil, tempfile, zipfile, logging\n"
        "import logging.handlers\n"
        "from shutil import copyfile as cf\n"
        "from tempfile import mkstemp\n"
        "def w(p, q, fd, mode, flags, sink, info, archive):\n"
        "    open(p, 'wb'); open(p, 'a'); open(p, mode); open(p, mode='x'); open(p, 'r+')\n"
        "    io.open(p, 'w'); os.fdopen(fd, 'wb'); p.open('w'); archive.open(info, mode='w')\n"
        "    os.open(p, os.O_WRONLY | os.O_CREAT); os.open(p, flags)\n"
        "    p.write_bytes(b''); p.write_text(''); p.touch()\n"
        "    os.rename(p, q); os.replace(p, q); p.rename(q); p.replace(q)\n"
        "    shutil.copy(p, q); shutil.copy2(p, q); cf(p, q); shutil.copytree(p, q)\n"
        "    shutil.copyfileobj(p, q); shutil.move(p, q)\n"
        "    mkstemp(); tempfile.mkdtemp(); tempfile.NamedTemporaryFile(delete=False)\n"
        "    p.mkdir(); os.mkdir(p); os.makedirs(p)\n"
        "    logging.FileHandler(p); logging.handlers.RotatingFileHandler(p)\n"
        "    zipfile.ZipFile(sink, mode='w'); p.symlink_to(q); os.link(p, q)\n"
        "class Box:\n"
        "    def m(self):\n"
        "        def inner(p):\n"
        "            p.write_bytes(b'')\n"
        "        return inner\n"
    )
    found = writers(source)
    assert found == {
        "w": ["open", "open", "open", "open", "open", "io.open", "os.fdopen", "p.open", "archive.open",
              "os.open", "os.open", "p.write_bytes", "p.write_text", "p.touch",
              "os.rename", "os.replace", "p.rename", "p.replace",
              "shutil.copy", "shutil.copy2", "cf", "shutil.copytree", "shutil.copyfileobj", "shutil.move",
              "mkstemp", "tempfile.mkdtemp", "tempfile.NamedTemporaryFile",
              "p.mkdir", "os.mkdir", "os.makedirs",
              "logging.FileHandler", "logging.handlers.RotatingFileHandler",
              "zipfile.ZipFile", "p.symlink_to", "os.link"],
        "Box.m.inner": ["p.write_bytes"],
    }


def test_the_scan_leaves_reads_and_other_objects_alone():
    source = (
        "import os, tempfile, zipfile\n"
        "from app.core import durable_write\n"
        "def r(p, s, d, items, archive):\n"
        "    open(p); open(p, 'rb'); open(p, mode='r'); p.open(); p.open('rb'); archive.open('name')\n"
        "    os.open(p, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))\n"
        "    s.replace('a', 'b'); d.replace(tzinfo=None); items.remove(1); p.read_bytes()\n"
        "    tempfile.NamedTemporaryFile(); tempfile.NamedTemporaryFile(delete=True)\n"
        "    tempfile.TemporaryDirectory(); zipfile.ZipFile(p)\n"
        "    durable_write.make_directories(p); durable_write.sync_file(p)\n"
    )
    assert writers(source) == {}


def test_a_new_writer_in_no_list_fails_and_so_does_a_listed_one_that_is_gone():
    found = _all_writers()
    before = set(unclassified(found))

    def new_problems(changed):
        return {k: v for k, v in unclassified(changed).items() if k not in before}

    added = dict(found)
    added[("app/services/vault_service.py", "VaultService.new_writer")] = ["open"]
    assert new_problems(added) == {("app/services/vault_service.py", "VaultService.new_writer"): {
        "found": ["open"], "listed": []}}
    brand = ("app/api/api_server.py", "upload_brand_asset")
    another = dict(found)
    another[brand] = found[brand] + ["shutil.copy"]
    assert list(new_problems(another)) == [brand]
    gone = {k: v for k, v in found.items() if k != ("app/sftp/heartbeat.py", "beat")}
    assert list(new_problems(gone)) == [("app/sftp/heartbeat.py", "beat")]


def test_a_synced_writer_whose_sync_is_gone_fails():
    rel = "app/sftp/host_key.py"
    source = (ROOT / rel).read_text(encoding="utf-8")
    assert source.count("durable_write.sync_directory(") == 1
    without = source.replace("durable_write.sync_directory(", "print(")
    sources = {k[0]: (ROOT / k[0]).read_text(encoding="utf-8") for k in SYNCED}
    assert missing_syncs(sources) == {}
    sources[rel] = without
    assert missing_syncs(sources) == {(rel, "generate_ed25519_host_key"): ["sync_directory"]}


def test_a_durable_call_imported_by_name_counts():
    source = ("def f(p):\n"
              "    from app.core.durable_write import make_directories\n"
              "    make_directories(p)\n")
    assert durable_calls(source, "f") == {"make_directories"}


# --------------------------------------------------------------------------- the application

def test_every_file_writer_in_the_application_is_synced_or_holds_no_stored_bytes():
    problems = unclassified(_all_writers())
    assert not problems, (
        "a call that writes a file is in no list, or a listed one is gone: if it writes stored bytes (anything a "
        "row or an answer points at), sync it through app/core/durable_write and add it to SYNCED; if it holds "
        f"none, add it to NO_STORED_BYTES with the reason: {problems}")


def test_each_synced_writer_is_synced_through_durable_write_where_its_entry_says():
    known = {n.name for n in ast.parse((ROOT / "app" / "core" / "durable_write.py").read_text(encoding="utf-8")).body
             if isinstance(n, ast.FunctionDef)}
    for key, (_calls, _site, needed) in SYNCED.items():
        assert needed and needed <= known, (key, needed - known)
    sources = {rel: (ROOT / rel).read_text(encoding="utf-8") for rel, _scope in SYNCED}
    assert missing_syncs(sources) == {}


def test_every_entry_says_why():
    for key, (calls, reason) in NO_STORED_BYTES.items():
        assert calls and reason in (HELPER, LOG, LIVENESS, WRITE_TEST, SCRATCH, RESUME_HINT, IN_MEMORY, NOT_A_FILE,
                                    LOCK), key
