"""Every place in the application that writes a file, and why each is safe over a power cut, offline.

Stored bytes reach the disk before a row or an answer says they exist (app/core/durable_write.py): every
writer of stored bytes syncs the file, its name in its directory, and each directory it makes, before
the commit. That holds only while no writer is added that skips it, so this lists every call in app/
that writes a file -- an open for writing (open, io.FileIO, the gzip, bz2, lzma and tar files, anyio's
open_file, a file database, fileinput in place), write_bytes and write_text, a rename or a replace into
place (os's, or aiofiles' async os), a shutil copy or move, Path's copy and move, an archive extracted, a
node made, a temporary file or directory that is kept, a log file handler (or a class made from one) or a
logging configuration given a file, an image or a document saved, a process started, a directory made,
any of them called through another name an assignment, a default argument or a class body gives it, held
in a dict, a list or a tuple, named by getattr, through a module import_module or __import__ gives,
through __call__, brought in by a star import, or handed to another call to run -- by the function it is
in, and requires each one to be either:

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
    # The SFTP host key: its directory made, the key written to a temporary file and synced, linked into place
    # (never over another key), its name synced; or, with no hard links, created at its path exclusively.
    ("app/sftp/host_key.py", "generate_ed25519_host_key"): (
        ["os.open", "os.link"], "generate_ed25519_host_key", {"make_directories", "sync_file", "sync_directory"}),
    ("app/sftp/host_key.py", "_write_in_place"): (["os.open"], "_write_in_place", {"sync_file", "sync_directory"}),
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
QR_IN_MEMORY = "the second factor's QR code, drawn into a buffer in memory and sent in the answer: never stored"
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
    ("app/core/second_factor.py", "otpauth_qr_svg"): (["qr.make_image(image_factory=SvgPathImage).save"],
                                                      QR_IN_MEMORY),
}

# --------------------------------------------------------------------------- the scan

_MODE = re.compile(r"^[rwxabtU+]{1,5}$")
# Functions and classes that open a file by name, with the mode as their second argument.
_OPENERS = {"open", "builtins.open", "io.open", "io.FileIO", "os.fdopen", "codecs.open", "gzip.open", "gzip.GzipFile",
            "bz2.open", "bz2.BZ2File", "lzma.open", "lzma.LZMAFile", "tarfile.open", "tarfile.TarFile",
            "anyio.open_file"}
# Databases kept in a file, with their flag as the second argument and the flag they take when given none: they
# write unless opened read-only ("r").
_FLAGGED_OPENERS = {"shelve.open": "c", "dbm.open": "r", "dbm.gnu.open": "r", "dbm.ndbm.open": "r",
                    "dbm.dumb.open": "c", "dbm.sqlite3.open": "r"}
_WRITE_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_APPEND", "O_TRUNC", "O_EXCL", "O_TMPFILE"}
# Functions that write, whatever their arguments.
_WRITERS = {
    "os.rename", "os.renames", "os.replace", "os.link", "os.symlink", "os.mkdir", "os.makedirs", "os.truncate",
    "os.mkfifo", "os.mknod", "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.copytree",
    "shutil.copyfileobj", "shutil.move", "shutil.make_archive", "shutil.unpack_archive", "tempfile.mkstemp",
    "tempfile.mkdtemp", "logging.FileHandler", "logging.handlers.RotatingFileHandler",
    "logging.handlers.TimedRotatingFileHandler", "logging.handlers.WatchedFileHandler",
    # A logging configuration may make file handlers of its own.
    "logging.config.dictConfig", "logging.config.fileConfig",
    # A process started may write anything.
    "subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen",
    "subprocess.getoutput", "subprocess.getstatusoutput", "os.system", "os.popen", "os.posix_spawn",
    "os.posix_spawnp", "os.spawnl", "os.spawnle", "os.spawnlp", "os.spawnlpe", "os.spawnv", "os.spawnve",
    "os.spawnvp", "os.spawnvpe", "os.execl", "os.execle", "os.execlp", "os.execlpe", "os.execv", "os.execve",
    "os.execvp", "os.execvpe", "asyncio.create_subprocess_exec", "asyncio.create_subprocess_shell", "pty.spawn",
}
# Modules that run another's calls: aiofiles' async os and tempfile write as os and tempfile do.
_STANDS_FOR = {"aiofiles.os.": "os.", "aiofiles.tempfile.": "tempfile."}
# Calls that give a module by its name (importlib.import_module("shutil").copyfile is shutil.copyfile).
_MODULE_GIVERS = {"importlib.import_module", "__import__"}
# Methods that write, on whatever object (a Path, as a rule; extract and extractall: a ZipFile's or a TarFile's).
_WRITING_METHODS = {"write_bytes", "write_text", "touch", "mkdir", "symlink_to", "hardlink_to", "copy_into",
                    "move_into", "extract", "extractall"}
# Methods that write when given a target: Path.copy and Path.move (a dict's or a list's copy takes none), and an
# image's or a document's save (PIL's Image.save, and the like: a buffer in memory is a target too, and is listed).
_TARGET_METHODS = {"copy", "move", "save"}
_NOT_TARGET_METHODS = {"copy.copy", "copy.deepcopy"}
# Every function the scan knows to write, by its full name: what a module's star import may bring in, and what a
# call may be handed to run.
_KNOWN = (_OPENERS | set(_FLAGGED_OPENERS) | _WRITERS
          | {"os.open", "sqlite3.connect", "tempfile.NamedTemporaryFile", "tempfile.TemporaryDirectory",
             "zipfile.ZipFile", "logging.basicConfig", "fileinput.input", "fileinput.FileInput"})
# The last part of each such name: what an attribute of a module the scan cannot name may be.
_KNOWN_LAST = {name.rsplit(".", 1)[1] for name in _KNOWN if "." in name}
# Modules whose attribute named by a string the scan cannot read may be any of their writers.
_WRITER_MODULES = {name.rsplit(".", 1)[0] for name in _KNOWN if "." in name} | {"builtins", "pathlib"}
# Calls that run a function they are handed, by where it is among their arguments (its own arguments follow it).
_RUNNERS = {"asyncio.to_thread": 0, "anyio.to_thread.run_sync": 0}
_RUNNER_METHODS = {"run_in_executor": 1, "submit": 0}


def _imports(tree) -> dict:
    """Local name -> what it names, for the modules and functions imported anywhere in the module; "*" -> the modules
    imported whole (``from shutil import *``)."""
    names = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    names[alias.asname] = alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
            for alias in node.names:
                if alias.name == "*":
                    names.setdefault("*", []).append(node.module)
                else:
                    names[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return names


def _text(node) -> str:
    """The source text of a name or a dotted name (as ast.unparse gives it, read directly), or of any other node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parts = [node.attr]
        value = node.value
        while isinstance(value, ast.Attribute):
            parts.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            return ".".join([value.id] + parts[::-1])
    return ast.unparse(node)


def _given_module(node, imports):
    """The module ``importlib.import_module("name")`` or ``__import__("name")`` gives: its name, "" for a name the scan
    cannot read, None when ``node`` is no such call."""
    if not (isinstance(node, ast.Call) and node.args and _qualified(node.func, imports) in _MODULE_GIVERS):
        return None
    first = node.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else ""


def _standing(name: str) -> str:
    for prefix, stands in _STANDS_FOR.items():
        if name.startswith(prefix):
            return stands + name[len(prefix):]
    return name


def _qualified(func, imports) -> str:
    if isinstance(func, ast.Attribute):
        module = _given_module(func.value, imports)
        if module:
            return _standing(f"{module}.{func.attr}")
    text = _text(func)
    head, _, rest = text.partition(".")
    if head in imports and head != "*":
        return _standing(imports[head] + ("." + rest if rest else ""))
    for module in imports.get("*", ()):
        if f"{module}.{text}" in _KNOWN:
            return f"{module}.{text}"
    return _standing(text)


def _named_attribute(call: ast.Call):
    """``getattr(obj, "name")`` as the attribute ``obj.name``; None for any other call."""
    if (isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 2
            and isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str)):
        return ast.Attribute(value=call.args[0], attr=call.args[1].value, ctx=ast.Load())
    return None


def _unknown_attribute_of_a_writer_module(call: ast.Call, imports) -> bool:
    """``getattr(module, name)`` with a name the scan cannot read, of a module that has writers."""
    return (isinstance(call.func, ast.Name) and call.func.id == "getattr" and len(call.args) >= 2
            and not (isinstance(call.args[1], ast.Constant) and isinstance(call.args[1].value, str))
            and _qualified(call.args[0], imports) in _WRITER_MODULES)


def _is_writer_reference(node, imports, aliases=None, depth: int = 0) -> bool:
    """A function that writes, named and not called (handed to another call to run): by its name, through
    __call__, a name an assignment binds to one, or a dict, a list or a tuple holding one."""
    if depth > 5:
        return False
    if isinstance(node, ast.Call):
        named = _named_attribute(node)
        return named is not None and _is_writer_reference(named, imports, aliases, depth + 1)
    if isinstance(node, ast.Subscript):
        return any(_is_writer_reference(held, imports, aliases, depth + 1)
                   for held in _held(node.value, imports, aliases))
    if isinstance(node, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
        return any(_is_writer_reference(held, imports, aliases, depth + 1)
                   for held in _held(node, imports, aliases))
    if not isinstance(node, (ast.Name, ast.Attribute)):
        return False
    if isinstance(node, ast.Attribute) and node.attr == "__call__":
        return _is_writer_reference(node.value, imports, aliases, depth + 1)
    if _qualified(node, imports) in _KNOWN:
        return True
    if isinstance(node, ast.Attribute) and _given_module(node.value, imports) == "" and node.attr in _KNOWN_LAST:
        return True
    if aliases and any(_is_writer_reference(bound, imports, aliases, depth + 1)
                       for bound in _bindings(node, imports, aliases)):
        return True
    return isinstance(node, ast.Attribute) and node.attr in _WRITING_METHODS


def _handed(call: ast.Call, imports) -> list:
    """The call ``call`` makes of the function it is handed, when it is a runner the scan knows (asyncio.to_thread,
    anyio's run_sync, a pool's submit, a loop's run_in_executor), with that function's own arguments."""
    name = _qualified(call.func, imports)
    at = _RUNNERS.get(name)
    if at is None and isinstance(call.func, ast.Attribute):
        at = _RUNNER_METHODS.get(call.func.attr)
    if at is None or len(call.args) <= at:
        return []
    return [ast.Call(func=call.args[at], args=list(call.args[at + 1:]), keywords=list(call.keywords))]


_BOUND = (ast.Name, ast.Attribute, ast.Call, ast.Subscript, ast.Dict, ast.List, ast.Tuple, ast.Set)


def _aliases(tree) -> dict:
    """Name -> the expressions bound to it, for a name or an attribute given a callable, a module, or a dict, a list
    or a tuple of them, anywhere in the module: by assignment (``o = open``, ``self.save = os.replace``, ``w =
    functools.partial(open, mode="w")``, ``sh = shutil``, ``table = {"w": open}``), as a parameter's default
    (``def f(p, w=open)``), in a class body (``save = os.replace``, called as ``self.save``), or as a class's base
    (``class Log(logging.FileHandler)``, made as ``Log(p)``): a call through it is judged as a call of what it
    names."""
    out = {}

    def bind(name, value):
        if isinstance(value, _BOUND):
            out.setdefault(name, []).append(value)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            args = node.args
            positional = args.posonlyargs + args.args
            for arg, default in zip(positional[len(positional) - len(args.defaults):], args.defaults):
                bind(arg.arg, default)
            for arg, default in zip(args.kwonlyargs, args.kw_defaults):
                if default is not None:
                    bind(arg.arg, default)
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, (ast.Name, ast.Attribute)):
                    bind(node.name, base)
            for stmt in node.body:
                if isinstance(stmt, ast.Assign):
                    names, value = [t for t in stmt.targets if isinstance(t, ast.Name)], stmt.value
                elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name):
                    names, value = [stmt.target], stmt.value
                else:
                    continue
                for target in names:
                    for through in ("self", "cls", node.name):
                        bind(f"{through}.{target.id}", value)
        if isinstance(node, ast.Assign):
            targets, value = node.targets, node.value
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            targets, value = [node.target], node.value
        else:
            continue
        for target in targets:
            if isinstance(target, (ast.Name, ast.Attribute)):
                bind(_text(target), value)
    return out


def _held(node, imports, aliases, depth: int = 0) -> list:
    """What a dict, a list, a tuple or a set holds (``{"w": open}``, ``dict(w=open)``, ``[open]``), directly or through a
    name bound to one: the expressions a subscript of it may give."""
    if depth > 5:
        return []
    if isinstance(node, ast.Dict):
        return list(node.values)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return list(node.elts)
    if isinstance(node, ast.Call) and _qualified(node.func, imports) == "dict":
        return list(node.args) + [k.value for k in node.keywords]
    if isinstance(node, (ast.Name, ast.Attribute)) and aliases:
        return [h for bound in aliases.get(_text(node), ()) for h in _held(bound, imports, aliases, depth + 1)]
    return []


def _keyword(call, name):
    return next((k.value for k in call.keywords if k.arg == name), None)


def _writes_in_mode(mode) -> bool:
    if mode is None:
        return False                                    # the default mode reads
    if isinstance(mode, ast.Constant) and isinstance(mode.value, str):
        return any(c in mode.value.split(":", 1)[0] for c in "wax+")    # tarfile's "r:xz" reads
    return True                                         # a mode the scan cannot read counts as a write


def _flags_write(flags) -> bool:
    """os.open's flags: a write when they name a writing flag, or name none the scan can read."""
    named = {n.attr for n in ast.walk(flags) if isinstance(n, ast.Attribute)}
    named |= {n.id for n in ast.walk(flags) if isinstance(n, ast.Name)}
    named |= {n.value for n in ast.walk(flags) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    flags_named = {n for n in named if n.startswith("O_")}
    return bool(flags_named & _WRITE_FLAGS) or not flags_named


def _through(bound, call: ast.Call) -> ast.Call:
    """``call`` made through a name bound to ``bound``: the call of what it names, a partial's own arguments first."""
    if isinstance(bound, ast.Call):
        return ast.Call(func=bound.args[0], args=list(bound.args[1:]) + list(call.args),
                        keywords=list(bound.keywords) + list(call.keywords))
    return ast.Call(func=bound, args=list(call.args), keywords=list(call.keywords))


def _bindings(func, imports: dict, aliases: dict) -> list:
    """What ``func`` is bound to by an assignment the scan can follow: callables, partials of one, and the attribute
    a getattr with a string names (``f = getattr(shutil, "copyfile")``)."""
    out = []
    for bound in aliases.get(_text(func), ()):
        if isinstance(bound, ast.Call):
            named = _named_attribute(bound)
            if named is not None:
                out.append(named)
            elif _qualified(bound.func, imports) in ("functools.partial", "partial") and bound.args:
                out.append(bound)
        elif isinstance(bound, (ast.Name, ast.Attribute, ast.Subscript)) and _text(bound) != _text(func):
            out.append(bound)
    if isinstance(func, ast.Attribute):
        # An attribute of a name bound to a module (``sh = shutil``, ``m = importlib.import_module("shutil")``).
        for bound in aliases.get(_text(func.value), ()):
            if isinstance(bound, (ast.Name, ast.Attribute, ast.Call)) and _text(bound) != _text(func.value):
                out.append(ast.Attribute(value=bound, attr=func.attr, ctx=ast.Load()))
    return out


def _callable(node, imports) -> bool:
    """Whether ``node``, held in a container, is something a call through it calls: a name, an attribute, a partial
    or a getattr with a string."""
    if isinstance(node, (ast.Name, ast.Attribute)):
        return True
    return isinstance(node, ast.Call) and bool(node.args) and (
        _named_attribute(node) is not None or _qualified(node.func, imports) in ("functools.partial", "partial"))


def _through_held(held, call: ast.Call) -> ast.Call:
    named = _named_attribute(held) if isinstance(held, ast.Call) else None
    return ast.Call(func=named, args=list(call.args), keywords=list(call.keywords)) if named is not None \
        else _through(held, call)


def is_writer(call: ast.Call, imports: dict, aliases: dict = None, depth: int = 0) -> bool:
    func = call.func
    if aliases and depth < 5:
        # A writer called through another name: `o = open` then `o(p, "w")`.
        if any(is_writer(_through(bound, call), imports, aliases, depth + 1)
               for bound in _bindings(func, imports, aliases)):
            return True
    if isinstance(func, ast.Subscript) and depth < 5:
        # A writer held in a dict, a list or a tuple, called from it: {"w": open}["w"](p, "w").
        return any(is_writer(_through_held(held, call), imports, aliases, depth + 1)
                   for held in _held(func.value, imports, aliases) if _callable(held, imports))
    if isinstance(func, ast.Attribute) and func.attr == "__call__" and depth < 5:
        return is_writer(ast.Call(func=func.value, args=list(call.args), keywords=list(call.keywords)), imports,
                         aliases, depth + 1)
    if isinstance(func, ast.Attribute) and _given_module(func.value, imports) == "":
        return func.attr in _KNOWN_LAST                 # a writer of a module the scan cannot name
    if isinstance(func, ast.Call) and depth < 5:
        # A writer that a call gives, called at once: getattr(shutil, "copyfile")(p, q), partial(open, mode="w")(p).
        named = _named_attribute(func)
        if named is not None:
            return is_writer(ast.Call(func=named, args=list(call.args), keywords=list(call.keywords)), imports,
                             aliases, depth + 1)
        if _unknown_attribute_of_a_writer_module(func, imports):
            return True                                 # a writer module's attribute the scan cannot name
        if _qualified(func.func, imports) in ("functools.partial", "partial") and func.args:
            return is_writer(_through(func, call), imports, aliases, depth + 1)
        return False
    name = _qualified(func, imports)
    if name == "logging.basicConfig":                   # a file handler of its own, given a file name
        return any(k.arg in ("filename", None) for k in call.keywords)
    if name == "os.open":
        return len(call.args) < 2 or _flags_write(call.args[1])
    if name in _OPENERS:
        mode = _keyword(call, "mode")
        if mode is None and len(call.args) > 1:
            mode = call.args[1]
        return _writes_in_mode(mode)
    if name in _FLAGGED_OPENERS:
        flag = _keyword(call, "flag")
        if flag is None:
            flag = call.args[1] if len(call.args) > 1 else ast.Constant(_FLAGGED_OPENERS[name])
        if isinstance(flag, ast.Constant) and isinstance(flag.value, str):
            return any(c in flag.value for c in "wcn")
        return True
    if name == "sqlite3.connect":                       # creates its database file, but for one in memory
        target = call.args[0] if call.args else _keyword(call, "database")
        return not (isinstance(target, ast.Constant) and target.value == ":memory:")
    if name in _WRITERS:
        return True
    if name in ("tempfile.NamedTemporaryFile", "tempfile.TemporaryDirectory"):
        delete = _keyword(call, "delete")              # kept unless deleted on close (the default)
        return delete is not None and not (isinstance(delete, ast.Constant) and delete.value is True)
    if name in ("fileinput.input", "fileinput.FileInput"):
        inplace = _keyword(call, "inplace")            # rewrites its files in place when told to
        if inplace is None and len(call.args) > 1:
            inplace = call.args[1]
        return inplace is not None and not (isinstance(inplace, ast.Constant) and not inplace.value)
    if name == "zipfile.ZipFile":
        mode = _keyword(call, "mode") or (call.args[1] if len(call.args) > 1 else None)
        return _writes_in_mode(mode)
    if isinstance(func, ast.Attribute):
        if func.attr == "open":                         # Path.open, ZipFile.open, aiofiles.open, ...
            mode = _keyword(call, "mode")
            if mode is None:
                mode = next((a for a in call.args if isinstance(a, ast.Constant) and isinstance(a.value, str)
                             and _MODE.match(a.value)), None)
            if mode is None and len(call.args) > 1:
                mode = call.args[1]                     # ZipFile.open(name, mode), aiofiles.open(file, mode)
            elif mode is None and len(call.args) == 1 and not isinstance(call.args[0], ast.Constant):
                # Path.open(mode) with the mode in a variable (or a ZipFile member named by one: the scan cannot
                # tell them apart, so it counts as a write, as any mode it cannot read does).
                mode = call.args[0]
            return _writes_in_mode(mode)
        if func.attr in _WRITING_METHODS:
            return True
        if func.attr in _TARGET_METHODS and (call.args or call.keywords) and name not in _NOT_TARGET_METHODS:
            return True                                 # Path.copy(target), Path.move(target)
        # Path.rename(target) and Path.replace(target): one argument, where str.replace takes two and
        # datetime.replace keywords.
        if func.attr in ("rename", "replace") and len(call.args) == 1 and not call.keywords:
            return True
    return False


def hands_a_writer(call: ast.Call, imports: dict, aliases: dict = None) -> bool:
    """Whether ``call`` is handed a function that writes, to run: by a runner the scan knows, judged as the call the
    runner makes (``asyncio.to_thread(open, p)`` reads); by any other call, a writer it is handed named and not
    called counts as a write (``Thread(target=os.replace, ...)``, ``map(Path.write_text, ...)``). A partial is not
    a run: the call made through it is judged where it is made."""
    if _qualified(call.func, imports) in ("functools.partial", "partial"):
        return False
    handed = _handed(call, imports)
    if handed:
        return any(is_writer(h, imports, aliases) for h in handed)
    return any(_is_writer_reference(arg, imports, aliases)
               for arg in list(call.args) + [k.value for k in call.keywords])


def writers(source: str) -> dict:
    """{enclosing function's dotted name: [callee text, ...]} of every call in ``source`` that writes a file."""
    tree = ast.parse(source)
    imports = _imports(tree)
    aliases = _aliases(tree)
    found = {}

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                visit(child, scope + [child.name])
                continue
            if isinstance(child, ast.Call) and (is_writer(child, imports, aliases)
                                                 or hands_a_writer(child, imports, aliases)):
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


_SCANNED: dict = {}


def _all_writers() -> dict:
    """Every writing call in app/, by (file, scope): scanned once a run (the files do not change while the tests
    run), a copy each time."""
    if "app" not in _SCANNED:
        out = {}
        for path in sorted((ROOT / "app").rglob("*.py")):
            rel = path.relative_to(ROOT).as_posix()
            for scope, calls in writers(path.read_text(encoding="utf-8")).items():
                out[(rel, scope)] = calls
        _SCANNED["app"] = out
    return {key: list(calls) for key, calls in _SCANNED["app"].items()}


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


def test_the_scan_finds_writers_through_other_openers_other_names_and_a_mode_in_a_variable():
    source = (
        "import io, gzip, bz2, lzma, functools, shelve, sqlite3, tarfile\n"
        "from functools import partial\n"
        "def w(p, mode, flag):\n"
        "    io.FileIO(p, 'w'); gzip.GzipFile(p, 'wb'); bz2.BZ2File(p, 'w'); lzma.LZMAFile(p, mode='w')\n"
        "    tarfile.TarFile(p, 'w')\n"
        "    o = open\n"
        "    o(p, 'w')\n"
        "    save = functools.partial(open, mode='w')\n"
        "    save(p)\n"
        "    later = partial(io.FileIO)\n"
        "    later(p, 'a')\n"
        "    p.open(mode)\n"
        "    shelve.open(p); shelve.open(p, flag); sqlite3.connect(p)\n"
        "class Box:\n"
        "    def __init__(self):\n"
        "        self.writer = io.open\n"
        "    def m(self, p):\n"
        "        self.writer(p, 'wb')\n"
    )
    assert writers(source) == {
        "w": ["io.FileIO", "gzip.GzipFile", "bz2.BZ2File", "lzma.LZMAFile", "tarfile.TarFile", "o", "save", "later",
              "p.open", "shelve.open", "shelve.open", "sqlite3.connect"],
        "Box.m": ["self.writer"],
    }


def test_reads_through_other_openers_and_other_names_stay_reads():
    source = (
        "import io, gzip, shelve, sqlite3, dbm, tarfile\n"
        "def r(p):\n"
        "    io.FileIO(p); gzip.GzipFile(p); gzip.GzipFile(p, 'rb'); tarfile.open(p, 'r:xz')\n"
        "    o = open\n"
        "    o(p); o(p, 'rb')\n"
        "    shelve.open(p, 'r'); dbm.open(p); sqlite3.connect(':memory:')\n"
        "    p = p\n"
        "    p.open()\n"
    )
    assert writers(source) == {}


@pytest.mark.parametrize("form", [
    "io.FileIO(path, 'w')", "gzip.GzipFile(path, 'wb')", "bz2.BZ2File(path, 'w')", "lzma.LZMAFile(path, 'w')",
    "o = open\n    o(path, 'w')", "Path(path).open(mode)",
    "Path(path).copy(path + '.b')", "Path(path).move(path + '.b')", "Path(path).copy_into(mode)",
    "Path(path).move_into(mode)", "os.mknod(path)", "zipfile.ZipFile(path).extract('a', mode)",
    "zipfile.ZipFile(path).extractall(mode)", "tarfile.open(path).extractall(mode)",
    "logging.basicConfig(filename=path)", "asyncio.get_event_loop().run_in_executor(None, open, path, 'w')",
    "asyncio.to_thread(open, path, 'w')", "getattr(shutil, 'copyfile')(path, mode)",
    "save = getattr(shutil, 'copyfile')\n    save(path, mode)"])
def test_a_writer_of_each_such_form_added_to_the_application_is_in_no_list(form):
    rel = "app/sftp/heartbeat.py"
    source = (ROOT / rel).read_text(encoding="utf-8") + (
        "\n\ndef added_writer(path, mode):\n"
        "    import asyncio, io, gzip, bz2, lzma, logging, os, shutil, tarfile, zipfile\n"
        "    from pathlib import Path\n"
        f"    {form}\n")
    found = dict(_all_writers())
    found.update({(rel, scope): calls for scope, calls in writers(source).items()})
    assert (rel, "added_writer") in unclassified(found)


def test_a_writer_a_star_import_brings_into_the_application_is_in_no_list():
    rel = "app/sftp/heartbeat.py"
    source = (ROOT / rel).read_text(encoding="utf-8") + (
        "\n\nfrom shutil import *  # noqa: E402,F403\n\n\ndef added_writer(path, other):\n"
        "    copyfile(path, other)  # noqa: F405\n")
    found = dict(_all_writers())
    found.update({(rel, scope): calls for scope, calls in writers(source).items()})
    assert unclassified(found)[(rel, "added_writer")] == {"found": ["copyfile"], "listed": []}


def test_the_scan_finds_the_forms_a_newer_python_and_a_call_handed_a_writer_write_through():
    """Path.copy, Path.move, copy_into and move_into (Python 3.14), os.mknod, an archive extracted, a logging
    configuration given a file; a writer handed to a runner (judged as the call it makes) or to any other call (a
    write), one named by getattr with a string, or by a name the scan cannot read on a module that has writers, a
    partial called at once; a writer a star import brings in."""
    source = (
        "import asyncio, os, shutil, logging, logging.config, threading\n"
        "from functools import partial\n"
        "from shutil import *\n"
        "from os import *\n"
        "def w(p, q, z, t, pool, loop, name):\n"
        "    p.copy(q); p.move(q); p.copy_into(q); p.move_into(q); p.copy(target=q)\n"
        "    os.mknod(p); z.extract('a', q); z.extractall(q); t.extractall(q)\n"
        "    logging.basicConfig(filename=p); logging.basicConfig(**name); logging.config.dictConfig({})\n"
        "    loop.run_in_executor(None, open, p, 'w'); asyncio.to_thread(open, p, 'a')\n"
        "    pool.submit(shutil.copyfile, p, q)\n"
        "    threading.Thread(target=os.replace, args=(p, q)); list(map(p.write_text, q))\n"
        "    getattr(shutil, 'copyfile')(p, q); getattr(os, name)(p)\n"
        "    partial(open, mode='w')(p)\n"
        "    f = getattr(shutil, 'move')\n"
        "    f(p, q)\n"
        "    copyfile(p, q); open(p, 'w'); open(p, O_RDONLY)\n"
    )
    assert writers(source) == {"w": [
        "p.copy", "p.move", "p.copy_into", "p.move_into", "p.copy", "os.mknod", "z.extract", "z.extractall",
        "t.extractall", "logging.basicConfig", "logging.basicConfig", "logging.config.dictConfig",
        "loop.run_in_executor", "asyncio.to_thread", "pool.submit", "threading.Thread", "map",
        "getattr(shutil, 'copyfile')", "getattr(os, name)", "partial(open, mode='w')", "f", "copyfile", "open"]}


def test_the_new_forms_that_read_or_hold_no_file_stay_alone():
    source = (
        "import asyncio, copy, os, shutil, logging\n"
        "from functools import partial\n"
        "def r(p, d, x, loop, pool, name):\n"
        "    d.copy(); copy.copy(x); copy.deepcopy(x); x.copy()\n"
        "    loop.run_in_executor(None, open, p); asyncio.to_thread(open, p, 'rb'); pool.submit(len, p)\n"
        "    loop.run_in_executor(None, lambda: len(p)); getattr(shutil, 'which')(p); getattr(x, name)()\n"
        "    logging.basicConfig(level=10); sorted(p, key=len); partial(open, mode='rb')(p)\n"
        "    os.open(p, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))\n"
    )
    assert writers(source) == {}


# Raw ways of writing a file, each added to a real function of the application: (the code, its scope).
_MORE_FORMS = {
    "a writer bound in a class body, called through self": (
        "class _Saver:\n    save = os.replace\n\n    def added_writer(self, path, mode):\n"
        "        self.save(path, mode)\n", "_Saver.added_writer"),
    "a writer bound in a class body, called through the class": (
        "class _Saver:\n    save = os.replace\n\n\ndef added_writer(path, mode):\n    _Saver.save(path, mode)\n",
        "added_writer"),
    "a file handler's subclass made": (
        "class _Log(logging.handlers.RotatingFileHandler):\n    pass\n\n\n"
        "def added_writer(path, mode):\n    _Log(path)\n", "added_writer"),
    "fileinput in place": (
        "def added_writer(path, mode):\n    import fileinput\n"
        "    for line in fileinput.input(path, inplace=True):\n        print(line)\n", "added_writer"),
    "a temporary directory kept": (
        "def added_writer(path, mode):\n    import tempfile\n    tempfile.TemporaryDirectory(delete=False)\n",
        "added_writer"),
    "a process started": (
        "def added_writer(path, mode):\n    import subprocess\n    subprocess.run(['cp', path, mode], check=True)\n",
        "added_writer"),
    "a process started without a shell": (
        "def added_writer(path, mode):\n    os.posix_spawn('/bin/cp', ['cp', path, mode], {})\n", "added_writer"),
    "anyio's open_file": (
        "async def added_writer(path, mode):\n    import anyio\n    await anyio.open_file(path, 'w')\n",
        "added_writer"),
    "aiofiles' async os": (
        "async def added_writer(path, mode):\n    import aiofiles.os\n    await aiofiles.os.replace(path, mode)\n",
        "added_writer"),
    "aiofiles' temporary file kept": (
        "async def added_writer(path, mode):\n    import aiofiles.tempfile\n"
        "    aiofiles.tempfile.NamedTemporaryFile(delete=False)\n", "added_writer"),
    "a module import_module gives": (
        "def added_writer(path, mode):\n    import importlib\n"
        "    importlib.import_module('shutil').copyfile(path, mode)\n", "added_writer"),
    "a module import_module gives by a name the scan cannot read": (
        "def added_writer(path, mode):\n    import importlib\n    importlib.import_module(mode).copyfile(path, mode)\n",
        "added_writer"),
    "a module __import__ gives": (
        "def added_writer(path, mode):\n    __import__('shutil').copyfile(path, mode)\n", "added_writer"),
    "a module bound to a name": (
        "def added_writer(path, mode):\n    import shutil\n    sh = shutil\n    sh.copyfile(path, mode)\n",
        "added_writer"),
    "a module import_module gives, bound to a name": (
        "def added_writer(path, mode):\n    import importlib\n    m = importlib.import_module('shutil')\n"
        "    m.move(path, mode)\n", "added_writer"),
    "a writer held in a dict": (
        "def added_writer(path, mode):\n    {'w': open}['w'](path, 'w')\n", "added_writer"),
    "a writer held in a dict bound to a name": (
        "_TABLE = dict(save=os.replace)\n\n\ndef added_writer(path, mode):\n    _TABLE['save'](path, mode)\n",
        "added_writer"),
    "a writer held in a list": (
        "def added_writer(path, mode):\n    writers = [os.replace]\n    writers[0](path, mode)\n", "added_writer"),
    "a default argument": (
        "def added_writer(path, mode, w=open):\n    w(path, 'w')\n", "added_writer"),
    "a keyword-only default argument": (
        "def added_writer(path, mode, *, move=os.rename):\n    move(path, mode)\n", "added_writer"),
    "__call__": (
        "def added_writer(path, mode):\n    import shutil\n    shutil.copyfile.__call__(path, mode)\n",
        "added_writer"),
    "an image saved": (
        "def added_writer(path, mode):\n    from PIL import Image\n    Image.new('RGB', (1, 1)).save(path)\n",
        "added_writer"),
    "a writer bound to a name, handed to a thread": (
        "def added_writer(path, mode):\n    import threading\n    save = os.replace\n"
        "    threading.Thread(target=save, args=(path, mode))\n", "added_writer"),
    "a writer held in a dict, handed to a call": (
        "def added_writer(path, mode):\n    list(map({'w': os.replace}['w'], [path], [mode]))\n", "added_writer"),
}


@pytest.mark.parametrize("form", sorted(_MORE_FORMS))
def test_a_writer_of_each_further_form_added_to_the_application_is_in_no_list(form):
    code, scope = _MORE_FORMS[form]
    rel = "app/sftp/heartbeat.py"
    source = (ROOT / rel).read_text(encoding="utf-8") + (
        "\n\nimport logging  # noqa: E402\nimport logging.handlers  # noqa: E402\n\n\n" + code)
    found = dict(_all_writers())
    found.update({(rel, s): calls for s, calls in writers(source).items()})
    assert (rel, scope) in unclassified(found), form


def test_the_further_forms_that_read_or_hold_no_file_stay_alone():
    source = (
        "import fileinput, importlib, os, tempfile, json\n"
        "class _Box:\n"
        "    size = len\n"
        "    def m(self, p):\n"
        "        return self.size(p)\n"
        "class _Error(ValueError):\n"
        "    pass\n"
        "def r(p, q, n=len, *, k=sorted):\n"
        "    tempfile.TemporaryDirectory(); tempfile.TemporaryDirectory(delete=True)\n"
        "    fileinput.input(p); fileinput.input(p, inplace=False)\n"
        "    importlib.import_module('json').dumps(p); __import__('json').loads(q)\n"
        "    {'r': len}['r'](p); [len][0](p); n(p); k(q); _Error(p)\n"
        "    len.__call__(p); q.save(); js = json\n"
        "    js.dumps(p)\n"
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
    assert source.count("durable_write.sync_directory(") == 2
    without = source.replace("durable_write.sync_directory(", "print(")
    sources = {k[0]: (ROOT / k[0]).read_text(encoding="utf-8") for k in SYNCED}
    assert missing_syncs(sources) == {}
    sources[rel] = without
    assert missing_syncs(sources) == {(rel, "generate_ed25519_host_key"): ["sync_directory"],
                                      (rel, "_write_in_place"): ["sync_directory"]}


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
                                    LOCK, QR_IN_MEMORY), key
