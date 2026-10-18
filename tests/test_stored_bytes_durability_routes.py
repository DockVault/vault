"""Where each upload route syncs what it stored, read from the source.

The behaviour is tested in test_stored_bytes_durability.py, on the code these routes call: the upload
context, the chunk sealer, the service. What a route adds is the ORDER around that code -- the commit
after the context has closed, the chunk directory synced after the rename and before the count -- and
the routes need a database and a request to run, so the order is read from the source here. Each pin
names the property it holds, and fails if the call moves or goes.
"""
import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"
SERVICE = ROOT / "app" / "services" / "vault_service.py"


def _function(source: Path, name: str, cls: str = None):
    """The one function `name` in `source` (in class `cls` when given)."""
    tree = ast.parse(source.read_text(encoding="utf-8"))
    if cls is not None:
        (tree,) = [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == cls]
    found = [node for node in ast.walk(tree)
             if isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)) and node.name == name]
    assert len(found) == 1, f"{name} found {len(found)} times in {source.name}"
    return found[0]


def _calls(node, attr, owner=None):
    """Calls to `<owner>.<attr>(...)` (any owner when None), in source order."""
    out = []
    for child in ast.walk(node):
        if not (isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute)
                and child.func.attr == attr):
            continue
        value = child.func.value
        if owner is not None and not (isinstance(value, ast.Name) and value.id == owner):
            continue
        out.append(child)
    return sorted(out, key=lambda c: (c.lineno, c.col_offset))


def _arg_name(call):
    first = call.args[0] if call.args else None
    if isinstance(first, ast.Name):
        return first.id
    if isinstance(first, ast.Attribute):
        return ast.unparse(first)
    return None


def _one(node, attr, owner, arg=None):
    calls = [c for c in _calls(node, attr, owner) if arg is None or _arg_name(c) == arg]
    assert len(calls) == 1, (
        f"{node.name}: expected one {owner}.{attr}({arg or '...'}) call, found {len(calls)}")
    return calls[0]


# ---- a chunk: sealed and synced, renamed, its name synced, then counted ---------------------------

@pytest.mark.parametrize("handler", ["upload_chunk", "receiver_upload_chunk"])
def test_a_chunk_name_is_synced_after_the_rename_and_before_it_is_counted(handler):
    node = _function(API, handler)
    sealed = [c for c in ast.walk(node) if isinstance(c, ast.Call)
              and isinstance(c.func, ast.Name) and c.func.id == "seal_stream_to_file"]
    assert len(sealed) == 1, "the chunk is no longer staged by the sealer that syncs it"
    rename = _one(node, "replace", "os")
    digest = _one(node, "write_text", None)
    synced = _one(node, "sync_directory", "durable_write", "sdir")
    commits = [c for c in _calls(node, "commit", "db") if c.lineno > rename.lineno]
    assert commits, "nothing commits the count after the rename"
    assert sealed[0].lineno < rename.lineno < digest.lineno < synced.lineno < commits[0].lineno, (
        f"{handler}: the chunk's name must be synced after the rename (line {rename.lineno}) and "
        f"its digest (line {digest.lineno}), before the count commits (line {commits[0].lineno}); "
        f"it is synced at line {synced.lineno}")


@pytest.mark.parametrize("handler", ["open_receiver_upload_session", "receiver_upload_chunk",
                                     "init_chunked_upload", "upload_chunk"])
def test_an_upload_session_directory_is_made_durably(handler):
    node = _function(API, handler)
    _one(node, "make_directories", "durable_write", "sdir")
    assert _calls(node, "mkdir") == [], f"{handler} makes a directory without syncing it"


# ---- a file assembled through the upload context: committed only after it has closed --------------

@pytest.mark.parametrize("handler", ["upload_file", "_complete_chunked_upload",
                                     "receiver_complete_upload"])
def test_a_file_row_is_committed_only_after_the_upload_context_has_closed(handler):
    """The context syncs the file and its name as it closes, so the row must come after the block.

    This order held before the sync existed; the pin keeps it, since a finalize moved into the block
    would commit the row before the file is on the disk."""
    node = _function(API, handler)
    blocks = [w for w in ast.walk(node) if isinstance(w, (ast.With, ast.AsyncWith))
              and any(isinstance(item.context_expr, ast.Name) and item.context_expr.id == "stream_ctx"
                      for item in w.items)]
    assert len(blocks) == 1, f"{handler}: expected one `with stream_ctx` block, found {len(blocks)}"
    final = _one(node, "finalize_streaming_upload", "vault_service")
    assert final.lineno > blocks[0].end_lineno, (
        f"{handler}: the row is committed at line {final.lineno}, inside the upload context that "
        f"ends at line {blocks[0].end_lineno}, before the file is synced")


# ---- a brand image: content, rename, name, then the row ------------------------------------------

def test_a_brand_image_is_on_the_disk_before_the_row_points_at_it():
    node = _function(API, "upload_brand_asset")
    _one(node, "make_directories", "durable_write", "BRAND_ASSET_DIR")
    assert _calls(node, "makedirs", "os") == [], "the image directory is made without a sync"
    writes = [w for w in ast.walk(node) if isinstance(w, ast.With)
              and any("tmp" in ast.unparse(item.context_expr) for item in w.items)]
    assert len(writes) == 1, "the temporary image file is no longer written in one block"
    content = _one(node, "sync_file", "durable_write", "fh")
    assert writes[0].lineno < content.lineno <= writes[0].end_lineno, (
        "the image's content is not synced inside the block that writes it")
    rename = _one(node, "replace", "os")
    name = _one(node, "sync_directory", "durable_write", "BRAND_ASSET_DIR")
    commit = _one(node, "commit", "db")
    row = [c for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)
           and c.func.id == "_update_brand_row"]
    assert len(row) == 1
    assert content.lineno < rename.lineno < name.lineno < row[0].lineno < commit.lineno, (
        "the brand row must be written after the image's content and name are synced")


# ---- the vault service ---------------------------------------------------------------------------

@pytest.mark.parametrize("method, arg", [("__init__", "self.storage_path"),
                                         ("create_vault", "vault_dir"),
                                         ("create_folder", "folder_path"),
                                         ("upload_file_streaming", "storage_path.parent")])
def test_the_service_makes_its_directories_durably(method, arg):
    node = _function(SERVICE, method, cls="VaultService")
    _one(node, "make_directories", "durable_write", arg)
    assert _calls(node, "mkdir") == [], f"{method} makes a directory without syncing it"


@pytest.mark.parametrize("method", ["copy_file", "move_file", "_copy_folder_recursive"])
def test_every_copy_writes_through_the_copy_that_is_tested(method):
    """test_a_copy_is_on_the_disk_before_its_row drives _stream_copy_file_record; a copy that wrote
    its bytes some other way would not be covered by it."""
    node = _function(SERVICE, method, cls="VaultService")
    assert _calls(node, "_stream_copy_file_record", "self"), (
        f"{method} no longer copies through _stream_copy_file_record")
    assert _calls(node, "upload_file_streaming") == [], f"{method} writes a copy of its own"
