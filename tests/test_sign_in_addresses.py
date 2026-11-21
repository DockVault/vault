"""No address the sign-in features give out is taken from a request.

A passkey's relying party, the redirect address a provider is handed, the place a sign-in sends the browser back to
and every emailed link are built on the vault's configured address (app/core/public_url.py, on
app/core/allowed_hosts.link_base). What a request says of its own address is the caller's to write: the Host
header, Origin, Referer, Forwarded and every X-Forwarded-* header, and the URL and scope the server made of them.
So none of the sign-in modules reads any of it, however the read is written. The check bans the reads, not a list of
spellings: any use of a request's ``url`` beyond its path and query, any use of its ``scope`` or of a ``base_url``,
any ``url_for``, any subscript of a request (it is a mapping over its scope) or of a raw scope, any ``getattr`` of
those from a request, and any read of one of those headers from anything that came from a request's headers, also
through another name, an attribute or a named constant; a header read whose name the check cannot see (a name in
a variable, every header at once, the raw list) is refused too. A request is known by its name and by what it is
declared as, whatever a parameter is called. A request or a scope read as the mapping it is (``.get``, ``.items``
and the like) is a read of it, and so is a ``URL`` or a set of ``Headers`` built from one; a name given a
``Request`` built from a scope, or a request itself, is a request. A parameter the framework fills from one of
those headers (``host: str = Header(None)``, or by its alias) is a read, and so are a request's headers handed
whole to another function, which the check cannot follow. A ``url`` is taken for a request's whatever it is read
from (a helper's parameter is declared as nothing and may be called anything), a reader taken off the headers and
called by another name (``get = request.headers.get``) is a read where it is called, and what builds a request
keeps a name the check knows: it is imported under no other.

This holds every module of the sign-in pipeline, passkeys and single sign-on: every module under app/ named for one
of them, so a new one is read without being listed, and the ones listed below by name, so a rename shows here and
not as a shorter list. It also holds the API's main module, which has most of the sign-in routes, function by
function (every one of them: two that share a name, as every middleware's ``__call__`` does, are two), with the
functions that read such a value for another purpose named below.
Offline, from the source."""
import ast
import copy
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
# A module whose file name holds one of these is a sign-in module.
NAMED = ("sign_in", "public_url", "active_factors", "step_up_methods", "privileged_accounts", "webauthn", "passkey",
         "sso", "oidc", "saml")
PIPELINE = ("app/services/sign_in.py", "app/core/sign_in_codes.py", "app/core/public_url.py",
            "app/core/active_factors.py", "app/core/step_up_methods.py")
PASSKEYS = ("app/services/webauthn_service.py", "app/core/webauthn_settings.py", "app/core/webauthn_challenges.py",
            "app/api/sign_in_settings_router.py")
SINGLE_SIGN_ON = ("app/api/sso_router.py", "app/api/sso_admin_router.py", "app/services/sso_sign_in.py",
                  "app/services/sso_freshness.py", "app/services/sso_groups.py", "app/services/oidc_client.py",
                  "app/core/sso_only.py", "app/core/sso_policy.py", "app/core/sso_state.py",
                  "app/core/privileged_accounts.py", "app/api/sso_providers_router.py",
                  "app/services/sso_providers.py", "app/core/sso_presets.py", "app/core/sso_settings.py")
MODULES = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "app").rglob("*.py")
                 if any(name in p.name for name in NAMED))

ADDRESS_HEADERS = ("host", "origin", "referer", "forwarded", "x-original-host", "x-host", "x-original-url",
                   "x-rewrite-url")
# What may be given a request's headers whole: it keeps them as headers, and a read of the result is seen.
HEADER_KEEPERS = ("dict", "list", "tuple", "Headers", "MutableHeaders", "len", "bool")
URL_PARTS_THAT_NAME_NO_HOST = ("path", "query")
HEADER_READS = ("get", "getlist", "get_all", "getall", "pop", "setdefault", "__getitem__")
# Reads of every header at once: which header is taken from the result cannot be seen here.
WHOLE_HEADER_READS = ("items", "keys", "values", "mutablecopy", "multi_items")
# A request, and a raw scope, read as the mapping it is: one part by its name, or the whole of it.
MAPPING_READS = ("get", "__getitem__", "pop", "setdefault")
WHOLE_MAPPING_READS = ("items", "keys", "values", "copy")
# The parts of a scope that name an address (the headers, the server's own name and port, the scheme, the mount
# point). Who called (``client``) and what was asked for (``path``, ``query_string``) name none. Other things
# called "scope" are read by other names (a credential's scope has ``files`` and ``caps``).
SCOPE_PARTS_THAT_NAME_AN_ADDRESS = ("headers", "server", "scheme", "root_path", "url", "base_url")
# What builds a request, its headers or its URL out of a scope.
REQUEST_BUILDERS = ("Request", "StarletteRequest", "HTTPConnection", "WebSocket")
REQUEST_PARTS_THAT_NAME_AN_ADDRESS = ("url", "scope", "base_url", "url_for")
# What a parameter is declared as when it holds a request, a connection, a socket or a raw ASGI scope.
REQUEST_TYPES = re.compile(r"\b(Request|StarletteRequest|HTTPConnection|WebSocket|Scope)\b")
MAIN_MODULE = "app/api/api_server.py"
# The functions of the main module that read what a request says of itself: why that is no address given out,
# exactly what each reads (as the check reports it), and the address headers each names. A read added to one of
# them, or a header named in one, changes its entry and is looked at again.
MAIN_MODULE_READS = {
    "_external_scheme": ("whether the browser came over https, for the transport-security header alone",
                         ["request.headers.get('x-forwarded-proto')", "request.url.scheme", "request.url.scheme"],
                         {"x-forwarded-proto"}),
    "_resolved_download_sink": ("the request's own origin, compared with a download's target and never given out",
                                ["request.url.hostname"], set()),
    "VaultPasscodeMiddleware.__call__": ("the passcode header of the raw scope, handed on for the vault's check",
                                         ["scope.get('headers')"], set()),
    "ClientIPMiddleware.__call__": ("the scheme a trusted proxy reports and the browser's name, from the raw scope",
                                    ["scope.get('headers')", "scope.get('scheme')"], set()),
}


def _names_an_address(header) -> bool:
    text = str(header).lower()
    return text in ADDRESS_HEADERS or text.startswith("x-forwarded-")


def _declared_requests(tree) -> set:
    """The parameters that hold a request by what they are declared as, whatever they are called."""
    named = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for arg in node.args.posonlyargs + node.args.args + node.args.kwonlyargs:
                if arg.annotation is not None and REQUEST_TYPES.search(ast.unparse(arg.annotation)):
                    named.add(arg.arg)
    return named


def _a_request(node, declared=frozenset(), *, short_names=True) -> bool:
    """Whether ``node`` is a name or attribute that holds a request (``request``, ``http_request``, ``self.request``,
    a parameter declared as one), a socket's connection (``websocket``) or a raw scope (``scope``). ``req`` is a
    request by its name where an attribute of it is read; where it is subscripted it is one only when declared so
    (the name is also used for other things that are subscripted)."""
    if isinstance(node, ast.Call):
        # A request built where it is read: ``Request(scope).url``, under whatever name the builder was imported
        # (``_Request``), is a request.
        return _called(node) in REQUEST_BUILDERS or _called(node).endswith("Request")
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    if isinstance(node, ast.Name) and name in declared:
        return True
    bare = name.lstrip("_").lower()            # ``self._scope`` and ``ctx._scope`` are the scope, kept
    return bare.endswith(("request", "websocket")) or bare == "scope" or (short_names and bare == "req")


def _called(node) -> str:
    """The name a call names: ``Headers`` for ``Headers(...)`` and for ``datastructures.Headers(...)``."""
    func = node.func if isinstance(node, ast.Call) else None
    return func.id if isinstance(func, ast.Name) else func.attr if isinstance(func, ast.Attribute) else ""


def _built_from_a_request(node, declared, builders) -> bool:
    """``Headers(scope=scope)``, ``URL(scope)``, ``Request(scope, receive)``: one of ``builders`` called with a
    request or a scope among what it is given (also a part of one: ``Headers(raw=scope['headers'])``)."""
    if not (isinstance(node, ast.Call) and _called(node) in builders):
        return False
    given = list(node.args) + [k.value for k in node.keywords]
    return any(_a_request(n, declared) for arg in given for n in ast.walk(arg) if isinstance(n, (ast.Name, ast.Attribute)))


def _header_parameters(tree) -> list:
    """The parameters the framework fills from a header that names an address: ``host: str = Header(None)``
    (the header is the parameter's name), ``x: str = Header(None, alias='X-Forwarded-Host')``, the same inside an
    ``Annotated[...]``; an alias the check cannot see is refused."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        positional = node.args.posonlyargs + node.args.args
        defaults = [None] * (len(positional) - len(node.args.defaults)) + list(node.args.defaults)
        for arg, default in list(zip(positional, defaults)) + list(zip(node.args.kwonlyargs, node.args.kw_defaults)):
            marker = default if _called(default) == "Header" else None
            if marker is None and arg.annotation is not None:
                marker = next((n for n in ast.walk(arg.annotation) if _called(n) == "Header"), None)
            if marker is None:
                continue
            alias = next((k.value for k in marker.keywords if k.arg == "alias"), None)
            named = arg.arg.replace("_", "-") if alias is None else alias.value if isinstance(alias, ast.Constant) else None
            if named is None or _names_an_address(named):
                found.append(f"{arg.arg}=Header(...)")
    return found


def _assignments(tree):
    """Every (target, value) a statement binds: a plain assignment, one with a declared type, one made inside an
    expression (``(h := request.headers)``), the name a ``with`` gives its value, and each pair of a tuple taken
    apart (``a, b = request.headers, 1``); where the two sides cannot be paired, every target gets the whole
    value."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            pairs = [(target, node.value) for target in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = [(node.target, node.value)]
        elif isinstance(node, ast.NamedExpr):
            pairs = [(node.target, node.value)]
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            pairs = [(item.optional_vars, item.context_expr) for item in node.items if item.optional_vars is not None]
        else:
            continue
        for target, value in pairs:
            if isinstance(target, (ast.Tuple, ast.List)):
                apart = (isinstance(value, (ast.Tuple, ast.List)) and len(value.elts) == len(target.elts))
                for index, element in enumerate(target.elts):
                    yield element, (value.elts[index] if apart else value)
            else:
                yield target, value


def _headers_by_getattr(node, declared) -> bool:
    """``getattr(<a request>, 'headers', ...)``: the request's headers by another spelling."""
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
            and len(node.args) > 1 and _a_request(node.args[0], declared)
            and isinstance(node.args[1], ast.Constant) and node.args[1].value == "headers")


def request_addresses(tree) -> list:
    """Every place ``tree`` reads what a request says of its own address."""
    found = []
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    declared = _declared_requests(tree)
    # A name given a request built from a scope is a request, whatever it is called, and so is a name given a
    # request itself (``r = request``).
    declared |= {target.id for target, value in _assignments(tree)
                 if isinstance(target, ast.Name) and (
                     _built_from_a_request(value, declared, REQUEST_BUILDERS)
                     or (isinstance(value, (ast.Name, ast.Attribute)) and _a_request(value, declared, short_names=False)))}
    found.extend(_header_parameters(tree))
    constants, from_headers, kept_as = {}, set(), set()
    for target, value in _assignments(tree):
        carries = any((isinstance(n, ast.Attribute) and n.attr == "headers") or _headers_by_getattr(n, declared)
                      or _built_from_a_request(n, declared, ("Headers",)) for n in ast.walk(value))
        if isinstance(target, ast.Name):
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                constants[target.id] = value.value
            if carries:
                from_headers.add(target.id)
        elif isinstance(target, ast.Attribute) and carries:
            kept_as.add(target.attr)                      # self.h = request.headers

    # A request's headers themselves, as against something read out of them: ``request.headers``, the same by
    # getattr or built from a scope, and a name given exactly that.
    def the_headers(node, known=frozenset()) -> bool:
        if isinstance(node, ast.Attribute) and node.attr == "headers":
            return _a_request(node.value, declared)
        return (_headers_by_getattr(node, declared) or _built_from_a_request(node, declared, ("Headers",))
                or (isinstance(node, ast.Name) and node.id in known))

    whole = {target.id for target, value in _assignments(tree) if isinstance(target, ast.Name) and the_headers(value)}

    def holds_headers(node) -> bool:
        return any((isinstance(n, ast.Attribute) and (n.attr == "headers" or n.attr in kept_as))
                   or (isinstance(n, ast.Name) and n.id in from_headers) or _headers_by_getattr(n, declared)
                   or _built_from_a_request(n, declared, ("Headers",)) for n in ast.walk(node))

    # A name that walks over a fixed list of names (``for name in ("purpose", "sec-purpose")``) names each of them.
    walked = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and isinstance(node.target, ast.Name) \
                and isinstance(node.iter, (ast.Tuple, ast.List)) and node.iter.elts \
                and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.iter.elts):
            walked[node.target.id] = [e.value for e in node.iter.elts]

    def header_named(node):
        """The header a read names (the worst of them where the name walks over a fixed list), or None when the
        check cannot see it."""
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id in walked:
            return next((name for name in walked[node.id] if _names_an_address(name)), walked[node.id][0])
        return constants.get(node.id) if isinstance(node, ast.Name) else None

    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute):
            if node.attr == "base_url":
                found.append(ast.unparse(node))
            elif node.attr == "url" or (node.attr == "scope" and _a_request(node.value, declared)):
                # A ``url`` of anything: a helper handed a request under a name of its own (``conn.url.hostname``)
                # reads the same address. A scope is known by its name: other things are called one.
                parent = parents.get(node)
                harmless = (node.attr == "url" and isinstance(parent, ast.Attribute)
                            and parent.attr in URL_PARTS_THAT_NAME_NO_HOST)
                if not harmless:
                    found.append(ast.unparse(parent if isinstance(parent, ast.Attribute) else node))
            elif node.attr == "raw" and holds_headers(node.value):
                found.append(ast.unparse(node))               # every header, as the server received them
        if isinstance(node, ast.Call):
            if getattr(node.func, "attr", None) == "url_for":
                found.append(ast.unparse(node))
            if _called(node) not in HEADER_KEEPERS and any(
                    the_headers(given, whole) for given in list(node.args) + [k.value for k in node.keywords]):
                found.append(ast.unparse(node))               # the headers, whole, to something the check cannot follow
            if _built_from_a_request(node, declared, ("URL",)):
                found.append(ast.unparse(node))               # the request's own URL, by its other door
            if isinstance(node.func, ast.Attribute) and _a_request(node.func.value, declared, short_names=False):
                # A request is a mapping over its scope. One part read by a name the check can see is a read of
                # that part; a name it cannot see, or the whole mapping, is refused.
                if node.func.attr in MAPPING_READS:
                    part = node.args[0] if node.args else None
                    if not (isinstance(part, ast.Constant) and part.value not in SCOPE_PARTS_THAT_NAME_AN_ADDRESS):
                        found.append(ast.unparse(node))
                elif node.func.attr in WHOLE_MAPPING_READS:
                    found.append(ast.unparse(node))
            if isinstance(node.func, ast.Name) and node.func.id in from_headers:
                # A reader taken off the headers and called by its new name: ``get = request.headers.get``.
                named = node.args[0] if node.args else None
                header = header_named(named) if named is not None else None
                if header is None or _names_an_address(header):
                    found.append(ast.unparse(node))
            if isinstance(node.func, ast.Attribute) and holds_headers(node.func.value):
                if node.func.attr in HEADER_READS:
                    named = node.args[0] if node.args else next(
                        (k.value for k in node.keywords if k.arg in ("key", "name")), None)
                    header = header_named(named) if named is not None else None
                    if header is None or _names_an_address(header):
                        found.append(ast.unparse(node))
                elif node.func.attr in WHOLE_HEADER_READS:
                    found.append(ast.unparse(node))
            if (isinstance(node.func, ast.Name) and node.func.id == "getattr" and node.args
                    and _a_request(node.args[0], declared)):
                part = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(part, ast.Constant) and part.value not in REQUEST_PARTS_THAT_NAME_AN_ADDRESS):
                    found.append(ast.unparse(node))
        if isinstance(node, ast.Subscript):
            if _a_request(node.value, declared, short_names=False):
                found.append(ast.unparse(node))               # a request is a mapping over its scope
            elif holds_headers(node.value):
                header = header_named(node.slice)
                if header is None or _names_an_address(header):
                    found.append(ast.unparse(node))
        if isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)) and _is_headers(node.iter, from_headers, kept_as):
            found.append("for ... in " + ast.unparse(node.iter))
    return found


def address_names_in(tree) -> set:
    """The address headers ``tree`` names anywhere, as text or as bytes (a raw scope's headers are bytes)."""
    named = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            text = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
            if _names_an_address(text):
                named.add(text.lower())
    return named


def _is_headers(node, from_headers, kept_as) -> bool:
    """Whether ``node`` is a request's headers themselves (to be walked over), not something read out of them."""
    if isinstance(node, ast.Attribute):
        return node.attr == "headers" or node.attr in kept_as
    return isinstance(node, ast.Name) and node.id in from_headers


def renamed_builders(tree) -> list:
    """The imports that give what builds a request, its headers or its URL a name the check does not know it by.
    A request's builder may be called anything that ends in "Request"; the others keep their own names."""
    found = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        for alias in node.names:
            name, bound = alias.name.split(".")[-1], alias.asname
            if bound is None or bound == name:
                continue
            if name in REQUEST_BUILDERS and not bound.endswith("Request"):
                found.append(f"{alias.name} as {bound}")
            elif name in ("Headers", "MutableHeaders", "URL"):
                found.append(f"{alias.name} as {bound}")
    return found


@pytest.mark.parametrize("module", MODULES + [MAIN_MODULE])
def test_what_builds_a_request_keeps_a_name_the_check_knows(module):
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    assert renamed_builders(tree) == [], module


def test_the_reads_a_name_of_ones_own_would_hide_are_seen():
    """A request handed to a helper under another name, a header reader called by another name, and a builder
    imported under another name: each is reported, and what looks like them and reads no address is not."""
    def reads(source):
        return request_addresses(ast.parse(source))
    assert reads("def _host(conn):\n    return conn.url.hostname\n") == ["conn.url.hostname"]
    assert reads("def _where(connection):\n    return str(connection.url)\n") == ["connection.url"]
    assert reads("def _path(conn):\n    return conn.url.path, conn.url.query\n") == []
    assert reads("def f(request):\n    get = request.headers.get\n    return get('host')\n") == ["get('host')"]
    assert reads("def f(request, name):\n    get = request.headers.get\n    return get(name)\n") == ["get(name)"]
    assert reads("def f(request):\n    get = request.headers.get\n    return get('user-agent')\n") == []
    planted = ast.parse("from starlette.requests import Request as R\nfrom starlette.datastructures import URL as U\n"
                        "from starlette.requests import Request as _Request\nimport starlette.requests\n")
    assert renamed_builders(planted) == ["Request as R", "URL as U"]


def test_the_modules_listed_by_name_are_among_those_read():
    """The pipeline's modules are on every tree. Passkeys and single sign-on arrive whole: a tree that has one of a
    group's modules has them all, so a module renamed or moved fails here."""
    assert set(PIPELINE) <= set(MODULES), sorted(set(PIPELINE) - set(MODULES))
    for group in (PASSKEYS, SINGLE_SIGN_ON):
        here = [m for m in group if (ROOT / m).is_file()]
        assert not here or len(here) == len(group), sorted(set(group) - set(here))
        assert set(here) <= set(MODULES)


@pytest.mark.parametrize("module", MODULES)
def test_no_sign_in_module_reads_what_a_request_says_of_its_address(module):
    tree = ast.parse((ROOT / module).read_text(encoding="utf-8"))
    assert request_addresses(tree) == [], module


def _functions_of(tree) -> list:
    """Every function of ``tree`` with the name it is reached by ("Class.method", "outer.inner"), in the order
    written. Two that share a name are two entries: nothing is dropped for being called what another is."""
    found = []

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                if not isinstance(child, ast.ClassDef):
                    found.append((prefix + child.name, child))
                visit(child, prefix + child.name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return found


def _main_module_functions() -> list:
    return _functions_of(ast.parse((ROOT / MAIN_MODULE).read_text(encoding="utf-8")))


def _outside_functions(tree):
    """``tree`` with every function taken out (each is read by itself): what is left runs when the module is
    loaded, a lambda bound to a name among it."""
    class _Without(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            return ast.Pass()
        visit_AsyncFunctionDef = visit_FunctionDef

    return ast.fix_missing_locations(_Without().visit(copy.deepcopy(tree)))


def test_the_main_modules_code_outside_its_functions_reads_no_address_either():
    tree = ast.parse((ROOT / MAIN_MODULE).read_text(encoding="utf-8"))
    assert request_addresses(_outside_functions(tree)) == []
    planted = ast.parse("class A:\n    def f(self, request):\n        return request.url.hostname\n"
                        "_host_of = lambda request: request.headers.get('host')\n")
    assert request_addresses(_outside_functions(planted)) == ["request.headers.get('host')"]


def test_every_function_is_read_also_the_ones_that_share_a_name():
    source = ("class A:\n    def __call__(self, scope):\n        return scope['server']\n"
              "class B:\n    def __call__(self, scope):\n        return 1\n"
              "def outer():\n    def __call__():\n        return 2\n    return __call__\n"
              "async def __call__():\n    return 3\n")
    tree = ast.parse(source)
    names = [name for name, _node in _functions_of(tree)]
    assert names == ["A.__call__", "B.__call__", "outer", "outer.__call__", "__call__"]
    reads = {name: request_addresses(node) for name, node in _functions_of(tree)}
    assert reads["A.__call__"] and not reads["B.__call__"]
    # And of the main module: as many entries as it has functions.
    whole = ast.parse((ROOT / MAIN_MODULE).read_text(encoding="utf-8"))
    written = sum(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) for node in ast.walk(whole))
    listed = _main_module_functions()
    assert len(listed) == written and len({node.name for _name, node in listed}) < written   # some do share a name
    assert len({name for name, _node in listed}) == written                  # and each is reached by its own
    assert [name for name, _node in listed].count("VaultPasscodeMiddleware.__call__") == 1


def test_no_function_of_the_main_module_reads_what_a_request_says_of_its_address():
    """The main module holds most of the sign-in routes (the finish, the policy, the passkey routes, the step-up,
    the sign-out): each of its functions is read by the same check, every middleware's ``__call__`` among them.
    The ones that read such a value for another purpose are named with the purpose, must still be there and must
    still read it, so the list cannot outlive its reasons."""
    functions = _main_module_functions()
    reads = [(name, request_addresses(node)) for name, node in functions]

    def named(name):                        # a function nested in a named one is read with it
        return any(name == known or name.startswith(known + ".") for known in MAIN_MODULE_READS)

    unexpected = {name: found for name, found in reads if found and not named(name)}
    assert unexpected == {}, unexpected
    for known, (_why, expected, names) in MAIN_MODULE_READS.items():
        (node,) = [node for name, node in functions if name == known]            # there, and one of a kind
        found = sorted(request_addresses(node))
        assert found, f"{known} no longer reads a request's address: take it off the list"
        assert found == sorted(expected), f"{known} reads something else now: read it again, then change its entry"
        assert address_names_in(node) == names, f"{known} names another address header now"


def test_a_read_added_to_a_function_that_may_read_one_is_seen():
    """What the entries above hold, shown on the middleware that reads the raw scope: one more read of it, and a
    host header named in the loop it already has, each change what the check reports."""
    source = (ROOT / MAIN_MODULE).read_text(encoding="utf-8")
    tree = ast.parse(source)
    (node,) = [node for name, node in _functions_of(tree) if name == "VaultPasscodeMiddleware.__call__"]
    text = ast.unparse(node)
    _why, expected, names = MAIN_MODULE_READS["VaultPasscodeMiddleware.__call__"]
    assert sorted(request_addresses(ast.parse(text))) == sorted(expected) and address_names_in(ast.parse(text)) == names
    one_more = text.replace("value = None", "value = None\n    seen = dict(scope['headers']).get(b'host')", 1)
    assert one_more != text and sorted(request_addresses(ast.parse(one_more))) != sorted(expected)
    in_the_loop = text.replace("if k == b'x-vault-passcode':", "if k == b'host':\n            seen = v\n        if k == b'x-vault-passcode':", 1)
    assert in_the_loop != text and sorted(request_addresses(ast.parse(in_the_loop))) == sorted(expected)
    assert address_names_in(ast.parse(in_the_loop)) == {"host"} != names


@pytest.mark.parametrize("source", [
    "base = str(request.base_url)",
    "host = request.headers.get('host')",
    "host = request.headers.get('X-Forwarded-Host', '')",
    "host = request.headers['Host']",
    "where = request.url.netloc",
    "name = request.url.hostname",
    "port = request.url.port",
    "whole = str(request.url)",
    "back = request.url_for('callback')",
    # The other headers a caller writes its address in.
    "o = request.headers.get('origin')",
    "o = request.headers.get('Origin')",
    "r = request.headers.get('referer')",
    "p = request.headers.get('x-forwarded-proto')",
    "p = request.headers.get('X-Forwarded-Port')",
    "f = request.headers.get('forwarded')",
    "h = request.headers.getlist('host')",
    "h = dict(request.headers)['host']",
    "h = request.headers.pop('host', None)",
    # The same reads through another name, a named constant, or a name the check cannot see.
    "h = request.headers\nx = h.get('host')",
    "h = dict(request.headers)\nx = h['origin']",
    "HOST = 'host'\nx = request.headers.get(HOST)",
    "x = request.headers.get(name)",
    "x = request.headers[name]",
    # The URL and the scope the server made of them, in every form.
    "s = request.url.scheme",
    "u = f'{request.url}'",
    "u = '%s' % request.url",
    "u = format(request.url)",
    "u = request.url.replace(path='')",
    "u = request.url.include_query_params(a=1)",
    "n = request.url.components.netloc",
    "u = request.url._url",
    "u = request.url\nx = u.hostname",
    "s = request.scope['server']",
    "s = request.scope['headers']",
    "s = request.scope",
    "x = self.request.url.netloc",
    "x = http_request.url.hostname",
    "x = websocket.url.hostname",
    # A request is a mapping over its scope; so is a raw scope, by its name or by what it is declared as.
    "h = request['headers']",
    "h = dict(request['headers']).get(b'host')",
    "s = request['server']",
    "s = scope['server']",
    "def f(conn: HTTPConnection):\n    return conn.url.hostname",
    "def f(r: Request):\n    return r['server']",
    "async def f(s: Scope, receive, send):\n    return s['headers']",
    "def f(c: 'Request'):\n    return c.scope",
    "u = getattr(request, 'url')",
    "u = getattr(request, name)",
    "h = getattr(request, 'headers')\nx = h.get('host')",
    "x = getattr(request, 'headers', None)['origin']",
    "def f(req: Request):\n    return req['server']",
    # A header named by keyword, every header at once, the raw list, a walk over them, an attribute that keeps them.
    "h = request.headers.get(key='host')",
    "h = request.headers.get()",
    "pairs = request.headers.items()",
    "names = request.headers.keys()",
    "raw = request.headers.raw",
    "for name, value in request.headers:\n    pass",
    "found = [v for k, v in request.headers.items()]",
    "found = [k for k in request.headers]",
    "self.h = request.headers\nx = self.h.get('host')",
    "self.h = request.headers\nx = self.h['origin']",
    "h = request.headers.__getitem__('host')",
    "for name in ('purpose', 'x-forwarded-host'):\n    x = request.headers.get(name)",
    # A request and a raw scope read as the mapping they are, and what is built out of one.
    "s = request.get('server')",
    "h = scope.get('headers')",
    "h = dict(scope.get('headers') or []).get(b'host')",
    "pairs = scope.items()",
    "s = scope.get(part)",
    "s = scope.get('scheme', 'http')",
    "s = request.scope.get('server')",
    "def f(conn: HTTPConnection):\n    return conn.get('headers')",
    "h = Headers(scope=scope).get('host')",
    "h = Headers(raw=scope['headers'])\nx = h.get('origin')",
    "u = URL(scope=scope)",
    "u = str(URL(scope=request.scope))",
    "r = Request(scope, receive)\nx = r['server']",
    "r = Request(scope)\nx = r.url.hostname",
    # A request built where it is read, under any name of the builder; the scope a context keeps.
    "x = _Request(scope).url.netloc",
    "x = Request(scope)['server']",
    "x = StarletteRequest(scope).headers.get('host')",
    "x = dict(ctx._scope.get('headers') or []).get(b'host')",
    "x = current_request_context()._scope['headers']",
    "x = Request(current_request_context()._scope).url.netloc",
    "x = self._request.url.hostname",
    # A parameter the framework fills from the header, by its name or its alias.
    "async def cb(host: str = Header(None)):\n    return host",
    "async def cb(x_forwarded_host: Optional[str] = Header(None)):\n    return x_forwarded_host",
    "async def cb(where: str = Header(None, alias='X-Forwarded-Host')):\n    return where",
    "async def cb(where: str = Header(None, alias=NAME)):\n    return where",
    "async def cb(origin: Annotated[str, Header()] = None):\n    return origin",
    "def cb(*, referer: str = Header(None)):\n    return referer",
    # A request under another name; headers bound inside an expression or by a with; headers handed to a helper.
    "r = request\nx = r.url.hostname",
    "conn = self.request\nx = conn['server']",
    "if (h := request.headers):\n    x = h.get('host')",
    "with seen(request.headers) as h:\n    x = h.get('origin')",
    "x = _hdr(request.headers, 'host')",
    "x = pick(headers=request.headers)",
    "h = request.headers\nx = pick(h)",
    # The headers some proxies write the address in.
    "x = request.headers.get('x-original-host')",
    "x = request.headers.get('X-Host')",
    "x = request.headers.get('X-Original-URL')",
    # A name bound with its type declared, and names bound by taking a tuple apart.
    "h: dict = request.headers\nx = h.get('host')",
    "a, b = request.headers, 1\nx = a.get('host')",
    "a, b = pair_of(request.headers)\nx = b.get('host')",
])
def test_the_check_finds_each_way_a_request_names_its_address(source):
    assert len(request_addresses(ast.parse(source))) >= 1, source


@pytest.mark.parametrize("source", [
    "host = urlsplit(provider.issuer).hostname",          # a provider's address, not the request's
    "query = request.url.query",
    "path = request.url.path",
    "agent = request.headers.get('user-agent')",
    "token = request.headers.get('authorization')",
    "kind = response.headers.get('content-type')",       # a provider's answer
    "peer = request.client.host",                         # who called, not the address they asked for
    "base = public_base_url()",
    "link = mint(db, user, base_url=base)",
    "where = provider.discovery_url",
    "headers = {'Accept': 'application/json'}\nheaders['Authorization'] = 'Basic x'",
    "origin = readiness().get('origin')",                 # the configured address, by its own name
    "state = getattr(request, 'state')",                  # nothing of the address
    "h = getattr(request, 'headers', None)\nx = h.get('sec-purpose')",
    "need = req['password'] or req['otp']",               # a requirement that happens to be called req
    "for name in ('purpose', 'sec-purpose'):\n    x = request.headers.get(name)",   # a walk over names that are no address
    "who = getattr(request, 'client', None)",
    "def f(r: Request):\n    return r.url.path",
    "pairs = settings.items()",                           # not a request's headers
    "for name, value in (headers or {}).items():\n    send(name, value)",   # headers the vault itself sends
    "value = scopes['read']",                             # another name altogether
    "page = requests.get(url)",                           # a call out, not a request that came in
    "kind = Headers({'content-type': 'text/plain'}).get('content-type')",    # headers the vault made itself
    "u = URL('https://idp.example/authorize')",           # an address written out
    "a, b = 1, request.headers\nx = a.get('host')",       # the other one of the pair holds the headers
    "h: dict = {}\nx = h.get('host')",
    "need = policy.get('otp')",
    "async def cb(user_agent: str = Header(None)):\n    return user_agent",       # a header that names no address
    "async def cb(token: str = Header(None, alias='X-Second-Factor')):\n    return token",
    "n = len(request.headers)",                           # how many, not which
    "agent = pick(request.headers.get('user-agent'))",    # one header that names no address, handed on
    "receipt = request.headers.get('X-Second-Factor')\nok = spend(receipt=receipt)",     # a value read out of them
    "headers = dict(refused.headers)\nanswer = respond(page, headers=headers)",          # headers the vault sends
    "r = requirement\nx = r['server']",                   # not a request, whatever it is given
    "ip = client_ip(_Request(scope))",                    # a request handed to what reads the caller, not the address
    "body = TotpEnrollRequest(code='1').code",            # a model that happens to be called a request
    "x = _scopes['read']",                                # another name altogether
    "peer = scope.get('client')",                         # who called
    "path = scope.get('path', '')",                       # what was asked for, not where
    "files = scope.get('files')",                         # a credential's scope, which happens to share the name
])
def test_the_check_leaves_what_names_no_request_address(source):
    assert request_addresses(ast.parse(source)) == [], source
