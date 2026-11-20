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
declared as, whatever a parameter is called.

This holds every module of the sign-in pipeline, passkeys and single sign-on: every module under app/ named for one
of them, so a new one is read without being listed, and the ones listed below by name, so a rename shows here and
not as a shorter list. It also holds the API's main module, which has most of the sign-in routes, function by
function, with the two functions that read such a value for another purpose named below.
Offline, from the source."""
import ast
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

ADDRESS_HEADERS = ("host", "origin", "referer", "forwarded")
URL_PARTS_THAT_NAME_NO_HOST = ("path", "query")
HEADER_READS = ("get", "getlist", "get_all", "getall", "pop", "setdefault", "__getitem__")
# Reads of every header at once: which header is taken from the result cannot be seen here.
WHOLE_HEADER_READS = ("items", "keys", "values", "mutablecopy", "multi_items")
REQUEST_PARTS_THAT_NAME_AN_ADDRESS = ("url", "scope", "base_url", "url_for")
# What a parameter is declared as when it holds a request, a connection, a socket or a raw ASGI scope.
REQUEST_TYPES = re.compile(r"\b(Request|StarletteRequest|HTTPConnection|WebSocket|Scope)\b")
MAIN_MODULE = "app/api/api_server.py"
# The functions of the main module that read what a request says of itself, and why that is no address given out.
MAIN_MODULE_READS = {
    "_external_scheme": "whether the browser came over https, for the transport-security header alone",
    "_resolved_download_sink": "the request's own origin, compared with a download's target and never given out",
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
    name = node.id if isinstance(node, ast.Name) else node.attr if isinstance(node, ast.Attribute) else ""
    if isinstance(node, ast.Name) and name in declared:
        return True
    return name.lower().endswith(("request", "websocket")) or name.lower() == "scope" or (short_names and name.lower() == "req")


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
    constants, from_headers, kept_as = {}, set(), set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            carries = any((isinstance(n, ast.Attribute) and n.attr == "headers") or _headers_by_getattr(n, declared)
                          for n in ast.walk(node.value))
            if isinstance(target, ast.Name):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                    constants[target.id] = node.value.value
                if carries:
                    from_headers.add(target.id)
            elif isinstance(target, ast.Attribute) and carries:
                kept_as.add(target.attr)                      # self.h = request.headers

    def holds_headers(node) -> bool:
        return any((isinstance(n, ast.Attribute) and (n.attr == "headers" or n.attr in kept_as))
                   or (isinstance(n, ast.Name) and n.id in from_headers) or _headers_by_getattr(n, declared)
                   for n in ast.walk(node))

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
            elif node.attr in ("url", "scope") and _a_request(node.value, declared):
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


def _is_headers(node, from_headers, kept_as) -> bool:
    """Whether ``node`` is a request's headers themselves (to be walked over), not something read out of them."""
    if isinstance(node, ast.Attribute):
        return node.attr == "headers" or node.attr in kept_as
    return isinstance(node, ast.Name) and node.id in from_headers


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


def _main_module_functions():
    tree = ast.parse((ROOT / MAIN_MODULE).read_text(encoding="utf-8"))
    return {node.name: node for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_no_function_of_the_main_module_reads_what_a_request_says_of_its_address():
    """The main module holds most of the sign-in routes (the finish, the policy, the passkey routes, the step-up,
    the sign-out): each of its functions is read by the same check. The two that read such a value for another
    purpose are named with the purpose, must still be there and must still read it, so the list cannot outlive
    its reasons."""
    functions = _main_module_functions()
    reads = {name: request_addresses(node) for name, node in functions.items()}
    unexpected = {name: found for name, found in reads.items() if found and name not in MAIN_MODULE_READS}
    # A function nested in a named one is read with it.
    nested = {inner.name for outer in MAIN_MODULE_READS if outer in functions
              for inner in ast.walk(functions[outer]) if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef))}
    unexpected = {name: found for name, found in unexpected.items() if name not in nested}
    assert unexpected == {}, unexpected
    for name in MAIN_MODULE_READS:
        assert reads.get(name), f"{name} no longer reads a request's address: take it off the list"


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
])
def test_the_check_leaves_what_names_no_request_address(source):
    assert request_addresses(ast.parse(source)) == [], source
