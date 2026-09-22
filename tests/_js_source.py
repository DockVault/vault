"""Read JavaScript source with its comments gone, for the pins that look at code.

A pin on the shape of code has to look at CODE. Dropping the lines that begin with `//` is not
that: a block comment holding the pinned line, or the pinned line commented out at the END of a
code line, satisfies "the string is present exactly once" with the behaviour gone. So this strips
every comment -- whole-line, trailing, and block -- while leaving strings, template literals and
regular-expression literals exactly as they are (a `//` inside a URL string is not a comment).

Newlines are kept where they were, so a line number into the stripped text is a line number into
the file.
"""

_REGEX_MAY_FOLLOW = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_MAY_FOLLOW_WORDS = ("return", "typeof", "case", "do", "else", "in", "of", "instanceof", "new",
                           "delete", "void", "throw")


def _regex_can_start_here(src: str, i: int) -> bool:
    """A `/` at i begins a regular-expression literal when what precedes it cannot end an operand."""
    j = i - 1
    while j >= 0 and src[j] in " \t":
        j -= 1
    if j < 0 or src[j] == "\n":
        return True
    if src[j] in _REGEX_MAY_FOLLOW:
        return True
    k = j
    while k >= 0 and (src[k].isalnum() or src[k] == "_" or src[k] == "$"):
        k -= 1
    word = src[k + 1:j + 1]
    return word in _REGEX_MAY_FOLLOW_WORDS


def strip_comments(src: str) -> str:
    out = []
    i, n = 0, len(src)
    # A stack of template-literal nesting: each entry is the brace depth at which `${` opened.
    template_depth = []
    brace_depth = 0
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j            # the newline itself is kept
            continue
        if c == "/" and nxt == "*":
            j = src.find("*/", i + 2)
            end = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, end))
            i = end
            continue
        if c in ("'", '"'):
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
            continue
        if c == "`":
            # Copy up to the matching backtick, or to the `${` that opens an expression.
            j = i + 1
            while j < n and src[j] != "`" and not (src[j] == "$" and src[j + 1:j + 2] == "{"):
                j += 2 if src[j] == "\\" else 1
            if j < n and src[j] == "$":
                out.append(src[i:j + 2])
                template_depth.append(brace_depth)
                brace_depth += 1
                i = j + 2
            else:
                out.append(src[i:j + 1])
                i = j + 1
            continue
        if c == "{":
            brace_depth += 1
        elif c == "}":
            brace_depth -= 1
            if template_depth and brace_depth == template_depth[-1]:
                # Back inside the template literal: copy its remainder the same way.
                template_depth.pop()
                out.append("}")
                j = i + 1
                while j < n and src[j] != "`" and not (src[j] == "$" and src[j + 1:j + 2] == "{"):
                    j += 2 if src[j] == "\\" else 1
                if j < n and src[j] == "$":
                    out.append(src[i + 1:j + 2])
                    template_depth.append(brace_depth)
                    brace_depth += 1
                    i = j + 2
                else:
                    out.append(src[i + 1:j + 1])
                    i = j + 1
                continue
        elif c == "/" and _regex_can_start_here(src, i):
            j = i + 1
            in_class = False
            while j < n and src[j] != "\n":
                if src[j] == "\\":
                    j += 2
                    continue
                if in_class:
                    in_class = src[j] != "]"
                elif src[j] == "[":
                    in_class = True
                elif src[j] == "/":
                    break
                j += 1
            out.append(src[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return "".join(out)
