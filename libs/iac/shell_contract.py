"""The bounded shell contract the scan gate recognizes in a workflow step's `run` script.

A step proves a scan or an upload only when the command is exactly a supported shape:

- scan: one `trivy image` invocation with known options and exactly one positional
  argument (the scanned reference), with no shell operator, control flow or command
  substitution on its line;
- upload: one `curl --fail ...` invocation to an ingest upload endpoint (not the receipt
  read) with no shell operator on its line (a `$(date ...)` timestamp is the one command
  substitution allowed).

The scanned reference and the upload arguments are expanded through the step's own
assignments and its `env` before they are judged, so a digest expression counts only when
it reaches the command's actual arguments; an unused variable holding it proves nothing.
Anything else that mentions a scan or an upload - `echo`, quoted text, `if ...; then`,
`&&`, `||`, `; `, pipes, subshells, `set +e`, an unknown option - is a gap: the gate is
not assessed, never passed. Pure: script text and an environment in, an analysis out.
Refs: docs/architecture/adrs/0108-iac-and-ci-assessment.md.
"""

from __future__ import annotations

import re
import shlex
from collections.abc import Mapping
from dataclasses import dataclass

__all__ = ["RunAnalysis", "analyse_run", "bound_digest", "expand"]

_EXPR = re.compile(r"\$\{\{.*?\}\}", re.S)
_PLACEHOLDER = re.compile(r"GHAEXPR(\d+)X")
_VAR = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$([A-Za-z_]\w*)")
_ASSIGN = re.compile(r"^[A-Za-z_]\w*=")
_FUNCTION_DEF = re.compile(r"^[A-Za-z_][\w-]*\s*\(\s*\)")
_SINGLE_QUOTED_DOLLAR = re.compile(r"'[^']*[$`][^']*'")
_DATE_SUBST = re.compile(r"\$\(date [^()]*\)")
_SCAN_LINE = re.compile(r"\btrivy\s+(image|fs|rootfs|sbom|repo|config|vm|k8s)\b")
_UPLOAD_LINE = re.compile(r"\b(curl|wget)\b")
_OPENERS = frozenset({"if", "for", "while", "until", "case", "select", "{"})
_CLOSERS = frozenset({"fi", "done", "esac", "}"})
# Constructs that change what a later command means: the contract stops at any of them.
_ALWAYS_GAP = frozenset({"function", "trap", "exec"})
# The ingest endpoints that take an upload; the receipt read is not one.
UPLOAD_ENDPOINT = re.compile(r"api/ingest/(ci/)?(sbom|secrets|iac)\b")
_OPERATORS = frozenset({"&&", "||", ";", ";;", "|", "|&", "&", "(", ")"})
_REDIRECTS = frozenset({">", ">>"})
# Trivy image options this contract follows: those that take a value and those that do not.
_VALUE_OPTIONS = frozenset(
    {
        "--format",
        "-f",
        "--output",
        "-o",
        "--scanners",
        "--pkg-types",
        "--severity",
        "-s",
        "--timeout",
        "--exit-code",
    }
)
_FLAG_OPTIONS = frozenset(
    {"--quiet", "-q", "--no-progress", "--skip-db-update", "--skip-java-db-update"}
)
# `<repository>@<one expression>`: the repository may itself hold expressions, the part
# after the last `@` is a single expression.
_BOUND_REF = re.compile(r"^.+@(\$\{\{(?:(?!\}\}).)*\}\})$", re.S)
_FAIL_FLAG = re.compile(r"^(--fail(-with-body)?|-[A-Za-z]*f[A-Za-z]*)$")
_OUTPUT_EXPR = re.compile(r"needs\.[A-Za-z0-9_-]+\.outputs(\.[A-Za-z0-9_-]+|\[)")


@dataclass(frozen=True)
class RunAnalysis:
    """What a script proves: the expanded scanned reference of every supported scan
    command, the needed-job output expressions reaching each supported upload command's
    arguments, and whether any scan or upload line fell outside the contract."""

    scans: tuple[str, ...] = ()
    upload_exprs: frozenset[str] = frozenset()
    gap: bool = False


def expand(text: str, scope: Mapping[str, str], _depth: int = 0) -> str:
    """`text` with each `$NAME` / `${NAME}` that `scope` defines replaced by its value,
    recursively; an unknown name stays as written."""
    if _depth > 8:
        return text

    def sub(m: re.Match[str]) -> str:
        name = m.group(1) or m.group(2)
        if name in scope:
            return expand(scope[name], scope, _depth + 1)
        return m.group(0)

    return _VAR.sub(sub, text)


def bound_digest(ref: str) -> str | None:
    """The needed-job output expression a scanned reference is pinned to
    (`<repository>@${{ needs.<job>.outputs... }}`, nothing after it), whitespace
    normalised; None for a tag, a literal digest or any other shape."""
    m = _BOUND_REF.match(ref.strip())
    if m is None:
        return None
    expr = "${{ " + " ".join(m.group(1)[3:-2].split()) + " }}"
    return expr if _OUTPUT_EXPR.search(expr) else None


def _logical_lines(text: str) -> list[str] | None:
    """The script's commands: split at newlines outside quotes, backticks and `$(...)`;
    None when a quote or substitution is left open."""
    lines: list[str] = []
    buf: list[str] = []
    quote = ""
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                buf.append(ch)
                i += 1
                ch = text[i] if i < len(text) else ""
        elif ch in "'\"":
            quote = ch
        elif ch == "\\":
            buf.append(ch)
            i += 1
            ch = text[i] if i < len(text) else ""
        elif ch == "$" and text[i + 1 : i + 2] == "(":
            depth += 1
            buf.append(ch)
            i += 1
            ch = "("
        elif ch == ")" and depth:
            depth -= 1
        elif ch == "\n" and not depth:
            lines.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    if quote or depth:
        return None
    lines.append("".join(buf).strip())
    return [line for line in lines if line]


def _tokens(line: str) -> list[str] | None:
    lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return list(lexer)
    except ValueError:
        return None


def _errexit_after(tokens: list[str], current: bool) -> bool:
    """The errexit state after a `set` command."""
    state = current
    i = 1
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-o", "+o") and i + 1 < len(tokens):
            if tokens[i + 1] == "errexit":
                state = tok == "-o"
            i += 2
            continue
        if tok[:1] in "-+" and len(tok) > 1 and not tok.startswith("--") and "e" in tok[1:]:
            state = tok[0] == "-"
        i += 1
    return state


def _scan_ref(tokens: list[str]) -> str | None:
    """The scanned reference of a supported `trivy image` command, None when the
    command is outside the contract."""
    if len(tokens) < 3 or tokens[0] != "trivy" or tokens[1] != "image":
        return None
    positional: list[str] = []
    i = 2
    while i < len(tokens):
        tok = tokens[i]
        if tok in _REDIRECTS and i + 1 < len(tokens):
            i += 2
        elif tok in _FLAG_OPTIONS:
            i += 1
        elif tok in _VALUE_OPTIONS and i + 1 < len(tokens):
            i += 2
        elif tok.startswith("--") and tok.partition("=")[0] in _VALUE_OPTIONS and "=" in tok:
            i += 1
        elif tok.startswith("-"):
            return None
        else:
            positional.append(tok)
            i += 1
    return positional[0] if len(positional) == 1 else None


def _upload_exprs(tokens: list[str], scope: Mapping[str, str]) -> frozenset[str] | None:
    """The needed-job output expressions reaching a supported upload command's
    arguments, None when the command is outside the contract."""
    if tokens[0] != "curl" or not any(_FAIL_FLAG.match(t) for t in tokens[1:]):
        return None
    if not any("/api/ingest/" in t for t in tokens):
        return None
    found = set()
    for tok in tokens[1:]:
        for m in _EXPR.finditer(expand(tok, scope)):
            expr = " ".join(m.group(0)[3:-2].split())
            if _OUTPUT_EXPR.search(expr):
                found.add("${{ " + expr + " }}")
    return frozenset(found)


def analyse_run(code: str, env: Mapping[str, str]) -> RunAnalysis:
    """Judge a comment-free `run` script against the contract, with `env` as the
    variables the step starts with."""
    exprs: list[str] = []

    def stash(m: re.Match[str]) -> str:
        exprs.append(m.group(0))
        return f"GHAEXPR{len(exprs) - 1}X"

    def restore(s: str) -> str:
        return _PLACEHOLDER.sub(lambda m: exprs[int(m.group(1))], s)

    lines = _logical_lines(_EXPR.sub(stash, code.replace("\\\n", " ")))
    if lines is None:
        return RunAnalysis(gap=True)
    if any(
        line.split(None, 1)[0] in _ALWAYS_GAP or _FUNCTION_DEF.match(line) or "<<" in line
        for line in lines
    ):
        return RunAnalysis(gap=True)
    scope = dict(env)
    scans: list[str] = []
    uploads: set[str] = set()
    errexit = True
    depth = 0
    for line in lines:
        first = line.split(None, 1)[0]
        if first in _OPENERS:
            depth += 1 - sum(w in _CLOSERS for w in re.split(r"[\s;]+", line))
        elif first in _CLOSERS:
            depth = max(depth - 1, 0)
        is_scan = bool(_SCAN_LINE.search(line))
        is_upload = bool(_UPLOAD_LINE.search(line)) and bool(UPLOAD_ENDPOINT.search(line))
        candidate = is_scan or is_upload
        if candidate and depth:
            return RunAnalysis(gap=True)
        if is_upload:
            line = _DATE_SUBST.sub("DATENOW", line)
        if candidate and (
            "`" in line or "$(" in line or _SINGLE_QUOTED_DOLLAR.search(line) or not errexit
        ):
            return RunAnalysis(gap=True)
        tokens = _tokens(line)
        if tokens is None:
            if candidate:
                return RunAnalysis(gap=True)
            continue
        if not tokens:
            continue
        if not candidate:
            if tokens[0] == "set":
                errexit = _errexit_after(tokens, errexit)
                continue
            body = tokens[1:] if tokens[0] == "export" else tokens
            if len(body) == 1 and _ASSIGN.match(body[0]):
                name, _, value = body[0].partition("=")
                if _SINGLE_QUOTED_DOLLAR.search(line):
                    value = value.replace("$", "\x01")
                # Inside control flow the value may not be the one a later command sees.
                scope[name] = restore(value) if not depth else "\x01unknown"
            continue
        if any(t in _OPERATORS for t in tokens) or _ASSIGN.match(tokens[0]):
            return RunAnalysis(gap=True)
        tokens = [restore(t) for t in tokens]
        if is_scan:
            ref = _scan_ref(tokens)
            if ref is None or is_upload:
                return RunAnalysis(gap=True)
            scans.append(expand(ref, scope))
        else:
            found = _upload_exprs(tokens, scope)
            if found is None:
                return RunAnalysis(gap=True)
            uploads |= found
    return RunAnalysis(tuple(scans), frozenset(uploads))
