"""Repository symbol index for the LLM scan layer (design doc 4).

The parser is deliberately approximate.  Its product is a scan-unit plan and
a coverage denominator, not a compiler front end: the agents navigate
precisely at run time, the index only decides what gets scheduled.  Where the
approximation is known to slip, the file records a lower ``parse_confidence``
instead of pretending.

Offsets are byte offsets.  Source is decoded through :func:`decode_source`,
which maps one byte to one character, so every index into the text is also a
byte offset into the file.

The stdlib implementation runs five passes:

A. lexical masking      comment / string / char contents blanked, offsets kept
B. preprocessor map     includes, defines, conditional arms, inactive regions
C. function extents     depth-0 brace matching confirmed by a declarator
D. types, macros, globals
E. approximate call graph, resolved against the repository symbol table

Known imprecision, all reflected in ``parse_confidence``: macro-generated
function headers are attributed to the macro name, functions produced wholly
by macro expansion are invisible, and C++ constructs (member functions defined
inside a class body, brace initialisers in a member-initialiser list,
templates, lambdas) are weaker than C.  Bodies inside an inactive ``#if 0``
arm are not compiled and are therefore not reported as functions; their bytes
stay covered by a module-scope unit.
"""
from __future__ import annotations

import bisect
import hashlib
import re
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..includes import normalize_include, resolve_include

INDEX_SCHEMA_VERSION = 1

# Below this a file's units are reported under unscanned_reasons.parse_confidence_low.
LOW_CONFIDENCE = 0.5

# Definitions travel into prompts; a runaway one would dominate the prefill.
MAX_DEFINITION_CHARS = 2000

_IDENT = re.compile(r"[A-Za-z_]\w*")
_CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_DIRECTIVE_NAME = re.compile(r"#\s*(\w+)")
_INCLUDE_TARGET = re.compile(r"#\s*include\s*([<\"])([^>\"]*)")
_DEFINE_NAME = re.compile(r"#\s*define\s+([A-Za-z_]\w*)(\()?")
_REJECT_LEAD = re.compile(
    r"^\s*(?:if|while|for|switch|do|else|return|case|default|try|catch|typedef|sizeof|goto)\b"
)
_TRAILING_QUALIFIER = re.compile(
    r"(?:\b(?:const|volatile|noexcept|override|final|mutable|restrict|__restrict|__restrict__"
    r"|_Noreturn|__noreturn__|constexpr)\b"
    r"|\b(?:noexcept|throw|__attribute__|__asm__|asm|alignas|_Alignas)\s*\((?:[^()]|\([^()]*\))*\)"
    r"|\[\[[^\]]*\]\])\s*$"
)
_INIT_LIST = re.compile(
    r"^\s*[A-Za-z_~][\w:<>]*\s*\((?:[^()]|\([^()]*\))*\)"
    r"(?:\s*,\s*[A-Za-z_~][\w:<>]*\s*\((?:[^()]|\([^()]*\))*\))*\s*$"
)
_KR_PARAM_DECL = re.compile(r"^[A-Za-z_][\w\s*,\[\]]*;$")
_KR_PARAM_LIST = re.compile(r"^\s*[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*\s*$")
_RECORD_HEAD = re.compile(r"^\s*(?:typedef\s+)?(struct|union|enum|class)\b\s*([A-Za-z_]\w*)?")
_TRAILING_NAME = re.compile(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])*\s*$")
_RAW_STRING_PREFIX = frozenset({"R", "u8R", "uR", "UR", "LR"})

_KEYWORDS = frozenset("""
alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t char16_t
char32_t class compl concept const consteval constexpr constinit const_cast continue co_await
co_return co_yield decltype default delete do double dynamic_cast else enum explicit export extern
false float for friend goto if inline int long mutable namespace new noexcept not not_eq nullptr
operator or or_eq private protected public register reinterpret_cast requires restrict return
short signed sizeof static static_assert static_cast struct switch template this thread_local
throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while
xor xor_eq defined offsetof va_arg va_start va_end
_Alignas _Alignof _Atomic _Bool _Complex _Generic _Imaginary _Noreturn _Static_assert _Thread_local
__attribute__ __asm__ __declspec __typeof__ __extension__ __restrict __restrict__ __inline__
""".split())


@dataclass(frozen=True)
class Symbols:
    """What one parsed translation unit contributes to the index."""

    functions: tuple[dict[str, Any], ...] = ()
    types: tuple[dict[str, Any], ...] = ()
    macros: tuple[dict[str, Any], ...] = ()
    globals: tuple[dict[str, Any], ...] = ()
    includes: tuple[dict[str, Any], ...] = ()
    conditionals: tuple[dict[str, Any], ...] = ()
    dead_spans: tuple[tuple[int, int], ...] = ()
    parse_confidence: float = 1.0
    parse_problems: tuple[str, ...] = ()
    unparsed_from: int | None = None


class Parser(Protocol):
    """Anything that can turn source text into :class:`Symbols`.

    A tree-sitter backed implementation drops in here; the stdlib one below is
    the only implementation that ships today because tree-sitter is an
    optional extra and the index must always be available.
    """

    name: str

    def parse(self, text: str) -> Symbols: ...


def decode_source(data: bytes) -> str:
    """Decode bytes so that character index == byte offset."""
    return data.decode("latin-1")


def source_text(data: bytes) -> str:
    """Decode bytes for human/model consumption, never for offsets."""
    return data.decode("utf-8", errors="replace")


def mask_source(text: str) -> str:
    """Pass A: blank comment, string and char contents; keep every offset."""
    return _mask_source(text)[0]


class StdlibParser:
    """Regex and brace-matching parser.  Always available, never exact."""

    name = "stdlib"

    def parse(self, text: str) -> Symbols:
        masked, problems = _mask_source(text)
        starts = line_starts(text)
        directives = _directives(masked, starts)
        arms, conditional_problems = _conditional_arms(directives, len(text), starts)
        problems = [*problems, *conditional_problems]
        dead = _merge_spans([(arm["body_start"], arm["body_end"]) for arm in arms if arm["dead"]])
        blanked = [(item["start"], item["end"]) for item in directives]
        code = _blank_regions(masked, [*blanked, *dead])
        macros = _macros(directives, text, starts)
        includes = _includes(directives, text, starts)
        macro_names = {item["name"] for item in macros}
        functions, function_problems, unparsed_from = _functions(code, text, starts, macro_names, arms)
        problems = [*problems, *function_problems]
        types, globals_, statement_problems = _declarations(code, text, starts, functions)
        problems = [*problems, *statement_problems]
        for record in functions:
            record["calls"] = _calls(code[record["body_start"]:record["end_byte"]])
        confidence = _confidence(functions, problems, unparsed_from, len(text))
        return Symbols(
            functions=tuple(functions),
            types=tuple(types),
            macros=tuple(macros),
            globals=tuple(globals_),
            includes=tuple(includes),
            conditionals=tuple(arms),
            dead_spans=tuple(dead),
            parse_confidence=confidence,
            parse_problems=tuple(dict.fromkeys(problems)),
            unparsed_from=unparsed_from,
        )


def default_parser() -> Parser:
    return StdlibParser()


def parse_source(text: str, *, parser: Parser | None = None) -> Symbols:
    return (parser or default_parser()).parse(text)


def line_starts(text: str) -> list[int]:
    starts = [0]
    for offset, char in enumerate(text):
        if char == "\n":
            starts.append(offset + 1)
    return starts


def line_of(starts: Sequence[int], offset: int) -> int:
    """1-based line number of a byte offset."""
    return bisect.bisect_right(starts, offset)


def build_index(
    source: Path,
    inventory: Sequence[dict[str, Any]],
    *,
    parser: Parser | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    """Parse every inventory record into one repository index.

    ``inventory`` is consumed as produced by :func:`code_analyzer.inventory.discover`;
    the tree is never re-walked here.  Nothing time-dependent enters the result.
    """
    parser = parser or default_parser()
    files: dict[str, Any] = {}
    for record in inventory:
        if cancelled is not None and cancelled():
            raise InterruptedError("run interrupted")
        relative = record["path"]
        try:
            data = (source / relative).read_bytes()
        except OSError:
            files[relative] = _unreadable(record)
            continue
        text = decode_source(data)
        symbols = parser.parse(text)
        files[relative] = {
            "path": relative,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
            "language": record.get("language", "c"),
            "is_header": bool(record.get("is_header")),
            "readable": True,
            "parse_confidence": symbols.parse_confidence,
            "parse_problems": list(symbols.parse_problems),
            "unparsed_from": symbols.unparsed_from,
            "functions": [dict(item) for item in symbols.functions],
            "types": [dict(item) for item in symbols.types],
            "macros": [dict(item) for item in symbols.macros],
            "globals": [dict(item) for item in symbols.globals],
            "includes": [dict(item) for item in symbols.includes],
            "conditionals": [dict(item) for item in symbols.conditionals],
            "dead_spans": [list(span) for span in symbols.dead_spans],
        }
    index: dict[str, Any] = {
        "index_schema_version": INDEX_SCHEMA_VERSION,
        "parser": parser.name,
        "files": files,
        "symbols": _symbol_table(files),
        "types": _definition_table(files, "types"),
        "macros": _definition_table(files, "macros"),
        "globals": _definition_table(files, "globals"),
    }
    index["call_graph"] = _call_graph(files, index["symbols"])
    index["include_graph"] = _include_graph(files)
    index["totals"] = {
        "files": len(files),
        "functions": sum(len(item.get("functions", ())) for item in files.values()),
        "bytes": sum(int(item.get("size", 0)) for item in files.values()),
        "unreadable": sum(1 for item in files.values() if not item.get("readable")),
        "parse_confidence_low": sum(
            1 for item in files.values() if float(item.get("parse_confidence", 0.0)) < LOW_CONFIDENCE
        ),
    }
    return index


# --- pass A: lexical masking -------------------------------------------------


def _mask_source(text: str) -> tuple[str, list[str]]:
    chars = list(text)
    total = len(text)
    problems: list[str] = []
    offset = 0
    while offset < total:
        char = text[offset]
        if char == "/" and offset + 1 < total and text[offset + 1] == "/":
            end = _line_comment_end(text, offset + 2)
            _blank(chars, offset, end)
            offset = end
            continue
        if char == "/" and offset + 1 < total and text[offset + 1] == "*":
            end = text.find("*/", offset + 2)
            if end < 0:
                problems.append("unterminated block comment")
                _blank(chars, offset, total)
                break
            _blank(chars, offset, end + 2)
            offset = end + 2
            continue
        if char == '"' and _is_raw_string(text, offset):
            offset = _mask_raw_string(text, chars, offset, problems)
            continue
        if char in "\"'":
            if char == "'" and _is_digit_separator(text, offset):
                offset += 1
                continue
            offset = _mask_literal(text, chars, offset, problems)
            continue
        offset += 1
    return "".join(chars), problems


def _blank(chars: list[str], start: int, end: int) -> None:
    for index in range(start, min(end, len(chars))):
        if chars[index] != "\n":
            chars[index] = " "


def _line_comment_end(text: str, offset: int) -> int:
    total = len(text)
    while offset < total:
        char = text[offset]
        if char == "\\":
            step = offset + 1
            if step < total and text[step] == "\r":
                step += 1
            if step < total and text[step] == "\n":
                offset = step + 1
                continue
            offset += 1
            continue
        if char == "\n":
            return offset
        offset += 1
    return total


def _is_raw_string(text: str, offset: int) -> bool:
    if offset == 0 or text[offset - 1] != "R":
        return False
    start = offset - 1
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
        start -= 1
    return text[start:offset] in _RAW_STRING_PREFIX


def _is_digit_separator(text: str, offset: int) -> bool:
    """C++14 ``1'000'000``.  The token has to start with a digit: ``L'a'`` is a
    character literal, ``0xaaaa'aaaa`` is not."""
    after = text[offset + 1] if offset + 1 < len(text) else ""
    if not (after.isalnum() or after == "_"):
        return False
    start = offset
    while start > 0 and (text[start - 1].isalnum() or text[start - 1] in "_.'"):
        start -= 1
    return start < offset and text[start].isdigit()


def _mask_raw_string(text: str, chars: list[str], offset: int, problems: list[str]) -> int:
    total = len(text)
    paren = text.find("(", offset + 1)
    if paren < 0 or paren - offset > 18:
        problems.append("unterminated raw string literal")
        _blank(chars, offset + 1, total)
        return total
    terminator = ")" + text[offset + 1:paren] + '"'
    end = text.find(terminator, paren + 1)
    if end < 0:
        problems.append("unterminated raw string literal")
        _blank(chars, offset + 1, total)
        return total
    _blank(chars, offset + 1, end + len(terminator) - 1)
    return end + len(terminator)


def _mask_literal(text: str, chars: list[str], offset: int, problems: list[str]) -> int:
    quote = text[offset]
    total = len(text)
    cursor = offset + 1
    while cursor < total:
        char = text[cursor]
        if char == "\\":
            cursor += 2
            continue
        if char == quote:
            _blank(chars, offset + 1, cursor)
            return cursor + 1
        if char == "\n":
            break
        cursor += 1
    problems.append("unterminated string or character literal")
    cursor = min(cursor, total)
    _blank(chars, offset + 1, cursor)
    return max(cursor, offset + 1)


# --- pass B: preprocessor map ------------------------------------------------


def _directives(masked: str, starts: Sequence[int]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    total = len(masked)
    consumed = 0
    for begin in starts:
        if begin < consumed:
            continue
        cursor = begin
        while cursor < total and masked[cursor] in " \t\r\f\v":
            cursor += 1
        if cursor >= total or masked[cursor] != "#":
            continue
        end = _logical_line_end(masked, cursor)
        text = masked[cursor:end]
        match = _DIRECTIVE_NAME.match(text)
        result.append({
            "kind": match.group(1) if match else "",
            "text": text,
            "start": cursor,
            "end": end,
        })
        consumed = end
    return result


def _logical_line_end(text: str, offset: int) -> int:
    total = len(text)
    while offset < total:
        if text[offset] == "\n":
            back = offset - 1
            if back >= 0 and text[back] == "\r":
                back -= 1
            if back >= 0 and text[back] == "\\":
                offset += 1
                continue
            return offset
        offset += 1
    return total


def _conditional_arms(
    directives: Sequence[dict[str, Any]], total: int, starts: Sequence[int]
) -> tuple[list[dict[str, Any]], list[str]]:
    arms: list[dict[str, Any]] = []
    stack: list[dict[str, Any]] = []
    problems: list[str] = []
    for item in directives:
        kind = item["kind"]
        if kind in {"if", "ifdef", "ifndef"}:
            parent_dead = bool(stack[-1]["dead"]) if stack else False
            arm = _arm(item, kind, len(stack), parent_dead, starts)
            arms.append(arm)
            stack.append(arm)
            continue
        if kind in {"elif", "elifdef", "elifndef", "else"} and stack:
            previous = stack[-1]
            previous["body_end"] = item["start"]
            previous["line_end"] = line_of(starts, max(item["start"] - 1, 0))
            arm = _arm(item, kind, len(stack) - 1, bool(previous["parent_dead"]), starts)
            arms.append(arm)
            stack[-1] = arm
            continue
        if kind == "endif":
            if not stack:
                problems.append("unbalanced #endif")
                continue
            previous = stack.pop()
            previous["body_end"] = item["start"]
            previous["line_end"] = line_of(starts, max(item["start"] - 1, 0))
    for leftover in stack:
        problems.append("unterminated conditional directive")
        leftover["body_end"] = total
        leftover["line_end"] = line_of(starts, max(total - 1, 0))
    return arms, problems


def _arm(
    item: dict[str, Any], kind: str, depth: int, parent_dead: bool, starts: Sequence[int]
) -> dict[str, Any]:
    condition = item["text"].split(None, 1)[1].strip() if len(item["text"].split(None, 1)) > 1 else ""
    condition = condition.lstrip("#").strip() if kind and item["text"].lstrip().startswith("# ") else condition
    dead = parent_dead or (kind in {"if", "elif"} and condition.replace(" ", "") in {"0", "(0)"})
    return {
        "kind": kind,
        "condition": condition,
        "depth": depth,
        "start": item["start"],
        "body_start": item["end"],
        "body_end": item["end"],
        "line_start": line_of(starts, item["start"]),
        "line_end": line_of(starts, item["end"]),
        "dead": dead,
        "parent_dead": parent_dead,
    }


def _macros(
    directives: Sequence[dict[str, Any]], text: str, starts: Sequence[int]
) -> list[dict[str, Any]]:
    result = []
    for item in directives:
        if item["kind"] != "define":
            continue
        match = _DEFINE_NAME.match(item["text"])
        if match is None:
            continue
        result.append({
            "name": match.group(1),
            "function_like": bool(match.group(2)),
            "start_byte": item["start"],
            "end_byte": item["end"],
            "line": line_of(starts, item["start"]),
            "definition": _definition(text, item["start"], item["end"]),
        })
    return result


def _includes(
    directives: Sequence[dict[str, Any]], text: str, starts: Sequence[int]
) -> list[dict[str, Any]]:
    result = []
    for item in directives:
        if item["kind"] != "include":
            continue
        # The quoted form is a string literal, so pass A blanked it: the target
        # has to be read back out of the original text.
        match = _INCLUDE_TARGET.match(text[item["start"]:item["end"]])
        result.append({
            "target": match.group(2) if match else "",
            "system": bool(match) and match.group(1) == "<",
            "line": line_of(starts, item["start"]),
        })
    return result


# --- pass C: function extents ------------------------------------------------


def _functions(
    code: str,
    text: str,
    starts: Sequence[int],
    macro_names: set[str],
    arms: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str], int | None]:
    functions: list[dict[str, Any]] = []
    problems: list[str] = []
    terminators = [0]
    total = len(code)
    offset = 0
    while offset < total:
        char = code[offset]
        if char == "{":
            header = _header_at(code, terminators, offset, macro_names)
            end = _match_brace(code, offset)
            if end is None:
                problems.append("unbalanced braces")
                start = header["start"] if header else _lstrip_offset(code, terminators[-1], offset)
                return functions, problems, start
            if header is not None:
                functions.append(_function_record(header, code, text, starts, offset, end, arms))
            terminators.append(end + 1)
            offset = end + 1
            continue
        if char == "}":
            problems.append("unbalanced closing brace")
            terminators.append(offset + 1)
            offset += 1
            continue
        if char == ";":
            terminators.append(offset + 1)
        offset += 1
    return functions, problems, None


def _function_record(
    header: dict[str, Any],
    code: str,
    text: str,
    starts: Sequence[int],
    brace: int,
    end: int,
    arms: Sequence[dict[str, Any]],
) -> dict[str, Any]:
    start = header["start"]
    return {
        "name": header["name"],
        "start_byte": start,
        "end_byte": end + 1,
        "body_start": brace,
        "line_start": line_of(starts, start),
        "line_end": line_of(starts, end),
        "signature": _collapse(text[start:brace]),
        "kr_style": header["kr_style"],
        "macro_header": header["macro_header"],
        "conditional": _condition_label(arms, start),
        "dead": _in_dead(arms, start),
        "calls": [],
    }


def _header_at(
    code: str, terminators: list[int], brace: int, macro_names: set[str]
) -> dict[str, Any] | None:
    base = terminators[-1]
    header = _analyse_header(code[base:brace], macro_names)
    if header is not None:
        header["start"] = base + header["offset"]
        return header
    # K&R: the parameter declarations sit between the declarator and the body,
    # so the walk-back has to cross them before a declarator can appear.
    for back in range(2, min(len(terminators), 9) + 1):
        start = terminators[-back]
        region = code[start:brace]
        close = _first_paren_close(region)
        if close is None:
            continue
        head, tail = region[:close + 1], region[close + 1:]
        if ";" in head or not tail.strip() or not _kr_declarations(tail):
            continue
        candidate = _analyse_header(head, macro_names)
        if candidate is not None and candidate["kr_candidate"]:
            candidate["start"] = start + candidate["offset"]
            candidate["kr_style"] = True
            return candidate
    return None


def _kr_declarations(tail: str) -> bool:
    parts = tail.split(";")
    if parts[-1].strip():
        return False
    return all(_KR_PARAM_DECL.match(part.strip() + ";") for part in parts[:-1] if part.strip())


def _first_paren_close(text: str) -> int | None:
    depth = 0
    for offset, char in enumerate(text):
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return offset
    return None


def _analyse_header(header: str, macro_names: set[str]) -> dict[str, Any] | None:
    if _REJECT_LEAD.match(header):
        return None
    body = header
    cut = _init_list_cut(body)
    if cut is not None:
        if not _INIT_LIST.match(body[cut + 1:]):
            return None
        body = body[:cut]
    previous = None
    while previous != body:
        previous = body
        body = _TRAILING_QUALIFIER.sub("", body.rstrip())
    body = body.rstrip()
    if not body.endswith(")"):
        return None
    open_paren = _match_paren_backwards(body)
    if open_paren is None:
        return None
    cursor = open_paren - 1
    while cursor >= 0 and body[cursor].isspace():
        cursor -= 1
    end = cursor + 1
    while cursor >= 0 and (body[cursor].isalnum() or body[cursor] in "_:~"):
        cursor -= 1
    name = body[cursor + 1:end].strip(":")
    if not name or name in _KEYWORDS or not _IDENT.match(name.split("::")[-1] or "x"):
        return None
    if body[max(cursor, 0):cursor + 1] == "." or body[cursor - 1:cursor + 1] == "->":
        return None
    params = body[open_paren + 1:-1]
    identifiers = [item for item in _IDENT.findall(params)] if params.strip() else []
    kr_candidate = bool(
        params.strip()
        and _KR_PARAM_LIST.match(params)
        and not any(item in _KEYWORDS or item.endswith("_t") for item in identifiers)
    )
    return {
        "name": name,
        "offset": len(header) - len(header.lstrip()),
        "kr_style": False,
        "kr_candidate": kr_candidate,
        "macro_header": name in macro_names or (name.isupper() and any(ch.isalpha() for ch in name)),
    }


def _init_list_cut(header: str) -> int | None:
    depth = 0
    for offset, char in enumerate(header):
        if char in "([{<":
            depth += 1 if char != "<" else 0
        elif char in ")]}>":
            depth -= 1 if char != ">" else 0
        elif char == ":" and depth == 0:
            if header[offset - 1:offset] == ":" or header[offset + 1:offset + 2] == ":":
                continue
            if header[:offset].rstrip().endswith(")"):
                return offset
    return None


def _match_paren_backwards(text: str) -> int | None:
    depth = 0
    for offset in range(len(text) - 1, -1, -1):
        char = text[offset]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                return offset
    return None


def _match_brace(code: str, offset: int) -> int | None:
    depth = 0
    for cursor in range(offset, len(code)):
        char = code[cursor]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return cursor
    return None


# --- pass D: types, macros, globals ------------------------------------------


def _declarations(
    code: str, text: str, starts: Sequence[int], functions: Sequence[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    types: list[dict[str, Any]] = []
    globals_: list[dict[str, Any]] = []
    problems: list[str] = []
    spans = {item["start_byte"]: item["end_byte"] for item in functions}
    total = len(code)
    offset = 0
    start = 0
    while offset < total:
        if offset in spans:
            offset = spans[offset]
            start = offset
            continue
        char = code[offset]
        if char == "{":
            end = _match_brace(code, offset)
            if end is None:
                problems.append("unbalanced braces")
                break
            offset = end + 1
            continue
        if char == "}":
            offset += 1
            start = offset
            continue
        if char == ";":
            statement = code[start:offset + 1]
            record = _classify(statement, text, starts, start)
            if record is not None:
                (types if record.pop("is_type") else globals_).append(record)
            offset += 1
            start = offset
            continue
        offset += 1
    return types, globals_, problems


def _classify(
    statement: str, text: str, starts: Sequence[int], start: int
) -> dict[str, Any] | None:
    stripped = statement.strip()
    if not stripped or stripped == ";":
        return None
    begin = start + len(statement) - len(statement.lstrip())
    end = start + len(statement)
    record = {
        "name": "",
        "kind": "global",
        "is_type": False,
        "start_byte": begin,
        "end_byte": end,
        "line": line_of(starts, begin),
        "definition": _definition(text, begin, end),
    }
    head = _RECORD_HEAD.match(stripped)
    if stripped.startswith("typedef"):
        match = _TRAILING_NAME.search(stripped[:-1])
        record.update(name=match.group(1) if match else "", kind="typedef", is_type=True)
        return record if record["name"] else None
    if head is not None and "(" not in stripped.split("{", 1)[0]:
        record.update(name=head.group(2) or "", kind=head.group(1), is_type=True)
        return record if record["name"] else None
    declarator = _analyse_header(stripped[:-1], set())
    if declarator is not None and "=" not in stripped.split("(", 1)[0]:
        record.update(name=declarator["name"], kind="prototype")
        return record
    lhs = stripped[:-1].split("=", 1)[0]
    candidates = [item for item in _IDENT.findall(lhs) if item not in _KEYWORDS]
    if not candidates:
        return None
    record.update(name=candidates[-1], kind="global")
    return record


# --- pass E: approximate call graph ------------------------------------------


def _calls(body: str) -> list[str]:
    names = {match.group(1) for match in _CALL.finditer(body)}
    return sorted(name for name in names if name not in _KEYWORDS)


def _call_graph(files: dict[str, Any], symbols: dict[str, Any]) -> dict[str, Any]:
    callees: dict[str, list[str]] = {}
    callers: dict[str, list[str]] = {}
    for path in sorted(files):
        for record in files[path].get("functions", ()):
            key = f"{path}::{record['name']}"
            resolved = sorted({name for name in record.get("calls", ()) if name in symbols})
            callees[key] = resolved
            for name in resolved:
                callers.setdefault(name, []).append(key)
    return {
        "callees": callees,
        "callers": {name: sorted(set(keys)) for name, keys in sorted(callers.items())},
    }


# --- pass F: include graph and header pairing --------------------------------


def _include_graph(files: dict[str, Any]) -> dict[str, Any]:
    """Which files include which, and which header states a unit's contract.

    A unit's caller-visible contract lives in its header, not beside it: the
    prototype says what callers may pass, and its *absence* says the function
    is not part of the interface at all.  Neither fact is reachable from the
    implementation file alone, so the pairing has to be an index-level fact.

    Resolution is textual and tree-local on purpose.  There is no preprocessor
    here and no ``-I`` search path, so a target that names no file in the
    scanned tree is recorded as unresolved (a system or vendor header) rather
    than guessed at.
    """
    by_path = {path: path for path in files}
    by_suffix: dict[str, list[str]] = {}
    for path in sorted(files):
        parts = path.split("/")
        for depth in range(len(parts)):
            by_suffix.setdefault("/".join(parts[depth:]), []).append(path)

    edges: dict[str, list[str]] = {}
    unresolved: dict[str, list[str]] = {}
    included_by: dict[str, set[str]] = {}
    for path in sorted(files):
        directory = path.rsplit("/", 1)[0] if "/" in path else ""
        resolved: set[str] = set()
        missing: set[str] = set()
        for item in files[path].get("includes", ()):
            target = str(item.get("target") or "").strip()
            if not target:
                continue
            found = _resolve_include(target, directory, by_path, by_suffix)
            if found is None or found == path:
                missing.add(target)
                continue
            resolved.add(found)
            included_by.setdefault(found, set()).add(path)
        if resolved:
            edges[path] = sorted(resolved)
        if missing:
            unresolved[path] = sorted(missing)

    pairs: dict[str, str] = {}
    for path in sorted(files):
        if files[path].get("is_header"):
            continue
        header = _paired_header(path, files, edges.get(path, ()), by_suffix)
        if header is not None:
            pairs[path] = header
    return {
        "edges": edges,
        "unresolved": unresolved,
        "included_by": {path: sorted(sources) for path, sources in sorted(included_by.items())},
        "pairs": pairs,
    }


def _resolve_include(
    target: str, directory: str, by_path: dict[str, str], by_suffix: dict[str, list[str]]
) -> str | None:
    """Resolve one include target to a file in the tree, or ``None`` (see includes.py)."""
    return resolve_include(target, directory, by_path, by_suffix)


def _normalize_include(target: str) -> str:
    return normalize_include(target)


def _paired_header(
    path: str, files: dict[str, Any], includes: Sequence[str], by_suffix: dict[str, list[str]]
) -> str | None:
    """The header that declares this implementation file's interface.

    An include edge is the evidence; the ``foo.c`` / ``foo.h`` name match is
    the tie-breaker among several included headers, and on its own is enough
    only when the file includes no header from the tree at all.
    """
    stem = path.rsplit("/", 1)[-1].rsplit(".", 1)[0]
    headers = [item for item in includes if files.get(item, {}).get("is_header")]
    named = [item for item in headers if item.rsplit("/", 1)[-1].rsplit(".", 1)[0] == stem]
    if named:
        return named[0]
    if headers:
        return None
    directory = path.rsplit("/", 1)[0] if "/" in path else ""
    for suffix in (".h", ".hpp", ".hh"):
        candidate = _normalize_include(f"{directory}/{stem}{suffix}" if directory else f"{stem}{suffix}")
        if files.get(candidate, {}).get("is_header"):
            return candidate
    return None


# --- shared helpers ----------------------------------------------------------


def _symbol_table(files: dict[str, Any]) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for path in sorted(files):
        record = files[path]
        for item in record.get("functions", ()):
            entry = {
                "kind": "function",
                "path": path,
                "line": item["line_start"],
                "signature": item["signature"],
                "summary": _summary(item, path),
            }
            _insert(table, item["name"], entry, prefer=True)
        for item in record.get("globals", ()):
            if item.get("kind") != "prototype":
                continue
            entry = {
                "kind": "prototype",
                "path": path,
                "line": item["line"],
                "signature": str(item.get("definition", "")).rstrip(";"),
                "summary": f"declared in {path}",
            }
            _insert(table, item["name"], entry, prefer=False)
    return table


def _definition_table(files: dict[str, Any], section: str) -> dict[str, Any]:
    table: dict[str, Any] = {}
    for path in sorted(files):
        for item in files[path].get(section, ()):
            if section == "globals" and item.get("kind") == "prototype":
                continue
            name = item.get("name", "")
            if not name:
                continue
            entry = {
                "kind": item.get("kind", section),
                "path": path,
                "line": item.get("line", 0),
                "definition": item.get("definition", ""),
            }
            _insert(table, name, entry, prefer=False)
    return table


def _insert(table: dict[str, Any], name: str, entry: dict[str, Any], *, prefer: bool) -> None:
    existing = table.get(name)
    if existing is None:
        table[name] = {**entry, "duplicates": 0}
        return
    existing["duplicates"] += 1
    if prefer and existing.get("kind") != "function":
        table[name] = {**entry, "duplicates": existing["duplicates"]}


def _summary(record: dict[str, Any], path: str) -> str:
    calls = record.get("calls", ())
    tail = f"; calls {', '.join(calls[:4])}" if calls else ""
    return f"defined at {path}:{record['line_start']}-{record['line_end']}{tail}"


def _definition(text: str, start: int, end: int) -> str:
    body = _collapse(text[start:end])
    return body if len(body) <= MAX_DEFINITION_CHARS else body[:MAX_DEFINITION_CHARS] + " ..."


def _collapse(text: str) -> str:
    return " ".join(source_text(text.encode("latin-1", "replace")).split())


def _condition_label(arms: Sequence[dict[str, Any]], offset: int) -> str:
    labels = [
        f"{'#' + arm['kind']} {arm['condition']}".strip()
        for arm in arms
        if arm["body_start"] <= offset < arm["body_end"]
    ]
    return " && ".join(labels)


def _in_dead(arms: Sequence[dict[str, Any]], offset: int) -> bool:
    return any(arm["dead"] and arm["body_start"] <= offset < arm["body_end"] for arm in arms)


def _merge_spans(spans: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(spans):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            continue
        merged.append((start, end))
    return merged


def _blank_regions(text: str, spans: Iterable[tuple[int, int]]) -> str:
    chars = list(text)
    for start, end in spans:
        _blank(chars, start, end)
    return "".join(chars)


def _lstrip_offset(code: str, start: int, limit: int) -> int:
    while start < limit and code[start].isspace():
        start += 1
    return start


def _confidence(
    functions: Sequence[dict[str, Any]], problems: Sequence[str], unparsed_from: int | None, size: int
) -> float:
    score = 1.0
    penalties = {
        "unterminated block comment": 0.4,
        "unterminated string or character literal": 0.4,
        "unterminated raw string literal": 0.4,
        "unbalanced braces": 0.5,
        "unbalanced closing brace": 0.2,
        "unterminated conditional directive": 0.2,
        "unbalanced #endif": 0.1,
    }
    for problem in dict.fromkeys(problems):
        score -= penalties.get(problem, 0.1)
    approximate = sum(1 for item in functions if item["macro_header"] or item["kr_style"])
    if functions:
        score -= 0.3 * approximate / len(functions)
    if unparsed_from is not None and size:
        score -= 0.5 * (size - unparsed_from) / size
    return round(max(0.0, min(1.0, score)), 4)


def _unreadable(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "path": record["path"],
        "sha256": record.get("sha256", ""),
        "size": int(record.get("size", 0)),
        "language": record.get("language", "c"),
        "is_header": bool(record.get("is_header")),
        "readable": False,
        "parse_confidence": 0.0,
        "parse_problems": ["unreadable"],
        "unparsed_from": None,
        "functions": [],
        "types": [],
        "macros": [],
        "globals": [],
        "includes": [],
        "conditionals": [],
        "dead_spans": [],
    }
