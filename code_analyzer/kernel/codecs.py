"""How the canonical conversation is spoken to the model, and how its answer is read back.

The ledger stores one neutral shape -- what the user said, what the agent said
and which tool it called, what the tool returned -- and a codec renders it
for the wire:

* ``NativeToolCodec`` uses the endpoint's own ``tools`` / ``tool_calls``.  It is
  the default: measured 2026-09-22, qwen3.8:27b on Ollama picks the right tool
  with sane arguments, even in parallel.
* ``JsonActionCodec`` is the fallback for an endpoint whose native calling
  fails: prose first, then at the very END of the reply at most one fenced
  ```call block (or a Qwen/Hermes ``<tool_call>``).  Only the tail is looked at,
  so a JSON example the agent shows the user in prose is never mistaken for a
  call -- the generic salvage in harness/schema.py (``_candidates``) would have
  taken any ``{...}`` anywhere, which is exactly the bug this avoids.

Untrusted text (findings, source, ST excerpts) only ever enters a prompt via
``data_block``, which escapes the delimiters a forger would need.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..model.client import DeltaSink, Reply
from ..progress import single_line
from .toolspec import ToolSpec

CALL_FENCE = "```call"
TOOL_CALL_OPEN = "<tool_call>"
TOOL_CALL_CLOSE = "</tool_call>"
_THINK = re.compile(r"<think>.*?</think>", re.S)
_QWEN_FUNCTION = re.compile(r"<function=([^>\s]+)>(.*?)</function>", re.S)
_QWEN_PARAMETER = re.compile(r"<parameter=([^>\s]+)>(.*?)</parameter>", re.S)
MAX_FINDING_CHARS = 240


# -- the canonical conversation ------------------------------------------------------

@dataclass(frozen=True)
class Call:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass(frozen=True)
class UserSaid:
    text: str


@dataclass(frozen=True)
class AgentSaid:
    say: str
    calls: tuple[Call, ...] = ()


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    name: str
    handle: str
    content: str


Entry = UserSaid | AgentSaid | ToolResult


@dataclass(frozen=True)
class Decoded:
    say: str
    calls: tuple[Call, ...] = ()
    problems: tuple[str, ...] = field(default=())


# -- untrusted text --------------------------------------------------------------------

# Every boundary a forged block would need: our DATA fence, both call syntaxes,
# thinking and tool-response tags, and chat-template control tokens.  "<|" and
# "|>" cover ChatML (<|im_start|>, <|im_end|>, <|endoftext|>), Llama-3 and GLM
# markers in one rule; "<｜" is DeepSeek's full-width form.
_DELIMITERS = (("<data", "‹data"), ("</data", "‹/data"), ("```", "ˋˋˋ"),
               ("<tool_call", "‹tool_call"), ("</tool_call", "‹/tool_call"),
               ("<tool_response", "‹tool_response"), ("</tool_response", "‹/tool_response"),
               ("<function=", "‹function="), ("<parameter=", "‹parameter="),
               ("<think", "‹think"), ("</think", "‹/think"),
               ("<|", "‹|"), ("|>", "|›"), ("<｜", "‹｜"))


def escape_untrusted(text: str) -> str:
    """Neutralise every delimiter a forged block would need, keeping the text readable."""
    for needle, replacement in _DELIMITERS:
        text = text.replace(needle, replacement)
    return text


def data_block(content: str, *, source: str, handle: str = "") -> str:
    """Untrusted content, fenced.  Instructions inside it are data, never commands."""
    attrs = f'source="{single_line(source)}"' + (f' handle="{single_line(handle)}"' if handle else "")
    return f'<data {attrs} trust="untrusted">\n{escape_untrusted(content)}\n</data>'


def finding_text(message: str) -> str:
    """One finding's message as it may enter a prompt: one line, bounded, escaped."""
    return escape_untrusted(single_line(message)[:MAX_FINDING_CHARS])


def _result_text(result: ToolResult) -> str:
    return f"[{result.handle} · {result.name}]\n{result.content}"


# -- native ----------------------------------------------------------------------------

class NativeToolCodec:
    name = "native"

    def render(self, system: str, entries: Sequence[Entry], tools: Sequence[ToolSpec]
               ) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
        messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        for entry in entries:
            if isinstance(entry, UserSaid):
                messages.append({"role": "user", "content": entry.text})
            elif isinstance(entry, AgentSaid):
                message: dict[str, Any] = {"role": "assistant", "content": entry.say}
                if entry.calls:
                    message["tool_calls"] = [{
                        "id": call.id, "type": "function",
                        "function": {"name": call.name, "arguments": _canonical(call.arguments)},
                    } for call in entry.calls]
                messages.append(message)
            else:
                messages.append({"role": "tool", "tool_call_id": entry.call_id, "name": entry.name,
                                 "content": _result_text(entry)})
        return messages, [tool.wire() for tool in tools] or None

    def decode(self, reply: Reply) -> Decoded:
        calls: list[Call] = []
        problems: list[str] = []
        for index, raw in enumerate(reply.tool_calls):
            arguments, problem = parse_arguments(raw.arguments)
            if problem:
                problems.append(f"{raw.name}: {problem}")
                continue
            calls.append(Call(raw.id or f"call_{index}", raw.name, arguments))
        return Decoded(reply.text.strip(), tuple(calls), tuple(problems))

    def stream_filter(self, sink: DeltaSink | None) -> DeltaSink | None:
        return sink


# -- JSON action (fallback) ------------------------------------------------------------------

JSON_PROTOCOL = """## 调用工具的格式
需要调用工具时，先写给用户看的话，然后在回复的**最末尾**写一个 call 围栏，里面是一个 JSON 对象：
```call
{"name": "<工具名>", "arguments": {<参数>}}
```
规则：围栏之后不能再有任何文字；每次回复最多一个调用；不需要工具时不要写 call 围栏。
工具结果会以 "[R<编号> · <工具名>]" 开头的用户消息返回。

## 可用工具
"""


class JsonActionCodec:
    name = "json"

    def render(self, system: str, entries: Sequence[Entry], tools: Sequence[ToolSpec]
               ) -> tuple[list[dict[str, Any]], list[dict[str, Any]] | None]:
        catalogue = "\n".join(tool.catalogue_line() for tool in tools)
        messages: list[dict[str, Any]] = [{"role": "system", "content": f"{system}\n\n{JSON_PROTOCOL}{catalogue}"}]
        for entry in entries:
            if isinstance(entry, UserSaid):
                messages.append({"role": "user", "content": entry.text})
            elif isinstance(entry, AgentSaid):
                text = entry.say
                if entry.calls:
                    call = entry.calls[0]
                    text = f"{text}\n{CALL_FENCE}\n" + _canonical({"name": call.name, "arguments": call.arguments}) \
                        + "\n```"
                messages.append({"role": "assistant", "content": text.strip()})
            else:
                # A tool result is a user turn: some chat templates reject a
                # tool role without native calls, and Ollama has answered a
                # conversation ending on one with HTTP 500 "no user query".
                messages.append({"role": "user", "content": _result_text(entry)})
        return messages, None

    def decode(self, reply: Reply) -> Decoded:
        say, raw = extract_call(reply.text)
        if raw is None:
            return Decoded(say)
        call, problem = parse_call(raw)
        if problem:
            return Decoded(say, (), (problem,))
        assert call is not None
        return Decoded(say, (call,))

    def stream_filter(self, sink: DeltaSink | None) -> DeltaSink | None:
        return ProseFilter(sink) if sink else None


def extract_call(text: str) -> tuple[str, str | None]:
    """Split a reply into prose and the raw call at its very end, if any.

    Only a fence that *ends* the reply counts, and its opener must start a
    line.  A fence in the middle of prose -- say, an example the agent shows
    the user -- is prose.
    """
    body = _THINK.sub("", text).rstrip()
    if body.endswith("```") and len(body) > 3:
        head = body[:-3]
        opener = head.rfind(CALL_FENCE)
        if opener != -1 and (opener == 0 or head[opener - 1] == "\n"):
            inner = head[opener + len(CALL_FENCE):]
            if "```" not in inner and (not inner or inner[0] in "\r\n \t"):
                return body[:opener].rstrip(), inner.strip()
    if body.endswith(TOOL_CALL_CLOSE):
        opener = body.rfind(TOOL_CALL_OPEN)
        if opener != -1 and TOOL_CALL_OPEN not in body[opener + len(TOOL_CALL_OPEN):]:
            return body[:opener].rstrip(), body[opener + len(TOOL_CALL_OPEN):-len(TOOL_CALL_CLOSE)].strip()
    return body, None


def parse_call(raw: str) -> tuple[Call | None, str | None]:
    """A call's name and arguments from Hermes JSON or Qwen XML, leniently.

    The XML form is recognised only when the block *starts* with it: a JSON
    call whose string argument happens to contain ``<function=export>`` must
    stay a JSON call, not have its tool name replaced by the argument.
    """
    function = _QWEN_FUNCTION.match(raw.strip())
    if function:
        arguments: dict[str, Any] = {}
        for key, value in _QWEN_PARAMETER.findall(function.group(2)):
            value = value.strip()
            try:
                arguments[key] = json.loads(value)
            except ValueError:
                arguments[key] = value
        return Call("call_0", function.group(1).strip(), arguments), None
    value, problem = _loads(raw)
    if problem:
        return None, f"call block is not valid JSON: {problem}"
    if not isinstance(value, dict):
        return None, "call block must be a JSON object"
    name = value.get("name", value.get("tool"))
    arguments = value.get("arguments", value.get("args", value.get("parameters", {})))
    if isinstance(arguments, str):
        arguments, problem = _loads(arguments or "{}")
        if problem:
            return None, f"arguments are not valid JSON: {problem}"
    if not isinstance(name, str) or not name:
        return None, "call block has no tool name"
    if not isinstance(arguments, dict):
        return None, "arguments must be a JSON object"
    return Call("call_0", name, arguments), None


def parse_arguments(raw: str) -> tuple[dict[str, Any], str | None]:
    value, problem = _loads(raw or "{}")
    if problem:
        return {}, f"arguments are not valid JSON: {problem}"
    if not isinstance(value, dict):
        return {}, "arguments must be a JSON object"
    return value, None


def _loads(text: str) -> tuple[Any, str | None]:
    from ..harness.schema import (
        _drop_trailing_commas,  # noqa: PLC0415 - moves with harness/schema in M9
    )

    try:
        return json.loads(text), None
    except ValueError as first:
        try:
            return json.loads(_drop_trailing_commas(text)), None
        except ValueError:
            return None, str(first)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class ProseFilter:
    """Streams prose to the UI and holds back what may be a call block.

    Mirrors ``extract_call``: a ```call fence counts only at the start of a
    line, a ``<tool_call>`` anywhere.  From a possible opener on, text is
    buffered rather than dropped; if more prose follows the block -- so it was
    not the reply's tail, and ``decode`` will treat it as prose -- the buffer is
    released.  ``flush`` releases whatever is still held unless it is a call.
    """

    def __init__(self, sink: Callable[[str, str], None]) -> None:
        self.sink = sink
        self.text = ""       # everything received
        self.emitted = 0     # how much of it reached the sink

    def __call__(self, kind: str, text: str) -> None:
        if kind != "text":
            self.sink(kind, text)
            return
        self.text += text
        safe = self._safe_end()
        if safe > self.emitted:
            self.sink("text", self.text[self.emitted:safe])
            self.emitted = safe

    def _safe_end(self) -> int:
        """How far the text can be shown without revealing a call block that may end the reply."""
        hold = len(self.text)
        # an opener that is complete, or still being typed at the end
        for opener, line_start in ((CALL_FENCE, True), (TOOL_CALL_OPEN, False)):
            index = self._last_opener(opener, line_start)
            if index is not None and index >= self.emitted:
                hold = min(hold, index)
        return hold

    def _last_opener(self, opener: str, line_start: bool) -> int | None:
        """Where a call block that may end the reply starts, if anywhere: the last complete
        opener (unless prose already followed its closed block), or an opener still being typed."""
        text = self.text
        complete = None
        start = 0
        while (index := text.find(opener, start)) != -1:
            if not line_start or text[:index].rsplit("\n", 1)[-1].strip(" \t") == "":
                complete = index
            start = index + 1
        if complete is not None and self._closed_before_more_prose(complete, opener):
            complete = None
        partial = None
        tail_start = text.rfind("\n") + 1 if line_start else 0
        for size in range(len(opener) - 1, 0, -1):
            if text.endswith(opener[:size]):
                candidate = len(text) - size
                if not line_start or text[tail_start:candidate].strip(" \t") == "":
                    partial = candidate
                break
        found = [index for index in (complete, partial) if index is not None]
        return min(found) if found else None

    def _closed_before_more_prose(self, index: int, opener: str) -> bool:
        """The block starting at ``index`` closed and prose followed: it is not the tail."""
        closer = "```" if opener == CALL_FENCE else TOOL_CALL_CLOSE
        body_start = index + len(opener)
        end = self.text.find(closer, body_start)
        return end != -1 and self.text[end + len(closer):].strip() != ""

    def flush(self) -> None:
        """The stream ended: show held text unless it really is the trailing call."""
        _, raw = extract_call(self.text)
        end = len(self.text)
        if raw is not None:
            say, _ = extract_call(self.text)
            end = min(end, len(say))
        if end > self.emitted:
            self.sink("text", self.text[self.emitted:end])
            self.emitted = end
