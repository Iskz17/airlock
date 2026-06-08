"""Defensive extraction of text from tool responses, and recovery of the user's
most recent intent from a Claude Code transcript (JSONL) for re-anchoring.

All functions are best-effort and never raise on malformed input.
"""
from __future__ import annotations

import json
import os


def _read_lines_bounded(path, max_bytes=2000000, head_bytes=0):
    """Read transcript lines without slurping an unbounded file into memory.

    Reads the last `max_bytes` (the recent turns the hot-path hooks care about);
    if `head_bytes` is set and the file is larger, also prepends the first chunk
    so build_trace still sees the original user goal. Never raises."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            head = b""
            if size > max_bytes:
                if head_bytes:
                    head = f.read(head_bytes)
                f.seek(-max_bytes, os.SEEK_END)
                f.readline()  # drop the partial first line after the seek
            tail = f.read()
        data = head + b"\n" + tail if head else tail
        return data.decode("utf-8", "replace").splitlines()
    except OSError:
        return []


def extract_text(tool_response) -> str:
    """Pull model-visible text out of a WebFetch/WebSearch tool_response, which
    may be a str, a {text}/{type,text} dict, or a list of result blocks (incl. the
    real WebSearch shape: results=[{tool_use_id, content:[{title,url,content}]}, "<summary>"])."""
    if tool_response is None:
        return ""
    if isinstance(tool_response, str):
        return tool_response
    if isinstance(tool_response, dict):
        for key in ("text", "content", "result", "output", "body"):
            if key in tool_response:
                return extract_text(tool_response[key])
        if "results" in tool_response:
            return extract_text(tool_response["results"])
        return ""
    if isinstance(tool_response, list):
        parts = []
        for item in tool_response:
            if isinstance(item, dict):
                # Recurse into nested result blocks rather than repr-stringifying them.
                nested = ""
                if isinstance(item.get("content"), (list, dict)):
                    nested = extract_text(item["content"])
                scalar = " ".join(
                    str(item.get(k, "")) for k in ("title", "snippet", "text", "url", "content")
                    if not isinstance(item.get(k), (list, dict))
                ).strip()
                joined = (scalar + ("\n" + nested if nested else "")).strip()
                if joined:
                    parts.append(joined)
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(tool_response)


def latest_user_intent(transcript_path: str, max_chars: int = 600) -> str:
    """Best-effort: the most recent genuine user prose from the transcript, used
    to re-anchor the agent after an injection is detected. Skips tool-result and
    empty turns."""
    if not transcript_path:
        return ""
    lines = _read_lines_bounded(transcript_path)
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "user" or obj.get("role") == "user":
            msg = obj.get("message", obj)
            content = msg.get("content") if isinstance(msg, dict) else None
            text = _content_to_text(content)
            # skip tool-result echoes, but NOT genuine prose that merely starts with '['
            if text and not text.lstrip().startswith("[tool_result"):
                return text[:max_chars]
    return ""


def latest_assistant_text(transcript_path: str, max_chars: int = 20000) -> str:
    """Best-effort: the most recent assistant prose, for the Stop-hook egress scan."""
    if not transcript_path:
        return ""
    lines = _read_lines_bounded(transcript_path)
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "assistant" or obj.get("role") == "assistant":
            msg = obj.get("message", obj)
            content = msg.get("content") if isinstance(msg, dict) else None
            text = _content_to_text(content)
            if text:
                return text[:max_chars]
    return ""


def build_trace(transcript_path: str, max_steps: int = 24, max_chars: int = 2000):
    """Reconstruct an ordered conversation trace for Stage 3 (AlignmentCheck).

    Returns a neutral list of {"role": "user"|"assistant", "content": str} in
    chronological order — the original user goal first, then the agent's turns.
    Dependency-free and never raises; the llamafirewall-specific conversion lives
    in scanners.align(). Tool calls are folded into the assistant turn as a short
    '[calls <tool> with {...}]' note so drift toward an unrequested action shows.
    """
    if not transcript_path:
        return []
    # Keep the head (original user goal) even for very large transcripts.
    lines = _read_lines_bounded(transcript_path, head_bytes=65536)

    steps = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        typ = obj.get("type") or obj.get("role")
        if typ not in ("user", "assistant"):
            continue
        msg = obj.get("message", obj)
        content = msg.get("content") if isinstance(msg, dict) else None
        text = _content_to_text(content)
        actions = _tool_calls_to_text(content)
        if actions:
            text = (text + " " + actions).strip() if text else actions
        if not text:
            continue
        # Skip bare tool-result echoes carried on user turns (not genuine intent).
        if typ == "user" and text.lstrip().startswith("[tool_result"):
            continue
        steps.append({"role": "user" if typ == "user" else "assistant",
                      "content": text[:max_chars]})

    if len(steps) > max_steps:
        # Keep the first step (original goal) + the most recent context.
        steps = steps[:1] + steps[-(max_steps - 1):]
    return steps


def _tool_calls_to_text(content) -> str:
    """Summarize tool_use blocks in an assistant turn as a compact action note."""
    if not isinstance(content, list):
        return ""
    notes = []
    for block in content:
        if isinstance(block, dict) and block.get("type") in ("tool_use", "tool_call"):
            name = block.get("name") or block.get("tool") or "tool"
            inp = block.get("input") or block.get("arguments") or {}
            try:
                rendered = json.dumps(inp, ensure_ascii=False)
            except (TypeError, ValueError):
                rendered = str(inp)
            if len(rendered) > 300:
                rendered = rendered[:297] + "..."
            notes.append("[calls %s with %s]" % (name, rendered))
    return " ".join(notes)


def _content_to_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        out = []
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                out.append(block.get("text", ""))
            elif isinstance(block, str):
                out.append(block)
        return " ".join(out).strip()
    return str(content).strip()
