"""Simulated tools and in-memory world state.

Nothing here touches the real filesystem, network, mail or shell. Every tool is a pure
function over a dictionary, so a model (or an attacker steering it) cannot cause real
side effects, and runs are fully reproducible.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .types import EmailSeed, ExtraTool, ToolSpec, WorldSeed

MAX_RESULT_CHARS = 4000
HOME = "/home/user"


def norm_path(path: str) -> str:
    """Normalise to an absolute POSIX path inside the simulated filesystem."""
    if not path.startswith("/"):
        path = f"{HOME}/{path}"
    return posixpath.normpath(path)


def host_of(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


@dataclass
class SentEmail:
    to: str
    subject: str
    body: str
    cc: str = ""


@dataclass
class World:
    files: dict[str, str] = field(default_factory=dict)
    inbox: list[EmailSeed] = field(default_factory=list)
    web: dict[str, str] = field(default_factory=dict)
    extra: dict[str, ExtraTool] = field(default_factory=dict)
    sent: list[SentEmail] = field(default_factory=list)
    deleted: list[str] = field(default_factory=list)

    @classmethod
    def from_seed(cls, seed: WorldSeed, extra_tools: list[ExtraTool]) -> World:
        return cls(
            files={norm_path(k): v for k, v in seed.files.items()},
            inbox=list(seed.inbox),
            web=dict(seed.web),
            extra={t.name: t for t in extra_tools},
        )


_S = {"type": "string"}


def _schema(props: dict, required: list[str]) -> dict:
    return {"type": "object", "properties": props, "required": required}


BUILTIN: dict[str, ToolSpec] = {
    "read_file": ToolSpec(
        "read_file",
        "Read a text file from the user's computer.",
        _schema({"path": _S}, ["path"]),
        untrusted=True,
    ),
    "list_files": ToolSpec(
        "list_files", "List the files directly inside a directory.", _schema({"path": _S}, ["path"])
    ),
    "write_file": ToolSpec(
        "write_file",
        "Create or overwrite a text file.",
        _schema({"path": _S, "content": _S}, ["path", "content"]),
    ),
    "delete_file": ToolSpec(
        "delete_file", "Permanently delete a file.", _schema({"path": _S}, ["path"])
    ),
    "read_inbox": ToolSpec(
        "read_inbox",
        "List the user's inbox (id, sender, subject).",
        _schema({}, []),
        untrusted=True,
    ),
    "read_email": ToolSpec(
        "read_email", "Read one email by id.", _schema({"id": _S}, ["id"]), untrusted=True
    ),
    "send_email": ToolSpec(
        "send_email",
        "Send an email on the user's behalf.",
        _schema({"to": _S, "subject": _S, "body": _S, "cc": _S}, ["to", "subject", "body"]),
    ),
    "fetch_url": ToolSpec(
        "fetch_url",
        "Fetch a web page over HTTP GET and return its text.",
        _schema({"url": _S}, ["url"]),
        untrusted=True,
    ),
}


def tool_specs(names: list[str], extra: list[ExtraTool]) -> list[ToolSpec]:
    unknown = [n for n in names if n not in BUILTIN]
    if unknown:
        raise ValueError(f"unknown built-in tool(s): {unknown}")
    specs = [BUILTIN[n] for n in names]
    specs += [ToolSpec(t.name, t.description, t.input_schema, untrusted=False) for t in extra]
    return specs


class ToolError(Exception):
    pass


def _need(args: dict, spec: ToolSpec) -> None:
    for key in spec.input_schema.get("required", []):
        if key not in args:
            raise ToolError(f"missing required argument: {key}")
    for key, val in args.items():
        if key in spec.input_schema.get("properties", {}) and not isinstance(val, str):
            raise ToolError(f"argument {key} must be a string")


def execute(world: World, spec: ToolSpec, args: dict) -> str:
    """Run one simulated tool. Raises ToolError for model-visible failures."""
    _need(args, spec)
    name = spec.name
    if name in world.extra:
        return world.extra[name].result
    if name == "read_file":
        path = norm_path(args["path"])
        if path not in world.files:
            raise ToolError(f"No such file: {path}")
        return world.files[path]
    if name == "list_files":
        base = norm_path(args["path"]).rstrip("/") + "/"
        names = sorted({p[len(base) :].split("/")[0] for p in world.files if p.startswith(base)})
        if not names:
            raise ToolError(f"No such directory or empty: {base}")
        return "\n".join(names)
    if name == "write_file":
        world.files[norm_path(args["path"])] = args["content"]
        return "File written."
    if name == "delete_file":
        path = norm_path(args["path"])
        if path not in world.files:
            raise ToolError(f"No such file: {path}")
        del world.files[path]
        world.deleted.append(path)
        return f"Deleted {path}."
    if name == "read_inbox":
        return "\n".join(f"{m.id} | {m.sender} | {m.subject}" for m in world.inbox) or "(empty)"
    if name == "read_email":
        for m in world.inbox:
            if m.id == args["id"]:
                return f"From: {m.sender}\nSubject: {m.subject}\n\n{m.body}"
        raise ToolError(f"No such email: {args['id']}")
    if name == "send_email":
        world.sent.append(SentEmail(args["to"], args["subject"], args["body"], args.get("cc", "")))
        return f"Email sent to {args['to']}."
    if name == "fetch_url":
        url = args["url"]
        if url in world.web:
            return world.web[url]
        raise ToolError(f"404 Not Found: {url}")
    raise ToolError(f"unknown tool: {name}")


def truncate(text: str) -> str:
    if len(text) <= MAX_RESULT_CHARS:
        return text
    return text[:MAX_RESULT_CHARS] + "\n[truncated]"
