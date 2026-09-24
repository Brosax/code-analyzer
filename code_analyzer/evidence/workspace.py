"""One evaluation's directory, and the append-only ledger that is its truth.

    <data_root>/<eval-id>/
      evaluation.json      source, confidentiality, the pinned model host
      ledger.jsonl         every event that changes state, in order; the truth
      profile/             profile.vN.toml, immutable versions
      buildctx/            buildctx.vN.toml, immutable versions
      calls/Cnnnn-<kind>/  one directory per tool call; native evidence, never overwritten
      index.sqlite         derived: rebuilt from the ledger and calls/ with no network
      exports/

The ledger is written one canonical JSON line at a time, each fsynced, and
read tolerantly: a process killed mid-write leaves at most a torn last line,
which is ignored.  ``reconcile`` closes whatever a killed process left open --
a call that started and never finished is recorded as interrupted, exactly
once -- so opening a workspace after SIGTERM or a crash always yields a
consistent account.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from ..errors import UserError
from ..persist import json_bytes, jsonl_bytes

EVALUATION_FILE = "evaluation.json"
LEDGER_FILE = "ledger.jsonl"
WORKSPACE_VERSION = 1


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


_FILE_LOCKS: dict[str, threading.Lock] = {}
_FILE_LOCKS_GUARD = threading.Lock()


def _file_lock(path: Path) -> threading.Lock:
    """One lock per ledger file for the whole process, however many Workspace objects point at it."""
    key = os.path.realpath(path)
    with _FILE_LOCKS_GUARD:
        return _FILE_LOCKS.setdefault(key, threading.Lock())


class Ledger:
    """Append-only, fsynced, one record per line; ``seq`` is unique and increasing across every writer.

    Every request builds its own Workspace, and a job and the conversation each hold one for minutes, so
    several Ledger objects append to the same file.  A seq counter cached per object let them number on
    independently -- the chat-during-review run of 2026-09-23 wrote seq 49-61 twice and then went back
    from 92 to 62, and the page, which resumes its event stream after the highest id it saw, never showed
    the conversation's next answers.  Now each append holds the file's process-wide lock and an flock
    (a headless run on the same evaluation is another process), and re-reads the highest seq whenever the
    file has grown since this object last wrote.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = _file_lock(path)
        self._seq: int | None = None
        self._size = -1

    def append(self, kind: str, /, **data: Any) -> dict[str, Any]:
        if "kind" in data or "seq" in data or "at" in data:
            raise ValueError("kind, seq and at are the ledger's own fields")
        return self.append_many([(kind, data)])[0]

    def append_many(self, entries: list[tuple[str, dict[str, Any]]]) -> list[dict[str, Any]]:
        """Append several records with one fsync; they share a timestamp."""
        with self._lock, open(self.path, "a+b") as handle:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
            try:
                size = handle.seek(0, os.SEEK_END)
                if self._seq is None or size != self._size:
                    # someone else wrote since: the highest seq, not the last line's (an older file may not be in order)
                    self._seq = max((int(record["seq"]) for record in self.read()), default=0)
                payload = bytearray()
                if size:
                    handle.seek(size - 1)
                    if handle.read(1) != b"\n":
                        payload += b"\n"  # a writer killed mid-line must not take this record down with it
                now = utc_now()
                written = []
                for kind, data in entries:
                    self._seq += 1
                    record = {"seq": self._seq, "at": now, "kind": kind, **data}
                    written.append(record)
                    payload += jsonl_bytes(record)
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
                self._size = handle.tell()
            finally:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            return written

    def read(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        records = []
        for line in self.path.read_bytes().splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue  # a torn last line from a killed writer
            if isinstance(value, dict) and "kind" in value:
                records.append(value)
        return records

    def of(self, *kinds: str) -> list[dict[str, Any]]:
        return [record for record in self.read() if record["kind"] in kinds]


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.ledger = Ledger(root / LEDGER_FILE)

    # -- creation ---------------------------------------------------------------------
    @classmethod
    def create(cls, data_root: Path, source: Path, *, confidentiality: str = "client",
               name: str = "", pin: dict[str, Any] | None = None) -> Workspace:
        if confidentiality not in {"client", "public"}:
            raise UserError("confidentiality must be client or public")
        source = source.expanduser().resolve()
        if not source.is_dir():
            raise UserError(f"source tree {source} is not a directory")
        slug = (name or source.name or "evaluation").replace("/", "-")
        root = data_root.expanduser() / f"{slug}-{uuid.uuid4().hex[:8]}"
        return cls.create_at(root, source, confidentiality=confidentiality, pin=pin)

    @classmethod
    def create_at(cls, root: Path, source: Path, *, confidentiality: str = "client",
                  pin: dict[str, Any] | None = None) -> Workspace:
        source = source.expanduser().resolve()
        if root.exists() and any(root.iterdir()):
            raise UserError(f"{root} already exists and is not empty")
        if root.resolve().is_relative_to(source):
            raise UserError(f"the evaluation directory {root} must not be inside the scanned tree {source}")
        for sub in ("profile", "buildctx", "calls", "exports"):
            (root / sub).mkdir(parents=True, exist_ok=True)
        evaluation = {"workspace_version": WORKSPACE_VERSION, "id": root.name, "source": str(source),
                      "confidentiality": confidentiality, "created_at": utc_now(), "model_pin": pin}
        _atomic(root / EVALUATION_FILE, json_bytes(evaluation))
        workspace = cls(root)
        workspace.ledger.append("evaluation_created", id=root.name, source=str(source),
                                confidentiality=confidentiality)
        return workspace

    @classmethod
    def open(cls, root: Path) -> Workspace:
        root = root.expanduser()
        if not (root / EVALUATION_FILE).is_file():
            raise UserError(f"{root} is not an evaluation directory (no {EVALUATION_FILE})")
        workspace = cls(root)
        workspace.reconcile()
        return workspace

    def pin_model(self, pin: dict[str, Any], *, by: str) -> None:
        """Pin the model host this evaluation's content may go to (a human act, recorded)."""
        evaluation = self.evaluation
        evaluation["model_pin"] = pin
        _atomic(self.root / EVALUATION_FILE, json_bytes(evaluation))
        self.ledger.append("model_pinned", host=pin.get("host"), port=pin.get("port"),
                           addresses=pin.get("addresses"), model=pin.get("model"), by=by)

    def allow_public_model(self, allow: bool, *, by: str) -> None:
        """Let batch jobs of a public evaluation use the third-party model (a human act, recorded)."""
        evaluation = self.evaluation
        if allow and evaluation["confidentiality"] != "public":
            raise UserError("only a public evaluation may use the public model; client code stays on the local GPU")
        evaluation["allow_public_model"] = bool(allow)
        _atomic(self.root / EVALUATION_FILE, json_bytes(evaluation))
        self.ledger.append("public_model_allowed", allow=bool(allow), by=by)

    # -- accessors ---------------------------------------------------------------------
    @property
    def evaluation(self) -> dict[str, Any]:
        return json.loads((self.root / EVALUATION_FILE).read_text(encoding="utf-8"))

    @property
    def source(self) -> Path:
        return Path(self.evaluation["source"])

    @property
    def index_path(self) -> Path:
        return self.root / "index.sqlite"

    def call_directory(self, call_id: str, kind: str) -> Path:
        return self.root / "calls" / f"{call_id}-{kind}"

    def next_call_id(self) -> str:
        started = self.ledger.of("call_started")
        return f"C{len(started) + 1:04d}"

    # -- versioned documents ------------------------------------------------------------
    def save_version(self, kind: str, text: str) -> tuple[int, str]:
        """Write the next immutable ``<kind>.vN.toml``; returns (N, sha256)."""
        directory = self.root / kind
        versions = sorted(int(p.stem.split(".v", 1)[1]) for p in directory.glob(f"{kind}.v*.toml")
                          if p.stem.split(".v", 1)[1].isdigit())
        number = (versions[-1] + 1) if versions else 1
        data = text.encode("utf-8")
        _atomic(directory / f"{kind}.v{number}.toml", data)
        return number, hashlib.sha256(data).hexdigest()

    def version_text(self, kind: str, number: int) -> str:
        return (self.root / kind / f"{kind}.v{number}.toml").read_text(encoding="utf-8")

    # -- consistency ---------------------------------------------------------------------
    def reconcile(self) -> list[str]:
        """Close calls a killed process left open.  Idempotent; returns the call ids it closed."""
        records = self.ledger.read()
        started = [r["call_id"] for r in records if r["kind"] == "call_started"]
        finished = {r["call_id"] for r in records if r["kind"] == "call_finished"}
        closed = []
        for call_id in started:
            if call_id not in finished:
                self.ledger.append("call_finished", call_id=call_id, status="interrupted", exit_code=130,
                                   reconciled=True)
                closed.append(call_id)
        return closed


def _atomic(path: Path, data: bytes) -> None:
    temporary = path.with_name(path.name + ".tmp")
    with open(temporary, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
