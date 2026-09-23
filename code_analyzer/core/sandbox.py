"""A bubblewrap jail for the one project command v3 ever runs: CMake's configure step.

Only ever reached after a human clicks an approval card (jobs/compile_db_job.py).
Inside the jail the whole filesystem is read-only -- the source tree included --
except one build directory inside the evaluation's workspace and a private
/tmp; there is no network, no view of other processes, and the jail dies with
its parent.  A configure step that tries to write into the source tree, or to
download a dependency, fails, and that failure is the answer: it is recorded,
never worked around.
"""
from __future__ import annotations

import shutil
from pathlib import Path

from ..errors import UserError


def available() -> str | None:
    return shutil.which("bwrap")


def jail(argv: list[str], *, writable: Path, cwd: Path, readable: list[Path] = ()) -> list[str]:
    """The argv that runs ``argv`` inside the jail.  ``writable`` must already exist.

    The jail gets a private, empty /tmp; ``readable`` paths that live under /tmp
    (a source tree unpacked there, the tool's own directory) are bound back
    read-only after it, and ``writable`` last, so it wins wherever it lives.
    """
    bwrap = available()
    if bwrap is None:
        raise UserError("bubblewrap (bwrap) is not installed; the configure step only runs inside it")
    writable = writable.resolve()
    if not writable.is_dir():
        raise UserError(f"the build directory {writable} does not exist")
    rebind: list[str] = []
    for path in sorted({p.resolve() for p in readable}):
        if path.is_relative_to("/tmp") and path.exists():
            rebind += ["--ro-bind", str(path), str(path)]
    return [
        bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", *rebind,
        "--bind", str(writable), str(writable),
        "--unshare-net", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session",
        "--setenv", "HOME", "/tmp", "--chdir", str(cwd.resolve()), "--", *argv,
    ]
