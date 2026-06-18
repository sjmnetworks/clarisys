"""Crash-safe JSON state-file writes.

Used by ROI metrics, SLO snapshot, Slack state, and decision lifecycle.
The write pattern (temp-file + fsync + os.replace) guarantees that the
target path either reflects the previous good snapshot or the new payload
in full, never a truncated/half-written file. This prevents silent state
loss on power/OOM/SIGKILL during long-running production processes.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def atomic_write_json(
    path: Path,
    payload: Any,
    *,
    indent: int | None = None,
    separators: tuple[str, str] | None = None,
) -> None:
    """Atomically serialise ``payload`` as JSON to ``path``.

    Writes to a unique temp file in the target directory, fsyncs the file,
    then renames over the target. Using a unique temp path avoids same-target
    races when overlapping requests persist the same state file concurrently.
    Caller is responsible for catching exceptions if they want graceful
    degradation; this function does not swallow errors.
    """
    if not isinstance(path, Path):
        raise TypeError(f"path must be a Path, got {type(path).__name__}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise OSError(f"cannot create parent dir {path.parent}: {exc}") from exc
    data = json.dumps(payload, indent=indent, separators=separators)
    fd = -1
    tmp_name = None
    # Write the whole payload first so we never call os.replace with a
    # truncated buffer.
    try:
        fd, tmp_name = tempfile.mkstemp(
            prefix=path.name + ".",
            suffix=".tmp",
            dir=path.parent,
            text=True,
        )
        tmp = Path(tmp_name)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fd = -1
            fh.write(data)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # fsync may not be supported on some filesystems (e.g. certain
                # network mounts). os.replace below is still atomic on POSIX
                # for same-filesystem renames, so we accept this degradation.
                pass
    except OSError as exc:
        if fd >= 0:
            os.close(fd)
        if tmp_name:
            try:
                Path(tmp_name).unlink(missing_ok=True)
            except OSError:
                pass
        raise OSError(f"cannot write to {tmp}: {exc}") from exc
    try:
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise OSError(f"cannot replace {path} (tmp={tmp}): {exc}") from exc
