"""
Atomic JSON writes with optional .bak rotation and fsync.

Why this exists
  Several modules persist JSON state to STATE_DIR (.sessions.json, .users.json,
  sessions/_index.json, etc.) and each rolled its own tempfile + os.replace
  pattern. As of issue #2 the user records and session records both need the
  same level of crash-safety, so the pattern is centralised here.

Contract
  atomic_write_json(path, data, *, mode=0o600, backup_path=None, fsync=True)
    1. Write `data` (json-serializable) to a uniquely-named tempfile in the
       same directory as `path`.
    2. fsync the tempfile (unless fsync=False).
    3. If `backup_path` is given AND `path` already exists, copy `path` to
       `backup_path` BEFORE the os.replace, so a previous-good copy survives
       the next write.
    4. os.replace tempfile -> path  (atomic on POSIX).
    5. On any failure, the tempfile is removed and the original file is
       untouched.

The helper deliberately does NOT take a lock — callers that need
concurrency guarantees must hold their own lock around it.
"""
from __future__ import annotations

import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def atomic_write_json(
    path: Path,
    data: Any,
    *,
    mode: int = 0o600,
    backup_path: Path | None = None,
    fsync: bool = True,
) -> None:
    """Atomically write `data` as JSON to `path`. See module docstring."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp = tempfile.mkstemp(
        dir=str(path.parent),
        prefix=path.name + '.',
        suffix='.tmp',
    )
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(data, f)
            f.flush()
            if fsync:
                try:
                    os.fsync(f.fileno())
                except OSError:
                    # fsync isn't supported on some FS (tmpfs, network mounts).
                    # The os.replace below is still atomic, just less durable.
                    pass
        os.chmod(tmp, mode)

        if backup_path is not None and path.exists():
            try:
                shutil.copy2(str(path), str(backup_path))
            except OSError as e:
                # A failed backup must not block the main write; the original
                # file is still intact at this point.
                logger.debug("Failed to write backup %s: %s", backup_path, e)

        os.replace(tmp, str(path))
    except Exception:
        # Best-effort cleanup of the orphaned tempfile.
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
