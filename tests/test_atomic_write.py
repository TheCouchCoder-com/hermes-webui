"""
Unit tests for api._atomic.atomic_write_json

The helper is the foundation for every JSON-state file in STATE_DIR:
  - .sessions.json (auth)
  - .users.json (multi-user RBAC, issue #2)
  - sessions/_index.json
  - workspaces.json, projects.json, settings.json

Crash-safety contract:
  - A successful write produces exactly one well-formed file at the target.
  - A failure during write must NOT leave a truncated file at the target.
  - The temp file used during the write is cleaned up on failure.
  - When a backup_path is given, the previous file content is copied to it
    BEFORE the new content overwrites the target, so the previous-good copy
    survives.
"""
import json
import os
from pathlib import Path

import pytest

from api._atomic import atomic_write_json


def test_writes_json_payload(tmp_path: Path):
    target = tmp_path / 'state.json'
    atomic_write_json(target, {'k': 'v', 'n': [1, 2, 3]})
    assert target.exists()
    assert json.loads(target.read_text(encoding='utf-8')) == {'k': 'v', 'n': [1, 2, 3]}


def test_uses_specified_mode(tmp_path: Path):
    target = tmp_path / 'state.json'
    atomic_write_json(target, {'a': 1}, mode=0o600)
    st_mode = target.stat().st_mode & 0o777
    # On some FS umask masks the mode; assert at least no group/world write.
    assert (st_mode & 0o077) == 0, f"unexpected permission bits: {oct(st_mode)}"


def test_creates_parent_directory(tmp_path: Path):
    target = tmp_path / 'nested' / 'deeper' / 'state.json'
    atomic_write_json(target, {'created': True})
    assert target.exists()


def test_atomic_replace_preserves_original_on_failure(tmp_path: Path, monkeypatch):
    target = tmp_path / 'state.json'
    target.write_text(json.dumps({'old': True}), encoding='utf-8')

    # Force os.replace to fail mid-flight.
    def boom(*args, **kwargs):
        raise OSError("simulated crash during replace")
    monkeypatch.setattr('api._atomic.os.replace', boom)

    with pytest.raises(OSError, match='simulated crash'):
        atomic_write_json(target, {'new': True})

    # Original file content untouched.
    assert json.loads(target.read_text(encoding='utf-8')) == {'old': True}
    # No orphan tempfiles left behind.
    leftover = [p for p in tmp_path.iterdir() if p.name != 'state.json']
    assert leftover == [], f"orphan tempfiles left behind: {leftover}"


def test_backup_path_captures_previous_content(tmp_path: Path):
    target = tmp_path / 'state.json'
    backup = tmp_path / 'state.json.bak'

    atomic_write_json(target, {'gen': 1})
    atomic_write_json(target, {'gen': 2}, backup_path=backup)

    assert json.loads(target.read_text(encoding='utf-8')) == {'gen': 2}
    assert backup.exists(), "backup_path was not written"
    assert json.loads(backup.read_text(encoding='utf-8')) == {'gen': 1}, (
        "backup must contain the previous (gen 1) content, not the new content"
    )


def test_backup_path_skipped_on_first_write(tmp_path: Path):
    target = tmp_path / 'state.json'
    backup = tmp_path / 'state.json.bak'

    # Target doesn't exist yet — backup_path should NOT be created.
    atomic_write_json(target, {'gen': 1}, backup_path=backup)

    assert target.exists()
    assert not backup.exists(), (
        "backup_path must not be created when there's no previous file to back up"
    )


def test_unique_tempfile_avoids_concurrent_collision(tmp_path: Path):
    """Concurrent writers must not clobber each other's tempfiles before the
    os.replace step. atomic_write_json uses tempfile.mkstemp with a unique
    suffix, so two simultaneous writes produce two distinct tempfile names.
    """
    import threading

    target_a = tmp_path / 'a.json'
    target_b = tmp_path / 'b.json'
    errors = []

    def writer(target, payload):
        try:
            for _ in range(20):
                atomic_write_json(target, payload)
        except Exception as e:
            errors.append(e)

    ta = threading.Thread(target=writer, args=(target_a, {'who': 'a'}))
    tb = threading.Thread(target=writer, args=(target_b, {'who': 'b'}))
    ta.start(); tb.start()
    ta.join(); tb.join()

    assert errors == []
    assert json.loads(target_a.read_text(encoding='utf-8')) == {'who': 'a'}
    assert json.loads(target_b.read_text(encoding='utf-8')) == {'who': 'b'}
