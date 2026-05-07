"""Hermes Web UI -- startup helpers."""
from __future__ import annotations
import os, stat, subprocess, sys
from pathlib import Path

# Credential files that should never be world-readable
_SENSITIVE_FILES = (
    '.env',
    'google_token.json',
    'google_client_secret.json',
    '.signing_key',
    'auth.json',
)


def fix_credential_permissions() -> None:
    """Ensure sensitive files in HERMES_HOME have safe permissions.

    Respects:
      - HERMES_SKIP_CHMOD=1  → bypass entirely
      - HERMES_HOME_MODE     → group bits are allowed if set by the operator,
                               only world-readable/world-writable files are fixed
    """
    if os.environ.get('HERMES_SKIP_CHMOD', '').strip() in ('1', 'true'):
        return

    # Parse operator-declared mode to know if group bits are intentional
    declared_mode = None
    raw_mode = os.environ.get('HERMES_HOME_MODE', '').strip()
    if raw_mode:
        try:
            declared_mode = int(raw_mode, 8)
        except ValueError:
            pass

    hermes_home = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))
    if not hermes_home.is_dir():
        return
    for name in _SENSITIVE_FILES:
        fpath = hermes_home / name
        if not fpath.exists():
            continue
        try:
            current = stat.S_IMODE(fpath.stat().st_mode)
            # If operator declared a mode, allow group bits but still fix world bits
            if declared_mode is not None:
                if current & 0o007:  # other bits set (world-readable/writable)
                    fpath.chmod(current & ~0o007)
                    print(f'  [security] removed world bits on {fpath.name} ({oct(current)} -> {oct(current & ~0o007)})', flush=True)
            else:
                if current & 0o077:  # group or other bits set
                    fpath.chmod(0o600)
                    print(f'  [security] fixed permissions on {fpath.name} ({oct(current)} -> 0600)', flush=True)
        except OSError:
            pass  # best-effort; don't abort startup


def _agent_dir() -> Path | None:
    hermes_home = Path(os.environ.get('HERMES_HOME', str(Path.home() / '.hermes')))
    for raw in [os.environ.get('HERMES_WEBUI_AGENT_DIR', '').strip(), str(hermes_home / 'hermes-agent')]:
        if not raw:
            continue
        p = Path(raw).expanduser()
        if p.is_dir():
            return p.resolve()
    return None

def _trusted_agent_dir(agent_dir: Path) -> bool:
    """Return True if agent_dir passes ownership and permission checks.

    Validates that the directory is not world- or group-writable and,
    on POSIX systems, is owned by the current process user.

    Intentionally does NOT enforce a canonical path (i.e. does not require
    the dir to be ~/.hermes/hermes-agent), so custom HERMES_WEBUI_AGENT_DIR
    paths work correctly when HERMES_WEBUI_AUTO_INSTALL=1 is set.
    """
    try:
        st = agent_dir.stat()
        if stat.S_IMODE(st.st_mode) & 0o022:
            # World- or group-writable — untrusted
            return False
        if hasattr(os, 'getuid') and st.st_uid != os.getuid():
            # Not owned by current user (POSIX only; Windows fallback skips)
            return False
        return True
    except OSError:
        return False


def auto_install_agent_deps() -> bool:
    enabled = os.environ.get('HERMES_WEBUI_AUTO_INSTALL', '').strip().lower() in ('1', 'true', 'yes')
    if not enabled:
        print('[!!] Auto-install disabled. Set HERMES_WEBUI_AUTO_INSTALL=1 to enable.', flush=True)
        return False
    agent_dir = _agent_dir()
    if agent_dir is None:
        print('[!!] Auto-install skipped: agent directory not found.', flush=True)
        return False
    if not _trusted_agent_dir(agent_dir):
        print('[!!] Auto-install skipped: agent directory failed trust check (check ownership/permissions).', flush=True)
        return False
    req_file = agent_dir / 'requirements.txt'
    pyproject = agent_dir / 'pyproject.toml'
    if req_file.exists():
        install_args = [sys.executable, '-m', 'pip', 'install', '--quiet', '-r', str(req_file)]
        print(f'     Installing from {req_file} ...', flush=True)
    elif pyproject.exists():
        install_args = [sys.executable, '-m', 'pip', 'install', '--quiet', str(agent_dir)]
        print(f'     Installing from {agent_dir} (pyproject.toml) ...', flush=True)
    else:
        print('[!!] Auto-install skipped: no requirements.txt or pyproject.toml in agent dir.', flush=True)
        return False
    try:
        result = subprocess.run(install_args, capture_output=True, text=True, timeout=120)
        if result.returncode != 0:
            print(f'[!!] pip install failed (exit {result.returncode}):', flush=True)
            for line in (result.stderr or '').splitlines()[-10:]:
                print(f'     {line}', flush=True)
            return False
        print('[ok] pip install completed.', flush=True)
        return True
    except subprocess.TimeoutExpired:
        print('[!!] Auto-install timed out after 120s.', flush=True)
        return False
    except Exception as e:
        print(f'[!!] Auto-install error: {e}', flush=True)
        return False


# ── Multi-user RBAC migration (issue #2) ────────────────────────────────────

def run_first_boot_migration() -> dict:
    """One-time migration from single-shared-password to multi-user records.

    States and actions (per issue #2 §3, locked-in decisions):

      .users.json exists & validates           → no-op
      .users.json missing,
      settings.json has password_hash,         → auto-create one admin user
      HERMES_WEBUI_PASSWORD env var NOT set      named 'admin' with that hash,
                                                 strip password_hash from settings
      .users.json missing,
      HERMES_WEBUI_PASSWORD env var IS set     → leave alone (legacy fallback);
                                                 manual upgrade required
      .users.json missing,
      no legacy password configured            → 'first_boot' state — UI offers
                                                 the bootstrap form
      .users.json malformed                    → handled by api.users._load_from_disk
                                                 (logs + falls back to .bak or empty)

    Returns a status dict for logging / tests:
      {action: <str>, admin_username: <str|None>, first_boot: <bool>}

    Called from server.py at startup. Idempotent: subsequent boots find
    .users.json populated and become no-ops.
    """
    from api import users as users_mod
    from api.config import load_settings

    status = {'action': 'noop', 'admin_username': None, 'first_boot': False}

    # Already migrated?
    if users_mod.has_users():
        status['action'] = 'already_migrated'
        return status

    legacy_env = os.environ.get('HERMES_WEBUI_PASSWORD', '').strip()
    if legacy_env:
        # Env-var deployments stay on the legacy single-password path during
        # the transition. Operators upgrade manually: unset the env var,
        # restart, walk through the bootstrap form. See issue #2 §9.2.
        status['action'] = 'env_var_legacy_preserved'
        return status

    settings = load_settings()
    legacy_hash = (settings.get('password_hash') or '').strip()
    if legacy_hash:
        # Upgrade path: copy the existing hash byte-for-byte into a new admin
        # user named 'admin', strip it from settings.json so there's a single
        # source of truth going forward.
        try:
            users_mod.create_user(
                username='admin',
                password='',                   # ignored when password_hash is set
                role='admin',
                assigned_profile='default',
                password_hash=legacy_hash,
                allowed_profiles=None,
                permissions={},
            )
        except Exception as e:
            print(f'[migration] Failed to create admin from legacy hash: {e}', flush=True)
            status['action'] = 'upgrade_failed'
            return status

        try:
            from api.config import save_settings
            settings.pop('password_hash', None)
            save_settings(settings)
        except Exception as e:
            # The user record is already correct; the leftover hash in
            # settings.json is harmless because get_password_hash() reads
            # env first then settings, but log loudly so operators know
            # something went sideways.
            print(f'[migration] Failed to clear password_hash from settings.json: {e}', flush=True)

        print('[migration] Upgraded to multi-user: created admin user from legacy password', flush=True)
        status['action'] = 'upgraded'
        status['admin_username'] = 'admin'
        return status

    # Truly fresh install. The login page enters bootstrap mode.
    status['action'] = 'first_boot'
    status['first_boot'] = True
    return status


def cleanup_legacy_sessions() -> int:
    """Drop session records that have no user_id binding. Run once at
    startup after run_first_boot_migration. Issue #2 design: legacy
    sessions can't be revoked when a user is deleted, so we force a
    one-time re-login at upgrade. Returns count removed."""
    try:
        from api.auth import drop_unbound_legacy_sessions
        return drop_unbound_legacy_sessions()
    except Exception as e:
        print(f'[migration] cleanup_legacy_sessions failed: {e}', flush=True)
        return 0


def is_first_boot() -> bool:
    """True iff the server has no users configured AND no legacy env-var
    password (so /login should render the bootstrap form). Used by
    /api/auth/status and the bootstrap endpoint."""
    legacy_env = os.environ.get('HERMES_WEBUI_PASSWORD', '').strip()
    if legacy_env:
        return False
    try:
        from api import users as users_mod
        return not users_mod.has_users()
    except Exception:
        return False
