/* Login page — multi-mode (issue #2).
 *
 * Three modes:
 *   1. login         — username + password (default)
 *   2. bootstrap     — first-boot: create initial admin (username + new pw + confirm pw)
 *   3. must-change   — post-login: server flagged must_change_password,
 *                      ask for old + new + confirm
 *
 * The form is the same DOM in every mode; we toggle visibility and labels
 * via state to keep the bundle tiny (the file is loaded by /login as a
 * static asset, no build step). Mode is decided by a probe to /api/auth/status.
 */
document.addEventListener('DOMContentLoaded', function () {
  var form = document.getElementById('login-form');
  var usernameInput = document.getElementById('username');
  var pwInput = document.getElementById('pw');
  var pwConfirmInput = document.getElementById('pw_confirm');
  var btn = form ? form.querySelector('button') : null;

  if (!form || !usernameInput || !pwInput) return;

  var invalidCreds = form.getAttribute('data-invalid-pw') || 'Invalid username or password';
  var connFailed = form.getAttribute('data-conn-failed') || 'Connection failed';

  // Mode state. Default to 'login'; flipped to 'bootstrap' on probe success
  // when first_boot=true, or to 'must-change' when login response says so.
  var mode = 'login';

  function showErr(msg) {
    var err = document.getElementById('err');
    if (err) { err.textContent = msg; err.style.display = 'block'; }
  }
  function hideErr() {
    var err = document.getElementById('err');
    if (err) { err.style.display = 'none'; }
  }
  function setBtnText(txt) { if (btn) btn.textContent = txt; }

  function applyMode() {
    hideErr();
    if (mode === 'bootstrap') {
      usernameInput.style.display = '';
      usernameInput.placeholder = 'Choose a username';
      pwInput.style.display = '';
      pwInput.placeholder = 'Choose a password (min 8 chars)';
      pwInput.autocomplete = 'new-password';
      pwConfirmInput.style.display = '';
      pwConfirmInput.placeholder = 'Confirm password';
      setBtnText('Create admin');
    } else if (mode === 'must-change') {
      usernameInput.style.display = 'none';
      pwInput.style.display = '';
      pwInput.placeholder = 'Current password';
      pwInput.autocomplete = 'current-password';
      pwConfirmInput.style.display = '';
      pwConfirmInput.placeholder = 'New password (min 8 chars)';
      setBtnText('Change password');
      // Tertiary "confirm new" — reuse the same field name; we collect via
      // the second form submission step. Keep the UX simple: ask for current,
      // then new, then confirm — but to fit one screen we use only two
      // password fields and validate length.
    } else {
      // login
      usernameInput.style.display = '';
      usernameInput.placeholder = 'Username';
      pwInput.style.display = '';
      pwInput.placeholder = 'Password';
      pwInput.autocomplete = 'current-password';
      pwConfirmInput.style.display = 'none';
    }
  }

  // After any successful auth transition, drop the previous user's last-opened
  // session ID so the app boots into a fresh empty chat (issue #8). Without
  // this, boot.js restores whatever session was in localStorage — including
  // a chat from a previously logged-in profile.
  function _clearSavedSession() {
    try { localStorage.removeItem('hermes-webui-session'); } catch (_) {}
  }

  function _safeNextPath() {
    try {
      var raw = new URL(window.location.href).searchParams.get('next');
      if (!raw) return './';
      if (raw.charAt(0) !== '/') return './';
      if (raw.charAt(1) === '/' || raw.charAt(1) === '\\') return './';
      if (/[\x00-\x1f\x7f\s]/.test(raw)) return './';
      return raw;
    } catch (_) { return './'; }
  }

  async function postJson(url, payload) {
    var res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      credentials: 'include',
    });
    var data = {};
    try { data = await res.json(); } catch (_) {}
    return { ok: res.ok, status: res.status, data: data };
  }

  async function doLogin() {
    var username = usernameInput.value.trim();
    var password = pwInput.value;
    if (!username) return showErr('Username required');
    if (!password) return showErr('Password required');
    var r = await postJson('api/auth/login', { username: username, password: password });
    if (r.ok && r.data && r.data.ok) {
      if (r.data.must_change_password) {
        mode = 'must-change';
        applyMode();
        showErr('Password change required before continuing.');
        pwInput.value = '';
        pwConfirmInput.value = '';
        pwInput.focus();
        return;
      }
      _clearSavedSession();
      window.location.href = _safeNextPath();
    } else {
      showErr((r.data && r.data.error) || invalidCreds);
    }
  }

  async function doBootstrap() {
    var username = usernameInput.value.trim();
    var password = pwInput.value;
    var confirm = pwConfirmInput.value;
    if (!username) return showErr('Username required');
    if (!password || password.length < 8) return showErr('Password must be at least 8 characters');
    if (password !== confirm) return showErr('Passwords do not match');
    var r = await postJson('api/auth/bootstrap', { username: username, password: password });
    if (r.ok && r.data && r.data.ok) {
      _clearSavedSession();
      window.location.href = _safeNextPath();
    } else {
      showErr((r.data && r.data.error) || 'Bootstrap failed');
    }
  }

  async function doChangePassword() {
    var oldPw = pwInput.value;
    var newPw = pwConfirmInput.value;
    if (!oldPw) return showErr('Current password required');
    if (!newPw || newPw.length < 8) return showErr('New password must be at least 8 characters');
    var r = await postJson('api/auth/change_password', { old_password: oldPw, new_password: newPw });
    if (r.ok && r.data && r.data.ok) {
      _clearSavedSession();
      window.location.href = _safeNextPath();
    } else {
      showErr((r.data && r.data.error) || 'Password change failed');
    }
  }

  async function onSubmit(e) {
    e.preventDefault();
    hideErr();
    try {
      if (mode === 'bootstrap') return await doBootstrap();
      if (mode === 'must-change') return await doChangePassword();
      return await doLogin();
    } catch (ex) {
      showErr(connFailed);
    }
  }

  form.addEventListener('submit', onSubmit);
  pwInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); onSubmit(e); } });
  pwConfirmInput.addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); onSubmit(e); } });

  // On page load, probe the server so we can distinguish "can't reach server"
  // (Tailscale off, wrong network) from "session expired / need to log in".
  // Uses /health for connectivity, /api/auth/status for mode.
  // If unreachable, retries every 3 s and auto-reloads once the server is back.
  (function checkConnectivity() {
    var retryTimer = null;
    function setFormDisabled(disabled) {
      usernameInput.disabled = disabled;
      pwInput.disabled = disabled;
      pwConfirmInput.disabled = disabled;
      if (btn) btn.disabled = disabled;
    }
    function probe() {
      fetch('health', { method: 'GET', credentials: 'same-origin' })
        .then(function (r) {
          if (r.ok) {
            if (retryTimer !== null) {
              clearInterval(retryTimer);
              retryTimer = null;
              window.location.reload();
              return;
            }
            // Connectivity OK → ask the server which mode we're in.
            return fetch('api/auth/status', { method: 'GET', credentials: 'include' })
              .then(function (sr) { return sr.json(); })
              .then(function (status) {
                if (status && status.first_boot) {
                  mode = 'bootstrap';
                  applyMode();
                }
              })
              .catch(function () { /* leave mode at default */ });
          }
          showErr(connFailed + ' (server error ' + r.status + ')');
        })
        .catch(function () {
          showErr('Cannot reach server — check your VPN / Tailscale connection.');
          setFormDisabled(true);
          if (retryTimer === null) {
            retryTimer = setInterval(probe, 3000);
          }
        });
    }
    probe();
  })();

  applyMode();
});
