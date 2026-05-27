# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project orientation

- Python web UI for Hermes (`server.py` + `api/` backend, `static/` frontend).
- Fork of [`nesquena/hermes-webui`](https://github.com/nesquena/hermes-webui); canonical remote is `TheCouchCoder-com/hermes-webui`.
- Released as multi-arch Docker images on GHCR (`ghcr.io/thecouchcoder-com/hermes-webui`) via `.github/workflows/release.yml`, triggered by pushing a `v*` tag.
- Tests run with pytest across Python 3.11–3.13 (`.github/workflows/tests.yml`).
- Runtime version is resolved by `api/updates.py` from `git describe --tags`, falling back to `api/_version.py` (written into the Docker image via the `HERMES_VERSION` build arg).

## Cutting a release

When asked to cut a release, follow these steps:

1. Find the last release tag: `git describe --tags --abbrev=0`.
2. Review what's changed since: `git log <last-tag>..HEAD --oneline` and look at the merged PRs.
3. **Decide the version bump (major / minor / patch) using the rules below — this is your call.**
4. Add a new `## [vX.Y.Z] — YYYY-MM-DD — <title>` section to `CHANGELOG.md`, matching the existing layout (fork entries above the "Fork notice" block, upstream entries below).
5. Commit the changelog entry on `master`.
6. Tag and push:
   ```sh
   git tag vX.Y.Z
   git push origin vX.Y.Z
   ```
7. Done. The release workflow auto-creates the GitHub Release (with auto-generated notes) and publishes multi-arch Docker images to GHCR. **Do not** create the GitHub Release manually.

## Bump decision (your call)

Use semver. When changes mix categories, take the highest-scoring change. When ambiguous, prefer the more conservative bump and explain the reasoning in the changelog entry.

### Major (X) — breaking changes

- Removed or renamed user-facing config keys, env vars, CLI flags, or Docker run args.
- Changed on-disk profile/session layout in a way that won't auto-migrate.
- Removed or incompatibly changed an HTTP API route consumed by the frontend or external clients.
- Removed a feature, provider, or endpoint.
- Minimum Python version bump that drops a previously supported version.

### Minor (Y) — backwards-compatible additions

- New feature, panel, command, or UI affordance.
- New API endpoint, or new optional field on an existing endpoint.
- New provider integration, model support, or locale.
- New opt-in setting or env var (default preserves existing behavior).
- Significant performance change with observable user impact, no interface break.

### Patch (Z) — fixes and internal changes

- Bug fixes that restore intended behavior.
- Refactors with no behavior change.
- Dependency bumps without API impact.
- Documentation, test, or CI changes.
- Small performance tweaks with no observable behavior change.

## Pre-1.0 caveat

The project is currently `v0.51.x`. Strict semver allows breaking changes in minor versions pre-1.0, but this repo's history shows real breakage staying in patch/minor without a 1.0 jump — match the observed style. If a change would be major post-1.0, still call it out explicitly in the changelog entry under a `### Breaking` heading.

## Syncing with upstream

We track `nesquena/hermes-webui` (the project we forked from) using `git
merge`, walking forward one upstream tag at a time. The fork was branched
at `4edcb68` (~v0.51.10); recurring sync is automated by
`.github/workflows/sync-upstream.yml`.

### Cadence and mechanism

- The workflow runs Mondays 06:00 UTC (`schedule: cron`) and on demand
  (`workflow_dispatch`, optional `target_tag` input, optional `mode`
  input — `next` (default) or `latest`).
- Scheduled runs always use `next`: pick the next un-merged upstream
  `v*` tag, create `sync/upstream-<tag>`, run `git merge --no-ff`, then
  `pytest`. Manual dispatch can set `mode: latest` to skip ahead to the
  newest un-merged tag in a single merge — use this only to catch up on
  a backlog, and expect bigger conflicts (the stage-by-stage policy
  below still applies to the default path).
- **Clean merge + green tests** → ready-for-review PR with label
  `sync-upstream`.
- **Conflicts or red tests** → draft PR with the partial state pushed
  (conflict markers are committed so a human or Claude can resolve them
  on the branch).

### Merging policy (do not deviate)

- **Always merge**, never `rebase` against upstream. Rebasing would orphan
  every prior merge commit and break the `git tag --no-merged master`
  logic the workflow depends on.
- **Never squash-merge** a sync PR. Keep the merge commit so the next
  sync run sees the correct merge-base.
- Stage-by-stage: do not batch many tags into one merge unless the
  intermediate tags are pure docs/changelog. Per-tag merges keep
  conflicts small and bisectable.

### Conflict playbook (hot files)

Conflicts concentrate in a small set of files where our fork and upstream
both churn. When resolving:

- **`api/auth.py`** — session schema. Our fork persists
  `_sessions[token] = {"user_id": ..., "expiry": ...}`. If upstream adds
  helpers like `_session_expiry()` / `_session_user_id()` that handle a
  legacy float-only shape, **keep upstream's helpers** and keep our
  dict-shape persistence. Validate with
  `pytest tests/test_issue2_session_schema.py`.
- **`static/login.js`** — both sides have rewritten chunks. Treat as a
  semantic merge: (a) preserve our multi-user mode dispatch;
  (b) make sure upstream's `_clearSavedSession()` / similar
  session-reset calls remain reachable from our code paths. Validate
  with `pytest tests/test_issue2_login_flow.py`.
- **`static/panels.js` / `api/routes.py`** — append-style conflicts.
  Prefer "ours" for our admin / RBAC additions, "theirs" for new
  upstream endpoints. After merge, audit any new upstream `/api/*` route
  for whether it needs an RBAC gate (`require_permission(...)` in
  `api/helpers.py`).
- **`static/ui.js`, `static/index.html`, `static/boot.js`,
  `server.py`, `api/helpers.py`** — usually small, take case-by-case.
- **`CHANGELOG.md`** — conflicts here are expected on almost every sync
  (both sides add entries). Resolution: keep both sets of entries with
  upstream's `## [vX.Y.Z]` block above any of our fork-only entries that
  follow it chronologically. Don't drop upstream's release notes.

### Auto-resolve tiers

Conflicts on a sync PR fall into three tiers. The sync babysitter (Claude
routine) follows these rules; humans should follow the same logic.

**Tier 1 — union-both auto-resolve.** Conflicts are almost always
additive (both sides added different entries to a list, doc, or
changelog). Generic rule: **keep all lines/entries from both sides,
preserving order where it matters**. No per-file judgement required.

Files: `.gitignore`, `CHANGELOG.md`, `ROADMAP.md`, `TESTING.md`,
`README.md`, `docs/**/*.md`.

Exception inside Tier 1: if a Tier 1 file has a *structural* conflict
(not just additive — e.g. upstream rewrote a section we also rewrote),
treat it as Tier 3 and escalate.

**Tier 2 — playbook auto-resolve.** Real semantic conflicts where the
per-file playbook above (hot files: `api/auth.py`, `static/login.js`,
etc.) tells Claude what to keep. Apply the playbook; validate with
`pytest`. Files: `api/auth.py`, `api/routes.py`, `api/helpers.py`,
`static/login.js`, `static/panels.js`, `static/ui.js`,
`static/index.html`, `static/boot.js`, `server.py`.

**Tier 2b — `tests/**` with mandatory green-suite gate.** Test-file
conflicts are usually additive (both sides added unrelated test
classes/functions to the same file). Auto-resolve rule: **union-both,
keeping all test classes and functions from both sides**. Do not edit
test bodies; only remove the conflict markers.

After resolving, validation is **mandatory and stricter than other
tiers** — a green resolution is not enough; the resulting suite must
also be green:

1. Run `pytest <conflicted-test-file> -v` and confirm every test passes.
2. Run the full suite: `pytest tests/ -q --timeout=60`.
3. **If any test fails — including upstream-added tests that fail
   against our fork — escalate to Tier 3.** Do not delete, skip, or
   "fix" failing upstream tests on your own; a fork-vs-upstream test
   failure usually means upstream tests a feature we deliberately
   rejected in an earlier sync (see PR #22 / v0.51.59: upstream's
   `TestUpdateCompareSource` tests assert the single-banner redesign
   that PR #21 explicitly discarded). That judgment call is the
   maintainer's, not the babysitter's.

When escalating from Tier 2b, the PR comment must list the failing
test names and link to the prior sync merge commit that rejected the
related production code, so the maintainer has the context to decide
whether to skip the test, port the feature, or drop the test.

**Tier 3 — always escalate.** Files where being wrong is
shipping-breaking, security-breaking, or self-corrupting. Never
auto-resolve. Open a PR comment summarizing the conflict and pinging the
maintainers.

Files: `CLAUDE.md` (load-bearing meta-config — corrupting this corrupts
all future sync runs), `.github/workflows/**`, `Dockerfile`,
`docker-compose*.yml`, `requirements*.txt`, `setup.py`, `pyproject.toml`,
`.env*`, anything under `secrets/` or matching `*key*`/`*token*`, and
**any file not explicitly named in Tier 1, Tier 2, or Tier 2b**.

### Validation after a sync merge

1. `pytest tests/ -q --timeout=60` — full suite.
2. If `api/auth.py` was touched, the issue-#2 suites are the load-bearing
   regression: `pytest tests/test_issue2_session_schema.py
   tests/test_issue2_login_flow.py
   tests/test_issue2_auth_enabled_after_users.py -v`.
3. Manual smoke: run `python server.py`, log in as a bootstrap user,
   confirm admin panel + profile switcher + sign-out still work.

## Don't

- Don't push tags to forks or non-canonical remotes — the workflow's `if: github.repository == 'TheCouchCoder-com/hermes-webui'` guard skips them, but it produces noise.
- Don't create the GitHub Release manually — the workflow handles it and a manual release will conflict.
- Don't bump a version inside source files. Version comes from `git describe` at runtime and the `HERMES_VERSION` build arg in Docker; there is no `__version__` constant or `VERSION` file to edit.
- Don't `git rebase` the fork onto upstream. Always `git merge` (see *Syncing with upstream*).
- Don't squash-merge a `sync/upstream-*` PR. Keep the merge commit.
