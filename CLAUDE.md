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

- The workflow runs daily 06:00 UTC (`schedule: cron`) and on demand
  (`workflow_dispatch`, optional `target_tag` input, optional `mode`
  input — `next` (default) or `latest`). The daily cadence is paired
  with the daily babysitter routine so the fork stays close to upstream.
- Scheduled runs default to `mode: latest`: jump straight to the newest
  un-merged upstream `v*` tag, create `sync/upstream-<tag>`, run
  `git merge --no-ff`, then `pytest`. This keeps the fork no more than a
  day behind upstream's tip instead of crawling one tag at a time (we
  were behind 24/7). Expect bigger conflicts than a single-tag merge —
  the babysitter routine is mandated to resolve them and iterate to green
  (see *Auto-resolve policy*). Manual dispatch can set `mode: next` to
  advance exactly one un-merged tag when you want a small, bisectable
  merge to investigate a specific tag.
- **Clean merge + green tests** → ready-for-review PR with label
  `sync-upstream`.
- **Conflicts or red tests** → the workflow pushes the partial state to a
  draft PR (conflict markers committed) and the babysitter routine then
  picks it up to resolve. The babysitter's mandate is to **make the merge
  happen** — attempt a resolution, validate, iterate to green, and (per
  the *Auto-resolve policy* below) merge it — escalating to a human only
  for the narrow set of genuine judgment calls listed there.

### Merging policy (do not deviate)

- **Always merge**, never `rebase` against upstream. Rebasing would orphan
  every prior merge commit and break the `git tag --no-merged master`
  logic the workflow depends on.
- **Never squash-merge** a sync PR. Keep the merge commit so the next
  sync run sees the correct merge-base.
- **Catch up to the latest tag, not the next one.** The default is a
  single `--no-ff` merge of upstream's newest un-merged tag (`mode:
  latest`), because the fork was perpetually behind merging one tag a
  day. A single merge to the newest tag is fine — `git merge` resolves
  the cumulative diff, and the merge-base stays correct because we still
  record one merge commit against an upstream tag that is on
  `upstream/master`'s history (the `git tag --no-merged master` logic
  only needs that, not per-tag merges). Use `mode: next` (one tag) only
  to isolate a specific tag's conflicts while investigating.

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

### Auto-resolve policy (the babysitter must really try)

The sync babysitter (Claude routine) exists so the fork stays in sync
with upstream **without** the maintainer hand-resolving every conflict.
Its standing mandate: **make the merge happen.** Attempt a best-effort
resolution on every conflict, validate it with the full test suite,
**iterate** when something is off, and escalate to a human **only** when
the right resolution is genuinely a judgment call the babysitter cannot
make. "This file isn't on a list" is *not* a reason to escalate — only
the hard-deny list and the genuine-ambiguity cases below are.

The default posture is **attempt, not escalate.** Work the problem before
handing it back.

#### What to attempt (almost everything)

Attempt a resolution for conflicts in **any** file except the hard-deny
list below. This covers all product code, tests, docs, and config —
whether or not the file is named in the hot-file playbook.

Resolution strategy, in order of preference:

1. **Union / additive** — the common case. Both sides added different
   entries to a list, dict, function, doc, or changelog. **Keep all
   entries from both sides**, preserving order where it matters. Applies
   to docs (`CHANGELOG.md`, `README.md`, `ROADMAP.md`, `TESTING.md`,
   `docs/**`, `.gitignore`) and to most code/test conflicts.
2. **Playbook semantic merge** — for the hot files with known
   fork-vs-upstream tension (`api/auth.py`, `static/login.js`,
   `static/panels.js`, `api/routes.py`, `static/ui.js`, etc.), apply the
   per-file guidance in the *Conflict playbook* above to decide what to
   keep from each side.
3. **Best-effort semantic merge** — for any other code file, reconstruct
   the intent of both changes and combine them so neither side's feature
   is lost. Prefer "ours" for fork-specific behavior (admin/RBAC,
   multi-user, our UI affordances) and "theirs" for new upstream
   features, then reconcile.

After resolving any `/api/*` route conflict, **audit new upstream routes
for whether they need an RBAC gate** (`require_permission(...)` in
`api/helpers.py`), per the playbook.

#### Iterate to green (don't escalate on the first red)

Validation is mandatory and the resolution is not done until the suite is
green:

1. Run `pytest tests/ -q --timeout=60` — full suite. (If a specific test
   file was conflicted, also run it with `-v` first for a fast signal.)
2. If `api/auth.py` was touched, also run the issue-#2 load-bearing
   suites (see *Validation after a sync merge*).
3. **If tests are red, fix the merge and re-run — up to ~3 attempts.**
   A red suite after a merge usually means the resolution dropped a
   change or our code needs a small adaptation to upstream's new shape.
   Legitimate moves: re-resolve the conflict differently; adapt our
   production code to upstream's changed API/signature; port the small
   upstream change our code now depends on. Re-run the full suite after
   each attempt.

Only after a genuine attempt to reach green should escalation be
considered, and only for the cases below.

#### When to escalate (genuine judgment calls only)

Escalate — push the partial state to the draft PR and post a PR comment
explaining the blocker — **only** when one of these is true:

- **Hard-deny file conflicted.** A conflict touches a file on the
  hard-deny list below. These are shipping-, security-, or
  self-corrupting if resolved wrong, so the babysitter never auto-resolves
  them.
- **Deliberately-rejected upstream feature.** Reaching green would
  require **deleting, skipping, or neutering an upstream-added test**, or
  reverting a fork decision. This almost always means upstream tests a
  feature the fork deliberately rejected in an earlier sync (e.g. PR #22 /
  v0.51.59: upstream's `TestUpdateCompareSource` asserts the single-banner
  redesign that PR #21 discarded). Whether to skip the test, port the
  feature, or drop the test is the **maintainer's** call. The PR comment
  must list the failing test names and link the prior sync merge commit
  that rejected the related code.
- **Irreducible ambiguity.** After a real attempt (including the iterate
  loop), the babysitter cannot determine the correct behavior — both
  resolutions are plausible and produce materially different runtime
  behavior, and no test disambiguates. Summarize the two options in the
  PR comment.

If none of these hold, **do not escalate** — finish the resolution.

#### Hard-deny list (always escalate, never auto-resolve)

`CLAUDE.md` (load-bearing meta-config — corrupting this corrupts all
future sync runs), `.github/workflows/**`, `Dockerfile`,
`docker-compose*.yml`, `requirements*.txt`, `setup.py`, `pyproject.toml`,
`.env*`, anything under `secrets/` or matching `*key*`/`*token*`.

Note: upstream edits to `.github/workflows/**` that arrive as a clean
merge (no conflict) are **not** an escalation — the sync workflow already
drops them automatically (the fork runs its own CI; see
`sync-upstream.yml`). The hard-deny entry is about *conflicts* in those
files, which need a human.

#### Auto-merge when green

When the merge is clean (or was cleanly auto-resolved per the policy
above) **and** the full CI on the PR is green, the babysitter **merges
the PR itself** — with a **merge commit** (`gh pr merge --merge`, never
`--squash`, never `--rebase`), then deletes the merged branch. Keeping the
merge commit preserves the merge-base the next sync run depends on. If CI
is not green, or the resolution required escalation, leave the PR for the
maintainer and do not merge.

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
