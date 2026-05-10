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

## Don't

- Don't push tags to forks or non-canonical remotes — the workflow's `if: github.repository == 'TheCouchCoder-com/hermes-webui'` guard skips them, but it produces noise.
- Don't create the GitHub Release manually — the workflow handles it and a manual release will conflict.
- Don't bump a version inside source files. Version comes from `git describe` at runtime and the `HERMES_VERSION` build arg in Docker; there is no `__version__` constant or `VERSION` file to edit.
