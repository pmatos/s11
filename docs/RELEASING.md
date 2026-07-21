# Releasing s11

Releases are cut automatically by [semantic-release](https://semantic-release.org/),
driven by the [`Release`](../.github/workflows/release.yml) GitHub Actions
workflow. It runs on **every push to `main`**, derives the next version from
[Conventional Commit](https://www.conventionalcommits.org/en/v1.0.0/) types
in the unreleased history, verifies the tree, builds a Linux release binary,
tags the commit, and publishes a GitHub Release with generated notes and a
`CHANGELOG.md` entry. There is no manual bump/draft/prerelease input — the
version and whether a release happens at all are derived entirely from
commit messages (see `.releaserc.json`).

## Cutting a release

1. Merge commits with Conventional Commit prefixes (`feat:`, `fix:`, `perf:`,
   `BREAKING CHANGE:` in the footer, etc.) to `main`. Non-release-worthy
   types (`chore:`, `docs:`, `ci:`, ...) don't trigger a release on their own.
2. That push is all it takes — the `Release` workflow runs automatically.
3. On success you get:
   - a `vX.Y.Z` tag and GitHub Release with generated notes and the build
     artifacts (`s11-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz`, `SHA256SUMS.txt`),
   - an updated `CHANGELOG.md`,
   - a `chore(release): X.Y.Z [skip ci]` commit (pushed back to `main` by
     `@semantic-release/git`) containing the CHANGELOG, `Cargo.toml`, and
     `Cargo.lock` changes. `[skip ci]` prevents this commit from re-triggering
     the release workflow.
4. `workflow_dispatch` is also available (Actions → Release → Run workflow)
   as a manual retry if a release run needs to be re-triggered on the same
   unreleased history — it takes no inputs.

## What the workflow does

1. **Install deps** — `libcapstone-dev`, `z3` + `libz3-dev`,
   `gcc-aarch64-linux-gnu`, `just`, and a stable Rust toolchain (mirrors CI).
2. **Run semantic-release** ([`cycjimmy/semantic-release-action`](https://github.com/cycjimmy/semantic-release-action)),
   which runs the plugin pipeline configured in
   [`.releaserc.json`](../.releaserc.json):
   - `@semantic-release/commit-analyzer` + `@semantic-release/release-notes-generator`
     determine whether a release is due and compute the next version from
     Conventional Commits.
   - `@semantic-release/changelog` updates `CHANGELOG.md`.
   - `@semantic-release/exec` runs [`.github/semantic-release/prepare.sh`](../.github/semantic-release/prepare.sh),
     which bumps `Cargo.toml`/`Cargo.lock` via
     [`scripts/bump-version.sh`](../scripts/bump-version.sh), runs the full
     [`ci_check.sh`](../ci_check.sh) gate (fmt check, build, `build_tests.sh`,
     `cargo test`, `test_all.sh`) to verify the tree, then builds the release
     binary and stages the tarball + `SHA256SUMS.txt`.
   - `@semantic-release/github` creates the GitHub Release and attaches the
     staged artifacts.
   - `@semantic-release/git` commits `CHANGELOG.md`, `Cargo.toml`, and
     `Cargo.lock` back to `main` and tags the release commit as `vX.Y.Z`.
3. **Upload build artifacts** (`if: always()`) — uploads `release-upload/`
   as a workflow artifact for post-mortem/rerun debugging even if a later
   step (e.g. the git push or GitHub publish) fails.

## Artifacts and runtime dependencies

The release tarball contains a dynamically linked `x86_64-unknown-linux-gnu`
binary. It links against the system **Z3** and **Capstone** libraries (the
project builds against `libz3-dev` / `libcapstone-dev`), so the target machine
must have `libz3` and `libcapstone` installed to run it. Verify a download with:

```sh
sha256sum --check SHA256SUMS.txt
```

## Cutting a version locally (without the workflow)

`scripts/bump-version.sh` is standalone and reusable:

```sh
scripts/bump-version.sh patch       # 0.1.0 -> 0.1.1
scripts/bump-version.sh patch       # 0.1.1-dev -> 0.1.1
scripts/bump-version.sh minor       # 0.1.0 -> 0.2.0
scripts/bump-version.sh 1.0.0-rc.1  # explicit version
```

It prints the new version to stdout and edits only the `[package]` version line.
Real releases are still driven by semantic-release (via Conventional Commits
on `main`) so tagging, verification, and note generation stay consistent —
use this script only for local experimentation.
