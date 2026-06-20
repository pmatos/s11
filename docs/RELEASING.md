# Releasing s11

Releases are cut by the [`Release`](../.github/workflows/release.yml) GitHub
Actions workflow. It is **manually triggered** (`workflow_dispatch`) and must be
run from `main`. The workflow bumps the version, verifies the tree, builds a
Linux release binary, tags the commit, and publishes a GitHub Release with
auto-generated notes.

## Cutting a release

1. Make sure `main` is green and contains everything you want to ship.
2. Go to **Actions → Release → Run workflow** (or `gh workflow run release.yml`).
3. Choose the inputs:

   | Input        | Default | Meaning                                                              |
   | ------------ | ------- | -------------------------------------------------------------------- |
   | `bump`       | `patch` | Semver increment: `patch`, `minor`, or `major`.                      |
   | `version`    | `''`    | Explicit version (e.g. `1.2.3`). Overrides `bump` when set.          |
   | `draft`      | `false` | Publish the GitHub Release as a draft.                               |
   | `prerelease` | `false` | Mark the GitHub Release as a pre-release.                            |

4. Run it. On success you get:
   - a `chore(release): vX.Y.Z` commit and an annotated `vX.Y.Z` tag on `main`,
   - a GitHub Release `vX.Y.Z` with generated notes and the build artifacts,
   - a follow-up `chore: open X.Y.(Z+1)-dev dev cycle` commit (skipped for
     draft / pre-release runs).

## What the workflow does

1. **Validate branch** — refuses to run anywhere but `main`.
2. **Install deps** — `libcapstone-dev`, `z3` + `libz3-dev`,
   `gcc-aarch64-linux-gnu`, `just`, and a stable Rust toolchain (mirrors CI).
3. **Bump version** — [`scripts/bump-version.sh`](../scripts/bump-version.sh)
   rewrites the `[package]` version in `Cargo.toml`.
4. **Verify** — runs [`ci_check.sh`](../ci_check.sh) (fmt check, build,
   `build_tests.sh`, `cargo test`, `test_all.sh`). This also refreshes
   `Cargo.lock` with the new version.
5. **Commit + tag** — commits `Cargo.toml` + `Cargo.lock` and creates an
   annotated tag.
6. **Build + package** — `cargo build --release --locked`, then tars the
   `s11` binary with `README.md` and `LICENSE` into
   `s11-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz` and writes `SHA256SUMS.txt`.
7. **Push + publish** — pushes the bump and tag, then
   `gh release create --generate-notes` attaches the artifacts.
8. **Open next dev cycle** — bumps to `X.Y.(Z+1)-dev` and pushes.

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
scripts/bump-version.sh patch     # 0.1.0 -> 0.1.1
scripts/bump-version.sh minor     # 0.1.0 -> 0.2.0
scripts/bump-version.sh 1.0.0-rc.1  # explicit version
```

It prints the new version to stdout and edits only the `[package]` version line.
Prefer the workflow for real releases so tagging, verification, and note
generation stay consistent.
