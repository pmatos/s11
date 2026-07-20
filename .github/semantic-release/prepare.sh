#!/usr/bin/env bash
# Invoked by semantic-release (@semantic-release/exec prepareCmd) with the next
# version. Syncs the crate version via the repo's bump script, builds the
# release binary, and stages the tarball + checksums for @semantic-release/github.
set -euo pipefail
VERSION="${1:?usage: prepare.sh <version>}"
TAG="v${VERSION}"
TARGET="${TARGET:-x86_64-unknown-linux-gnu}"

scripts/bump-version.sh "${VERSION}" >/dev/null
cargo update -p s11

# Fast release-time gate: fmt + unit tests. test.yml already runs the full
# suite (incl. AArch64 integration tests) on the same push independently;
# this catches an unformatted/broken tree before a release is cut from it.
cargo fmt -- --check
cargo test --lib --bins

cargo build --release --locked

STAGE="s11-${TAG}-${TARGET}"
rm -rf release-upload
mkdir -p "release-upload/${STAGE}"
cp target/release/s11 README.md LICENSE "release-upload/${STAGE}/"
tar -C release-upload -czf "release-upload/${STAGE}.tar.gz" "${STAGE}"
rm -rf "release-upload/${STAGE:?}"
( cd release-upload && sha256sum ./*.tar.gz > SHA256SUMS.txt )
ls -la release-upload
