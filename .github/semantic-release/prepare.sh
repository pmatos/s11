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

# Full synchronous gate before cutting a release: fmt, build, AArch64
# integration-test binaries, and the full test suite. test.yml runs the
# same checks independently on the same push, but release.yml has no
# ordering dependency on it, so this is the only thing that actually
# stops a broken tree from being tagged and published.
./ci_check.sh

cargo build --release --locked

STAGE="s11-${TAG}-${TARGET}"
rm -rf release-upload
mkdir -p "release-upload/${STAGE}"
cp target/release/s11 README.md LICENSE "release-upload/${STAGE}/"
tar -C release-upload -czf "release-upload/${STAGE}.tar.gz" "${STAGE}"
rm -rf "release-upload/${STAGE:?}"
( cd release-upload && sha256sum ./*.tar.gz > SHA256SUMS.txt )
ls -la release-upload
