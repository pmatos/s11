#!/usr/bin/env bash
# Bump the [package] version in Cargo.toml.
#
# Usage:
#   scripts/bump-version.sh <patch|minor|major>     # semver increment
#   scripts/bump-version.sh <X.Y.Z[-suffix]>        # set an explicit version
#
# The new version is printed to stdout (and nothing else), so it can be
# captured directly:  NEW="$(scripts/bump-version.sh patch)"
# All human-facing logging goes to stderr.
#
# Only the first `version = "..."` line (the [package] version) is rewritten;
# dependency version specifiers are inline tables and are left untouched.
set -euo pipefail

MANIFEST="${MANIFEST:-Cargo.toml}"

log() { echo "$@" >&2; }

if [ "$#" -ne 1 ]; then
  log "usage: $0 <patch|minor|major|X.Y.Z[-suffix]>"
  exit 2
fi

if [ ! -f "$MANIFEST" ]; then
  log "error: $MANIFEST not found (run from the repository root)"
  exit 1
fi

current="$(grep -m1 -E '^version = "' "$MANIFEST" | sed -E 's/^version = "([^"]+)".*/\1/')"
if [ -z "$current" ]; then
  log "error: could not find a [package] version in $MANIFEST"
  exit 1
fi

case "$1" in
  patch | minor | major)
    base="${current%%-*}" # drop any pre-release / build suffix
    IFS='.' read -r major minor patch <<EOF
$base
EOF
    if ! [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ && "$patch" =~ ^[0-9]+$ ]]; then
      log "error: current version '$current' is not a plain X.Y.Z; pass an explicit version"
      exit 1
    fi
    case "$1" in
      patch) patch=$((patch + 1)) ;;
      minor)
        minor=$((minor + 1))
        patch=0
        ;;
      major)
        major=$((major + 1))
        minor=0
        patch=0
        ;;
    esac
    new="${major}.${minor}.${patch}"
    ;;
  [0-9]*)
    new="$1"
    if ! [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?(\+[0-9A-Za-z.]+)?$ ]]; then
      log "error: '$new' is not a valid version (expected X.Y.Z, optionally -prerelease and/or +build)"
      exit 2
    fi
    ;;
  *)
    log "error: unknown bump '$1' (expected patch|minor|major or an explicit X.Y.Z)"
    exit 2
    ;;
esac

# Rewrite only the first `version = "..."` line. `$new` is validated above
# (no `/`), and the substitution uses `|` as its delimiter so the replacement
# text can never be mistaken for the end of the s command.
sed -i -E "0,/^version = \"[^\"]+\"/s|^version = \"[^\"]+\"|version = \"${new}\"|" "$MANIFEST"

log "bumped $current -> $new"
echo "$new"
