#!/usr/bin/env bash

set -ex

if [ $# -lt 3 ]; then
  echo "Usage: $0 <repo> <branch> <directory>" 1>&2
  exit 2
fi

REPO="$1"
COMMIT="$2"
DIR="$3"

echo "Copy '$COMMIT' from '$REPO' to '$DIR'"
ACTUAL=$(git ls-remote "$REPO" "$COMMIT" | cut -c 1-40 -)
if [ -z "$ACTUAL" ]; then
  # Use this directly on the hope that it works.
  ACTUAL="$COMMIT"
fi
echo "Using commit hash '$ACTUAL'"
if [ -f "$DIR"/.git-copy ]; then
  CURRENT=$(cat "$DIR"/.git-copy)
  if [ "$CURRENT" = "$ACTUAL" ]; then
    echo "Up to date."
    exit
  fi
fi

rm -rf "$DIR"
git init -q "$DIR"
git -C "$DIR" pull -q --depth=1 "$REPO" "$ACTUAL"
git -C "$DIR" rev-parse --verify HEAD > "$DIR"/.git-copy
rm -rf "$DIR"/.git
