#!/usr/bin/env bash
# Hosted runner only. A pinned private brew prefix; no cask installation.
set -euo pipefail
test -n "$RUNNER_TEMP"
prefix="$RUNNER_TEMP/release-brew"
git clone --quiet --depth 1 --branch 7.0.13 https://github.com/Homebrew/brew "$prefix"
test "$(git -C "$prefix" rev-parse HEAD)" = bc63375ac3a4d6debb1ceb441ae6e22854f0909a
test "$(cat "$prefix/Library/Homebrew/vendor/portable-ruby-version")" = 4.0.9
grep -Fx 'ruby_SHA=43ff285a82f48c84a06d0676a3800815a19d290d32e44182ddd7a6e95478e18e' "$prefix/Library/Homebrew/vendor/portable-ruby-arm64-darwin"
