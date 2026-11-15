#!/usr/bin/env bash
# Real public Homebrew CLI evaluation in a throwaway prefix. No installation,
# archive downloads or tap publication. Each plant changes installer semantics.
set -euo pipefail
T="$RUNNER_TEMP/brew-controls"
mkdir -p "$T/fixture"
go test -p 1 -parallel 2 -c -o "$T/caskbrew.test" ./internal/caskbrew
(cd internal/caskbrew && A2A_BREW_FIXTURE_DIR="$T/fixture" "$T/caskbrew.test" -test.run '^TestWriteBrewEvaluationFixture$' -test.v)
export HOME="$T/home" HOMEBREW_CACHE="$T/cache" HOMEBREW_LOGS="$T/logs" HOMEBREW_TEMP="$T/tmp"
export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1 HOMEBREW_NO_INSTALL_CLEANUP=1
mkdir -p "$HOME" "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$HOMEBREW_TEMP"
git clone --quiet --depth 1 --branch 7.0.13 https://github.com/Homebrew/brew "$T/brew"
test "$(git -C "$T/brew" rev-parse HEAD)" = bc63375ac3a4d6debb1ceb441ae6e22854f0909a
BREW="$T/brew/bin/brew"
"$BREW" --version
"$BREW" tap-new --no-git relux-works/assembly-controls
tap=$("$BREW" --repository relux-works/assembly-controls)
mkdir -p "$tap/Casks"
cp "$T/fixture/a2a.rb" "$tap/Casks/a2a.rb"
"$BREW" trust relux-works/assembly-controls
export A2A_BREW_MANIFEST="$T/fixture/manifest.json" A2A_BREW_PREFIX="$T/brew"
if [ "$(uname -s)" = Darwin ]; then export A2A_BREW_PLATFORM=darwin/arm64; else export A2A_BREW_PLATFORM=linux/amd64; fi
for plant in valid url sha256 version binary-target binary-source unknown-artifact; do
  python3 - "$T/fixture/a2a.rb" "$tap/Casks/a2a.rb" "$plant" <<'PY'
import pathlib,sys
s=pathlib.Path(sys.argv[1]).read_text();p=sys.argv[3]
if p=='url':s=s.replace('https://github.com/relux-works/a2a-swarm/releases/download/', 'https://example.invalid/')
if p=='sha256':
 import re
 s=re.sub(r'sha256 "[0-9a-f]{64}"','sha256 "'+'0'*64+'"',s)
if p=='version':s=s.replace('version "0.1.1"','version "0.1.2"')
if p=='binary-target':s=s.replace('binary "a2a"','binary "a2a", target: "another-target"')
if p=='binary-source':s=s.replace('binary "a2a"','binary "another-source"')
if p=='unknown-artifact':s=s.replace('  binary "a2a"','  manpage "a2a.1"\n  binary "a2a"')
pathlib.Path(sys.argv[2]).write_text(s)
PY
  export A2A_BREW_CASK="$tap/Casks/a2a.rb" A2A_BREW_INFO="$T/info-$plant.json" A2A_BREW_EXPECT_REFUSAL=
  "$BREW" info --cask --json=v2 --variations relux-works/assembly-controls/a2a > "$A2A_BREW_INFO"
  case "$plant" in
    url) export A2A_BREW_EXPECT_REFUSAL=brew-effective-url;;
    sha256) export A2A_BREW_EXPECT_REFUSAL=brew-effective-sha256;;
    version) export A2A_BREW_EXPECT_REFUSAL=brew-effective-metadata;;
    binary-target|binary-source) export A2A_BREW_EXPECT_REFUSAL=brew-effective-binary-target;;
    unknown-artifact) export A2A_BREW_EXPECT_REFUSAL=brew-effective-artifacts;;
  esac
  "$T/caskbrew.test" -test.run '^TestRealBrewEvaluation$' -test.v > "$T/result-$plant.log" 2>&1
  cat "$T/result-$plant.log"
done
