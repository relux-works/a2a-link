# Sourced by the cask qualification workflow. A pinned Homebrew lives in a throwaway prefix
# under RUNNER_TEMP, with HOME, cache, logs and temp there too, so no runner
# Homebrew, user Homebrew or real home is touched. Needs T, Q, Q0_RESULTS and
# the BREW_TAG / BREW_COMMIT pins from the workflow environment.

q0_brew_setup() {
	export HOME="$T/home"
	export HOMEBREW_CACHE="$T/brew-cache" HOMEBREW_LOGS="$T/brew-logs" HOMEBREW_TEMP="$T/brew-tmp"
	export HOMEBREW_NO_AUTO_UPDATE=1 HOMEBREW_NO_ANALYTICS=1 HOMEBREW_NO_ENV_HINTS=1
	export HOMEBREW_NO_INSTALL_CLEANUP=1 HOMEBREW_NO_INSTALLED_DEPENDENTS_CHECK=1
	mkdir -p "$HOME" "$HOMEBREW_CACHE" "$HOMEBREW_LOGS" "$HOMEBREW_TEMP"
	BREW_PREFIX="$T/brew"
	git clone --quiet --depth 1 --branch "$BREW_TAG" https://github.com/Homebrew/brew "$BREW_PREFIX"
	BREW="$BREW_PREFIX/bin/brew"
	export BREW BREW_PREFIX
	"$Q" check brew-pinned-commit -- test "$(git -C "$BREW_PREFIX" rev-parse HEAD)" = "$BREW_COMMIT"
	"$Q" check brew-pinned-version -- sh -c "'$BREW' --version | tee /dev/stderr | grep -q '^Homebrew $BREW_TAG\$'"
	"$Q" check brew-isolated-prefix -- test "$("$BREW" --prefix)" = "$BREW_PREFIX"
}

# q0_brew_tap CASKFILE: a local tap holding exactly the cask under test.
q0_brew_tap() {
	"$Q" check brew-tap-new -- "$BREW" tap-new --no-git relux-works/q0
	local tap
	tap="$("$BREW" --repository relux-works/q0)"
	mkdir -p "$tap/Casks"
	cp "$1" "$tap/Casks/a2a.rb"
	"$Q" check cask-under-test-unchanged -- cmp "$1" "$tap/Casks/a2a.rb"
}

q0_brew_lint() {
	"$Q" check brew-style -- "$BREW" style --cask relux-works/q0/a2a
	"$Q" check brew-readall-all-os-arch -- "$BREW" readall --os=all --arch=all relux-works/q0
	"$Q" check brew-audit-strict -- "$BREW" audit --cask --strict relux-works/q0/a2a
}

# q0_home_snapshot NAME: the list of every path under the isolated HOME.
q0_home_snapshot() {
	find "$HOME" -print | LC_ALL=C sort >"$T/home-$1.txt"
}

# q0_tamper_negative CASKFILE OS: the same cask with every sha256 zeroed must
# be refused by a checksum mismatch, the intended reason, and leave nothing.
q0_tamper_negative() {
	local tap zero
	tap="$("$BREW" --repository relux-works/q0)"
	zero=0000000000000000000000000000000000000000000000000000000000000000
	sed -e 's/^cask "a2a" do/cask "a2a-tamper" do/' -E -e "s/sha256 \"[0-9a-f]{64}\"/sha256 \"$zero\"/" "$1" >"$tap/Casks/a2a-tamper.rb"
	"$Q" check tamper-cask-has-only-zero-digests -- sh -c "! grep -E 'sha256 \"[0-9a-f]{64}\"' '$tap/Casks/a2a-tamper.rb' | grep -v '$zero'"
	local domain=""
	[ "$2" = linux ] && domain="HOMEBREW_ARTIFACT_DOMAIN=http://127.0.0.1:8765 HOMEBREW_ARTIFACT_DOMAIN_NO_FALLBACK=1"
	"$Q" check install-refuses-wrong-sha256 -- sh -c "if env $domain '$BREW' install --cask relux-works/q0/a2a-tamper >'$T/tamper.log' 2>&1; then cat '$T/tamper.log'; exit 1; fi; cat '$T/tamper.log'; grep -Eqi 'sha.?256 mismatch|checksum.*(mismatch|does not match)' '$T/tamper.log'"
	"$Q" refuse tampered-install-left-no-binary -- test -e "$BREW_PREFIX/bin/a2a"
}
