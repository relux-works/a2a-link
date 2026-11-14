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
	# Homebrew 7 refuses to load casks from an untrusted tap; the local test tap is trusted explicitly.
	"$Q" check brew-trust-local-tap -- "$BREW" trust relux-works/q0
}

# q0_brew_preseed TOKEN FILE: put FILE where `brew --cache` says this cask's
# download for the current OS lives. Homebrew still verifies its sha256 on
# install. Used on Linux only, where v0.1.1 publishes no Linux assets.
q0_brew_preseed() {
	local dest
	dest="$("$BREW" --cache --cask "relux-works/q0/$1")"
	mkdir -p "$(dirname "$dest")"
	cp "$2" "$dest"
	"$Q" check "preseed-$1-at-brew-cache-path" -- test -s "$dest"
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

# q0_tamper_negative CASKFILE OS [ARCHIVE]: the same cask with every sha256 zeroed must
# be refused by a checksum mismatch, the intended reason, and leave nothing.
q0_tamper_negative() {
	local tap zero
	tap="$("$BREW" --repository relux-works/q0)"
	zero=0000000000000000000000000000000000000000000000000000000000000000
	sed -e 's/^cask "a2a" do/cask "a2a-tamper" do/' -E -e "s/sha256 \"[0-9a-f]{64}\"/sha256 \"$zero\"/" "$1" >"$tap/Casks/a2a-tamper.rb"
	"$Q" check tamper-cask-has-only-zero-digests -- sh -c "! grep -E 'sha256 \"[0-9a-f]{64}\"' '$tap/Casks/a2a-tamper.rb' | grep -v '$zero'"
	# On Linux this negative cannot be executed honestly: v0.1.1 publishes no
	# Linux assets, and Homebrew 7 discards a cached download whose digest does
	# not match and re-fetches it, so the refusal would be a 404, not the
	# checksum. It is recorded as a skip; macOS runs it against the real asset.
	if [ "$2" = linux ]; then
		"$Q" skip install-refuses-wrong-sha256 "Linux: no published Linux asset; Homebrew re-fetches a mismatched cached download (404), so the checksum refusal is only executable on macOS."
		return 0
	fi
	"$Q" check install-refuses-wrong-sha256 -- sh -c "if '$BREW' install --cask relux-works/q0/a2a-tamper >'$T/tamper.log' 2>&1; then cat '$T/tamper.log'; exit 1; fi; cat '$T/tamper.log'; grep -Eqi 'sha.?256 mismatch|checksum.*(mismatch|does not match)|reports different checksum' '$T/tamper.log'"
	"$Q" refuse tampered-install-left-no-binary -- test -e "$BREW_PREFIX/bin/a2a"
}
