package tmuxwake

import (
	"strings"
	"testing"
)

// shortRedraw builds a Claude screen that was redrawn short: history and the
// composer occupy the top rows and the rest of the pane is blank padding.
func shortRedraw(history []string, composer string, pad int, padRow string) string {
	rows := append([]string{}, history...)
	rows = append(rows, "──────────", composer, "──────────", "  ⏵⏵ bypass permissions on (shift+tab to cycle)")
	for i := 0; i < pad; i++ {
		rows = append(rows, padRow)
	}
	return strings.Join(rows, "\n") + "\n"
}

// A composer drawn high above blank padding is classified from the last drawn
// row, as on a full screen. Before the fix the 18-row window held only padding
// and returned layout_unrecognized on every observation (issue #499).
func TestShortRedrawComposerAboveBlankPadding(t *testing.T) {
	history := []string{"⏺ Compacted while idle, before the prompt cache expired", ""}
	row := len(history) + 1
	for _, tc := range []struct {
		name   string
		pad    int
		padRow string
	}{
		{"no padding", 0, ""},
		{"padding below window", 25, ""},
		{"padding with spaces", 25, "                    "},
		{"padding with SGR resets only", 25, "\x1b[0m\x1b[39m"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			screen := shortRedraw(history, "❯ ", tc.pad, tc.padRow)
			if got := assessInput(screen, "claude", 2, row); got != (InputAssessment{InputEmpty, InputReasonNone}) {
				t.Fatalf("short redraw = %+v, want empty", got)
			}
			// The kept rows keep their indexes: a cursor one row lower is refused.
			if got := assessInput(screen, "claude", 2, row+1); got != (InputAssessment{InputUnavailable, InputReasonCursorMismatch}) {
				t.Fatalf("shifted cursor = %+v, want cursor_mismatch", got)
			}
		})
	}
}

// Trimming padding never hides a refusal: busy text, dialogs and drafts on a
// short screen are still refused, and a non-blank row at the very bottom of
// the pane still anchors the window there.
func TestShortRedrawRefusalsSurviveTrim(t *testing.T) {
	row := 1
	for _, tc := range []struct {
		name, screen string
		x, y         int
		want         InputAssessment
	}{
		{"busy marker above composer", shortRedraw([]string{"✻ Working… (esc to interrupt)"}, "❯ ", 30, ""), 2, row + 1, InputAssessment{InputUnavailable, InputReasonBusyOrDialog}},
		{"dialog above composer", shortRedraw([]string{"Do you want to proceed?"}, "❯ ", 30, ""), 2, row + 1, InputAssessment{InputUnavailable, InputReasonBusyOrDialog}},
		{"draft in composer", shortRedraw(nil, "❯ KEEP", 30, ""), 6, row, InputAssessment{InputNonempty, InputReasonInputNonempty}},
		{"busy text on the last pane row", shortRedraw(nil, "❯ ", 30, "") + "Esc to interrupt\n", 2, row, InputAssessment{InputUnavailable, InputReasonBusyOrDialog}},
		{"stray text on the last pane row", shortRedraw(nil, "❯ ", 30, "") + "x\n", 2, row, InputAssessment{InputUnavailable, InputReasonLayoutUnrecognized}},
		{"blank screen", strings.Repeat("\n", 40), 0, 0, InputAssessment{InputUnavailable, InputReasonLayoutUnrecognized}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := assessInput(tc.screen, "claude", tc.x, tc.y); got != tc.want {
				t.Fatalf("assessment = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// screenLines drops only trailing blank rows and keeps every other row,
// including blank rows between content, at its original index.
func TestScreenLinesTrimsOnlyTrailingBlankRows(t *testing.T) {
	got := screenLines("a\n\nb\n \n\x1b[0m\n\n")
	want := []string{"a", "", "b"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("screenLines = %q, want %q", got, want)
	}
	if got := screenLines(""); len(got) != 0 {
		t.Fatalf("empty capture = %q", got)
	}
}

// Codex keeps its raw rows: an owned no-hint prompt followed by a trailing
// blank, space-only or SGR-only separator is still the exact owned notice
// (regression from the first revision, which trimmed that separator away).
// A prompt with no separator and a foreign no-hint prompt stay refused.
func TestCodexOwnedNoHintKeepsTrailingSeparator(t *testing.T) {
	owned := Notice(1)
	prompt := "› " + owned
	for _, tc := range []struct {
		name, screen, owned string
		wantReason          InputReason
		wantText            string
	}{
		{"owned, blank separator", prompt + "\n\n", owned, InputReasonNone, owned},
		{"owned, space separator", prompt + "\n   \n", owned, InputReasonNone, owned},
		{"owned, SGR separator", prompt + "\n\x1b[0m\n", owned, InputReasonNone, owned},
		{"owned, no separator", prompt + "\n", owned, InputReasonLayoutUnrecognized, ""},
		{"foreign no-hint prompt", "› KEEP\n\n", owned, InputReasonLayoutUnrecognized, ""},
		{"neutral, no owned notice", prompt + "\n\n", "", InputReasonLayoutUnrecognized, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b, reason := inputWithNoticeReason(tc.screen, "codex", tc.owned)
			if reason != tc.wantReason || b.Text != tc.wantText {
				t.Fatalf("got %q/%s, want %q/%s", b.Text, reason, tc.wantText, tc.wantReason)
			}
		})
	}
}

// Only Claude trims padding; every other runtime reads the raw rows.
func TestRuntimeLinesTrimsOnlyClaude(t *testing.T) {
	screen := "a\n\n \n"
	if got := runtimeLines(screen, "claude"); len(got) != 1 {
		t.Fatalf("claude rows = %q", got)
	}
	for _, runtime := range []string{"codex", "other"} {
		if got := runtimeLines(screen, runtime); len(got) != 3 {
			t.Fatalf("%s rows = %q", runtime, got)
		}
	}
}
