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
