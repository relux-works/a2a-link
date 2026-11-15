package voice

import (
	"context"
	"os"
	"path/filepath"
	"strings"
)

// workerPaths is the path boundary consumed by the native constructor.
type workerPaths struct {
	model, tokens, data, output string
}

// WithWorkerModel validates the installed pinned model through a held
// directory descriptor and runs inference while that directory remains the
// process cwd. It is for the standalone native worker; shared callers must not
// change their working directory.
func WithWorkerModel(dir, out string, infer func(model, tokens, data, output string) int) int {
	if infer == nil {
		return 1
	}
	return withWorkerModel(dir, out, manifestSHA256, func(paths workerPaths) int {
		return infer(paths.model, paths.tokens, paths.data, paths.output)
	})
}

// voiceOpenModel permits deterministic directory-replacement tests in a child.
var voiceOpenModel = os.Open

// withWorkerModel is only for the dedicated a2a-voice-worker process. Chdir
// must never run in the shared CLI/render process. A directory descriptor binds
// cwd across source renames; revalidate through that cwd before native opens.
// The callback includes native destruction, so cwd lasts for all native use.
// No alias, resource copy, or temporary root is needed, even on native exit(1).
func withWorkerModel(dir, out, manifestPin string, infer func(workerPaths) int) int {
	if dir == "" || out == "" || strings.ContainsRune(dir, 0) || strings.ContainsRune(out, 0) {
		return 1
	}
	// Resolve output against the caller's cwd, not the model directory.
	output, err := filepath.Abs(out)
	if err != nil {
		return 1
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() {
		return 1
	}
	f, err := voiceOpenModel(dir)
	if err != nil {
		return 1
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.IsDir() || !os.SameFile(st, opened) {
		return 1
	}
	if err := f.Chdir(); err != nil {
		return 1
	}
	if err := validateModel(context.Background(), ".", manifestPin); err != nil {
		return 1
	}
	// In particular, never expand DataDir back to the long physical spelling.
	// Its byte length is always 14, independent of config root and TMPDIR.
	return infer(workerPaths{
		model:  "ru_RU-irina-medium.onnx",
		tokens: "tokens.txt",
		data:   "espeak-ng-data",
		output: output,
	})
}
