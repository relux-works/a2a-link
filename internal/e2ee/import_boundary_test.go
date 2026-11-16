package e2ee

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// forbiddenImport names the library surfaces this package must never import
// (docs/e2ee.md sections 2 and 4): the mautrix network client, the high-level
// crypto package (OlmMachine: network side effects before payload admission and
// the libolm-by-default driver selection), the libolm cgo driver itself and the
// cryptohelper convenience layer. Everything under crypto/goolm/ is the admitted
// pure-Go primitive set, including goolm/libolmpickle, which the U1 adapter uses
// on purpose for explicit pickle codecs.
func forbiddenImport(path string) bool {
	switch {
	case path == "maunium.net/go/mautrix", path == "maunium.net/go/mautrix/crypto":
		return true
	case path == "maunium.net/go/mautrix/crypto/libolm", strings.HasPrefix(path, "maunium.net/go/mautrix/crypto/libolm/"):
		return true
	case path == "maunium.net/go/mautrix/crypto/cryptohelper", strings.HasPrefix(path, "maunium.net/go/mautrix/crypto/cryptohelper/"):
		return true
	}
	return false
}

// Every production file of this package imports the library only through its
// concrete goolm packages, canonicaljson and id; the OlmMachine package, the
// mautrix client, libolm (cgo) and cryptohelper are refused. Controls: the
// predicate flags each forbidden import, admits each allowed one including
// goolm/libolmpickle, and the scan must have seen the actual goolm imports, so
// an empty or unscanned package cannot pass.
func TestImportBoundary(t *testing.T) {
	for _, path := range []string{"maunium.net/go/mautrix", "maunium.net/go/mautrix/crypto", "maunium.net/go/mautrix/crypto/libolm", "maunium.net/go/mautrix/crypto/libolm/internal", "maunium.net/go/mautrix/crypto/cryptohelper"} {
		if !forbiddenImport(path) {
			t.Fatalf("predicate control missed %s", path)
		}
	}
	for _, path := range []string{"maunium.net/go/mautrix/crypto/goolm/pk", "maunium.net/go/mautrix/crypto/goolm/account", "maunium.net/go/mautrix/crypto/goolm/libolmpickle", "maunium.net/go/mautrix/crypto/goolm/crypto", "maunium.net/go/mautrix/crypto/canonicaljson", "maunium.net/go/mautrix/crypto/olm", "maunium.net/go/mautrix/id"} {
		if forbiddenImport(path) {
			t.Fatalf("predicate control refused allowed %s", path)
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatal("no package files scanned", err)
	}
	seenGoolm := false
	scanned := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.ParseFile(token.NewFileSet(), file, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(file, err)
		}
		scanned++
		for _, spec := range parsed.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				t.Fatal(file, err)
			}
			if forbiddenImport(path) {
				t.Fatalf("%s imports forbidden %s", file, path)
			}
			if strings.HasPrefix(path, "maunium.net/go/mautrix/crypto/goolm/") {
				seenGoolm = true
			}
		}
	}
	if scanned == 0 || !seenGoolm {
		t.Fatal("scan control: production goolm imports were not observed")
	}
}
