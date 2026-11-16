package originproducer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const plantSharedChecker = `

var plantOnce sync.Once
var plantChecker originChecker
var plantErr error

func plantShared(p *Producer, s cg1.OriginScope) (originChecker, error) {
	plantOnce.Do(func() { plantChecker, plantErr = p.open(s) })
	return plantChecker, plantErr
}
`

// Claim: each opt-in overlay produces its named assertion failure between green controls without changing source; the double-envelope plant produces facts.
func TestOriginProducerPlants(t *testing.T) {
	if os.Getenv("A2A_ORIGIN_PRODUCER_PLANTS") != "1" {
		t.Skip("opt-in origin producer gate-removal plants")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	plants := []struct{ name, file, from, to, extra, pkg, test, witness string }{
		{"grant-check-skipped", "internal/cg1/origin.go",
			"\tif code = originGrantCode(verdict); code != OriginLive { // grant gate\n\t\treturn zero, code\n\t}\n",
			"\t_ = verdict\n", "",
			"./internal/cg1", "^TestOriginCheckGrantRefusals$", "TestOriginCheckGrantRefusals/no-grant"},
		{"validate-returns-cached-verdict", "internal/originproducer/producer.go",
			"fresh, err := s.evaluate(ctx) // fresh validation gate",
			"fresh, err := want, error(nil)", "",
			"./internal/originproducer", "^TestValidateRefusesChangedGrantState$", "TestValidateRefusesChangedGrantState/seal-spent"},
		{"mapping-falls-back-to-launcher-identity", "internal/originproducer/producer.go",
			"\treturn agentEntry{}, refuse(ReasonMappingMissing) // mapping gate\n",
			"\tfallback := m.Agents[0]\n\tfallback.Input = sel.Input\n\treturn fallback, nil\n", "",
			"./internal/originproducer", "^TestOpenRefusesMissingMapping$", "TestOpenRefusesMissingMapping/unmapped-input-principal"},
		{"both-envelope-verifications-removed", "internal/cg1/origin.go",
			"originEnvelopeCode(verifyMatrixEnvelope(", "originEnvelopeCode(plantAcceptEnvelope(",
			"\nfunc plantAcceptEnvelope(_ matrixSettings, _ []byte, _, _ string, _ []byte, _ time.Time, _, _ string, _ []byte) string { return \"accept\" }\n",
			"./internal/cg1", "^TestOriginCheckInnerSignatureInvalid$", "TestOriginCheckInnerSignatureInvalid/forged-author-signature"},
		{"live-consistency-weakened", "internal/cg1/origin.go",
			"v.Decision == grantcheck.Live && !v.Retryable && !v.Closed &&", "v.Decision == grantcheck.Live &&", "",
			"./internal/cg1", "^TestOriginCheckGrantRefusals$", "TestOriginCheckGrantRefusals/retryable-live"},
		{"tip-only-retry-removed", "internal/originproducer/producer.go",
			"if withoutTip == want {", "if false {", "",
			"./internal/originproducer", "^TestValidateTipOnlyChange$", "TestValidateTipOnlyChange"},
		{"connection-binding-removed", "internal/originproducer/producer.go",
			"if !entry.connectionBound(p.owner) {", "if false {", "",
			"./internal/originproducer", "^TestOpenBindsConnection$", "TestOpenBindsConnection/another-account"},
		{"production-constructor-disconnected", "internal/originproducer/producer.go",
			"open: openOwnedChecker", "open: func(cg1.OriginScope) (originChecker, error) { return nil, errMapping }", "",
			"./internal/originproducer", "^TestProductionCheckerComposition$", "TestProductionCheckerComposition"},
		{"construction-cancellation-ignored", "internal/originproducer/producer.go",
			"if ctx.Err() != nil {\n\t\tif checker != nil {", "if false {\n\t\tif checker != nil {", "",
			"./internal/originproducer", "^TestOpenCancellationDuringConstruction$", "TestOpenCancellationDuringConstruction"},
		{"cleanup-failure-ignored", "internal/originproducer/producer.go",
			"if checkerErr != nil || removeErr != nil {", "_ = checkerErr\n\t\t_ = removeErr\n\t\tif false {", "",
			"./internal/originproducer", "^TestCloseReportsScopeRemovalFailure$", "TestCloseReportsScopeRemovalFailure"},
		{"mailbox-kind-ignored", "internal/originproducer/store.go",
			" || entry.Kind != config.MailEvent", "", "",
			"./internal/originproducer", "^TestOpenRefusesNonEventEntry$", "TestOpenRefusesNonEventEntry"},
		{"content-equality-ignored", "internal/originproducer/producer.go",
			"sha256.Sum256(event.Content) != s.digest", "false", "",
			"./internal/originproducer", "^TestRetainedContentReplacement$", "TestRetainedContentReplacement/before-prepare"},
		{"inner-signature-check-removed", "internal/cg1/origin.go",
			"\tif code != OriginLive { // inner request gate\n\t\treturn zero, code\n\t}\n",
			"", "",
			"./internal/cg1", "^TestOriginCheckInnerSignatureInvalid$", "TestOriginCheckInnerSignatureInvalid/forged-author-signature"},
		{"shared-checker-reused", "internal/originproducer/producer.go",
			"checker, err := p.open(owned) // owned checker gate",
			"checker, err := plantShared(p, owned)", plantSharedChecker,
			"./internal/originproducer", "^TestConcurrentSessionsOwnDistinctCheckers$", "TestConcurrentSessionsOwnDistinctCheckers"},
	}
	for _, plant := range plants {
		t.Run(plant.name, func(t *testing.T) {
			source := filepath.Join(root, filepath.FromSlash(plant.file))
			original, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			matches := 1
			if plant.name == "both-envelope-verifications-removed" {
				matches = 2
			}
			if strings.Count(string(original), plant.from) != matches {
				t.Fatal("plant no longer applies the expected number of times")
			}
			output, err := plantCommand(root, "test", plant.pkg, "-run", plant.test, "-count=1", "-v")
			if err != nil {
				t.Fatalf("initial control failed: %v\n%s", err, output)
			}
			t.Logf("before=%s command=go test %s -run %s -count=1 -v exit=0\n%s", plant.name, plant.pkg, plant.test, output)
			mutated := append(bytes.ReplaceAll(original, []byte(plant.from), []byte(plant.to)), []byte(plant.extra)...)
			dir := t.TempDir()
			replacement := filepath.Join(dir, filepath.Base(source))
			if err = os.WriteFile(replacement, mutated, 0600); err != nil {
				t.Fatal(err)
			}
			diff, diffErr := exec.Command("diff", "-u", "--label", plant.file, "--label", plant.file, source, replacement).CombinedOutput()
			if exit, ok := diffErr.(*exec.ExitError); !ok || exit.ExitCode() != 1 {
				t.Fatalf("plant diff failed: %v", diffErr)
			}
			t.Logf("command=diff -u original mutant exit=1\n%s", diff)
			overlay, err := json.Marshal(map[string]any{"Replace": map[string]string{source: replacement}})
			if err != nil {
				t.Fatal(err)
			}
			overlayPath := filepath.Join(dir, "overlay.json")
			if err = os.WriteFile(overlayPath, overlay, 0600); err != nil {
				t.Fatal(err)
			}
			output, err = plantCommand(root, "test", "-overlay", overlayPath, plant.pkg, "-run", plant.test, "-count=1", "-v")
			exit, ok := err.(*exec.ExitError)
			if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "--- FAIL: "+plant.witness) || bytes.Contains(output, []byte("panic:")) || bytes.Contains(output, []byte("build failed")) {
				t.Fatalf("plant needs the intended named failure, err=%v\n%s", err, output)
			}
			if plant.name == "both-envelope-verifications-removed" && !bytes.Contains(output, []byte("refusal carried origin facts")) {
				t.Fatalf("signature plant failed without producing facts:\n%s", output)
			}
			t.Logf("mutant=%s command=go test -overlay overlay.json %s -run %s -count=1 -v sha256=%x exit=1 killed-by=%s\n%s", plant.name, plant.pkg, plant.test, sha256.Sum256(mutated), plant.witness, output)
			output, err = plantCommand(root, "test", plant.pkg, "-run", plant.test, "-count=1", "-v")
			if err != nil {
				t.Fatalf("restored control failed: %v\n%s", err, output)
			}
			t.Logf("restored=%s command=go test %s -run %s -count=1 -v sha256=%x exit=0\n%s", plant.name, plant.pkg, plant.test, sha256.Sum256(original), output)
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(after, original) {
				t.Fatal("plant changed the original source")
			}
		})
	}
}

// plantCommand runs go from the repository root. A2A_ORIGIN_GO_ENV may name an
// absolute environment file that the subprocess sources first, as the upstream
// plant runner allows.
func plantCommand(root string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	var cmd *exec.Cmd
	if envFile := os.Getenv("A2A_ORIGIN_GO_ENV"); envFile != "" {
		// Positional arguments keep paths literal; nothing is interpolated by the shell.
		argv := append([]string{"-c", `. "$1" && shift && exec go "$@"`, "origin-producer-plant", envFile}, args...)
		cmd = exec.CommandContext(ctx, "bash", argv...)
	} else {
		cmd = exec.CommandContext(ctx, "go", args...)
	}
	cmd.Dir = root
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, fmt.Errorf("plant command deadline: %w", ctx.Err())
	}
	return output, err
}
