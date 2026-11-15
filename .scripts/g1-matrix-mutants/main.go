// g1-matrix-mutants runs only this fork's fixed admission controls using source overlays.
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type edit struct {
	File, Old, New string
	Count          int
}
type plant struct {
	Name, Gate, Package, Test, Fragment string
	Edits                               []edit
}
type result struct {
	Name, Gate, Test, Result, Bound string
	Exit, PID                       int
}

var controlModfile string

const checker = "internal/cg1/matrix_checker.go"
const crypto = "internal/cg1cosign/cosign.go"
const cli = "internal/cli/admission.go"
const live = `admission.Decision{Verdict: admission.Live, Reason: "allowed"}`

func plants() []plant {
	in := func(name string) string { return "TestMatrixInboundRefusals/" + name }
	coerr := "signer, e := c.cosign.Verify(envelope, obj[cg1cosign.ContentKey])\n\tif e != nil {\n\t\treturn matrixDenied()\n\t}"
	fallback := func(condition string) string {
		return "signer, e := c.cosign.Verify(envelope, obj[cg1cosign.ContentKey])\n\tif e != nil && (" + condition + ") { signer = cfg.Pins[sender].Key } else if e != nil { return matrixDenied() }"
	}
	return append([]plant{
		{"s-plus-n-overflow", "pre-parser s<n rejects a bounded 64-byte modulo-order alias", "./internal/cg1cosign", "TestCoSignatureMalleatedScalar", "malleated scalar accepted before verification", []edit{{crypto, `if bytes.Compare(raw[32:], bip340GroupOrder[:]) >= 0 {`, `if false && bytes.Compare(raw[32:], bip340GroupOrder[:]) >= 0 {`, 1}}},
		{"cosignature-replay-key", "one envelope keeps one identity across distinct valid co-signatures", "./internal/cg1", "TestMatrixCosignatureIndependentReplay/in", "co-signature bytes created a second message", []edit{{checker, "import (", "import (\n\t\"crypto/sha256\"\n\t\"encoding/hex\"", 1}, {checker, `key := strings.TrimPrefix(parsed.ID, "sha256:")`, `contentHash := sha256.Sum256(raw); key := hex.EncodeToString(contentHash[:])`, 1}}},
		{"startup-evidence-shapes", "all host evidence is validated before a binding is persisted", "./internal/cg1", "TestMatrixStartupEvidenceShapes/empty-service-root", "invalid envelope evidence admitted at startup", []edit{{"internal/cg1/matrix_config.go", `if !matrixEvidenceShape(cfg.Evidence) {`, `if false && !matrixEvidenceShape(cfg.Evidence) {`, 1}}},
		{"failed-startup-binding", "backend rejection leaves no binding and correction can start", "./internal/cg1", "TestMatrixRejectedStartupCanRecover/agent", "failed startup persisted binding", []edit{{"internal/cg1/matrix_config.go", `core, e := grantcheck.NewForTransport`, `if e = commitMatrixJournal(journal, binding, cfg.InitialWatermark); e != nil { return nil, errConfig }; core, e := grantcheck.NewForTransport`, 1}, {"internal/cg1/matrix_config.go", `if !success {
				_ = os.Remove`, `if false && !success {
				_ = os.Remove`, 1}}},
		{"missing-envelope", "envelope required", "./internal/cg1", in("no-envelope"), "Verdict:0", []edit{{checker, "encoded, ok := obj[matrix.EnvelopeContentKey].(string)\n\tif !ok {\n\t\treturn matrixDenied()\n\t}", "encoded, ok := obj[matrix.EnvelopeContentKey].(string)\n\tif !ok { return " + live + " }", 1}}},
		{"envelope-verifier", "existing Ed25519 verifier required", "./internal/cg1", in("bad-envelope-signature"), "Verdict:0", []edit{{"internal/cg1/matrix_envelope.go", `return verifier.New(c).VerifyMessage(raw).Code`, `return "accept"`, 1}}},
		{"missing-cosignature", "missing co-signature cannot become a pin assertion", "./internal/cg1", in("cosign-missing"), "Verdict:0", []edit{{checker, coerr, fallback("obj[cg1cosign.ContentKey] == nil"), 1}}},
		{"signature-math", "BIP-340 signature equation required", "./internal/cg1", in("cosign-bad"), "Verdict:0", []edit{{crypto, `if !sig.Verify(digest[:], pk) {`, `if false && !sig.Verify(digest[:], pk) {`, 1}}},
		{"exact-envelope-bytes", "co-signature must not trim envelope bytes", "./internal/cg1", in("cosign-different-bytes"), "Verdict:0", []edit{{crypto, `tag := sha256.Sum256([]byte(Domain))`, `envelope = []byte(strings.TrimSpace(string(envelope))); tag := sha256.Sum256([]byte(Domain))`, 1}}},
		{"different-cosigner", "verified key must match the protected peer constraint", "./internal/cg1", in("cosign-different-key"), "Verdict:0", []edit{{checker, `!exists || peer.Key != signer || peer.Author != parsed.Author`, `!exists || peer.Author != parsed.Author`, 1}}},
		{"matrix-id-key-fallback", "a Matrix id cannot replace BIP-340 verification", "./internal/cg1", in("matrix-id-key"), "Verdict:0", []edit{{checker, coerr, "signer, e := c.cosign.Verify(envelope, obj[cg1cosign.ContentKey])\n coObject,_:=obj[cg1cosign.ContentKey].(map[string]any)\n if e != nil && coObject[\"key\"] == sender { signer=cfg.Pins[sender].Key } else if e != nil { return matrixDenied() }", 1}}},
		{"unpinned-to", "signed recipient requires an authenticated pin", "./internal/cg1", "TestMatrixOutboundRefusals/to-unpinned", "Verdict:0", []edit{{checker, "target, exists := cfg.Pins[parsed.To]\n\tif !exists || !validKey(target.Key) {\n\t\treturn matrixDenied()\n\t}", "target, exists := cfg.Pins[parsed.To]\n\tif !exists || !validKey(target.Key) { return " + live + " }", 1}}},
		{"mismatched-to", "actual local recipient must bind signed to", "./internal/cg1", in("to-mismatch"), "Verdict:0", []edit{{checker, `recipient := c.userID`, `recipient := parsed.To`, 1}}},
		{"oversize-proof", "decoded presentation limit is exactly 16384", "./internal/cg1", in("oversize-presentation"), "Verdict:0", []edit{{"internal/cg1/matrix_envelope.go", `grantcheck.MaxPresentationBytes`, `(grantcheck.MaxPresentationBytes+1)`, 2}}},
		{"owner-inbound-bypass", "protected owner inbound remains outside peer admission", "./internal/cli", "TestCG1MatrixOwnerDMBypass", "owner inbound was gated", []edit{{cli, `if p.ownerBypass != nil && p.ownerBypass(ctx, in.RoomID, in.Sender, true) {`, `if false && p.ownerBypass != nil && p.ownerBypass(ctx, in.RoomID, in.Sender, true) {`, 1}}},
		{"owner-outbound-bypass", "protected owner outbound remains outside peer admission", "./internal/cli", "TestCG1MatrixOwnerDMBypass", "owner outbound was gated", []edit{{cli, `if p.ownerBypass != nil && p.ownerBypass(ctx, out.RoomID, "", false) {`, `if false && p.ownerBypass != nil && p.ownerBypass(ctx, out.RoomID, "", false) {`, 1}}},
		{"owner-foreign-sender", "owner route cannot bypass a foreign sender", "./internal/cli", "TestCG1MatrixOwnerDMBypass", "foreign sender bypassed admission", []edit{{cli, `if inbound && sender != pin.Owner {`, `if false && inbound && sender != pin.Owner {`, 1}}},
		{"closed-cosignature-version", "co-signature version is closed", "./internal/cg1cosign", "TestCoSignatureCryptoRefusals/wrong-version", "invalid co-signature accepted", []edit{{crypto, ` || obj["version"] != Version`, ``, 1}}},
		{"closed-cosignature-members", "co-signature members are closed", "./internal/cg1cosign", "TestCoSignatureCryptoRefusals/unknown-field", "invalid co-signature accepted", []edit{{crypto, ` || len(obj) != 3`, ``, 1}}},
		{"wrong-algorithm-refusal", "an Ed25519 key id cannot assert a BIP-340 co-signature", "./internal/cg1cosign", "TestCoSignatureCryptoRefusals/ed25519-id", "invalid co-signature accepted", []edit{{crypto, "if !ok || !strings.HasPrefix(key, \"bip340:\") {\n\t\treturn \"\", ErrInvalid\n\t}", "if !ok || !strings.HasPrefix(key, \"bip340:\") { return \"unverified\", nil }", 1}}},
		{"curve-refusal", "invalid curve points cannot assert a verified key", "./internal/cg1cosign", "TestCoSignatureCryptoRefusals/wrong-curve", "invalid co-signature accepted", []edit{{crypto, "pk, e := schnorr.ParsePubKey(pub)\n\tif e != nil {\n\t\treturn \"\", ErrInvalid\n\t}", "pk, e := schnorr.ParsePubKey(pub)\n\tif e != nil { return key, nil }", 1}}},
		{"scalar-refusal", "canonical scalar encoding is checked before signature math", "./internal/cg1cosign", "TestCoSignatureCanonicalScalar", "noncanonical scalar normalized", []edit{{crypto, `if bytes.Compare(raw[32:], bip340GroupOrder[:]) >= 0 {`, `if false && bytes.Compare(raw[32:], bip340GroupOrder[:]) >= 0 {`, 1}}},
		{"odd-y", "BIP-340 even-y R is required", "./internal/cg1cosign", "TestCoSignatureOddY", "odd-y R accepted", []edit{{crypto, `if !sig.Verify(digest[:], pk) {`, `if false && !sig.Verify(digest[:], pk) {`, 1}}},
		{"daemon-carrier-pair", "station co-signature inputs require exactly one envelope", "./internal/daemon", "TestCG1CosignatureFileAuthorization", "unpaired co-signature admitted", []edit{{"internal/daemon/execution.go", `if p.Command == "post" && cosignatureCount > 0 && (cosignatureCount != 1 || envelopeCount != 1) {`, `if false && p.Command == "post" && cosignatureCount > 0 && (cosignatureCount != 1 || envelopeCount != 1) {`, 1}}},
		{"config-case-alias", "protected config uses exact closed field names", "./internal/cg1", "TestMatrixFactoryConfiguration/alias", "unsafe config accepted", []edit{{"internal/cg1/matrix_config.go", `if !matrixConfigShape(value) {`, `if false && !matrixConfigShape(value) {`, 1}}},
		{"transaction-record", "one transaction cannot switch signed records", "./internal/cg1", "TestMatrixTransactionBinding", "Verdict:0", []edit{{checker, `if knownID != key && known == rec {`, `if false && knownID != key && known == rec {`, 1}}},
		{"post-grant-window", "grant work cannot outlive the envelope window", "./internal/cg1", "TestMatrixRecheckAfterGrant/expired", "Verdict:0", []edit{{checker, `code = verifyMatrixEnvelope(current, envelope, room, recipient, []byte(text), finalNow, finalStamp, parsed.ID, previous)`, `code = "accept"`, 1}}},
		{"replay-event", "an admitted id cannot be replayed as another event", "./internal/cg1", "TestMatrixPresentationAndReplay", "Verdict:0", []edit{{checker, `if seen && prior != rec {`, `if false && seen && prior != rec {`, 1}}},
	}, signedBodyPlants()...)
}
func main() {
	if e := run(); e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
}
func run() error {
	rootFlag := flag.String("root", ".", "repository root")
	identity := flag.Bool("identity", false, "identity expiry/RPC mapping controls (Core witnesses require explicit Core opt-in)")
	corePolicy := flag.Bool("core-policy", false, "genuine Core executor/freshness/provisioning controls (requires explicit Core environment)")
	outFlag := flag.String("out", ".temp/g1-matrix-mutants", "fresh evidence directory under .temp")
	flag.Parse()
	root, e := filepath.Abs(*rootFlag)
	if e != nil {
		return e
	}
	root, e = filepath.EvalSymlinks(root)
	if e != nil {
		return e
	}
	out := *outFlag
	if !filepath.IsAbs(out) {
		out = filepath.Join(root, out)
	}
	out = filepath.Clean(out)
	if !strings.HasPrefix(out, filepath.Join(root, ".temp")+string(os.PathSeparator)) {
		return errors.New("evidence must stay below root/.temp")
	}
	if _, e = os.Stat(out); !os.IsNotExist(e) {
		return errors.New("use a fresh evidence directory")
	}
	if e = os.MkdirAll(out, 0700); e != nil {
		return e
	}
	if *identity && *corePolicy {
		return errors.New("choose one control suite")
	}
	selected := plants()
	if *identity {
		selected = identityPlants()
	}
	if *corePolicy {
		if os.Getenv("CG1_REGTEST") != "1" || os.Getenv("CG1_A2A_BINARY") == "" {
			return errors.New("core-policy requires explicit Core opt-in and a freshly built CG1_A2A_BINARY")
		}
		cmd := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/relux-works/swarma-chain-lab/experiments/grantcheck")
		cmd.Dir = root
		module, err := cmd.Output()
		if err != nil {
			return errors.New("selected grantcheck module unavailable")
		}
		// Go forbids overlays beneath GOMODCACHE. Mirror the exact selected
		// module into this fresh fixture, then replace it only in an alternate
		// modfile. Product go.mod and the downloaded module remain untouched.
		source := strings.TrimSpace(string(module))
		mirror := filepath.Join(out, "grantcheck-source")
		if err = os.CopyFS(mirror, os.DirFS(source)); err != nil {
			return err
		}
		for _, name := range []string{"checker.go", "freshness.go", "provision.go"} {
			original, err := os.ReadFile(filepath.Join(source, name))
			if err != nil {
				return err
			}
			copied, err := os.ReadFile(filepath.Join(mirror, name))
			if err != nil || sha256.Sum256(original) != sha256.Sum256(copied) {
				return errors.New("module mirror differs from selected source")
			}
		}
		mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
		if err != nil {
			return err
		}
		controlModfile = filepath.Join(out, "policy.mod")
		mod = append(mod, []byte("\nreplace github.com/relux-works/swarma-chain-lab/experiments/grantcheck => "+strconv.Quote(filepath.ToSlash(mirror))+"\n")...)
		if err = os.WriteFile(controlModfile, mod, 0600); err != nil {
			return err
		}
		sum, err := os.ReadFile(filepath.Join(root, "go.sum"))
		if err != nil {
			return err
		}
		if err = os.WriteFile(filepath.Join(out, "policy.sum"), sum, 0600); err != nil {
			return err
		}
		relative, err := filepath.Rel(root, mirror)
		if err != nil {
			return err
		}
		selected = policyPlants(relative)
	}
	before := map[string][32]byte{}
	for _, p := range selected {
		for _, ed := range p.Edits {
			path := filepath.Join(root, ed.File)
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			before[path] = sha256.Sum256(b)
		}
	}
	baselineArgs := []string{"test", "-p", "1", "-parallel", "2", "-count=1", "-json", "-timeout=2m", "./internal/cg1", "./internal/cg1cosign", "./internal/cli", "./internal/daemon", "-run", "^(TestMatrix|TestCoSignature|TestFixture|TestCG1Matrix|TestCG1Cosignature)"}
	if *corePolicy {
		baselineArgs = []string{"test", "-p", "1", "-parallel", "2", "-count=1", "-json", "-timeout=2m", "./internal/cg1", "-run", "^TestCoreMatrixPolicy$"}
	}
	if *identity {
		baselineArgs = []string{"test", "-p", "1", "-parallel", "2", "-count=1", "-json", "-timeout=2m", "./internal/cg1", "-run", "^(TestReadNodeRPC.*|TestIdentityExpiredMapping|TestNodeAnswerScope|TestCoreIdentityExpired)$"}
	}
	code, _, e := child(root, out, "baseline", baselineArgs)
	if e != nil || code != 0 {
		return fmt.Errorf("baseline failed exit=%d: %v", code, e)
	}
	results := []result{}
	for _, p := range selected {
		dir := filepath.Join(out, p.Name)
		if e = os.Mkdir(dir, 0700); e != nil {
			return e
		}
		sources := map[string]string{}
		for _, ed := range p.Edits {
			original := filepath.Join(root, ed.File)
			input := original
			if prior, exists := sources[original]; exists {
				input = prior // Compose multiple edits to one file instead of overwriting the earlier plant.
			}
			b, e := os.ReadFile(input)
			if e != nil {
				return e
			}
			text := string(b)
			if n := strings.Count(text, ed.Old); n != ed.Count {
				return fmt.Errorf("%s: anchor count %d, expected %d", p.Name, n, ed.Count)
			}
			text = strings.ReplaceAll(text, ed.Old, ed.New)
			replacement := filepath.Join(dir, filepath.Base(ed.File))
			if e = os.WriteFile(replacement, []byte(text), 0600); e != nil {
				return e
			}
			sources[original] = replacement
		}
		overlay := filepath.Join(dir, "overlay.json")
		b, _ := json.Marshal(map[string]any{"Replace": sources})
		if e = os.WriteFile(overlay, b, 0600); e != nil {
			return e
		}
		parts := strings.Split(p.Test, "/")
		for i, x := range parts {
			parts[i] = "^" + x + "$"
		}
		mask := strings.Join(parts, "/")
		args := []string{"test", "-p", "1", "-parallel", "2", "-count=1", "-json", "-timeout=2m", "-overlay", overlay, p.Package, "-run", mask}
		code, pid, e := child(root, dir, "mutant", args)
		if e != nil {
			return e
		}
		matched, e := intended(filepath.Join(dir, "mutant.jsonl"), p.Test, p.Fragment)
		if e != nil {
			return e
		}
		verdict, bound := "SURVIVED", "No named intended failure; this control does not establish the claimed gate."
		if code == 1 && matched {
			verdict, bound = "KILLED", ""
		}
		results = append(results, result{p.Name, p.Gate, p.Test, verdict, bound, code, pid})
		b, _ = json.MarshalIndent(results, "", "  ")
		if e = os.WriteFile(filepath.Join(out, "results.json"), append(b, '\n'), 0600); e != nil {
			return e
		}
		fmt.Printf("%s %s exit=%d test=%s\n", verdict, p.Name, code, p.Test)
	}
	code, _, e = child(root, out, "restored", baselineArgs)
	if e != nil || code != 0 {
		return fmt.Errorf("restored positive failed exit=%d: %v", code, e)
	}
	for path, want := range before {
		b, e := os.ReadFile(path)
		if e != nil || sha256.Sum256(b) != want {
			return errors.New("source changed during overlays")
		}
	}
	hashes := map[string]string{}
	for p, h := range before {
		hashes[strings.TrimPrefix(p, root+string(os.PathSeparator))] = hex.EncodeToString(h[:])
	}
	b, _ := json.MarshalIndent(hashes, "", "  ")
	if e = os.WriteFile(filepath.Join(out, "source-hashes.json"), append(b, '\n'), 0600); e != nil {
		return e
	}
	for _, r := range results {
		if r.Result != "KILLED" {
			return errors.New("one or more controls survived; see exact bounds in results.json")
		}
	}
	return nil
}
func child(root, out, name string, args []string) (int, int, error) {
	if controlModfile != "" {
		args = append([]string{args[0], "-modfile=" + controlModfile}, args[1:]...)
	}
	stdout, e := os.Create(filepath.Join(out, name+".jsonl"))
	if e != nil {
		return -1, 0, e
	}
	defer stdout.Close()
	stderr, e := os.Create(filepath.Join(out, name+".stderr"))
	if e != nil {
		return -1, 0, e
	}
	defer stderr.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", args...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2")
	if os.Getenv("CG1_REGTEST") == "1" {
		cmd.Env = append(cmd.Env, "CG1_RUN_ROOT="+filepath.Join(out, name+"-core"))
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if e = cmd.Start(); e != nil {
		return -1, 0, e
	}
	pid := cmd.Process.Pid
	fmt.Printf("owned child pid=%d phase=%s\n", pid, name)
	wait := cmd.Wait()
	code := 0
	if wait != nil {
		var ee *exec.ExitError
		if !errors.As(wait, &ee) {
			return -1, pid, wait
		}
		code = ee.ExitCode()
	}
	b, _ := json.Marshal(map[string]any{"pid": pid, "argv": args, "exit": code})
	if e = os.WriteFile(filepath.Join(out, name+"-process.json"), append(b, '\n'), 0600); e != nil {
		return code, pid, e
	}
	if ctx.Err() != nil {
		return code, pid, fmt.Errorf("owned child %d timed out; not a successful control", pid)
	}
	return code, pid, nil
}
func intended(path, test, fragment string) (bool, error) {
	f, e := os.Open(path)
	if e != nil {
		return false, e
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 16384), 1<<20)
	failed, diagnostic := false, false
	for s.Scan() {
		var row struct{ Action, Test, Output string }
		if e = json.Unmarshal(s.Bytes(), &row); e != nil {
			return false, e
		}
		if row.Test == test {
			if row.Action == "fail" {
				failed = true
			}
			if strings.Contains(row.Output, fragment) {
				diagnostic = true
			}
		}
	}
	return failed && diagnostic, s.Err()
}
