package daemon

import "testing"

// Proves co-signature files use the same authenticated streaming boundary as envelope files; bare paths remain refused.
func TestCG1CosignatureFileAuthorization(t *testing.T) {
	argv := []string{"post", "!pair:fixture.invalid", "--topic", "$root", "--envelope", "@envelope.json", "--cg1-cosignature", "@cosignature.json", "hello"}
	p, e := Authorize(argv, "alice")
	if e != nil || len(p.Inputs) != 2 {
		t.Fatal("co-signature input was not streamed", p, e)
	}
	for _, index := range []int{5, 7} {
		bad := append([]string{}, argv...)
		bad[index] = "bare-path.json"
		if _, e := Authorize(bad, "alice"); e == nil {
			t.Fatal("bare co-signature/envelope path admitted")
		}
	}
	for _, bad := range [][]string{
		{"post", "!pair:fixture.invalid", "--topic", "$root", "--cg1-cosignature", "@co.json", "hello"},
		{"post", "!pair:fixture.invalid", "--topic", "$root", "--envelope", "@envelope.json", "--cg1-cosignature", "@one.json", "--cg1-cosignature", "@two.json", "hello"},
	} {
		if _, e := Authorize(bad, "alice"); e == nil {
			t.Fatal("unpaired co-signature admitted")
		}
	}

}
