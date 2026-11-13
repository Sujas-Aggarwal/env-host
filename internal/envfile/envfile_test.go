package envfile

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	input := "\ufeff# comment\r\nexport A=first\r\nA='last # literal'\nEMPTY=\nB=\"line\\nnext\" # comment\nC=value#literal # comment\nD=$(do-not-run)\n"
	values, dups, e := Parse(strings.NewReader(input))
	if e != nil {
		t.Fatal(e)
	}
	want := map[string]string{"A": "last # literal", "EMPTY": "", "B": "line\nnext", "C": "value#literal", "D": "$(do-not-run)"}
	for k, v := range want {
		if values[k] != v {
			t.Errorf("%s mismatch", k)
		}
	}
	if len(values) != len(want) || len(dups) != 1 || dups[0] != "A" {
		t.Fatal("incorrect declarations/duplicates")
	}
}
func TestRejectMalformedWithoutValues(t *testing.T) {
	for _, input := range []string{"BAD-NAME=secret-sentinel", "A='secret-sentinel", "A=\"secret-sentinel\" junk", "A=\"secret-sentinel\\q\"", "A=secret-sentinel\x00", "ENVH_PASSPHRASE=secret-sentinel"} {
		_, _, e := Parse(strings.NewReader(input))
		if e == nil {
			t.Errorf("accepted malformed input")
		} else if strings.Contains(e.Error(), "secret-sentinel") {
			t.Fatal("value leaked in error")
		}
	}
}
func FuzzParse(f *testing.F) {
	for _, s := range []string{"A=", "export X='test'", "X=\"a\\n\""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		v, _, e := Parse(strings.NewReader(s))
		if e == nil && Validate(v) != nil {
			t.Fatal("parser returned invalid environment")
		}
	})
}
