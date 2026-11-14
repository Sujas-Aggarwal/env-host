package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRulesAndDirectoryValidation(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "data"), 0700); err != nil {
		t.Fatal(err)
	}
	p, err := Parse("default allow\nallow *.example.com\nblock bad.example.com\nallow 127.0.0.1:8080\nread ./data\n", root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		host, port string
		want       bool
	}{
		{"api.example.com", "443", true},
		{"bad.example.com", "443", false},
		{"example.com", "443", true},
		{"127.0.0.1", "8080", true},
		{"127.0.0.1", "80", false},
	} {
		got, _ := p.Decide(tc.host, tc.port)
		if got != tc.want {
			t.Fatalf("%s:%s allowed=%v, want %v", tc.host, tc.port, got, tc.want)
		}
	}
	physical, err := filepath.EvalSymlinks(filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ReadDirs) != 1 || p.ReadDirs[0] != physical {
		t.Fatalf("wrong read directory: %v", p.ReadDirs)
	}
	for _, text := range []string{"default allow\ndefault block\n", "allow https://example.com\n", "write ./missing\n", "allow example.com:0\n"} {
		if _, err := Parse(text, root); err == nil || !strings.Contains(err.Error(), "policy line") {
			t.Fatalf("accepted malformed policy %q: %v", text, err)
		}
	}
	wildcard, err := Parse("allow *.1.2.3\n", root)
	if err != nil {
		t.Fatal(err)
	}
	if allowed, _ := wildcard.Decide("4.1.2.3", "443"); allowed {
		t.Fatal("domain wildcard allowed an IP literal")
	}
}
