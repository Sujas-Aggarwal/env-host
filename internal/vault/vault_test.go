package vault

import (
	"bytes"
	"encoding/json"
	"env-host/internal/project"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptionAuthenticationAndProjectBinding(t *testing.T) {
	s := &Store{Dir: t.TempDir()}
	a, b := project.NewID(), project.NewID()
	pass := "fixture passphrase"
	values := map[string]string{"TOKEN": "unique-synthetic-canary", "EMPTY": ""}
	if e := s.Save(a, pass, "/fixture", values); e != nil {
		t.Fatal(e)
	}
	path, _ := s.path(a)
	disk, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(disk, []byte(values["TOKEN"])) || bytes.Contains(disk, []byte(a)) || bytes.Contains(disk, []byte(pass)) {
		t.Fatal("plaintext credential/ID persisted")
	}
	got, root, e := s.Load(a, pass)
	if e != nil || root != "/fixture" || got["TOKEN"] != values["TOKEN"] {
		t.Fatal("round trip failed", e)
	}
	if _, ok := got["EMPTY"]; !ok {
		t.Fatal("empty entry lost")
	}
	if _, _, e = s.Load(a, "wrong password"); e != ErrAuth {
		t.Fatal("wrong password accepted", e)
	}
	other, _ := s.path(b)
	if e = os.WriteFile(other, disk, 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e = s.Load(b, pass); e != ErrAuth {
		t.Fatal("cross-project ciphertext accepted")
	}
	var r Record
	if e = json.Unmarshal(disk, &r); e != nil {
		t.Fatal(e)
	}
	r.Root = "/tampered"
	data, _ := json.Marshal(r)
	os.WriteFile(path, data, 0600)
	if _, _, e = s.Load(a, pass); e != ErrAuth {
		t.Fatal("modified metadata accepted")
	}
}
func TestAtomicWriteRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	os.WriteFile(target, []byte("original"), 0600)
	if e := os.Symlink(target, link); e != nil {
		t.Skip("symlinks unavailable")
	}
	if e := AtomicWrite(link, []byte("changed"), 0600); e == nil {
		t.Fatal("accepted symlink")
	}
	got, _ := os.ReadFile(target)
	if string(got) != "original" {
		t.Fatal("target changed")
	}
}
