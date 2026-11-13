// Package vault stores one authenticated, encrypted environment per project.
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"env-host/internal/envfile"
	"env-host/internal/project"
)

const iterations = 600000
const maxRecord = 4 << 20

var ErrAuth = errors.New("cannot unlock project: incorrect passphrase or damaged vault")

type Record struct {
	Version    int    `json:"version"`
	Auth       string `json:"auth,omitempty"`
	Root       string `json:"root"`
	Salt       []byte `json:"salt"`
	Ciphertext []byte `json:"ciphertext"`
}
type payload struct {
	Values   map[string]string `json:"values"`
	Document string            `json:"document"`
}
type Store struct{ Dir string }
type Password func(creating bool) (string, error)

func Open() (*Store, error) {
	root := os.Getenv("ENVH_HOME")
	if root == "" {
		var err error
		root, err = os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		root = filepath.Join(root, "env-host")
	}
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err = privateDir(root); err != nil {
		return nil, err
	}
	dir := filepath.Join(root, "projects")
	if err = privateDir(dir); err != nil {
		return nil, err
	}
	return &Store{Dir: dir}, nil
}
func privateDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("cannot create vault directory")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("unsafe vault directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("vault directory must have owner-only permissions (0700)")
	}
	return nil
}
func (s *Store) Lock() (func(), error) { return lock(filepath.Join(s.Dir, ".lock")) }
func (s *Store) path(id string) (string, error) {
	loc, err := project.Locator(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(s.Dir, loc+".json"), nil
}
func (s *Store) Exists(id string) (bool, error) {
	p, e := s.path(id)
	if e != nil {
		return false, e
	}
	_, e = os.Lstat(p)
	if errors.Is(e, os.ErrNotExist) {
		return false, nil
	}
	return e == nil, e
}
func (s *Store) Root(id string) (string, error) {
	p, e := s.path(id)
	if e != nil {
		return "", e
	}
	r, e := readRecord(p)
	return r.Root, e
}
func (s *Store) AuthMethod(id string) (string, error) {
	p, e := s.path(id)
	if e != nil {
		return "", e
	}
	r, e := readRecord(p)
	if e != nil {
		return "", e
	}
	if r.Auth == "" {
		return "passphrase", nil
	}
	return r.Auth, nil
}
func readRecord(path string) (Record, error) {
	var r Record
	info, err := os.Lstat(path)
	if err != nil {
		return r, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRecord || (runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0) {
		return r, fmt.Errorf("invalid vault file or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return r, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, maxRecord+1))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || (r.Version != 1 && r.Version != 2) || (r.Auth != "" && r.Auth != "passphrase" && r.Auth != "keychain") || len(r.Salt) != 32 || len(r.Ciphertext) < 28 {
		return r, ErrAuth
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return r, ErrAuth
	}
	return r, nil
}
func (s *Store) RegisteredRoot(root string) (bool, error) {
	files, err := os.ReadDir(s.Dir)
	if err != nil {
		return false, err
	}
	for _, f := range files {
		if filepath.Ext(f.Name()) != ".json" {
			continue
		}
		r, err := readRecord(filepath.Join(s.Dir, f.Name()))
		if err != nil {
			return false, fmt.Errorf("cannot read project registry")
		}
		if r.Root == root {
			return true, nil
		}
	}
	return false, nil
}
func aead(password, id string, salt []byte) (cipher.AEAD, error) {
	p, err := project.Decode(id)
	if err != nil {
		return nil, err
	}
	fullSalt := append(append([]byte("envh/kdf/v1\x00"), salt...), p...)
	key, err := pbkdf2.Key(sha256.New, password, fullSalt, iterations, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}
func aad(id, root string) []byte {
	loc, _ := project.Locator(id)
	return []byte("envh/vault/v1\x00" + loc + "\x00" + root)
}
func (s *Store) Load(id, password string) (map[string]string, string, error) {
	values, root, _, err := s.LoadDocument(id, password)
	return values, root, err
}
func (s *Store) LoadDocument(id, password string) (map[string]string, string, string, error) {
	p, err := s.path(id)
	if err != nil {
		return nil, "", "", err
	}
	r, err := readRecord(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", "", fmt.Errorf("project is not registered on this machine")
	}
	if err != nil {
		return nil, "", "", err
	}
	c, err := aead(password, id, r.Salt)
	if err != nil {
		return nil, "", "", err
	}
	plain, err := c.Open(nil, nil, r.Ciphertext, aad(id, r.Root))
	if err != nil {
		return nil, "", "", ErrAuth
	}
	defer clear(plain)
	var values map[string]string
	document := ""
	if r.Version == 1 {
		if json.Unmarshal(plain, &values) != nil {
			return nil, "", "", ErrAuth
		}
	} else {
		var p payload
		if json.Unmarshal(plain, &p) != nil {
			return nil, "", "", ErrAuth
		}
		values, document = p.Values, p.Document
	}
	if values == nil || envfile.Validate(values) != nil {
		return nil, "", "", ErrAuth
	}
	if document == "" {
		document = Render(values)
	} else {
		parsed, _, e := envfile.Parse(strings.NewReader(document))
		if e != nil || !equal(parsed, values) {
			return nil, "", "", ErrAuth
		}
	}
	return values, r.Root, document, nil
}
func (s *Store) Save(id, password, root string, values map[string]string) error {
	document := Render(values)
	method := "passphrase"
	if exists, e := s.Exists(id); e != nil {
		return e
	} else if exists {
		var old map[string]string
		var previous string
		old, _, previous, e = s.LoadDocument(id, password)
		if e != nil {
			return e
		}
		document = Reconcile(previous, old, values)
		method, e = s.AuthMethod(id)
		if e != nil {
			return e
		}
	}
	return s.SaveWithDocument(id, password, root, values, document, method)
}
func (s *Store) SaveWithDocument(id, password, root string, values map[string]string, document, method string) error {
	if err := envfile.Validate(values); err != nil {
		return err
	}
	if method != "passphrase" && method != "keychain" {
		return fmt.Errorf("unsupported authentication method")
	}
	parsed, _, parseErr := envfile.Parse(strings.NewReader(document))
	if parseErr != nil || !equal(parsed, values) {
		return fmt.Errorf("edited document does not match environment values")
	}
	p, err := s.path(id)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(payload{Values: values, Document: document})
	if err != nil {
		return err
	}
	defer clear(plain)
	salt := make([]byte, 32)
	if _, err = rand.Read(salt); err != nil {
		return err
	}
	c, err := aead(password, id, salt)
	if err != nil {
		return err
	}
	r := Record{Version: 2, Auth: method, Root: root, Salt: salt, Ciphertext: c.Seal(nil, nil, plain, aad(id, root))}
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return AtomicWrite(p, append(data, '\n'), 0600)
}
func equal(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}
func Render(values map[string]string) string {
	names := make([]string, 0, len(values))
	for n := range values {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		b.WriteString(n + "=" + strconv.Quote(values[n]) + "\n")
	}
	return b.String()
}

// Reconcile retains comments and blank lines while reflecting set/unset/import.
func Reconcile(document string, old, next map[string]string) string {
	remaining := make(map[string]string, len(next))
	for k, v := range next {
		remaining[k] = v
	}
	var b strings.Builder
	for _, line := range strings.SplitAfter(document, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			b.WriteString(line)
			continue
		}
		name, _, ok := strings.Cut(trimmed, "=")
		name = strings.TrimSpace(strings.TrimPrefix(name, "export "))
		if !ok || !envfile.ValidName(name) {
			continue
		}
		value, keep := remaining[name]
		if !keep {
			continue
		}
		if old[name] == value {
			b.WriteString(line)
		} else {
			b.WriteString(name + "=" + strconv.Quote(value) + "\n")
		}
		delete(remaining, name)
	}
	names := make([]string, 0, len(remaining))
	for n := range remaining {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) > 0 && b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
		b.WriteByte('\n')
	}
	for _, n := range names {
		b.WriteString(n + "=" + strconv.Quote(remaining[n]) + "\n")
	}
	return b.String()
}

// AtomicWrite rejects nonregular targets and publishes a complete sibling file.
func AtomicWrite(path string, data []byte, mode os.FileMode) error {
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("refusing to overwrite a nonregular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".envh-write-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(mode); err == nil {
		_, err = io.Copy(f, bytes.NewReader(data))
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}
