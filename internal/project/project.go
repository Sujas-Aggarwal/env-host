package project

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const Marker = ".h.env"

var codec = base32.StdEncoding.WithPadding(base32.NoPadding)

func NewID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("secure random source unavailable")
	}
	return "ehp1_" + strings.ToLower(codec.EncodeToString(b))
}
func Decode(id string) ([]byte, error) {
	if !strings.HasPrefix(id, "ehp1_") || len(id) != 57 {
		return nil, fmt.Errorf("invalid project ID")
	}
	b, err := codec.DecodeString(strings.ToUpper(id[5:]))
	if err != nil || len(b) != 32 || "ehp1_"+strings.ToLower(codec.EncodeToString(b)) != id {
		return nil, fmt.Errorf("invalid project ID")
	}
	return b, nil
}
func Locator(id string) (string, error) {
	b, err := Decode(id)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("envh/project/v1\x00"), b...))
	return hex.EncodeToString(h[:]), nil
}
func Read(root string) (string, error) {
	path := filepath.Join(root, Marker)
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 1024 {
		return "", fmt.Errorf("invalid .h.env file")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("cannot read .h.env")
	}
	line := strings.TrimSpace(string(b))
	if !strings.HasPrefix(line, "PROJECT_ID=") {
		return "", fmt.Errorf("invalid .h.env contents")
	}
	id := strings.TrimPrefix(line, "PROJECT_ID=")
	if _, err := Decode(id); err != nil {
		return "", err
	}
	return id, nil
}
func Discover(cwd string) (string, string, error) {
	root, err := filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", "", err
	}
	for {
		id, err := Read(root)
		if err == nil {
			return id, root, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", "", err
		}
		parent := filepath.Dir(root)
		if parent == root {
			return "", "", fmt.Errorf("no project found; run envh init")
		}
		root = parent
	}
}
func Write(root, id string) error {
	if _, err := Decode(id); err != nil {
		return err
	}
	f, err := os.OpenFile(filepath.Join(root, Marker), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return fmt.Errorf("cannot create .h.env")
	}
	_, err = f.WriteString("PROJECT_ID=" + id + "\n")
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
