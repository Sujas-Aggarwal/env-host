package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"env-host/internal/policy"
	"env-host/internal/project"
	"env-host/internal/vault"
)

func policyPath(store *vault.Store, id string) (string, error) {
	locator, err := project.Locator(id)
	if err != nil {
		return "", err
	}
	return filepath.Join(store.Dir, locator+".policy"), nil
}

func readPolicyDocument(store *vault.Store, id string) (string, error) {
	path, err := policyPath(store, id)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return policy.DefaultDocument, nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > policy.MaxBytes {
		return "", fmt.Errorf("invalid policy file or permissions")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, policy.MaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > policy.MaxBytes {
		return "", fmt.Errorf("policy exceeds %d bytes", policy.MaxBytes)
	}
	return string(data), nil
}

func loadPolicy(store *vault.Store, id, root string) (policy.Policy, string, error) {
	document, err := readPolicyDocument(store, id)
	if err != nil {
		return policy.Policy{}, "", err
	}
	parsed, err := policy.Parse(document, root)
	return parsed, document, err
}

func managePolicy(id string) error {
	selected, _, err := resolve(id)
	if err != nil {
		return err
	}
	store, err := vault.Open()
	if err != nil {
		return err
	}
	pass, err := unlockProject(store, selected)
	if err != nil {
		return err
	}
	unlock, err := store.Lock()
	if err != nil {
		return err
	}
	_, root, err := store.Load(selected, pass)
	if err != nil {
		unlock()
		return err
	}
	before, err := readPolicyDocument(store, selected)
	unlock()
	if err != nil {
		return err
	}
	work, err := os.CreateTemp(store.Dir, ".envh-policy-edit-*")
	if err != nil {
		return err
	}
	path := work.Name()
	defer os.Remove(path)
	if err = work.Chmod(0600); err == nil {
		_, err = work.WriteString(before)
	}
	if err == nil {
		err = work.Sync()
	}
	closeErr := work.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = edit(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > policy.MaxBytes {
		return fmt.Errorf("editor did not leave a valid policy file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	modified := string(data)
	if _, err := policy.Parse(modified, root); err != nil {
		return err
	}
	if modified == before {
		return nil
	}
	unlock, err = store.Lock()
	if err != nil {
		return err
	}
	defer unlock()
	current, err := readPolicyDocument(store, selected)
	if err != nil {
		return err
	}
	if current != before {
		return fmt.Errorf("policy changed while editing; reopen envh policy manage")
	}
	policyFile, err := policyPath(store, selected)
	if err != nil {
		return err
	}
	if err = vault.AtomicWrite(policyFile, []byte(modified), 0600); err != nil {
		return err
	}
	fmt.Println("Policy saved.")
	return nil
}

func showPolicy(id string) error {
	selected, _, err := resolve(id)
	if err != nil {
		return err
	}
	store, err := vault.Open()
	if err != nil {
		return err
	}
	pass, err := unlockProject(store, selected)
	if err != nil {
		return err
	}
	_, _, err = store.Load(selected, pass)
	if err != nil {
		return err
	}
	document, err := readPolicyDocument(store, selected)
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, strings.TrimSuffix(document, "\n")+"\n")
	return err
}
