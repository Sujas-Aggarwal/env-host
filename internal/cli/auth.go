package cli

import (
	"env-host/internal/auth"
	"env-host/internal/project"
	"env-host/internal/vault"
	"fmt"
)

func unlockProject(store *vault.Store, id string) (string, error) {
	method, e := store.AuthMethod(id)
	if e != nil {
		return "", e
	}
	if method == auth.Method {
		loc, e := project.Locator(id)
		if e != nil {
			return "", e
		}
		return auth.Read(loc)
	}
	return password(false)
}
func credentialForInit(store *vault.Store, id string, exists, forcePassphrase bool) (string, string, error) {
	if exists {
		method, e := store.AuthMethod(id)
		if e != nil {
			return "", "", e
		}
		pass, e := unlockProject(store, id)
		return pass, method, e
	}
	if auth.Available && !forcePassphrase {
		if err := auth.Ready(); err != nil {
			return "", auth.Method, fmt.Errorf("%w; use envh init --passphrase", err)
		}
		loc, e := project.Locator(id)
		if e != nil {
			return "", "", e
		}
		key, e := auth.Create(loc)
		if e != nil {
			return "", auth.Method, e
		}
		if _, e = auth.Read(loc); e != nil {
			auth.Delete(loc)
			return "", auth.Method, fmt.Errorf("cannot verify macOS authentication: %w", e)
		}
		return key, auth.Method, nil
	}
	pass, e := password(true)
	return pass, "passphrase", e
}
func migrate(id string) error {
	if err := auth.Ready(); err != nil {
		return err
	}
	selected, _, e := resolve(id)
	if e != nil {
		return e
	}
	store, e := vault.Open()
	if e != nil {
		return e
	}
	method, e := store.AuthMethod(selected)
	if e != nil {
		return e
	}
	if method == auth.Method {
		return fmt.Errorf("project already uses macOS Keychain authentication")
	}
	pass, e := password(false)
	if e != nil {
		return e
	}
	unlock, e := store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	values, root, document, e := store.LoadDocument(selected, pass)
	if e != nil {
		return e
	}
	locator, e := project.Locator(selected)
	if e != nil {
		return e
	}
	key, e := auth.Create(locator)
	if e != nil {
		return e
	}
	if _, e = auth.Read(locator); e != nil {
		auth.Delete(locator)
		return fmt.Errorf("cannot verify macOS authentication: %w", e)
	}
	if e = store.SaveWithDocument(selected, key, root, values, document, auth.Method); e != nil {
		auth.Delete(locator)
		return e
	}
	fmt.Println("Project now uses macOS Keychain authentication.")
	return nil
}
