//go:build !darwin || !cgo

package auth

import "fmt"

const Available = false
const Method = "keychain"

func Ready() error        { return fmt.Errorf("macOS Keychain authentication is unavailable in this build") }
func Probe() error        { return Ready() }
func Authenticate() error { return Ready() }

func Create(string) (string, error) {
	return "", fmt.Errorf("macOS Keychain authentication is unavailable in this build")
}
func Read(string) (string, error) {
	return "", fmt.Errorf("macOS Keychain authentication is unavailable in this build")
}
func Delete(string) error {
	return fmt.Errorf("macOS Keychain authentication is unavailable in this build")
}
