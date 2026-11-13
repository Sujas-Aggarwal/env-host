package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/term"
)

func console() (*os.File, error) {
	name := "/dev/tty"
	if runtime.GOOS == "windows" {
		name = "CONIN$"
	}
	f, e := os.OpenFile(name, os.O_RDWR, 0)
	if e != nil {
		return nil, fmt.Errorf("a terminal is required; for automation set ENVH_PASSPHRASE")
	}
	return f, nil
}
func hidden(prompt string) (string, error) {
	f, e := console()
	if e != nil {
		return "", e
	}
	defer f.Close()
	state, e := term.GetState(int(f.Fd()))
	if e != nil {
		return "", fmt.Errorf("cannot read terminal state")
	}
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt, syscall.SIGTERM)
	done, finished := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(finished)
		select {
		case s := <-interrupts:
			term.Restore(int(f.Fd()), state)
			fmt.Fprintln(os.Stderr)
			if n, ok := s.(syscall.Signal); ok {
				os.Exit(128 + int(n))
			}
			os.Exit(130)
		case <-done:
		}
	}()
	defer func() { signal.Stop(interrupts); close(done); <-finished }()
	fmt.Fprint(os.Stderr, prompt)
	b, e := term.ReadPassword(int(f.Fd()))
	fmt.Fprintln(os.Stderr)
	if e != nil {
		return "", fmt.Errorf("input canceled")
	}
	defer clear(b)
	return string(b), nil
}
func password(creating bool) (string, error) {
	return passwordFrom("ENVH_PASSPHRASE", creating)
}
func passwordFrom(variable string, creating bool) (string, error) {
	p, ok := os.LookupEnv(variable)
	if !ok {
		var e error
		p, e = hidden("Vault passphrase: ")
		if e != nil {
			return "", e
		}
		if creating {
			again, e := hidden("Confirm passphrase: ")
			if e != nil {
				return "", e
			}
			if p != again {
				return "", fmt.Errorf("passphrases do not match")
			}
		}
	}
	if p == "" || len(p) > 4096 {
		return "", fmt.Errorf("passphrase must not be empty or exceed 4096 bytes")
	}
	if creating && len(p) < 12 {
		return "", fmt.Errorf("use a passphrase of at least 12 characters")
	}
	return p, nil
}
func line(prompt string) (string, error) {
	f, e := console()
	if e != nil {
		return "", e
	}
	defer f.Close()
	fmt.Fprint(os.Stderr, prompt)
	s, e := bufio.NewReader(io.LimitReader(f, 8192)).ReadString('\n')
	if e != nil {
		return "", fmt.Errorf("input canceled")
	}
	return strings.TrimSpace(s), nil
}
