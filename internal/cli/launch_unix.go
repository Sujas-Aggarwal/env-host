//go:build darwin || linux

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func launch(args, env []string) (int, error) {
	executable, code, err := resolveExecutable(args[0], env)
	if err != nil {
		return code, err
	}
	// Replacing envh preserves the terminal, signals, cwd, pipes and exit status.
	if e := syscall.Exec(executable, args, env); e != nil {
		return 126, fmt.Errorf("could not execute command: %w", e)
	}
	return 0, nil
}

func resolveExecutable(name string, env []string) (string, int, error) {
	executable := ""
	var lookupErr error
	if strings.ContainsRune(name, '/') {
		executable, lookupErr = exec.LookPath(name)
	} else {
		path := ""
		for _, v := range env {
			if strings.HasPrefix(v, "PATH=") {
				path = strings.TrimPrefix(v, "PATH=")
			}
		}
		cwd, e := os.Getwd()
		if e != nil {
			return "", 126, fmt.Errorf("cannot determine working directory")
		}
		for _, dir := range filepath.SplitList(path) {
			if dir == "" {
				dir = "."
			}
			if !filepath.IsAbs(dir) {
				dir = filepath.Join(cwd, dir)
			}
			p, e := exec.LookPath(filepath.Join(dir, name))
			if e == nil {
				executable = p
				break
			}
			if !errors.Is(e, os.ErrNotExist) {
				lookupErr = e
			}
		}
	}
	if executable == "" {
		if lookupErr != nil && !errors.Is(lookupErr, os.ErrNotExist) && !errors.Is(lookupErr, exec.ErrNotFound) {
			return "", 126, fmt.Errorf("command is not executable")
		}
		return "", 127, fmt.Errorf("command not found")
	}
	return executable, 0, nil
}
