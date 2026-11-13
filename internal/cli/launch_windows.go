//go:build windows

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
)

func launch(args, env []string) (int, error) {
	c := exec.Command(args[0], args[1:]...)
	c.Env = env
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	e := c.Run()
	if e == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(e, &exit) {
		return exit.ExitCode(), nil
	}
	return 127, fmt.Errorf("could not start command")
}
