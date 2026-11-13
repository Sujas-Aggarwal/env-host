package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func edit(path string) error {
	editor := os.Getenv("VISUAL")
	if editor == "" {
		editor = os.Getenv("EDITOR")
	}
	if editor == "" {
		editor = "vi"
	}
	fields := strings.Fields(editor)
	if len(fields) == 0 {
		return fmt.Errorf("empty editor command")
	}
	cmd := exec.Command(fields[0], append(fields[1:], path)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	for _, v := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(v), "ENVH_PASSPHRASE=") && !strings.HasPrefix(strings.ToUpper(v), "ENVH_NEW_PASSPHRASE=") {
			cmd.Env = append(cmd.Env, v)
		}
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor exited without saving: %w", err)
	}
	return nil
}
