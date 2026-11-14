//go:build !darwin

package cli

import (
	"fmt"

	"env-host/internal/policy"
)

func launchNormal(args, env []string, root, storeDir string, rules policy.Policy) (int, error) {
	return 2, fmt.Errorf("normal mode needs macOS Seatbelt; use --unsafe to run directly")
}
