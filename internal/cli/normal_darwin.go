//go:build darwin

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"env-host/internal/policy"
)

var systemReadDirs = []string{
	"/Applications", "/Library", "/System", "/bin", "/dev", "/etc", "/opt",
	"/private/etc", "/private/var/db", "/private/var/select", "/sbin", "/usr", "/usr/local",
}

func inRoot(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

func sandboxProfile(root, temporary string, port int, rules policy.Policy) string {
	var b strings.Builder
	write := func(line string) { b.WriteString(line); b.WriteByte('\n') }
	write("(version 1)")
	write("(allow default)")
	write("(deny file-read*)")
	write("(deny file-write*)")
	write("(deny network-outbound)")
	write(`(allow file-read* (literal "/"))`)
	for _, dir := range []string{"/Users", "/private"} {
		write("(allow file-read* (literal " + strconv.Quote(dir) + "))")
	}
	for dir := filepath.Dir(root); dir != "/" && dir != "."; dir = filepath.Dir(dir) {
		write("(allow file-read* (literal " + strconv.Quote(dir) + "))")
	}
	write(`(allow file-write* file-ioctl (regex #"^/dev/(null|tty[a-z0-9]*)$"))`)
	for _, dir := range append(append([]string{}, systemReadDirs...), rules.ReadDirs...) {
		write("(allow file-read* (subpath " + strconv.Quote(dir) + "))")
	}
	for _, dir := range []string{root, temporary} {
		write("(allow file-read* file-write* (subpath " + strconv.Quote(dir) + "))")
	}
	for _, dir := range rules.WriteDirs {
		write("(allow file-read* file-write* (subpath " + strconv.Quote(dir) + "))")
	}
	write(fmt.Sprintf(`(allow network-outbound (remote ip "localhost:%d"))`, port))
	write(`(allow network-bind network-inbound (local ip "localhost:*"))`)
	return b.String()
}

func proxyEnvironment(env []string, url, temporary string) []string {
	filtered := make([]string, 0, len(env)+10)
	for _, variable := range env {
		name, _, ok := strings.Cut(variable, "=")
		if !ok {
			continue
		}
		switch strings.ToUpper(name) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "TMPDIR", "TMP", "TEMP", "NODE_USE_ENV_PROXY":
			continue
		}
		filtered = append(filtered, variable)
	}
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		filtered = append(filtered, name+"="+url)
	}
	filtered = append(filtered, "NO_PROXY=", "no_proxy=", "NODE_USE_ENV_PROXY=1", "TMPDIR="+temporary, "TMP="+temporary, "TEMP="+temporary)
	return filtered
}

func launchNormal(args, env []string, root, storeDir string, rules policy.Policy) (int, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return 1, err
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return 1, err
	}
	if !inRoot(cwd, root) {
		return 1, fmt.Errorf("normal mode requires the current directory inside the project root; use --unsafe to run elsewhere")
	}
	if _, code, lookupErr := resolveExecutable(args[0], env); lookupErr != nil {
		return code, lookupErr
	}
	storeDir, err = filepath.EvalSymlinks(storeDir)
	if err != nil {
		return 1, err
	}
	if inRoot(storeDir, root) {
		return 1, fmt.Errorf("normal mode requires ENVH_HOME outside the project root")
	}
	for _, dir := range rules.WriteDirs {
		if inRoot(storeDir, dir) {
			return 1, fmt.Errorf("policy write rule includes the env-host vault directory")
		}
	}
	temporary, err := os.MkdirTemp("", "envh-run-*")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(temporary)
	temporary, err = filepath.EvalSymlinks(temporary)
	if err != nil {
		return 1, err
	}
	proxy, err := startPolicyProxy(rules)
	if err != nil {
		return 1, err
	}
	defer proxy.Close()
	profile := sandboxProfile(root, temporary, proxy.port, rules)
	wrapped := append([]string{"-p", profile, "--"}, args...)
	child := exec.Command("/usr/bin/sandbox-exec", wrapped...)
	child.Env = proxyEnvironment(env, proxy.URL(), temporary)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err = child.Start(); err != nil {
		return 126, fmt.Errorf("cannot start sandboxed command: %w", err)
	}
	signals := make(chan os.Signal, 4)
	done := make(chan struct{})
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(signals)
	go func() {
		for {
			select {
			case sig := <-signals:
				child.Process.Signal(sig)
			case <-done:
				return
			}
		}
	}()
	err = child.Wait()
	close(done)
	if err == nil {
		return 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if status, ok := exit.Sys().(syscall.WaitStatus); ok && status.Signaled() {
			return 128 + int(status.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	return 126, fmt.Errorf("sandboxed command failed: %w", err)
}
