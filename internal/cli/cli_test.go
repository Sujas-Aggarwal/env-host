package cli

import (
	"bytes"
	"encoding/json"
	"env-host/internal/auth"
	"env-host/internal/project"
	"env-host/internal/vault"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "__editor" {
		path := os.Args[len(os.Args)-1]
		if os.Getenv("EDITOR_FIXTURE") != "" {
			if err := os.WriteFile(path, []byte(os.Getenv("EDITOR_FIXTURE")), 0600); err != nil {
				os.Exit(1)
			}
		}
		os.Exit(0)
	}
	if len(os.Args) > 1 && os.Args[1] == "__cli" {
		os.Exit(Main(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "__child" {
		switch os.Args[2] {
		case "inspect":
			cwd, _ := os.Getwd()
			json.NewEncoder(os.Stdout).Encode(map[string]any{"cwd": cwd, "secret": os.Getenv("FIXTURE_SECRET"), "empty": os.Getenv("EMPTY"), "password": os.Getenv("ENVH_PASSPHRASE"), "args": os.Args[3:]})
		case "exit":
			fmtExit()
		case "copy":
			io.Copy(os.Stdout, os.Stdin)
		case "wait":
			os.Stdout.WriteString("ready\n")
			for {
				time.Sleep(time.Second)
			}
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}
func fmtExit() {
	os.Stdout.WriteString("application-out\n")
	os.Stderr.WriteString("application-err\n")
	os.Exit(23)
}

type fixture struct {
	t              *testing.T
	dir, home, exe string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "project")
	os.Mkdir(dir, 0700)
	exe, _ := os.Executable()
	return &fixture{t, dir, filepath.Join(base, "state"), exe}
}
func (f *fixture) cmd(args ...string) *exec.Cmd {
	c := exec.Command(f.exe, append([]string{"__cli"}, args...)...)
	c.Dir = f.dir
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "ENVH_") && !strings.HasPrefix(v, "FIXTURE_SECRET=") {
			c.Env = append(c.Env, v)
		}
	}
	c.Env = append(c.Env, "ENVH_HOME="+f.home, "ENVH_PASSPHRASE=synthetic test passphrase", "FIXTURE_SECRET=ambient-value")
	return c
}
func (f *fixture) invoke(input string, args ...string) (string, string, int) {
	f.t.Helper()
	c := f.cmd(args...)
	c.Stdin = strings.NewReader(input)
	var out, err bytes.Buffer
	c.Stdout = &out
	c.Stderr = &err
	e := c.Run()
	code := 0
	if e != nil {
		if x, ok := e.(*exec.ExitError); ok {
			code = x.ExitCode()
		} else {
			f.t.Fatal(e)
		}
	}
	return out.String(), err.String(), code
}
func (f *fixture) ok(input string, args ...string) string {
	f.t.Helper()
	out, err, code := f.invoke(input, args...)
	if code != 0 {
		f.t.Fatalf("%s: exit %d: %s", args[0], code, err)
	}
	return out
}

func TestMigrationChecksAuthenticationBeforePassphrase(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS authentication test")
	}
	if err := auth.Ready(); err == nil {
		t.Skip("macOS authentication is available")
	}
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	c := f.cmd("migrate")
	for i, v := range c.Env {
		if strings.HasPrefix(v, "ENVH_PASSPHRASE=") {
			c.Env = append(c.Env[:i], c.Env[i+1:]...)
			break
		}
	}
	c.Stdin = strings.NewReader("")
	output, err := c.CombinedOutput()
	if err == nil || !strings.Contains(string(output), "LocalAuthentication") || strings.Contains(string(output), "terminal") {
		t.Fatalf("expected authentication availability error before passphrase prompt, got %q: %v", output, err)
	}
	_, statusErr, code := f.invoke("", "auth", "status")
	if code != 1 || !strings.Contains(statusErr, "LocalAuthentication") {
		t.Fatalf("unexpected auth status: exit %d, %q", code, statusErr)
	}
}

func TestFullWorkflow(t *testing.T) {
	f := newFixture(t)
	source := "FIXTURE_SECRET='synthetic value'\nEMPTY=\nDEBUG=true\n"
	os.WriteFile(filepath.Join(f.dir, ".env"), []byte(source), 0600)
	out := f.ok("", "init", "--passphrase", "--env", ".env")
	if strings.Contains(out, "synthetic value") {
		t.Fatal("import exposed value")
	}
	id, e := project.Read(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	f.ok("", "init", "--passphrase")
	again, _ := project.Read(f.dir)
	if again != id {
		t.Fatal("repeat init changed identity")
	}
	ignored, _ := os.ReadFile(filepath.Join(f.dir, ".gitignore"))
	if strings.Count(string(ignored), "/.h.env") != 1 {
		t.Fatal("duplicate ignore entry")
	}
	if got := f.ok("", "list"); got != "DEBUG\nEMPTY\nFIXTURE_SECRET\n" {
		t.Fatal("unexpected list", got)
	}
	f.ok("replacement\nwith newline", "set", "FIXTURE_SECRET", "--stdin")
	if got := f.ok("", "get", "FIXTURE_SECRET"); got != "replacement\nwith newline" {
		t.Fatal("value round trip")
	}
	f.ok("", "snap")
	snap, _ := os.ReadFile(filepath.Join(f.dir, ".env.example"))
	if string(snap) != "DEBUG=\nEMPTY=\nFIXTURE_SECRET=\n" {
		t.Fatal("unsafe snapshot")
	}
	f.ok("", "snap", "--force")
	original, _ := os.ReadFile(filepath.Join(f.dir, ".env"))
	if string(original) != source {
		t.Fatal("import source changed")
	}
	got := f.ok("", "--unsafe", "--run", f.exe, "__child", "inspect", "--secure", "two words")
	var child struct {
		Cwd, Secret, Empty, Password string
		Args                         []string
	}
	if e = json.Unmarshal([]byte(got), &child); e != nil {
		t.Fatal("application stdout polluted", got)
	}
	physical, _ := filepath.EvalSymlinks(f.dir)
	if child.Cwd != physical || child.Secret != "replacement\nwith newline" || child.Password != "" || len(child.Args) != 2 || child.Args[0] != "--secure" {
		t.Fatalf("child contract failed: %#v", child)
	}
	out, err, code := f.invoke("", "--unsafe", "--run", f.exe, "__child", "exit")
	if out != "application-out\n" || err != "application-err\n" || code != 23 {
		t.Fatal("streams or exit status altered", out, err, code)
	}
	if got = f.ok("piped input\n", "--unsafe", "--run", f.exe, "__child", "copy"); got != "piped input\n" {
		t.Fatal("stdin altered")
	}
	f.ok("", "unset", "DEBUG")
	if got = f.ok("", "list"); strings.Contains(got, "DEBUG") {
		t.Fatal("unset failed")
	}
}

func TestImportFailureIsAtomicAndProjectsIndependent(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	f.ok("first", "set", "FIXTURE_SECRET", "--stdin")
	os.WriteFile(filepath.Join(f.dir, "input.env"), []byte("NEW=x\nFIXTURE_SECRET=second\n"), 0600)
	if _, _, code := f.invoke("", "import", "input.env"); code == 0 {
		t.Fatal("conflict accepted")
	}
	if got := f.ok("", "list"); got != "FIXTURE_SECRET\n" {
		t.Fatal("partial import")
	}
	f.ok("", "import", "--replace", "input.env")
	if got := f.ok("", "get", "FIXTURE_SECRET"); got != "second" {
		t.Fatal("replace failed")
	}
	firstID, _ := project.Read(f.dir)
	firstRoot := f.dir
	f.dir = filepath.Join(filepath.Dir(f.dir), "other")
	os.Mkdir(f.dir, 0700)
	f.ok("", "init", "--passphrase")
	f.ok("other", "set", "FIXTURE_SECRET", "--stdin")
	if got := f.ok("", "get", "FIXTURE_SECRET"); got != "other" {
		t.Fatal("namespace bleed")
	}
	if got := f.ok("", "get", "FIXTURE_SECRET", "--project-id", firstID); got != "second" {
		t.Fatal("explicit selection failed")
	}
	f.dir = firstRoot
	os.Remove(filepath.Join(f.dir, project.Marker))
	if _, _, code := f.invoke("", "init"); code == 0 {
		t.Fatal("lost identity silently replaced")
	}
}

func TestWrongPasswordAndUnsafeTargets(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	f.ok("sentinel", "set", "A", "--stdin")
	c := f.cmd("get", "A")
	for i, v := range c.Env {
		if strings.HasPrefix(v, "ENVH_PASSPHRASE=") {
			c.Env[i] = "ENVH_PASSPHRASE=wrong"
		}
	}
	out, e := c.CombinedOutput()
	if e == nil || bytes.Contains(out, []byte("sentinel")) {
		t.Fatal("failed authentication released value")
	}
	target := filepath.Join(f.dir, ".env")
	os.WriteFile(target, []byte("original"), 0600)
	if e := os.Symlink(target, filepath.Join(f.dir, ".env.example")); e == nil {
		if _, _, code := f.invoke("", "snap", "--force"); code == 0 {
			t.Fatal("symlink snapshot allowed")
		}
		data, _ := os.ReadFile(target)
		if string(data) != "original" {
			t.Fatal("source overwritten")
		}
	}
	if _, _, code := f.invoke("", "--secure", "--run", f.exe, "__child", "copy"); code == 0 {
		t.Fatal("unsupported mode allowed")
	}
	if _, _, code := f.invoke("", "--unsafe", "--run", "envh-nonexistent-fixture-command"); code != 127 {
		t.Fatal("not-found exit", code)
	}
}

func TestConcurrentEdits(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	a, b := f.cmd("set", "A", "--stdin"), f.cmd("set", "B", "--stdin")
	a.Stdin = strings.NewReader("a")
	b.Stdin = strings.NewReader("b")
	if e := a.Start(); e != nil {
		t.Fatal(e)
	}
	if e := b.Start(); e != nil {
		t.Fatal(e)
	}
	if e := a.Wait(); e != nil {
		t.Fatal(e)
	}
	if e := b.Wait(); e != nil {
		t.Fatal(e)
	}
	if got := f.ok("", "list"); got != "A\nB\n" {
		t.Fatal("lost update", got)
	}
}

func TestRunReceivesInterrupt(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX signal test")
	}
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	c := f.cmd("--unsafe", "--run", f.exe, "__child", "wait")
	out, e := c.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	if e = c.Start(); e != nil {
		t.Fatal(e)
	}
	defer c.Process.Kill()
	ready := make(chan error, 1)
	go func() { b := make([]byte, 6); _, e := io.ReadFull(out, b); ready <- e }()
	select {
	case e := <-ready:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child failed to start")
	}
	if e = c.Process.Signal(os.Interrupt); e != nil {
		t.Fatal(e)
	}
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("interrupt reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("interrupt not delivered")
	}
}

func TestMacPolicyControlsProxyAndDirectAccess(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Seatbelt integration")
	}
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "allowed-response")
	}))
	defer server.Close()
	host, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + net.JoinHostPort(host, port) + "/"
	if _, _, code := f.invoke("", "--run", "/usr/bin/curl", "-sSf", "--max-time", "3", url); code == 0 {
		t.Fatal("default network block was bypassed")
	}
	c := f.cmd("policy", "manage")
	c.Env = append(c.Env, "VISUAL="+f.exe+" __editor", "EDITOR_FIXTURE=default block\nallow "+net.JoinHostPort(host, port)+"\n")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("policy edit failed: %v: %s", err, out)
	}
	if got := f.ok("", "--run", "/usr/bin/curl", "-sSf", "--max-time", "3", url); got != "allowed-response" {
		t.Fatalf("allowed host failed: %q", got)
	}
	if _, _, code := f.invoke("", "--run", "/usr/bin/curl", "-sSf", "--noproxy", "*", "--max-time", "3", url); code == 0 {
		t.Fatal("direct socket bypassed Seatbelt")
	}
	if got := f.ok("", "--unsafe", "--run", "/usr/bin/curl", "-sSf", "--max-time", "3", url); got != "allowed-response" {
		t.Fatalf("unsafe bypass did not connect: %q", got)
	}
	outside := filepath.Join(filepath.Dir(f.dir), "outside.txt")
	if err := os.WriteFile(outside, []byte("outside-data"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, code := f.invoke("", "--run", "/bin/cat", outside); code == 0 {
		t.Fatal("normal mode read outside project")
	}
	if got := f.ok("", "--unsafe", "--run", "/bin/cat", outside); got != "outside-data" {
		t.Fatalf("unsafe file bypass failed: %q", got)
	}
	if _, _, code := f.invoke("", "--run", "/bin/sh", "-c", "exit 23"); code != 23 {
		t.Fatalf("normal mode lost child exit status: %d", code)
	}
	if _, _, code := f.invoke("", "--run", "envh-nonexistent-fixture-command"); code != 127 {
		t.Fatalf("normal mode lost missing-command exit status: %d", code)
	}
}

func TestMacNormalRunForwardsInterrupt(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Seatbelt integration")
	}
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	c := f.cmd("--run", "/bin/sh", "-c", "echo ready; exec sleep 30")
	stdout, err := c.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Process.Kill()
	ready := make([]byte, 6)
	if _, err = io.ReadFull(stdout, ready); err != nil || string(ready) != "ready\n" {
		t.Fatalf("child did not start: %q, %v", ready, err)
	}
	if err = c.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { finished <- c.Wait() }()
	select {
	case err := <-finished:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 130 {
			t.Fatalf("interrupt exit = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("normal run did not forward interrupt")
	}
}

func TestEnvironmentOverlayRemovesControlVariables(t *testing.T) {
	got := environment([]string{"PATH=/bin", "TOKEN=old", "TOKEN=duplicate", "envh_passphrase=canary", "ENVH_HOME=/private/state"}, map[string]string{"TOKEN": "new", "EMPTY": ""})
	if strings.Join(got, "\n") != "EMPTY=\nPATH=/bin\nTOKEN=new" {
		t.Fatalf("unexpected environment: %v", got)
	}
}

func TestManageEditsAndKeepsComments(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	f.ok("first", "set", "ONE", "--stdin")
	apply := func(doc string) {
		t.Helper()
		c := f.cmd("manage")
		c.Env = append(c.Env, "VISUAL="+f.exe+" __editor", "EDITOR_FIXTURE="+doc)
		out, e := c.CombinedOutput()
		if e != nil {
			t.Fatalf("manage failed: %v: %s", e, out)
		}
	}
	apply("# Keep this note\nONE=\"changed\"\n# TWO=disabled\nTHREE=\"new\"\n")
	if got := f.ok("", "list"); got != "ONE\nTHREE\n" {
		t.Fatalf("commented entry active: %q", got)
	}
	if got := f.ok("", "get", "ONE"); got != "changed" {
		t.Fatal("edit not applied")
	}
	// A later set updates the active line while preserving the comment.
	f.ok("again", "set", "ONE", "--stdin")
	c := f.cmd("manage")
	c.Env = append(c.Env, "VISUAL="+f.exe+" __editor")
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("open failed: %v: %s", e, out)
	}
	// Inspect the encrypted document through the package API, not raw file bytes.
	id, e := project.Read(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	s := &vault.Store{Dir: filepath.Join(f.home, "projects")}
	_, _, doc, e := s.LoadDocument(id, "synthetic test passphrase")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(doc, "# Keep this note") || !strings.Contains(doc, "# TWO=disabled") || !strings.Contains(doc, "ONE=\"again\"") {
		t.Fatalf("document was not preserved: %q", doc)
	}
}

func TestManageRejectsMalformedEditWithoutChangingVault(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	f.ok("good", "set", "ONE", "--stdin")
	c := f.cmd("manage")
	c.Env = append(c.Env, "VISUAL="+f.exe+" __editor", "EDITOR_FIXTURE=ONE=\"unterminated")
	if e := c.Run(); e == nil {
		t.Fatal("invalid editor result saved")
	}
	if got := f.ok("", "get", "ONE"); got != "good" {
		t.Fatal("vault changed after invalid edit")
	}
}

func TestPolicyEditorRepairsMalformedPolicy(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	id, err := project.Read(f.dir)
	if err != nil {
		t.Fatal(err)
	}
	path, err := policyPath(&vault.Store{Dir: filepath.Join(f.home, "projects")}, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("default invalid\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c := f.cmd("policy", "manage")
	c.Env = append(c.Env, "VISUAL="+f.exe+" __editor", "EDITOR_FIXTURE=default block\nallow example.com\n")
	if out, err := c.CombinedOutput(); err != nil {
		t.Fatalf("policy repair failed: %v: %s", err, out)
	}
	if got := f.ok("", "policy", "show"); got != "default block\nallow example.com\n" {
		t.Fatalf("policy not repaired: %q", got)
	}
}

func TestChangePassphraseKeepsValuesAndComments(t *testing.T) {
	f := newFixture(t)
	f.ok("", "init", "--passphrase")
	f.ok("old-value", "set", "ONE", "--stdin")
	c := f.cmd("manage")
	c.Env = append(c.Env, "VISUAL="+f.exe+" __editor", "EDITOR_FIXTURE=# retained\nONE=\"old-value\"\n")
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("manage: %v %s", e, out)
	}
	c = f.cmd("passwd")
	c.Env = append(c.Env, "ENVH_NEW_PASSPHRASE=new synthetic password")
	if out, e := c.CombinedOutput(); e != nil {
		t.Fatalf("passwd: %v %s", e, out)
	}
	if _, _, code := f.invoke("", "get", "ONE"); code == 0 {
		t.Fatal("old password still opens vault")
	}
	c = f.cmd("get", "ONE")
	for i, v := range c.Env {
		if strings.HasPrefix(v, "ENVH_PASSPHRASE=") {
			c.Env[i] = "ENVH_PASSPHRASE=new synthetic password"
		}
	}
	out, e := c.Output()
	if e != nil || string(out) != "old-value" {
		t.Fatalf("new password failed: %v %s", e, out)
	}
	id, _ := project.Read(f.dir)
	s := &vault.Store{Dir: filepath.Join(f.home, "projects")}
	_, _, document, e := s.LoadDocument(id, "new synthetic password")
	if e != nil || !strings.Contains(document, "# retained") {
		t.Fatalf("comment lost after rekey: %v %q", e, document)
	}
}
