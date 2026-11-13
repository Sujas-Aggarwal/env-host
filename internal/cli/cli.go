package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"env-host/internal/auth"
	"env-host/internal/envfile"
	"env-host/internal/project"
	"env-host/internal/vault"
)

const Version = "0.2.0"
const help = `envh - project environments, direct host execution

  envh init [--env FILE] [--replace]        Initialize and optionally import
  envh init --passphrase                   Use a project passphrase if Keychain is unavailable
  envh import [--replace] FILE             Import dotenv (last duplicate wins)
  envh set NAME [--stdin]                  Set a value (hidden prompt by default)
  envh get NAME                           Reveal one value to stdout
  envh list                               List variable names only
  envh unset NAME [NAME...]                Delete variables
  envh passwd                             Change a passphrase project's passphrase
  envh manage                             Edit environment in your CLI editor
  envh migrate                            Move a passphrase project to macOS Keychain
  envh auth status                        Check whether macOS user authentication is available
  envh auth probe                         Test Touch ID/login prompt and Keychain access
  envh snap [--force]                      Write names to .env.example
  envh --run COMMAND [ARGS...]             Run with project values injected
  envh --unsafe --run COMMAND [ARGS...]    Same direct execution
  envh --project-id ID --run COMMAND       Select a project explicitly
  envh version

Project variables override inherited variables. Commands run without isolation.
Flags after --run belong to the application. No shell is inserted.
macOS user authentication prompts for Touch ID or the login password before
envh reads a project key from Keychain. Existing passphrase projects remain usable.
Passphrases are read from the terminal or ENVH_PASSPHRASE for automation.
ENVH_HOME selects the local storage directory; envh control variables are not
passed to the application. Each project has its own encrypted vault/passphrase.
Use init --register for an existing marker without a local vault, or
init --new-project to explicitly replace a lost identity at a registered path.
`

func Main(args []string) int {
	code, err := dispatch(args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "envh:", err)
		if code == 0 {
			code = 1
		}
	}
	return code
}
func dispatch(args []string) (int, error) {
	id := ""
	for len(args) > 0 {
		switch args[0] {
		case "--help", "-h", "help":
			fmt.Print(help)
			return 0, nil
		case "--version", "version":
			fmt.Println("envh " + Version)
			return 0, nil
		case "--secure", "--standard":
			return 2, fmt.Errorf("only direct (unsafe) execution is implemented")
		case "--unsafe":
			args = args[1:]
		case "--project-id":
			if len(args) < 2 {
				return 2, fmt.Errorf("--project-id requires a value")
			}
			id = args[1]
			args = args[2:]
		case "--run", "run":
			args = args[1:]
			if len(args) > 0 && args[0] == "--" {
				args = args[1:]
			}
			return run(id, args)
		default:
			return command(id, args[0], args[1:])
		}
	}
	fmt.Print(help)
	return 0, nil
}

// Options may appear before or after operands; --run is parsed separately.
func options(args []string, allowed map[string]bool) (map[string]string, []string, error) {
	opts := map[string]string{}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") {
			positional = append(positional, a)
			continue
		}
		takes, ok := allowed[a]
		if !ok {
			return nil, nil, fmt.Errorf("unknown option %s", a)
		}
		if _, ok = opts[a]; ok {
			return nil, nil, fmt.Errorf("duplicate option %s", a)
		}
		opts[a] = "true"
		if takes {
			i++
			if i == len(args) {
				return nil, nil, fmt.Errorf("%s requires a value", a)
			}
			opts[a] = args[i]
		}
	}
	return opts, positional, nil
}

func command(id, cmd string, args []string) (int, error) {
	allowed := map[string]bool{"--project-id": true}
	switch cmd {
	case "init":
		allowed["--env"] = true
		allowed["--replace"] = false
		allowed["--new-project"] = false
		allowed["--register"] = false
		allowed["--passphrase"] = false
	case "import":
		allowed["--replace"] = false
	case "set":
		allowed["--stdin"] = false
	case "snap":
		allowed["--force"] = false
	case "get", "list", "unset", "manage", "passwd", "migrate", "auth":
	default:
		return 2, fmt.Errorf("unknown command; run envh --help")
	}
	opts, pos, err := options(args, allowed)
	if err != nil {
		return 2, err
	}
	if selected, ok := opts["--project-id"]; ok {
		if id != "" {
			return 2, fmt.Errorf("project specified twice")
		}
		id = selected
	}
	if id != "" {
		if _, err = project.Decode(id); err != nil {
			return 2, err
		}
	}
	if cmd == "auth" {
		if len(pos) != 1 {
			return 2, fmt.Errorf("usage: envh auth status|probe")
		}
		switch pos[0] {
		case "status":
			if err := auth.Ready(); err != nil {
				return 1, err
			}
			fmt.Println("macOS Touch ID or login-password authentication is available.")
		case "probe":
			if err := auth.Probe(); err != nil {
				return 1, err
			}
			fmt.Println("macOS authentication and Keychain access succeeded.")
		default:
			return 2, fmt.Errorf("usage: envh auth status|probe")
		}
		return 0, nil
	}
	switch cmd {
	case "init", "list", "snap", "manage", "passwd", "migrate":
		if len(pos) != 0 {
			return 2, fmt.Errorf("unexpected arguments")
		}
	case "get", "set", "import":
		if len(pos) != 1 {
			return 2, fmt.Errorf("%s requires one argument", cmd)
		}
	case "unset":
		if len(pos) == 0 {
			return 2, fmt.Errorf("unset requires at least one name")
		}
	}
	if cmd == "init" {
		if id != "" {
			return 2, fmt.Errorf("init uses the current directory's identity")
		}
		return 0, initialize(opts)
	}
	if cmd == "manage" {
		return 0, manage(id)
	}
	if cmd == "migrate" {
		return 0, migrate(id)
	}
	selected, root, err := resolve(id)
	if err != nil {
		return 1, err
	}
	store, err := vault.Open()
	if err != nil {
		return 1, err
	}
	// Parse and read input before authentication/storage mutation.
	var incoming map[string]string
	if cmd == "import" {
		incoming, err = readEnv(pos[0])
		if err != nil {
			return 1, err
		}
	}
	if cmd == "set" {
		if !envfile.ValidName(pos[0]) {
			return 2, fmt.Errorf("invalid or reserved variable name")
		}
		value := ""
		if opts["--stdin"] != "" {
			b, e := io.ReadAll(io.LimitReader(os.Stdin, 65537))
			if e != nil {
				return 1, fmt.Errorf("cannot read value")
			}
			value = string(b)
			clear(b)
		} else {
			value, err = hidden("Value: ")
			if err != nil {
				return 1, err
			}
		}
		incoming = map[string]string{pos[0]: value}
		if err = envfile.Validate(incoming); err != nil {
			return 1, err
		}
	}
	pass, err := unlockProject(store, selected)
	if err != nil {
		return 1, err
	}
	unlock, err := store.Lock()
	if err != nil {
		return 1, err
	}
	defer unlock()
	values, registeredRoot, err := store.Load(selected, pass)
	if err != nil {
		return 1, err
	}
	if root == "" {
		root = registeredRoot
	}
	switch cmd {
	case "list":
		for _, n := range names(values) {
			fmt.Println(n)
		}
	case "get":
		v, ok := values[pos[0]]
		if !ok {
			return 1, fmt.Errorf("variable not found")
		}
		_, err = fmt.Fprint(os.Stdout, v)
	case "set":
		values[pos[0]] = incoming[pos[0]]
		err = store.Save(selected, pass, registeredRoot, values)
	case "unset":
		for _, n := range pos {
			if !envfile.ValidName(n) {
				return 2, fmt.Errorf("invalid variable name")
			}
			if _, ok := values[n]; !ok {
				return 1, fmt.Errorf("variable %s not found", n)
			}
		}
		for _, n := range pos {
			delete(values, n)
		}
		err = store.Save(selected, pass, registeredRoot, values)
	case "import":
		err = merge(values, incoming, opts["--replace"] != "")
		if err == nil {
			err = store.Save(selected, pass, registeredRoot, values)
			if err == nil {
				fmt.Printf("Imported %d variables.\n", len(incoming))
			}
		}
	case "snap":
		err = snapshot(root, values, opts["--force"] != "")
	case "passwd":
		method, e := store.AuthMethod(selected)
		if e != nil {
			return 1, e
		}
		if method != "passphrase" {
			return 1, fmt.Errorf("this project uses macOS authentication; no env-host passphrase to change")
		}
		fmt.Fprintln(os.Stderr, "Choose the new passphrase.")
		var next string
		next, err = passwordFrom("ENVH_NEW_PASSPHRASE", true)
		if err == nil {
			_, _, document, readErr := store.LoadDocument(selected, pass)
			if readErr != nil {
				err = readErr
			} else {
				err = store.SaveWithDocument(selected, next, registeredRoot, values, document, "passphrase")
			}
		}
	}
	return 0, err
}

func resolve(id string) (string, string, error) {
	if id != "" {
		if _, err := project.Decode(id); err != nil {
			return "", "", err
		}
		return id, "", nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	return project.Discover(cwd)
}
func names(values map[string]string) []string {
	ns := make([]string, 0, len(values))
	for n := range values {
		ns = append(ns, n)
	}
	sort.Strings(ns)
	return ns
}
func readEnv(path string) (map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, fmt.Errorf("cannot open environment file")
	}
	defer f.Close()
	values, dups, e := envfile.Parse(f)
	if e != nil {
		return nil, e
	}
	for _, n := range dups {
		fmt.Fprintf(os.Stderr, "envh: duplicate %s; using its last declaration\n", n)
	}
	return values, nil
}
func merge(dst, src map[string]string, replace bool) error {
	if !replace {
		for _, n := range names(src) {
			if _, ok := dst[n]; ok {
				return fmt.Errorf("%s already exists; use --replace to overwrite", n)
			}
		}
	}
	for k, v := range src {
		dst[k] = v
	}
	return envfile.Validate(dst)
}

func initialize(opts map[string]string) error {
	cwd, e := os.Getwd()
	if e != nil {
		return e
	}
	root, e := filepath.EvalSymlinks(cwd)
	if e != nil {
		return e
	}
	incoming := map[string]string{}
	if source, ok := opts["--env"]; ok {
		incoming, e = readEnv(source)
		if e != nil {
			return e
		}
	}
	store, e := vault.Open()
	if e != nil {
		return e
	}
	id, e := project.Read(root)
	hasMarker := e == nil
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if hasMarker && opts["--new-project"] != "" {
		return fmt.Errorf("a project marker already exists; refusing to replace it")
	}
	if !hasMarker && opts["--register"] != "" {
		return fmt.Errorf("--register requires an existing .h.env")
	}
	if !hasMarker {
		id = project.NewID()
	}
	exists, e := store.Exists(id)
	if e != nil {
		return e
	}
	if hasMarker && !exists && opts["--register"] == "" {
		return fmt.Errorf("marker found but no local vault; use init --register to create one (this does not recover lost data)")
	}
	if exists && opts["--env"] == "" {
		previous, e := store.Root(id)
		if e != nil {
			return e
		}
		if previous == root {
			if e = ensureIgnored(root); e != nil {
				return e
			}
			fmt.Println("Project already initialized.")
			return nil
		}
	}
	pass, method, e := credentialForInit(store, id, exists, opts["--passphrase"] != "")
	if e != nil {
		return e
	}
	keychainCreated := !exists && method == auth.Method
	finished := false
	defer func() {
		if keychainCreated && !finished {
			locator, _ := project.Locator(id)
			auth.Delete(locator)
		}
	}()
	unlock, e := store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	// Repeat existence checks under the writer lock to prevent lost initialization.
	current, e := store.Exists(id)
	if e != nil {
		return e
	}
	if current != exists {
		return fmt.Errorf("project changed concurrently; retry")
	}
	if !hasMarker {
		if _, e = project.Read(root); e == nil {
			return fmt.Errorf("project was initialized concurrently; retry")
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		registered, e := store.RegisteredRoot(root)
		if e != nil {
			return e
		}
		if registered && opts["--new-project"] == "" {
			return fmt.Errorf("this directory has a registered project but its ID is missing; restore .h.env, or use --new-project for a separate empty identity")
		}
	}
	values := map[string]string{}
	if exists {
		values, _, e = store.Load(id, pass)
		if e != nil {
			return e
		}
	}
	if e = merge(values, incoming, opts["--replace"] != ""); e != nil {
		return e
	}
	if e = ensureIgnored(root); e != nil {
		return e
	}
	// Marker first: interrupted initialization can resume with init --register.
	if !hasMarker {
		if e = project.Write(root, id); e != nil {
			return e
		}
	}
	if !exists && method == auth.Method {
		e = store.SaveWithDocument(id, pass, root, values, vault.Render(values), method)
	} else {
		e = store.Save(id, pass, root, values)
	}
	if e != nil {
		return fmt.Errorf("could not save vault; marker preserved for retry: %w", e)
	}
	finished = true
	fmt.Printf("Initialized project (%d variables).\n", len(values))
	return nil
}

func ensureIgnored(root string) error {
	if exec.Command("git", "-C", root, "ls-files", "--error-unmatch", "--", project.Marker).Run() == nil {
		return fmt.Errorf(".h.env is tracked by Git; untrack it before continuing")
	}
	if exec.Command("git", "-C", root, "check-ignore", "--no-index", "--quiet", "--", project.Marker).Run() == nil {
		return nil
	}
	path := filepath.Join(root, ".gitignore")
	var data []byte
	mode := os.FileMode(0644)
	if info, e := os.Lstat(path); e == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf(".gitignore must be a regular file")
		}
		mode = info.Mode().Perm()
		data, e = os.ReadFile(path)
		if e != nil {
			return e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	trimmed := strings.TrimRight(string(data), "\r\n")
	if trimmed == "/.h.env" || strings.HasSuffix(trimmed, "\n/.h.env") {
		return nil
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		data = append(data, '\n')
	}
	data = append(data, []byte("/.h.env\n")...)
	return vault.AtomicWrite(path, data, mode)
}

func snapshot(root string, values map[string]string, force bool) error {
	path := filepath.Join(root, ".env.example")
	info, e := os.Lstat(path)
	if e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("snapshot target must be a regular file")
		}
		if original, e := os.Stat(filepath.Join(root, ".env")); e == nil && os.SameFile(info, original) {
			return fmt.Errorf("snapshot target aliases .env")
		}
		if !force {
			answer, e := line("Overwrite existing .env.example? [y/N] ")
			if e != nil {
				return fmt.Errorf("snapshot exists; use --force to overwrite noninteractively")
			}
			if strings.ToLower(answer) != "y" && strings.ToLower(answer) != "yes" {
				return fmt.Errorf("snapshot canceled")
			}
		}
	}
	current, checkErr := os.Lstat(path)
	if info == nil {
		if !errors.Is(checkErr, os.ErrNotExist) {
			return fmt.Errorf("snapshot target changed; retry")
		}
	} else if checkErr != nil || !os.SameFile(info, current) || info.Size() != current.Size() || !info.ModTime().Equal(current.ModTime()) {
		return fmt.Errorf("snapshot target changed; retry")
	}
	var b strings.Builder
	for _, n := range names(values) {
		b.WriteString(n + "=\n")
	}
	if e = vault.AtomicWrite(path, []byte(b.String()), 0644); e != nil {
		return e
	}
	fmt.Println("Wrote .env.example.")
	return nil
}

func manage(id string) error {
	selected, _, e := resolve(id)
	if e != nil {
		return e
	}
	store, e := vault.Open()
	if e != nil {
		return e
	}
	pass, e := unlockProject(store, selected)
	if e != nil {
		return e
	}
	unlock, e := store.Lock()
	if e != nil {
		return e
	}
	before, root, document, e := store.LoadDocument(selected, pass)
	unlock()
	if e != nil {
		return e
	}
	work, e := os.CreateTemp(store.Dir, ".envh-edit-*")
	if e != nil {
		return e
	}
	path := work.Name()
	defer os.Remove(path)
	if e = work.Chmod(0600); e == nil {
		_, e = work.WriteString(document)
	}
	if e == nil {
		e = work.Sync()
	}
	closeErr := work.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if e = edit(path); e != nil {
		return e
	}
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > envfile.MaxBytes {
		return fmt.Errorf("editor did not leave a valid environment file")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	defer clear(data)
	modified := string(data)
	after, dups, e := envfile.Parse(strings.NewReader(modified))
	if e != nil {
		return e
	}
	if len(dups) > 0 {
		return fmt.Errorf("duplicate variable %s in edited file", dups[0])
	}
	if modified == document {
		return nil
	}
	unlock, e = store.Lock()
	if e != nil {
		return e
	}
	defer unlock()
	current, currentRoot, currentDoc, e := store.LoadDocument(selected, pass)
	if e != nil {
		return e
	}
	if currentRoot != root || currentDoc != document || !reflect.DeepEqual(current, before) {
		return fmt.Errorf("environment changed while editing; reopen envh manage")
	}
	method, e := store.AuthMethod(selected)
	if e != nil {
		return e
	}
	if e = store.SaveWithDocument(selected, pass, root, after, modified, method); e != nil {
		return e
	}
	fmt.Printf("Saved %d variables.\n", len(after))
	return nil
}

func run(id string, args []string) (int, error) {
	if len(args) == 0 {
		return 2, fmt.Errorf("--run requires an executable")
	}
	id, _, e := resolve(id)
	if e != nil {
		return 1, e
	}
	store, e := vault.Open()
	if e != nil {
		return 1, e
	}
	pass, e := unlockProject(store, id)
	if e != nil {
		return 1, e
	}
	unlock, e := store.Lock()
	if e != nil {
		return 1, e
	}
	values, _, e := store.Load(id, pass)
	unlock()
	if e != nil {
		return 1, e
	}
	env := environment(os.Environ(), values)
	return launch(args, env)
}
func environment(base []string, values map[string]string) []string {
	all := map[string]string{}
	for _, s := range base {
		k, v, ok := strings.Cut(s, "=")
		if ok && !strings.HasPrefix(strings.ToUpper(k), "ENVH_") {
			all[k] = v
		}
	}
	for k, v := range values {
		all[k] = v
	}
	result := make([]string, 0, len(all))
	for _, k := range names(all) {
		result = append(result, k+"="+all[k])
	}
	return result
}
