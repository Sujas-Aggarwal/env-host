package policy

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const MaxBytes = 64 << 10

const DefaultDocument = `# Network rules: block wins over allow, then default applies.
# A rule may include a port, for example allow api.example.com:443.
# *.example.com matches subdomains only.
default block
# allow api.example.com
# block *.ads.example.com

# Extra readable and writable directories, relative to this project or absolute.
# read ./data
# write ./build
`

type Rule struct {
	Allow bool
	Host  string
	Port  string
}

type Policy struct {
	DefaultAllow bool
	Rules        []Rule
	ReadDirs     []string
	WriteDirs    []string
}

func Parse(document, root string) (Policy, error) {
	var p Policy
	if len(document) > MaxBytes {
		return p, fmt.Errorf("policy exceeds %d bytes", MaxBytes)
	}
	seenDefault := false
	for i, raw := range strings.Split(document, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		fail := func(message string) (Policy, error) {
			return Policy{}, fmt.Errorf("policy line %d: %s", i+1, message)
		}
		switch fields[0] {
		case "default":
			if len(fields) != 2 || seenDefault || (fields[1] != "allow" && fields[1] != "block") {
				return fail("expected one default allow or default block rule")
			}
			p.DefaultAllow = fields[1] == "allow"
			seenDefault = true
		case "allow", "block":
			if len(fields) != 2 {
				return fail("expected one host or host:port")
			}
			host, port, err := parsePattern(fields[1])
			if err != nil {
				return fail(err.Error())
			}
			p.Rules = append(p.Rules, Rule{Allow: fields[0] == "allow", Host: host, Port: port})
		case "read", "write":
			arg := strings.TrimSpace(strings.TrimPrefix(line, fields[0]))
			if arg == "" {
				return fail("expected a directory")
			}
			dir, err := directory(root, arg)
			if err != nil {
				return fail(err.Error())
			}
			if fields[0] == "read" {
				p.ReadDirs = append(p.ReadDirs, dir)
			} else {
				p.WriteDirs = append(p.WriteDirs, dir)
			}
		default:
			return fail("unknown rule; use default, allow, block, read, or write")
		}
	}
	return p, nil
}

func directory(root, arg string) (string, error) {
	if strings.ContainsAny(arg, "\x00\r\n") || strings.HasPrefix(arg, "~") {
		return "", fmt.Errorf("invalid directory path")
	}
	if !filepath.IsAbs(arg) {
		arg = filepath.Join(root, arg)
	}
	physical, err := filepath.EvalSymlinks(arg)
	if err != nil {
		return "", fmt.Errorf("directory must already exist: %s", arg)
	}
	info, err := os.Stat(physical)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", arg)
	}
	return physical, nil
}

func parsePattern(input string) (string, string, error) {
	host, port := input, ""
	if strings.HasPrefix(input, "[") {
		end := strings.IndexByte(input, ']')
		if end < 0 {
			return "", "", fmt.Errorf("invalid IPv6 address")
		}
		host = input[1:end]
		if len(input) > end+1 {
			if input[end+1] != ':' {
				return "", "", fmt.Errorf("invalid port")
			}
			port = input[end+2:]
		}
	} else if strings.Count(input, ":") == 1 {
		host, port, _ = strings.Cut(input, ":")
	}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid port")
		}
		port = strconv.Itoa(n)
	} else if strings.HasSuffix(input, ":") {
		return "", "", fmt.Errorf("invalid port")
	}
	if strings.Count(host, ":") > 0 && net.ParseIP(host) == nil {
		return "", "", fmt.Errorf("invalid host")
	}
	host, err := NormalizeHost(host)
	if err != nil {
		return "", "", err
	}
	return host, port, nil
}

func NormalizeHost(input string) (string, error) {
	host := strings.ToLower(strings.TrimSuffix(input, "."))
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	} else if strings.ContainsAny(host, "[]") {
		return "", fmt.Errorf("invalid host")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), nil
	}
	wild := strings.HasPrefix(host, "*.")
	if wild {
		host = strings.TrimPrefix(host, "*.")
	}
	if len(host) == 0 || len(host) > 253 || strings.Contains(host, "..") {
		return "", fmt.Errorf("invalid host")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", fmt.Errorf("invalid host")
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return "", fmt.Errorf("invalid host")
			}
		}
	}
	if wild {
		return "*." + host, nil
	}
	return host, nil
}

// Decide gives block rules precedence over allow rules, then applies default.
// IP literals require an explicit allow rule even when the default is allow.
func (p Policy) Decide(host, port string) (allowed, explicit bool) {
	host, err := NormalizeHost(host)
	if err != nil {
		return false, false
	}
	matchedAllow := false
	literalIP := net.ParseIP(host) != nil
	for _, rule := range p.Rules {
		if rule.Port != "" && rule.Port != port {
			continue
		}
		match := host == rule.Host
		if strings.HasPrefix(rule.Host, "*.") {
			match = !literalIP && strings.HasSuffix(host, rule.Host[1:]) && host != rule.Host[2:]
		}
		if !match {
			continue
		}
		if !rule.Allow {
			return false, true
		}
		matchedAllow = true
	}
	if matchedAllow {
		return true, true
	}
	if literalIP {
		return false, false
	}
	return p.DefaultAllow, false
}
