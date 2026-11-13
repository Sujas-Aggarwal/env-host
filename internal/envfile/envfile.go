// Package envfile parses dotenv data without executing or expanding it.
package envfile

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxBytes = 1 << 20

var namePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

func ValidName(name string) bool {
	return namePattern.MatchString(name) && !strings.HasPrefix(strings.ToUpper(name), "ENVH_")
}
func Validate(values map[string]string) error {
	if len(values) > 1024 {
		return fmt.Errorf("too many variables (maximum 1024)")
	}
	size := 0
	for k, v := range values {
		if !ValidName(k) {
			return fmt.Errorf("invalid or reserved variable name")
		}
		if !utf8.ValidString(v) || strings.ContainsRune(v, 0) || len(v) > 65536 {
			return fmt.Errorf("invalid or oversized value for %s", k)
		}
		size += len(k) + len(v)
	}
	if size > MaxBytes {
		return fmt.Errorf("environment exceeds 1 MiB")
	}
	return nil
}

// Parse accepts single-line quoted values, export prefixes and comments.
// Duplicate declarations use the last value. Diagnostics never contain values.
func Parse(r io.Reader) (map[string]string, []string, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("cannot read environment file")
	}
	if len(data) > MaxBytes || !utf8.Valid(data) {
		return nil, nil, fmt.Errorf("environment file is oversized or not UTF-8")
	}
	values := map[string]string{}
	duplicates := map[string]bool{}
	s := bufio.NewScanner(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	s.Buffer(make([]byte, 4096), MaxBytes+1)
	line := 0
	for s.Scan() {
		line++
		text := strings.TrimSpace(s.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		if strings.HasPrefix(text, "export ") || strings.HasPrefix(text, "export\t") {
			text = strings.TrimSpace(text[6:])
		}
		k, v, ok := strings.Cut(text, "=")
		k = strings.TrimSpace(k)
		if !ok || !ValidName(k) {
			return nil, nil, fmt.Errorf("invalid declaration on line %d", line)
		}
		value, err := parseValue(strings.TrimSpace(v))
		if err != nil {
			return nil, nil, fmt.Errorf("invalid value on line %d", line)
		}
		if _, ok := values[k]; ok {
			duplicates[k] = true
		}
		values[k] = value
	}
	if err := s.Err(); err != nil {
		return nil, nil, fmt.Errorf("cannot parse environment file")
	}
	if err := Validate(values); err != nil {
		return nil, nil, err
	}
	names := make([]string, 0, len(duplicates))
	for n := range duplicates {
		names = append(names, n)
	}
	sort.Strings(names)
	return values, names, nil
}

func parseValue(v string) (string, error) {
	if v == "" {
		return "", nil
	}
	if v[0] != '\'' && v[0] != '"' {
		for i := 0; i < len(v); i++ {
			if v[i] == '#' && (i == 0 || v[i-1] == ' ' || v[i-1] == '\t') {
				v = v[:i]
				break
			}
		}
		return strings.TrimSpace(v), nil
	}
	quote := v[0]
	end := -1
	for i := 1; i < len(v); i++ {
		if quote == '"' && v[i] == '\\' {
			i++
			continue
		}
		if v[i] == quote {
			end = i
			break
		}
	}
	if end < 0 {
		return "", fmt.Errorf("unterminated quote")
	}
	tail := strings.TrimSpace(v[end+1:])
	if tail != "" && !strings.HasPrefix(tail, "#") {
		return "", fmt.Errorf("trailing input")
	}
	if quote == '\'' {
		return v[1:end], nil
	}
	// Go's quoted escapes cover all control bytes emitted by the editor renderer.
	// Unquote only decodes escapes; it never expands variables or runs commands.
	return strconv.Unquote(v[:end+1])
}
