package osdetect

import "strings"

// osReleasePaths are the two locations of os-release(5), in the order the
// specification mandates: /etc wins over the vendor copy in /usr/lib.
var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// readOSRelease returns the parsed os-release file and the path it came from.
func readOSRelease(e env) (map[string]string, string) {
	for _, path := range osReleasePaths {
		b, err := e.readFile(path)
		if err != nil {
			continue
		}
		if kv := parseOSRelease(b); len(kv) > 0 {
			return kv, path
		}
	}
	return nil, ""
}

// parseOSRelease reads the KEY=VALUE format of os-release(5). Values may be
// single- or double-quoted; inside double quotes, a backslash escapes the next
// byte. Unknown lines are skipped rather than reported: the file is written by
// distributions, not by osfp, and a stray line must not stop a scan.
func parseOSRelease(b []byte) map[string]string {
	kv := make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || key == "" {
			continue
		}
		kv[key] = unquote(strings.TrimSpace(value))
	}
	return kv
}

func unquote(s string) string {
	if len(s) < 2 {
		return s
	}
	switch q := s[0]; {
	case q == '\'' && s[len(s)-1] == '\'':
		return s[1 : len(s)-1]
	case q == '"' && s[len(s)-1] == '"':
		s = s[1 : len(s)-1]
		if !strings.Contains(s, `\`) {
			return s
		}
		var b strings.Builder
		b.Grow(len(s))
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}
