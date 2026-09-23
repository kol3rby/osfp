// Package osdetect identifies the operating system, its version and its
// architecture, and derives from them the fingerprint key that names the
// fingerprint file and guards the comparison.
//
// Detection reads files first and forks a process only as a last resort: a
// fingerprint is often taken on a freshly installed or partly broken system,
// where reading /etc/os-release works long after running a helper binary has
// stopped working.
//
// Every parser here is a pure function over bytes, and the system facilities
// they need are reached through the env struct. That is deliberate: CI runs on
// Linux, so the Solaris, macOS, AIX and BSD paths would otherwise never be
// executed by a single test. With env, all of them are tested everywhere, from
// captured fixtures.
package osdetect

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// maxComponent caps each component of the key. A key ends up in a file name
// and in the fingerprint header; a system that reports a paragraph as its
// version must not produce an unusable path.
const maxComponent = 32

// Info is everything osfp knows about the scanned system. It is recorded as-is
// in the fingerprint header, where it serves both to check that a comparison
// is being run against the right system and to make a report readable months
// later.
type Info struct {
	OS       string // GOOS: linux, freebsd, openbsd, netbsd, solaris, illumos, darwin, aix
	Distro   string // debian, alpine, omnios, macos… empty when the OS has no notion of one
	Version  string // 12, 24.04, 11.4, r151046 — empty on a rolling release
	Arch     string // GOARCH
	Kernel   string // uname release, or the build identifier that plays that role
	Pretty   string // human-readable name, for report headers
	Hostname string
	Source   string // what the version was read from, e.g. "/etc/os-release"
}

// Key returns the fingerprint key, for instance "linux-debian-12-amd64".
//
// The distro is omitted when it adds nothing to the OS name, which is why
// Solaris yields "solaris-11.4-sparc64" and not "solaris-solaris-11.4-sparc64".
// A missing version is dropped rather than replaced by a placeholder: a rolling
// release honestly has none, and "linux-arch-amd64" says so.
func (i Info) Key() string {
	parts := make([]string, 0, 4)
	add := func(s string) {
		if c := normalizeComponent(s); c != "" {
			parts = append(parts, c)
		}
	}
	add(i.OS)
	if !strings.EqualFold(i.Distro, i.OS) {
		add(i.Distro)
	}
	add(i.Version)
	add(i.Arch)
	if len(parts) == 0 {
		return "unknown"
	}
	return strings.Join(parts, "-")
}

// String returns the most descriptive one-line form available.
func (i Info) String() string {
	if i.Pretty != "" {
		return fmt.Sprintf("%s (%s)", i.Pretty, i.Key())
	}
	return i.Key()
}

// NormalizeKey validates and normalises a key supplied by the user through
// --os-id, so that a hand-written key and a detected one are spelled the same
// way and end up in the same file name.
func NormalizeKey(s string) (string, error) {
	parts := strings.Split(s, "-")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if c := normalizeComponent(p); c != "" {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return "", fmt.Errorf("os key %q is empty once normalized", s)
	}
	return strings.Join(out, "-"), nil
}

// normalizeComponent lowercases a component, keeps only letters, digits and
// dots, and turns every other byte into a separator.
//
// Dots survive because they carry meaning in a version — "freebsd-14.1-amd64"
// reads as a version where "freebsd-14-1-amd64" reads as two components. The
// comparison is done on raw bytes, so no Unicode case folding is attempted:
// a non-ASCII byte is a separator, which is the conservative answer for
// something that becomes a file name.
func normalizeComponent(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	dash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
			fallthrough
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.':
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteByte(c)
		default:
			dash = b.Len() > 0
		}
		if b.Len() >= maxComponent {
			break
		}
	}
	return strings.Trim(b.String(), ".-")
}

// utsname is the portable subset of uname(2) that osfp uses.
type utsname struct {
	Sysname  string
	Nodename string
	Release  string
	Version  string
	Machine  string
}

// env is the set of system facilities the detectors use. Production code uses
// hostEnv; tests build one from fixtures.
type env struct {
	goos     string
	goarch   string
	readFile func(name string) ([]byte, error)
	uname    func() (utsname, error)
	hostname func() (string, error)
	run      func(name string, args ...string) (string, error)
}

func hostEnv() env {
	return env{
		goos:     runtime.GOOS,
		goarch:   runtime.GOARCH,
		readFile: os.ReadFile,
		uname:    sysUname,
		hostname: os.Hostname,
		run:      runCommand,
	}
}

// runCommand is the last-resort path: a helper binary. It is bounded in time
// because a hung helper must not hang a scan.
func runCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s: %w", name, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Detect identifies the running system.
//
// It returns an Info even when it cannot name the distribution: a key such as
// "linux-amd64" is still usable, and refusing to produce anything would leave
// the operator with no way forward on an unknown system. It returns an error
// only for an operating system osfp does not support at all.
func Detect() (*Info, error) { return detect(hostEnv()) }

func detect(e env) (*Info, error) {
	info := &Info{OS: e.goos, Arch: e.goarch}
	if h, err := e.hostname(); err == nil {
		info.Hostname = h
	}
	if u, err := e.uname(); err == nil {
		info.Kernel = u.Release
		if info.Arch == "" {
			info.Arch = u.Machine
		}
	}

	switch e.goos {
	case "linux":
		detectLinux(e, info)
	case "freebsd", "openbsd", "netbsd", "dragonfly":
		detectBSD(e, info)
	case "solaris", "illumos":
		detectSolaris(e, info)
	case "darwin":
		detectDarwin(e, info)
	case "aix":
		detectAIX(e, info)
	default:
		return info, fmt.Errorf("unsupported operating system %q", e.goos)
	}
	return info, nil
}

// firstLine returns the first non-empty, trimmed line of b.
func firstLine(b []byte) string {
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			return line
		}
	}
	return ""
}

// isNumericVersion reports whether s looks like 11, 11.4 or 7.9.2009.
func isNumericVersion(s string) bool {
	if s == "" {
		return false
	}
	digit := false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] >= '0' && s[i] <= '9':
			digit = true
		case s[i] == '.':
		default:
			return false
		}
	}
	return digit
}
