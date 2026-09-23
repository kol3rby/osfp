package exclude

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Options describes the three cumulative layers of §6.1.
type Options struct {
	GOOS        string   // which built-in list to use
	Root        string   // the scan root, if it is not "/"
	NoDefaults  bool     // --no-default-excludes
	Patterns    []string // --exclude and --exclude-from
	Auto        []string // computed at run time: the binary, the output files…
	NoVolatiles bool     // do not mark the expected-noise directories
}

// Set answers "must this path be left alone?".
type Set struct {
	root      string   // the scan root, which no prefix may exclude
	prefixes  []string // absolute path prefixes, matched component-wise
	pathGlobs []string // absolute globs, matched against the whole path
	nameGlobs []string // relative patterns, matched against the base name
	volatile  []string
	patterns  []string // every pattern as given, for the fingerprint header
	dropped   []string // prefixes that cover the scan root, so cannot apply
}

// New compiles an exclusion set. It fails on a malformed glob rather than
// silently ignoring it: a pattern that matches nothing because of a typo would
// put files in the fingerprint that the operator believes are out of scope.
func New(o Options) (*Set, error) {
	s := &Set{}
	if o.Root != "" {
		s.root = filepath.Clean(o.Root)
	}
	if !o.NoDefaults {
		if err := s.add(Defaults(o.GOOS)); err != nil {
			return nil, err
		}
	}
	if err := s.add(o.Patterns); err != nil {
		return nil, err
	}
	if err := s.addAuto(o.Auto); err != nil {
		return nil, err
	}
	if !o.NoVolatiles {
		s.volatile = Volatile(o.GOOS)
	}
	return s, nil
}

// addAuto adds the exclusions osfp computes for itself — its own binary, the
// fingerprint it is writing, the report it is writing — and skips any that an
// already-compiled pattern covers.
//
// The skip matters because the recorded list is the audit trail of the
// perimeter: it states what the fingerprint claims to cover. An operator who
// keeps the binary and the output under /tmp, which the built-in list already
// excludes, would otherwise read three entries that change nothing and have to
// work out what they were for. These are not requests from the operator but
// consequences of how the command was invoked, so dropping the inert ones
// loses nothing.
func (s *Set) addAuto(patterns []string) error {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || s.Match(p) {
			continue
		}
		if err := s.addOne(p); err != nil {
			return err
		}
	}
	return nil
}

func (s *Set) add(patterns []string) error {
	for _, p := range patterns {
		p = strings.TrimSpace(p)
		if p == "" || strings.HasPrefix(p, "#") {
			continue
		}
		if err := s.addOne(p); err != nil {
			return err
		}
	}
	return nil
}

// addOne classifies a pattern:
//
//   - "/var/lib/docker"  → a path prefix: the directory and everything under it
//   - "/var/lib/*/cache" → a glob matched against the whole path
//   - "*.swp", ".git"    → a glob matched against the base name, at any depth
//
// The distinction is the leading slash, which is also how an operator reads
// it: an absolute pattern names a place, a relative one names a kind of file.
func (s *Set) addOne(p string) error {
	isGlob := strings.ContainsAny(p, "*?[")

	// A prefix that contains the scan root cannot apply: --root /srv/chroot
	// says the perimeter is that subtree, and the built-in exclusion of /srv
	// would otherwise empty it. The explicit root wins, and the pattern is
	// reported as dropped rather than silently kept in the header.
	if !isGlob && strings.HasPrefix(p, "/") && s.root != "" && under(s.root, filepath.Clean(p)) {
		s.dropped = append(s.dropped, p)
		return nil
	}

	s.patterns = append(s.patterns, p)
	if isGlob {
		if _, err := filepath.Match(p, "/"); err != nil {
			return fmt.Errorf("invalid exclusion pattern %q: %w", p, err)
		}
	}

	if !strings.HasPrefix(p, "/") {
		s.nameGlobs = append(s.nameGlobs, p)
		return nil
	}
	if isGlob {
		s.pathGlobs = append(s.pathGlobs, p)
		return nil
	}
	s.prefixes = append(s.prefixes, filepath.Clean(p))
	return nil
}

// Match reports whether path is excluded. path must be absolute and cleaned,
// which is what the walker produces.
func (s *Set) Match(path string) bool {
	for _, p := range s.prefixes {
		if under(path, p) {
			return true
		}
	}
	for _, g := range s.pathGlobs {
		if ok, _ := filepath.Match(g, path); ok {
			return true
		}
	}
	if len(s.nameGlobs) > 0 {
		base := filepath.Base(path)
		for _, g := range s.nameGlobs {
			if ok, _ := filepath.Match(g, base); ok {
				return true
			}
		}
	}
	return false
}

// Volatile reports whether path sits in a directory whose churn is expected.
// It never prevents a scan; it only tells the report where to file the result.
func (s *Set) Volatile(path string) bool {
	for _, p := range s.volatile {
		if under(path, p) {
			return true
		}
	}
	return false
}

// Patterns returns every pattern in effect, in the order they were added. This
// is what goes into the fingerprint header and what compare checks against.
func (s *Set) Patterns() []string {
	out := make([]string, len(s.patterns))
	copy(out, s.patterns)
	return out
}

// Dropped returns the prefixes that were discarded because they contain the
// scan root. They are not applied and not recorded in the fingerprint, so the
// caller should say so rather than let the difference pass unnoticed.
func (s *Set) Dropped() []string {
	out := make([]string, len(s.dropped))
	copy(out, s.dropped)
	return out
}

// under reports whether path is prefix or sits under it, comparing whole path
// components: /var/tmp excludes /var/tmp/x but never /var/tmpfoo.
func under(path, prefix string) bool {
	if prefix == "/" {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// SelfPaths returns the paths osfp must exclude to avoid fingerprinting
// itself: the binary it is running from, resolved through symlinks.
//
// os.Executable is used rather than os.Args[0], which any caller can set to
// anything at all — and the whole point of the exclusion is that the file it
// names is the one actually being executed.
func SelfPaths() []string {
	exe, err := os.Executable()
	if err != nil {
		return nil
	}
	out := []string{exe}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil && resolved != exe {
		out = append(out, resolved)
	}
	return out
}

// LoadPatterns reads exclusion patterns from a file, one per line. Blank lines
// and lines starting with '#' are comments; they are dropped when the set is
// built, so they never reach the fingerprint header.
func LoadPatterns(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), nil
}
