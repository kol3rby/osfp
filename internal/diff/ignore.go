package diff

import (
	"fmt"
	"os"
	"strings"

	"osfp/internal/exclude"
)

// Ignore drops classified changes the operator has decided not to see.
//
// The filter is applied after classification, never before: a change that is
// ignored is still counted, so the summary can say "1,240 differences hidden
// by ignore rules". A rule that silently shrinks a scan and a rule that
// silently shrinks a report are not the same thing, and only the second is
// acceptable in an audit.
type Ignore struct {
	rules []ignoreRule
}

type ignoreRule struct {
	ops   map[Op]bool // nil means every category
	match *exclude.Set
	raw   string
}

// LoadIgnore reads rules from a file, one per line.
func LoadIgnore(path string) (*Ignore, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseIgnore(strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"))
}

// ParseIgnore compiles rules of the form
//
//	/var/lib/myapp            every change under this path
//	~F,%F:/etc/adjtime        only these categories, for this path
//	*.pyc                     every change to a file with this name
//
// The pattern syntax is the one --exclude uses, so an operator who has written
// one has already learned the other.
func ParseIgnore(lines []string) (*Ignore, error) {
	ig := &Ignore{}
	for n, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		raw := line

		var ops map[Op]bool
		if codes, pattern, found := strings.Cut(line, ":"); found {
			parsed, err := ParseOps(codes)
			if err != nil {
				return nil, fmt.Errorf("ignore rule on line %d: %w", n+1, err)
			}
			ops, line = parsed, strings.TrimSpace(pattern)
		}
		if line == "" {
			return nil, fmt.Errorf("ignore rule on line %d has no pattern: %q", n+1, raw)
		}

		set, err := exclude.New(exclude.Options{
			NoDefaults:  true,
			NoVolatiles: true,
			Patterns:    []string{line},
		})
		if err != nil {
			return nil, fmt.Errorf("ignore rule on line %d: %w", n+1, err)
		}
		ig.rules = append(ig.rules, ignoreRule{ops: ops, match: set, raw: raw})
	}
	return ig, nil
}

// Match reports whether a classified change is covered by a rule.
func (i *Ignore) Match(op Op, path string) bool {
	if i == nil {
		return false
	}
	for _, r := range i.rules {
		if r.ops != nil && !r.ops[op] {
			continue
		}
		if r.match.Match(path) {
			return true
		}
	}
	return false
}

// Rules returns the rules as written, for the report header.
func (i *Ignore) Rules() []string {
	if i == nil {
		return nil
	}
	out := make([]string, len(i.rules))
	for j, r := range i.rules {
		out[j] = r.raw
	}
	return out
}
