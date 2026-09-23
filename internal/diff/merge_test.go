package diff

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"

	"osfp/internal/scan"
)

// source mimics a real fingerprint cursor, down to the part that matters: it
// returns a pointer to one reused entry, so a joiner that kept the pointer
// across a call would be caught here rather than in production.
type source struct {
	entries []scan.Entry
	i       int
	cur     scan.Entry
}

func (s *source) Next() (*scan.Entry, error) {
	if s.i >= len(s.entries) {
		s.cur = scan.Entry{}
		return nil, io.EOF
	}
	s.cur = s.entries[s.i]
	s.i++
	return &s.cur, nil
}

// entry builds an entry from a compact description: the path, the type letter,
// and a content marker that becomes the hash.
func entry(path string, typ scan.Type, content string) scan.Entry {
	e := scan.Entry{Path: path, Type: typ, Mode: 0o644, Size: int64(len(content)), MTime: 1700000000}
	if typ == scan.TypeDir {
		e.Mode = 0o755
	}
	if typ == scan.TypeFile {
		copy(e.Hash[:], content)
		e.Hashed = true
	}
	if typ == scan.TypeSymlink {
		e.Link = content
	}
	return e
}

// join runs a complete comparison and returns the changes as "OP PATH".
func join(t *testing.T, base, live []scan.Entry, opts Options) ([]string, Stats) {
	t.Helper()
	var got []string
	j, err := NewJoiner(&source{entries: base}, opts, func(c *Change) error {
		got = append(got, fmt.Sprintf("%s %s", c.Op, c.Path))
		checkChangeShape(t, c)
		return nil
	})
	if err != nil {
		t.Fatalf("NewJoiner: %v", err)
	}
	for i := range live {
		if err := j.Feed(&live[i]); err != nil {
			t.Fatalf("Feed(%s): %v", live[i].Path, err)
		}
	}
	stats, err := j.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return got, stats
}

// checkChangeShape verifies that every change carries the sides it claims.
func checkChangeShape(t *testing.T, c *Change) {
	t.Helper()
	switch c.Op {
	case OpAdded, OpAddedDir:
		if c.Old != nil || c.New == nil {
			t.Errorf("%s %s: an addition must carry only the live entry", c.Op, c.Path)
		}
	case OpRemoved, OpRemovedDir:
		if c.Old == nil || c.New != nil {
			t.Errorf("%s %s: a deletion must carry only the recorded entry", c.Op, c.Path)
		}
	default:
		if c.Old == nil || c.New == nil {
			t.Errorf("%s %s: a modification must carry both sides", c.Op, c.Path)
		}
	}
	if c.New != nil && c.New.Path != c.Path {
		t.Errorf("%s: the live entry is for %s", c.Path, c.New.Path)
	}
	if c.Old != nil && c.Old.Path != c.Path {
		t.Errorf("%s: the recorded entry is for %s", c.Path, c.Old.Path)
	}
}

func TestJoin(t *testing.T) {
	tests := []struct {
		name       string
		base, live []scan.Entry
		want       []string
	}{
		{
			name: "both empty",
		},
		{
			name: "everything was deleted",
			base: []scan.Entry{
				entry("/etc", scan.TypeDir, ""),
				entry("/etc/passwd", scan.TypeFile, "a"),
			},
			want: []string{"-D /etc", "-F /etc/passwd"},
		},
		{
			name: "everything is new",
			live: []scan.Entry{
				entry("/etc", scan.TypeDir, ""),
				entry("/etc/passwd", scan.TypeFile, "a"),
			},
			want: []string{"+D /etc", "+F /etc/passwd"},
		},
		{
			name: "unchanged produces nothing",
			base: []scan.Entry{entry("/etc", scan.TypeDir, ""), entry("/etc/passwd", scan.TypeFile, "a")},
			live: []scan.Entry{entry("/etc", scan.TypeDir, ""), entry("/etc/passwd", scan.TypeFile, "a")},
		},
		{
			name: "interleaved additions and deletions",
			base: []scan.Entry{
				entry("/a", scan.TypeFile, "1"),
				entry("/c", scan.TypeFile, "3"),
				entry("/e", scan.TypeFile, "5"),
			},
			live: []scan.Entry{
				entry("/b", scan.TypeFile, "2"),
				entry("/c", scan.TypeFile, "3"),
				entry("/d", scan.TypeFile, "4"),
			},
			want: []string{"-F /a", "+F /b", "+F /d", "-F /e"},
		},
		{
			// The pair a plain byte comparison of whole paths gets wrong:
			// /a/b sorts before /a.txt. If the join used the wrong order it
			// would report both as added and both as deleted.
			name: "canonical order around the separator",
			base: []scan.Entry{
				entry("/a", scan.TypeDir, ""),
				entry("/a/b", scan.TypeFile, "1"),
				entry("/a.txt", scan.TypeFile, "2"),
			},
			live: []scan.Entry{
				entry("/a", scan.TypeDir, ""),
				entry("/a/b", scan.TypeFile, "1"),
				entry("/a.txt", scan.TypeFile, "changed"),
			},
			want: []string{"~F /a.txt"},
		},
		{
			name: "a directory replaced by a file",
			base: []scan.Entry{entry("/x", scan.TypeDir, "")},
			live: []scan.Entry{entry("/x", scan.TypeFile, "a")},
			want: []string{"!T /x"},
		},
		{
			name: "deletion at the end of the fingerprint",
			base: []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/z", scan.TypeFile, "2")},
			live: []scan.Entry{entry("/a", scan.TypeFile, "1")},
			want: []string{"-F /z"},
		},
		{
			name: "addition at the end of the scan",
			base: []scan.Entry{entry("/a", scan.TypeFile, "1")},
			live: []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/z", scan.TypeFile, "2")},
			want: []string{"+F /z"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, stats := join(t, tt.base, tt.live, Options{})
			if !slices.Equal(got, tt.want) {
				t.Errorf("changes = %v, want %v", got, tt.want)
			}
			if stats.Total() != int64(len(tt.want)) {
				t.Errorf("Stats.Total() = %d, want %d", stats.Total(), len(tt.want))
			}
		})
	}
}

func TestJoinCountsComparisons(t *testing.T) {
	base := []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/b", scan.TypeFile, "2")}
	live := []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/c", scan.TypeFile, "3")}
	_, stats := join(t, base, live, Options{})
	if stats.Compared != 1 {
		t.Errorf("Compared = %d, want 1 (only /a is on both sides)", stats.Compared)
	}
	if stats.Counts[OpRemoved] != 1 || stats.Counts[OpAdded] != 1 {
		t.Errorf("counts = %v", stats.Counts)
	}
}

func TestJoinShowFilter(t *testing.T) {
	base := []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/b", scan.TypeFile, "2")}
	live := []scan.Entry{entry("/a", scan.TypeFile, "changed"), entry("/c", scan.TypeFile, "3")}

	got, stats := join(t, base, live, Options{Show: map[Op]bool{OpChangedFile: true}})
	if !slices.Equal(got, []string{"~F /a"}) {
		t.Errorf("changes = %v, want only the content change", got)
	}
	if stats.Hidden != 2 {
		t.Errorf("Hidden = %d, want 2", stats.Hidden)
	}
	if stats.Total() != 1 {
		t.Errorf("Total() = %d, want 1: hidden changes are not counted as reported", stats.Total())
	}
}

func TestJoinIgnoreRules(t *testing.T) {
	ig, err := ParseIgnore([]string{
		"# noise from the package manager",
		"/var/lib/dpkg",
		"~F,%F:/etc/adjtime",
		"*.pyc",
	})
	if err != nil {
		t.Fatalf("ParseIgnore: %v", err)
	}

	base := []scan.Entry{
		entry("/etc/adjtime", scan.TypeFile, "1"),
		entry("/etc/passwd", scan.TypeFile, "1"),
		entry("/usr/lib/x.pyc", scan.TypeFile, "1"),
		entry("/var/lib/dpkg/status", scan.TypeFile, "1"),
	}
	live := []scan.Entry{
		entry("/etc/adjtime", scan.TypeFile, "changed"),
		entry("/etc/passwd", scan.TypeFile, "changed"),
		entry("/usr/lib/x.pyc", scan.TypeFile, "changed"),
		entry("/var/lib/dpkg/status", scan.TypeFile, "changed"),
	}

	got, stats := join(t, base, live, Options{Ignore: ig})
	if !slices.Equal(got, []string{"~F /etc/passwd"}) {
		t.Errorf("changes = %v, want only /etc/passwd", got)
	}
	if stats.Ignored != 3 {
		t.Errorf("Ignored = %d, want 3", stats.Ignored)
	}

	t.Run("the category selector is honoured", func(t *testing.T) {
		// The rule covers ~F and %F for /etc/adjtime, so a deletion of it is
		// still reported.
		got, _ := join(t,
			[]scan.Entry{entry("/etc/adjtime", scan.TypeFile, "1")},
			nil,
			Options{Ignore: ig})
		if !slices.Equal(got, []string{"-F /etc/adjtime"}) {
			t.Errorf("changes = %v, want the deletion to survive the rule", got)
		}
	})

	if got, want := len(ig.Rules()), 3; got != want {
		t.Errorf("Rules() returned %d rules, want %d (comments dropped)", got, want)
	}
}

func TestParseIgnoreRejectsBadRules(t *testing.T) {
	for _, line := range []string{"~F,zz:/etc", "~F:", "/var/[a-"} {
		if _, err := ParseIgnore([]string{line}); err == nil {
			t.Errorf("ParseIgnore(%q) accepted a malformed rule", line)
		}
	}
	if ig, err := ParseIgnore(nil); err != nil || ig.Match(OpAdded, "/x") {
		t.Errorf("an empty rule set must match nothing: %v, %v", ig, err)
	}
	var nilIgnore *Ignore
	if nilIgnore.Match(OpAdded, "/x") || nilIgnore.Rules() != nil {
		t.Error("a nil Ignore must behave as an empty one")
	}
}

func TestJoinSummarizesAddedDirectoriesOnly(t *testing.T) {
	var asked []string
	opts := Options{
		Summarize: func(path string) *DirSummary {
			asked = append(asked, path)
			return &DirSummary{Files: 412, Dirs: 18, Bytes: 88 << 20}
		},
		Ignore: mustIgnore(t, []string{"/opt/ignored"}),
	}

	base := []scan.Entry{entry("/etc", scan.TypeDir, "")}
	live := []scan.Entry{
		entry("/etc", scan.TypeDir, ""),
		entry("/opt", scan.TypeDir, ""),
		entry("/opt/ignored", scan.TypeDir, ""),
		entry("/srv", scan.TypeFile, "a"),
	}

	var summaries int
	j, err := NewJoiner(&source{entries: base}, opts, func(c *Change) error {
		if c.Summary != nil {
			summaries++
			if c.Op != OpAddedDir {
				t.Errorf("%s carries a directory summary", c.Op)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("NewJoiner: %v", err)
	}
	for i := range live {
		if err := j.Feed(&live[i]); err != nil {
			t.Fatalf("Feed: %v", err)
		}
	}
	if _, err := j.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	if summaries != 1 {
		t.Errorf("%d summaries produced, want 1", summaries)
	}
	// An ignored directory must not be walked: the point of the summary is to
	// avoid work, and doing it for a line nobody will read is the opposite.
	if !slices.Equal(asked, []string{"/opt"}) {
		t.Errorf("summarized %v, want only /opt", asked)
	}
}

func TestJoinRejectsOutOfOrderInput(t *testing.T) {
	j, err := NewJoiner(&source{}, Options{}, func(*Change) error { return nil })
	if err != nil {
		t.Fatalf("NewJoiner: %v", err)
	}
	for _, p := range []string{"/a", "/a.txt"} {
		e := entry(p, scan.TypeFile, "1")
		if err := j.Feed(&e); err != nil {
			t.Fatalf("Feed(%s): %v", p, err)
		}
	}
	// /a/b sorts before /a.txt, so it arrives out of order.
	e := entry("/a/b", scan.TypeFile, "1")
	if err := j.Feed(&e); err == nil || !strings.Contains(err.Error(), "canonical order") {
		t.Fatalf("Feed out of order returned %v, want a canonical order error", err)
	}
}

func TestJoinPropagatesCallbackErrors(t *testing.T) {
	want := errors.New("report is full")
	j, err := NewJoiner(&source{entries: []scan.Entry{entry("/a", scan.TypeFile, "1")}},
		Options{}, func(*Change) error { return want })
	if err != nil {
		t.Fatalf("NewJoiner: %v", err)
	}
	if _, err := j.Finish(); !errors.Is(err, want) {
		t.Fatalf("Finish returned %v, want %v", err, want)
	}
}

func TestJoinCopiesEntries(t *testing.T) {
	// The fingerprint side reuses one entry; a change must not point at it.
	base := []scan.Entry{entry("/a", scan.TypeFile, "1"), entry("/b", scan.TypeFile, "2")}
	var kept []*Change
	j, err := NewJoiner(&source{entries: base}, Options{}, func(c *Change) error {
		kept = append(kept, c)
		return nil
	})
	if err != nil {
		t.Fatalf("NewJoiner: %v", err)
	}
	if _, err := j.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if len(kept) != 2 {
		t.Fatalf("got %d changes, want 2", len(kept))
	}
	if kept[0].Old.Path != "/a" || kept[1].Old.Path != "/b" {
		t.Errorf("changes share a buffer: %s and %s", kept[0].Old.Path, kept[1].Old.Path)
	}
}

func mustIgnore(t *testing.T, lines []string) *Ignore {
	t.Helper()
	ig, err := ParseIgnore(lines)
	if err != nil {
		t.Fatalf("ParseIgnore: %v", err)
	}
	return ig
}

func BenchmarkJoinUnchanged(b *testing.B) {
	const n = 100000
	entries := make([]scan.Entry, n)
	for i := range entries {
		entries[i] = entry(fmt.Sprintf("/usr/share/doc/package-%06d/changelog.gz", i), scan.TypeFile, "x")
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		j, err := NewJoiner(&source{entries: entries}, Options{}, func(*Change) error {
			b.Fatal("an unchanged system produced a change")
			return nil
		})
		if err != nil {
			b.Fatalf("NewJoiner: %v", err)
		}
		for k := range entries {
			if err := j.Feed(&entries[k]); err != nil {
				b.Fatalf("Feed: %v", err)
			}
		}
		if _, err := j.Finish(); err != nil {
			b.Fatalf("Finish: %v", err)
		}
	}
	b.ReportMetric(float64(b.N*n)/b.Elapsed().Seconds(), "entries/s")
}
