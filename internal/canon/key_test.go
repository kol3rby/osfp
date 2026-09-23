package canon

import (
	"cmp"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestCompareKey(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"identical", "/etc/passwd", "/etc/passwd", 0},
		{"both empty", "", "", 0},
		{"empty sorts first", "", "/", -1},
		{"root sorts first", "/", "/etc", -1},

		// The case the whole function exists for: '.' is lower than '/' as a
		// raw byte, but a walk descends into the directory first.
		{"directory before its dotted sibling", "/a/b", "/a.txt", -1},
		{"dotted sibling after the directory", "/a.txt", "/a/b", 1},
		{"parent before child", "/a", "/a/b", -1},
		{"child before dotted sibling", "/a/b", "/a.txt", -1},
		{"parent before dotted sibling", "/a", "/a.txt", -1},

		// '-' (0x2D) and '.' (0x2E) are below '/', digits and letters above.
		{"dash sibling after the directory", "/a/b", "/a-b", -1},
		{"digit sibling after the directory", "/a/b", "/a0", -1},
		{"bang sibling after the directory", "/a/b", "/a!", -1},
		{"tilde sibling after the directory", "/a/b", "/a~", -1},

		// Ordinary byte order applies everywhere '/' is not involved.
		{"plain byte order", "/etc/a", "/etc/b", -1},
		{"uppercase before lowercase", "/etc/A", "/etc/a", -1},
		{"prefix name first", "/etc/a", "/etc/ab", -1},
		{"deep before shallow sibling", "/a/b/c/d", "/a/b2", -1},
		{"high bytes compare as bytes", "/\xff", "/\x01", 1},

		// A trailing slash is never produced by the walker, but the order must
		// stay total and antisymmetric if one ever appears.
		{"trailing slash before content", "/a/", "/a/b", -1},
		{"trailing slash after the bare path", "/a", "/a/", -1},

		{"relative paths use the same rule", "a/b", "a.txt", -1},
		{"no leading slash needed", "a", "b", -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CompareKey(tt.a, tt.b); got != tt.want {
				t.Errorf("CompareKey(%q, %q) = %d, want %d", tt.a, tt.b, got, tt.want)
			}
			if got := CompareKey(tt.b, tt.a); got != -tt.want {
				t.Errorf("CompareKey(%q, %q) = %d, want %d (antisymmetry)", tt.b, tt.a, got, -tt.want)
			}
		})
	}
}

// corpus holds paths that exercise the byte values around '/' as well as
// ordinary ones. It is deliberately unsorted.
var corpus = []string{
	"", "/", "/a", "/a/", "/a/b", "/a/b/c", "/a/b.txt", "/a.txt", "/a-b",
	"/a-b/c", "/a0", "/a0/b", "/a!", "/a~", "/a b", "/aa", "/ab", "/b",
	"/etc", "/etc/ssh", "/etc/ssh/sshd_config", "/etc/ssh.old", "/etc/sshd",
	"/usr/lib", "/usr/lib64", "/usr/lib/x", "/usr/libexec", "/var/log",
	"/\xff", "/\x01", "/é", "/e", "a", "a/b", "a.txt",
}

func TestCompareKeyIsATotalOrder(t *testing.T) {
	for _, a := range corpus {
		for _, b := range corpus {
			ab, ba := CompareKey(a, b), CompareKey(b, a)
			if ab != -ba {
				t.Errorf("antisymmetry: CompareKey(%q, %q) = %d but CompareKey(%q, %q) = %d", a, b, ab, b, a, ba)
			}
			if (ab == 0) != (a == b) {
				t.Errorf("CompareKey(%q, %q) = 0 for distinct paths", a, b)
			}
			for _, c := range corpus {
				bc, ac := CompareKey(b, c), CompareKey(a, c)
				if ab < 0 && bc < 0 && ac >= 0 {
					t.Errorf("transitivity: %q < %q < %q but CompareKey(%q, %q) = %d", a, b, c, a, c, ac)
				}
			}
		}
	}
}

// TestCompareKeyMatchesWalkDir is the property this package exists for: a real
// depth-first walk must emit entries in strictly increasing CompareKey order,
// with no sorting step anywhere in the scanner.
func TestCompareKeyMatchesWalkDir(t *testing.T) {
	// Names chosen around the bytes that surround '/': '!' 0x21, ' ' 0x20,
	// '-' 0x2D, '.' 0x2E, '/' 0x2F, '0' 0x30, then letters and a non-ASCII
	// name. Each directory has a sibling file whose name extends it.
	layout := []string{
		"a/",
		"a/b/",
		"a/b/c.txt",
		"a/b.txt",
		"a/c/",
		"a/c/d/",
		"a/c/d/e.txt",
		"a/c.cfg",
		"a.txt",
		"a-b/",
		"a-b/x.txt",
		"a-b.txt",
		"a0/",
		"a0/y.txt",
		"a0.txt",
		"a!",
		"a~",
		"a b",
		"aa/",
		"aa/deep/",
		"aa/deep/deeper/",
		"aa/deep/deeper/leaf",
		"ab.txt",
		"B.txt",
		"é/",
		"é/ü.txt",
		"z/",
		"z/z/",
		"z/z/z",
	}
	root := buildTree(t, layout)

	var walked []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		walked = append(walked, path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}
	if len(walked) != len(layout)+1 { // +1 for the root itself
		t.Fatalf("walked %d entries, want %d", len(walked), len(layout)+1)
	}

	assertStrictlyOrdered(t, walked)
}

// TestCompareKeyMatchesWalkDirOnRandomTrees replays the same property on
// randomly shaped trees, where the interleaving of files and directories is
// not one a human would have thought to write down.
func TestCompareKeyMatchesWalkDirOnRandomTrees(t *testing.T) {
	// Fixed seeds: a failure must be replayable.
	for _, seed := range []int64{1, 2, 3, 20260923} {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) {
			layout := randomLayout(rand.New(rand.NewSource(seed)))
			root := buildTree(t, layout)

			var walked []string
			err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				walked = append(walked, path)
				return nil
			})
			if err != nil {
				t.Fatalf("WalkDir: %v", err)
			}
			assertStrictlyOrdered(t, walked)
		})
	}
}

// TestSortingWithCompareKeyReproducesWalkOrder checks the converse direction:
// sorting a shuffled set of paths with CompareKey yields the walk order. This
// is what lets the fingerprint writer trust the order it is handed.
func TestSortingWithCompareKeyReproducesWalkOrder(t *testing.T) {
	layout := randomLayout(rand.New(rand.NewSource(7)))
	root := buildTree(t, layout)

	var walked []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		walked = append(walked, path)
		return nil
	})
	if err != nil {
		t.Fatalf("WalkDir: %v", err)
	}

	shuffled := slices.Clone(walked)
	rng := rand.New(rand.NewSource(11))
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	slices.SortFunc(shuffled, CompareKey)

	if !slices.Equal(shuffled, walked) {
		for i := range walked {
			if shuffled[i] != walked[i] {
				t.Fatalf("sorted order diverges at index %d: got %q, want %q", i, shuffled[i], walked[i])
			}
		}
		t.Fatal("sorted order differs in length from the walk order")
	}
}

// referenceCompare is the obvious, allocating implementation: compare paths
// one component at a time. CompareKey must agree with it on every input.
func referenceCompare(a, b string) int {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	for i := 0; i < len(as) && i < len(bs); i++ {
		if c := strings.Compare(as[i], bs[i]); c != 0 {
			return c
		}
	}
	return cmp.Compare(len(as), len(bs))
}

func TestCompareKeyAgreesWithReference(t *testing.T) {
	for _, a := range corpus {
		for _, b := range corpus {
			if got, want := CompareKey(a, b), referenceCompare(a, b); got != want {
				t.Errorf("CompareKey(%q, %q) = %d, reference = %d", a, b, got, want)
			}
		}
	}
}

func FuzzCompareKeyAgreesWithReference(f *testing.F) {
	for _, a := range corpus {
		for _, b := range corpus {
			f.Add(a, b)
		}
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		// A NUL byte cannot occur in a path read from a filesystem, and the
		// '/' → 0x00 mapping is only injective without it.
		if strings.ContainsRune(a, 0) || strings.ContainsRune(b, 0) {
			t.Skip()
		}
		if got, want := CompareKey(a, b), referenceCompare(a, b); got != want {
			t.Errorf("CompareKey(%q, %q) = %d, reference = %d", a, b, got, want)
		}
		if got, want := CompareKey(b, a), -CompareKey(a, b); got != want {
			t.Errorf("antisymmetry broken for (%q, %q)", a, b)
		}
	})
}

func BenchmarkCompareKey(b *testing.B) {
	const x = "/usr/lib/x86_64-linux-gnu/perl/5.36.0/auto/POSIX/POSIX.so"
	const y = "/usr/lib/x86_64-linux-gnu/perl/5.36.0/auto/Socket/Socket.so"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if CompareKey(x, y) == 0 {
			b.Fatal("unexpected equality")
		}
	}
}

// buildTree materialises a layout — entries ending in "/" are directories —
// under a fresh temporary directory and returns its root.
func buildTree(t *testing.T, layout []string) string {
	t.Helper()
	root := t.TempDir()
	for _, rel := range layout {
		full := filepath.Join(root, rel)
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(full, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", rel, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(rel), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// randomLayout builds a tree whose names collide on the bytes around '/' far
// more often than a real filesystem would.
func randomLayout(rng *rand.Rand) []string {
	// Suffixes that turn a name into a sibling sorting just before or just
	// after the same name used as a directory.
	suffixes := []string{"", ".txt", ".d", "-1", "0", "!", "~", "a", " b", "Z"}

	var layout []string
	var grow func(prefix string, depth int)
	grow = func(prefix string, depth int) {
		// A name is a file or a directory, never both: the point of the tree
		// is the ordering, not the filesystem's tolerance for collisions.
		used := make(map[string]bool)
		for i := 0; i < 2+rng.Intn(4); i++ {
			name := string(rune('a'+rng.Intn(4))) + suffixes[rng.Intn(len(suffixes))]
			if used[name] {
				continue
			}
			used[name] = true
			path := prefix + name
			if depth > 0 && rng.Intn(2) == 0 {
				layout = append(layout, path+"/")
				grow(path+"/", depth-1)
				continue
			}
			layout = append(layout, path)
		}
	}
	grow("", 4)
	return layout
}

// assertStrictlyOrdered fails if paths is not strictly increasing under
// CompareKey, naming the first offending pair.
func assertStrictlyOrdered(t *testing.T, paths []string) {
	t.Helper()
	if len(paths) < 2 {
		t.Fatalf("expected a non-trivial walk, got %d entries", len(paths))
	}
	for i := 1; i < len(paths); i++ {
		if c := CompareKey(paths[i-1], paths[i]); c >= 0 {
			t.Fatalf("walk order violated at index %d: CompareKey(%q, %q) = %d, want < 0",
				i, paths[i-1], paths[i], c)
		}
	}
}
