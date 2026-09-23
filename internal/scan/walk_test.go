package scan

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"osfp/internal/canon"
	"osfp/internal/exclude"
)

// content of the files the reference tree is built from, so that tests can
// check hashes against the source rather than against a recorded digest.
var treeFiles = map[string]string{
	"a.txt":            "a dot txt",
	"a/b":              "inside a",
	"a/b.txt":          "sibling of b",
	"bin/app":          "#!/bin/sh\necho hello\n",
	"etc/passwd":       "root:x:0:0:root:/root:/bin/sh\n",
	"etc/ssh/sshd_cfg": "PermitRootLogin no\n",
	"var/log/app.log":  "noise\n",
	"empty":            "",
}

var treeDirs = []string{"a", "bin", "etc", "etc/ssh", "var", "var/log", "emptydir"}

// buildTree creates a tree that exercises the awkward parts: names that
// collide around '/', every file type, and permissions that are not 0644.
func buildTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	for _, d := range treeDirs {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	for rel, content := range treeFiles {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	if err := os.Chmod(filepath.Join(root, "bin/app"), 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// setuid, to prove the mode is recorded beyond the permission bits
	if err := os.Chmod(filepath.Join(root, "etc/passwd"), 0o644|os.ModeSetuid); err != nil {
		t.Fatalf("chmod setuid: %v", err)
	}
	if err := os.Symlink("app", filepath.Join(root, "bin/link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Symlink("/nowhere/at/all", filepath.Join(root, "bin/dangling")); err != nil {
		t.Fatalf("dangling symlink: %v", err)
	}
	if err := os.Link(filepath.Join(root, "etc/passwd"), filepath.Join(root, "etc/passwd-")); err != nil {
		t.Fatalf("hard link: %v", err)
	}
	if err := unix.Mkfifo(filepath.Join(root, "var/fifo"), 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	return root
}

// scanAll runs a scan and returns copies of every entry, so that the reorder
// buffer is free to recycle its cells.
func scanAll(t *testing.T, opts Options) ([]Entry, Stats) {
	t.Helper()
	var got []Entry
	stats, err := Walk(context.Background(), opts, func(e *Entry) error {
		got = append(got, *e)
		return nil
	})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	return got, stats
}

func paths(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

func find(t *testing.T, entries []Entry, path string) Entry {
	t.Helper()
	for _, e := range entries {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no entry for %s", path)
	return Entry{}
}

// assertCanonicalOrder is the property the whole pipeline exists to preserve:
// hashing in parallel must not disturb the order of the walk.
func assertCanonicalOrder(t *testing.T, entries []Entry) {
	t.Helper()
	for i := 1; i < len(entries); i++ {
		if c := canon.CompareKey(entries[i-1].Path, entries[i].Path); c >= 0 {
			t.Fatalf("entries %d and %d are out of canonical order: %q then %q",
				i-1, i, entries[i-1].Path, entries[i].Path)
		}
	}
}

func TestWalkProducesCanonicalOrder(t *testing.T) {
	root := buildTree(t)
	entries, _ := scanAll(t, Options{Root: root})
	assertCanonicalOrder(t, entries)

	// The order must be the one CompareKey defines, not merely some order.
	sorted := slices.Clone(paths(entries))
	slices.SortFunc(sorted, canon.CompareKey)
	if !slices.Equal(sorted, paths(entries)) {
		t.Error("the walk order is not the canonical order")
	}
}

// TestWalkIsIndependentOfJobCount is the reorder buffer's reason to exist: the
// number of hashing workers must not be observable in the output.
func TestWalkIsIndependentOfJobCount(t *testing.T) {
	root := buildTree(t)
	reference, refStats := scanAll(t, Options{Root: root, Jobs: 1})
	assertCanonicalOrder(t, reference)

	for _, jobs := range []int{2, 3, 8, 32} {
		t.Run(fmt.Sprintf("jobs=%d", jobs), func(t *testing.T) {
			got, stats := scanAll(t, Options{Root: root, Jobs: jobs})
			assertCanonicalOrder(t, got)
			if len(got) != len(reference) {
				t.Fatalf("got %d entries, want %d", len(got), len(reference))
			}
			for i := range got {
				if got[i].Path != reference[i].Path {
					t.Fatalf("entry %d: got %q, want %q", i, got[i].Path, reference[i].Path)
				}
				if got[i].Hash != reference[i].Hash || got[i].Hashed != reference[i].Hashed {
					t.Fatalf("entry %d (%s): hash differs between job counts", i, got[i].Path)
				}
			}
			if stats.Total() != refStats.Total() || stats.Hashed != refStats.Hashed {
				t.Errorf("stats differ: %+v vs %+v", stats, refStats)
			}
		})
	}
}

func TestWalkRecordsEveryType(t *testing.T) {
	root := buildTree(t)
	entries, stats := scanAll(t, Options{Root: root})

	t.Run("regular file", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "etc/ssh/sshd_cfg"))
		if e.Type != TypeFile {
			t.Errorf("Type = %v, want file", e.Type)
		}
		want := sha256.Sum256([]byte(treeFiles["etc/ssh/sshd_cfg"]))
		if !e.Hashed || e.Hash != want {
			t.Errorf("hash = %x (hashed=%v), want %x", e.Hash, e.Hashed, want)
		}
		if e.Size != int64(len(treeFiles["etc/ssh/sshd_cfg"])) {
			t.Errorf("Size = %d, want %d", e.Size, len(treeFiles["etc/ssh/sshd_cfg"]))
		}
		if e.MTime == 0 {
			t.Error("MTime was not recorded")
		}
	})

	t.Run("empty file", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "empty"))
		if want := sha256.Sum256(nil); !e.Hashed || e.Hash != want {
			t.Errorf("an empty file must still be hashed: got %x hashed=%v", e.Hash, e.Hashed)
		}
	})

	t.Run("mode beyond the permission bits", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "etc/passwd"))
		if e.Mode != 0o4644 {
			t.Errorf("Mode = %#o, want %#o (setuid must survive)", e.Mode, 0o4644)
		}
		if e.Nlink != 2 {
			t.Errorf("Nlink = %d, want 2 (the hard link)", e.Nlink)
		}
		if e.Ino == 0 {
			t.Error("Ino was not recorded")
		}
	})

	t.Run("hard link shares the inode", func(t *testing.T) {
		a := find(t, entries, filepath.Join(root, "etc/passwd"))
		b := find(t, entries, filepath.Join(root, "etc/passwd-"))
		if a.Ino != b.Ino || a.Dev != b.Dev {
			t.Errorf("hard links do not share dev:ino: %d:%d vs %d:%d", a.Dev, a.Ino, b.Dev, b.Ino)
		}
		if a.Hash != b.Hash {
			t.Error("hard links must hash identically")
		}
	})

	t.Run("symlink is recorded, not followed", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "bin/link"))
		if e.Type != TypeSymlink {
			t.Errorf("Type = %v, want symlink", e.Type)
		}
		if e.Link != "app" {
			t.Errorf("Link = %q, want %q", e.Link, "app")
		}
		if e.Hashed {
			t.Error("a symlink must not be hashed")
		}
	})

	t.Run("dangling symlink is not an error", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "bin/dangling"))
		if e.Type != TypeSymlink || e.Link != "/nowhere/at/all" {
			t.Errorf("got %v %q, want a symlink to /nowhere/at/all", e.Type, e.Link)
		}
		if e.Err != "" {
			t.Errorf("Err = %q, want none: the link itself is readable", e.Err)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "var/fifo"))
		if e.Type != TypeFIFO {
			t.Errorf("Type = %v, want fifo", e.Type)
		}
		if e.Hashed {
			t.Error("a fifo must never be opened for hashing: the scan would block")
		}
	})

	t.Run("directory", func(t *testing.T) {
		e := find(t, entries, filepath.Join(root, "emptydir"))
		if e.Type != TypeDir || !e.IsDir() {
			t.Errorf("Type = %v, want directory", e.Type)
		}
		if e.Hashed {
			t.Error("a directory must not be hashed")
		}
	})

	t.Run("stats", func(t *testing.T) {
		if got, want := stats.Dirs, int64(len(treeDirs)+1); got != want { // +1 for the root
			t.Errorf("Dirs = %d, want %d", got, want)
		}
		if got, want := stats.Files, int64(len(treeFiles)+1); got != want { // +1 for the hard link
			t.Errorf("Files = %d, want %d", got, want)
		}
		if got, want := stats.Symlinks, int64(2); got != want {
			t.Errorf("Symlinks = %d, want %d", got, want)
		}
		if got, want := stats.Others, int64(1); got != want {
			t.Errorf("Others = %d, want %d (the fifo)", got, want)
		}
		if stats.Errors != 0 {
			t.Errorf("Errors = %d, want 0", stats.Errors)
		}
		if stats.Elapsed <= 0 {
			t.Error("Elapsed was not measured")
		}
	})
}

func TestWalkSymlinkToDirectoryIsNotDescended(t *testing.T) {
	root := buildTree(t)
	if err := os.Symlink(filepath.Join(root, "etc"), filepath.Join(root, "a/loop")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	entries, _ := scanAll(t, Options{Root: root})
	for _, e := range entries {
		if strings.HasPrefix(e.Path, filepath.Join(root, "a/loop")+"/") {
			t.Fatalf("the walk followed a symlink to a directory: %s", e.Path)
		}
	}
	assertCanonicalOrder(t, entries)
}

func TestWalkExcludes(t *testing.T) {
	root := buildTree(t)
	set, err := exclude.New(exclude.Options{
		NoDefaults: true,
		Patterns:   []string{filepath.Join(root, "var"), "*.txt"},
	})
	if err != nil {
		t.Fatalf("exclude.New: %v", err)
	}
	entries, stats := scanAll(t, Options{Root: root, Exclude: set})

	for _, e := range entries {
		if strings.HasPrefix(e.Path, filepath.Join(root, "var")) {
			t.Errorf("%s should have been excluded", e.Path)
		}
		if strings.HasSuffix(e.Path, ".txt") {
			t.Errorf("%s should have been excluded by the name pattern", e.Path)
		}
	}
	if stats.Total() == 0 {
		t.Fatal("everything was excluded")
	}
	assertCanonicalOrder(t, entries)
}

// TestWalkRootIsNeverExcluded covers --root pointing at a directory that the
// default list excludes, such as /tmp.
func TestWalkRootIsNeverExcluded(t *testing.T) {
	root := buildTree(t)
	set, err := exclude.New(exclude.Options{NoDefaults: true, Patterns: []string{root}})
	if err != nil {
		t.Fatalf("exclude.New: %v", err)
	}
	entries, _ := scanAll(t, Options{Root: root, Exclude: set})
	if len(entries) != 1 || entries[0].Path != root {
		t.Fatalf("got %d entries, want only the root itself", len(entries))
	}
}

func TestWalkDescendHookPrunes(t *testing.T) {
	root := buildTree(t)
	pruned := filepath.Join(root, "etc")

	entries, stats := scanAll(t, Options{
		Root: root,
		Descend: func(e *Entry) bool {
			return e.Path != pruned
		},
	})

	if _, ok := slices.BinarySearchFunc(paths(entries), pruned, canon.CompareKey); !ok {
		t.Fatal("the pruned directory must still be reported")
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Path, pruned+"/") {
			t.Errorf("%s is below a pruned directory and must not have been listed", e.Path)
		}
	}
	if stats.Pruned != 1 {
		t.Errorf("Pruned = %d, want 1", stats.Pruned)
	}
	assertCanonicalOrder(t, entries)
}

func TestWalkMaxDepth(t *testing.T) {
	root := buildTree(t)
	entries, stats := scanAll(t, Options{Root: root, MaxDepth: 1})

	for _, e := range entries {
		rel, err := filepath.Rel(root, e.Path)
		if err != nil {
			t.Fatalf("Rel: %v", err)
		}
		if depth := strings.Count(rel, "/"); depth > 1 {
			t.Errorf("%s is at depth %d, beyond MaxDepth", e.Path, depth+1)
		}
	}
	if stats.Pruned == 0 {
		t.Error("MaxDepth pruned nothing")
	}
}

func TestWalkMaxFileSizeMarksPartial(t *testing.T) {
	root := buildTree(t)
	big := filepath.Join(root, "bin/big")
	if err := os.WriteFile(big, make([]byte, 4096), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	entries, stats := scanAll(t, Options{Root: root, MaxFileSize: 100})

	e := find(t, entries, big)
	if !e.Partial {
		t.Error("the oversized file was not marked partial")
	}
	if e.Hashed {
		t.Error("the oversized file was hashed despite MaxFileSize")
	}
	if e.Size != 4096 || e.MTime == 0 {
		t.Errorf("a partial entry must still carry size and mtime, got size=%d mtime=%d", e.Size, e.MTime)
	}
	if stats.Partial != 1 {
		t.Errorf("Partial = %d, want 1", stats.Partial)
	}

	small := find(t, entries, filepath.Join(root, "etc/passwd"))
	if small.Partial || !small.Hashed {
		t.Error("a file under the limit must still be hashed")
	}
}

func TestWalkUnreadableEntries(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permissions cannot be made to fail")
	}
	root := buildTree(t)

	secretDir := filepath.Join(root, "etc/private")
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "key"), []byte("secret"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	secretFile := filepath.Join(root, "etc/unreadable")
	if err := os.WriteFile(secretFile, []byte("secret"), 0o000); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Chmod(secretDir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// TempDir cleanup needs the permissions back.
	t.Cleanup(func() { _ = os.Chmod(secretDir, 0o755) })

	entries, stats := scanAll(t, Options{Root: root})
	assertCanonicalOrder(t, entries)

	t.Run("unreadable directory yields exactly one entry", func(t *testing.T) {
		var count int
		for _, e := range entries {
			if e.Path == secretDir {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("got %d entries for the unreadable directory, want exactly 1", count)
		}
		e := find(t, entries, secretDir)
		if e.Type != TypeDir {
			t.Errorf("Type = %v, want directory: it is still a directory", e.Type)
		}
		if e.Err == "" {
			t.Error("the listing failure was not recorded on the directory")
		}
	})

	t.Run("unreadable file keeps its type and records why", func(t *testing.T) {
		e := find(t, entries, secretFile)
		if e.Type != TypeFile {
			t.Errorf("Type = %v, want file", e.Type)
		}
		if e.Hashed {
			t.Error("an unreadable file cannot have been hashed")
		}
		if !strings.Contains(e.Err, "permission denied") {
			t.Errorf("Err = %q, want a permission error", e.Err)
		}
	})

	if stats.Errors != 2 {
		t.Errorf("Errors = %d, want 2", stats.Errors)
	}
	if stats.Files == 0 {
		t.Error("the scan stopped at the first unreadable entry")
	}
}

func TestWalkEmitErrorStopsTheScan(t *testing.T) {
	root := buildTree(t)
	want := errors.New("writer is full")
	var seen int

	_, err := Walk(context.Background(), Options{Root: root, Jobs: 2}, func(e *Entry) error {
		seen++
		if seen == 3 {
			return want
		}
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("Walk error = %v, want %v", err, want)
	}
	if seen != 3 {
		t.Errorf("emit was called %d times after returning an error, want 3", seen)
	}
}

func TestWalkContextCancellation(t *testing.T) {
	root := buildTree(t)
	ctx, cancel := context.WithCancel(context.Background())

	_, err := Walk(ctx, Options{Root: root, Jobs: 1}, func(e *Entry) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Walk error = %v, want context.Canceled", err)
	}
}

func TestWalkRejectsABadRoot(t *testing.T) {
	root := buildTree(t)
	tests := []struct {
		name string
		root string
	}{
		{"missing", filepath.Join(root, "nope")},
		{"not a directory", filepath.Join(root, "etc/passwd")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Walk(context.Background(), Options{Root: tt.root}, func(*Entry) error {
				t.Fatal("emit was called for an invalid root")
				return nil
			}); err == nil {
				t.Fatal("Walk accepted an invalid root")
			}
		})
	}
}

func TestWalkIsRepeatable(t *testing.T) {
	root := buildTree(t)
	first, _ := scanAll(t, Options{Root: root, Jobs: 4})
	second, _ := scanAll(t, Options{Root: root, Jobs: 4})
	if len(first) != len(second) {
		t.Fatalf("two scans of the same tree produced %d and %d entries", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("entry %d differs between two scans:\n%+v\n%+v", i, first[i], second[i])
		}
	}
}

func TestDefaultJobsIsBounded(t *testing.T) {
	if got := DefaultJobs(); got < 1 || got > maxJobs {
		t.Errorf("DefaultJobs() = %d, want between 1 and %d", got, maxJobs)
	}
}

// TestScanRealTree is the phase's field test. It is opt-in because it reads a
// real filesystem:
//
//	OSFP_SCAN_ROOT=/usr go test ./internal/scan/ -run TestScanRealTree -v
func TestScanRealTree(t *testing.T) {
	root := os.Getenv("OSFP_SCAN_ROOT")
	if root == "" {
		t.Skip("set OSFP_SCAN_ROOT to a directory to run the real scan")
	}

	// The same rules baseline will use: built-in exclusions and no crossing of
	// mount points.
	set, err := exclude.New(exclude.Options{GOOS: runtime.GOOS})
	if err != nil {
		t.Fatalf("exclude.New: %v", err)
	}

	var last string
	var outOfOrder int
	stats, err := Walk(context.Background(), Options{Root: root, Exclude: set, Mounts: MountLocal},
		func(e *Entry) error {
			if last != "" && canon.CompareKey(last, e.Path) >= 0 {
				outOfOrder++
				if outOfOrder < 5 {
					t.Errorf("out of order: %q then %q", last, e.Path)
				}
			}
			last = e.Path
			return nil
		})
	if err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if outOfOrder > 0 {
		t.Fatalf("%d entries were out of canonical order", outOfOrder)
	}

	rate := float64(stats.Bytes) / (1 << 20) / stats.Elapsed.Seconds()
	t.Logf("%s: %d entries (%d dirs, %d files, %d symlinks, %d other), %d hashed, %d errors",
		root, stats.Total(), stats.Dirs, stats.Files, stats.Symlinks, stats.Others, stats.Hashed, stats.Errors)
	t.Logf("%.1f MiB hashed in %s (%.0f MiB/s), %.0f entries/s",
		float64(stats.Bytes)/(1<<20), stats.Elapsed.Round(time.Millisecond), rate,
		float64(stats.Total())/stats.Elapsed.Seconds())
}

func BenchmarkWalk(b *testing.B) {
	root := b.TempDir()
	// 32 directories of 64 files of 4 KiB: enough to make the pipeline work
	// without turning the benchmark into a disk benchmark.
	payload := make([]byte, 4096)
	for d := 0; d < 32; d++ {
		dir := filepath.Join(root, fmt.Sprintf("dir%02d", d))
		if err := os.Mkdir(dir, 0o755); err != nil {
			b.Fatalf("mkdir: %v", err)
		}
		for f := 0; f < 64; f++ {
			if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("file%02d", f)), payload, 0o644); err != nil {
				b.Fatalf("write: %v", err)
			}
		}
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		stats, err := Walk(context.Background(), Options{Root: root}, func(*Entry) error { return nil })
		if err != nil {
			b.Fatalf("Walk: %v", err)
		}
		b.SetBytes(stats.Bytes)
	}
}
