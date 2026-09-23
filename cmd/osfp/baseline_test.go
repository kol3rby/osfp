package main

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"osfp/internal/scan"
	"osfp/internal/store"
)

// treeWithContent builds a small tree to fingerprint.
func treeWithContent(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, d := range []string{"etc", "etc/ssh", "usr/bin", "var/log"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for rel, content := range map[string]string{
		"etc/passwd":         "root:x:0:0::/root:/bin/sh\n",
		"etc/ssh/sshd_conf":  "PermitRootLogin no\n",
		"usr/bin/app":        "#!/bin/sh\n",
		"var/log/syslog":     "noise\n",
		"var/log/syslog.1":   "older noise\n",
		"etc/machine-id.swp": "editor droppings\n",
	} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	if err := os.Symlink("app", filepath.Join(root, "usr/bin/link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	return root
}

func runCmd(t *testing.T, args ...string) int {
	t.Helper()
	return dispatch(context.Background(), args)
}

// readFingerprint opens a fingerprint, verifies its digest and returns its
// metadata together with every entry.
func readFingerprint(t *testing.T, path string) (*store.Meta, []scan.Entry) {
	t.Helper()
	r, err := store.Open(path)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var entries []scan.Entry
	if err := r.Iterate(func(e *scan.Entry) error {
		entries = append(entries, *e)
		return nil
	}); err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	return r.Meta(), entries
}

func pathsOf(entries []scan.Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path
	}
	return out
}

func TestBaselineWritesAReadableFingerprint(t *testing.T) {
	root := treeWithContent(t)
	target := filepath.Join(t.TempDir(), "fp.osfp")

	out := captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target); code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}

	meta, entries := readFingerprint(t, target)

	// The fingerprint must hold exactly what a direct scan sees.
	var want []scan.Entry
	if _, err := scan.Walk(context.Background(), scan.Options{Root: root},
		func(e *scan.Entry) error {
			want = append(want, *e)
			return nil
		}); err != nil {
		t.Fatalf("Walk: %v", err)
	}
	if len(entries) != len(want) {
		t.Fatalf("fingerprint holds %d entries, a direct scan sees %d", len(entries), len(want))
	}
	for i := range want {
		if entries[i] != want[i] {
			t.Fatalf("entry %d differs:\n  stored %+v\n  scanned %+v", i, entries[i], want[i])
		}
	}

	t.Run("metadata", func(t *testing.T) {
		if meta.Tool != "osfp" || meta.ToolVersion == "" {
			t.Errorf("tool identity is missing: %+v", meta)
		}
		if meta.Key == "" || meta.Key != meta.System.Key() {
			t.Errorf("Key = %q, System.Key() = %q", meta.Key, meta.System.Key())
		}
		if meta.Scan.Root != root {
			t.Errorf("Scan.Root = %q, want %q", meta.Scan.Root, root)
		}
		if meta.Scan.Mounts != "local" {
			t.Errorf("Scan.Mounts = %q, want the default policy \"local\"", meta.Scan.Mounts)
		}
		if meta.Scan.Jobs <= 0 {
			t.Errorf("Scan.Jobs = %d, want the resolved worker count", meta.Scan.Jobs)
		}
		if meta.Entries != int64(len(entries)) {
			t.Errorf("Meta.Entries = %d, want %d", meta.Entries, len(entries))
		}
		if meta.Privileged != (os.Geteuid() == 0) {
			t.Errorf("Privileged = %v for euid %d", meta.Privileged, os.Geteuid())
		}
		if len(meta.Exclusions) == 0 {
			t.Error("the default exclusions were not recorded")
		}
		if meta.CreatedAt.IsZero() {
			t.Error("CreatedAt was not recorded")
		}
	})

	t.Run("summary", func(t *testing.T) {
		for _, want := range []string{"wrote ", "system   ", "entries  ", "hashed   ", "size     "} {
			if !strings.Contains(out.String(), want) {
				t.Errorf("summary is missing %q:\n%s", want, out)
			}
		}
	})
}

func TestBaselineRefusesWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the refusal cannot be triggered")
	}
	root := treeWithContent(t)
	target := filepath.Join(t.TempDir(), "fp.osfp")

	captureStdout(t)
	if code := runCmd(t, "baseline", "--root", root, "-o", target); code != exitPrivilege {
		t.Fatalf("baseline exited %d, want %d", code, exitPrivilege)
	}
	// Nothing at all must be left behind, not even a temporary file.
	for _, p := range []string{target, target + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s was created despite the refusal", p)
		}
	}
}

func TestBaselineRefusesToOverwrite(t *testing.T) {
	root := treeWithContent(t)
	target := filepath.Join(t.TempDir(), "fp.osfp")

	captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target); code != exitOK {
		t.Fatalf("first baseline exited %d", code)
	}
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target); code != exitError {
		t.Fatalf("second baseline exited %d, want %d", code, exitError)
	}
	after, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(before) != string(after) {
		t.Error("the existing fingerprint was modified despite the refusal")
	}

	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target, "--force"); code != exitOK {
		t.Fatalf("baseline --force exited %d", code)
	}
	if _, entries := readFingerprint(t, target); len(entries) == 0 {
		t.Error("--force produced an empty fingerprint")
	}
}

func TestBaselineExclusions(t *testing.T) {
	root := treeWithContent(t)
	dir := t.TempDir()
	target := filepath.Join(dir, "fp.osfp")
	listFile := filepath.Join(dir, "excludes.txt")
	if err := os.WriteFile(listFile, []byte("# editor leftovers\n*.swp\n\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	captureStdout(t)
	code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target,
		"--exclude", filepath.Join(root, "var/log"),
		"--exclude-from", listFile)
	if code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}

	meta, entries := readFingerprint(t, target)
	for _, p := range pathsOf(entries) {
		if strings.HasPrefix(p, filepath.Join(root, "var/log")) {
			t.Errorf("%s should have been excluded by --exclude", p)
		}
		if strings.HasSuffix(p, ".swp") {
			t.Errorf("%s should have been excluded by --exclude-from", p)
		}
	}
	if !slices.Contains(meta.Exclusions, "*.swp") {
		t.Errorf("the pattern from --exclude-from is missing from the recorded exclusions: %v", meta.Exclusions)
	}
	if slices.Contains(meta.Exclusions, "# editor leftovers") {
		t.Error("a comment line was recorded as an exclusion pattern")
	}
}

// TestBaselineExcludesItsOwnOutput covers the auto-exclusion of §6.1: a
// fingerprint that recorded itself could never compare equal to anything.
func TestBaselineExcludesItsOwnOutput(t *testing.T) {
	root := treeWithContent(t)
	target := filepath.Join(root, "var", "fp.osfp")

	captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", target); code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}

	_, entries := readFingerprint(t, target)
	for _, p := range pathsOf(entries) {
		if p == target || p == target+".tmp" {
			t.Errorf("the fingerprint recorded itself: %s", p)
		}
	}
}

func TestBaselineOsIDOverride(t *testing.T) {
	root := treeWithContent(t)
	dir := t.TempDir()

	captureStdout(t)
	code := runCmd(t, "baseline", "--allow-non-root", "--root", root,
		"-o", filepath.Join(dir, "fp.osfp"), "--os-id", "Linux-Frobnix-3.2-AMD64")
	if code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}
	meta, _ := readFingerprint(t, filepath.Join(dir, "fp.osfp"))
	if got, want := meta.Key, "linux-frobnix-3.2-amd64"; got != want {
		t.Errorf("Key = %q, want %q (normalized)", got, want)
	}
	if meta.System.OS == "" {
		t.Error("--os-id should override the key, not erase the detected system")
	}
}

// TestBaselineDefaultOutputName covers step 1 of §8: the file is named after
// the detected system, in the current directory.
func TestBaselineDefaultOutputName(t *testing.T) {
	root := treeWithContent(t)
	dir := t.TempDir()

	cwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}
	t.Cleanup(func() { os.Chdir(cwd) })

	captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "--os-id", "test-key-1"); code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "test-key-1.osfp")); err != nil {
		names, _ := os.ReadDir(dir)
		t.Fatalf("test-key-1.osfp was not created; directory holds %v", names)
	}
}

func TestBaselineInterrupted(t *testing.T) {
	root := treeWithContent(t)
	target := filepath.Join(t.TempDir(), "fp.osfp")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	captureStdout(t)
	if code := dispatch(ctx, []string{"baseline", "--allow-non-root", "--root", root, "-o", target}); code != exitInterrupted {
		t.Fatalf("interrupted baseline exited %d, want %d", code, exitInterrupted)
	}
	for _, p := range []string{target, target + ".tmp"} {
		if _, err := os.Stat(p); err == nil {
			t.Errorf("%s survived the interruption", p)
		}
	}
}

func TestBaselineRejectsBadArguments(t *testing.T) {
	tests := [][]string{
		{"baseline", "--root", "/nonexistent-root-for-osfp", "--allow-non-root", "-o", filepath.Join(t.TempDir(), "a.osfp")},
		{"baseline", "--allow-non-root", "--exclude", "/var/[a-", "-o", filepath.Join(t.TempDir(), "b.osfp")},
		{"baseline", "--allow-non-root", "--exclude-from", "/nonexistent-file", "-o", filepath.Join(t.TempDir(), "c.osfp")},
		{"baseline", "--allow-non-root", "--os-id", "---", "-o", filepath.Join(t.TempDir(), "d.osfp")},
		{"baseline", "stray-argument"},
	}
	captureStdout(t)
	for _, args := range tests {
		t.Run(strings.Join(args[1:], " "), func(t *testing.T) {
			if code := runCmd(t, args...); code != exitError {
				t.Errorf("exited %d, want %d", code, exitError)
			}
		})
	}
}

// TestBaselineSummarySingulars pins the wording of counts of one: the porting
// pass found "1 jobs", "1 symlinks" and "1 directories not descended" one at a
// time, on four different systems.
func TestBaselineSummarySingulars(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "f"), []byte("x\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.Symlink("f", filepath.Join(root, "l")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := os.Mkdir(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	out := captureStdout(t)
	fp := filepath.Join(t.TempDir(), "fp.osfp")
	if code := runCmd(t, "baseline", "-o", fp, "--root", root, "--no-default-excludes",
		"--max-depth", "1", "--allow-non-root"); code != exitOK {
		t.Fatalf("baseline exited %d\n%s", code, out)
	}
	text := out.String()
	for _, want := range []string{"2 directories, 1 file, 1 symlink, 0 other", "hashed   1 file,", "1 directory not descended"} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in:\n%s", want, text)
		}
	}
	for _, wrong := range []string{"1 files", "1 symlinks", "1 directories"} {
		if strings.Contains(text, wrong) {
			t.Errorf("%q in:\n%s", wrong, text)
		}
	}
}
