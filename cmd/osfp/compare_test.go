package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"osfp/internal/canon"
	"osfp/internal/diff"
	"osfp/internal/osdetect"
	"osfp/internal/scan"
	"osfp/internal/store"
)

// changeLines keeps only the lines that report a change, stripping the tree
// root so that expectations can be written as absolute-looking paths. Report
// lines are indented under their section heading.
func changeLines(out *bytes.Buffer, root string) []string {
	var got []string
	for _, line := range strings.Split(out.String(), "\n") {
		line = strings.TrimLeft(line, " ")
		if len(line) < 3 || line[2] != ' ' {
			continue
		}
		switch line[:2] {
		case "+D", "-D", "~D", "+F", "-F", "~F", "%F", "!T", "~L", "?E":
			line = strings.TrimRight(strings.ReplaceAll(line, root, ""), " ")
			// The path column is padded; collapse it so that expectations
			// stay readable.
			got = append(got, strings.Join(strings.Fields(line), " "))
		}
	}
	return got
}

// reportOrder puts expectations in the order the text report prints them: by
// section, in the order of diff.AllOps, then by canonical path within each.
func reportOrder(lines []string) []string {
	rank := make(map[string]int, len(diff.AllOps))
	for i, op := range diff.AllOps {
		rank[op.String()] = i
	}
	out := slices.Clone(lines)
	slices.SortFunc(out, func(a, b string) int {
		fa, fb := strings.Fields(a), strings.Fields(b)
		if c := rank[fa[0]] - rank[fb[0]]; c != 0 {
			return c
		}
		return canon.CompareKey(fa[1], fb[1])
	})
	return out
}

// baselineTree builds a tree, fingerprints it and returns both paths.
func baselineTree(t *testing.T) (root, fingerprint string) {
	t.Helper()
	root = t.TempDir()
	for _, d := range []string{"etc/ssh", "usr/bin", "var/lib"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatalf("mkdir: %v", err)
		}
	}
	for rel, content := range map[string]string{
		"etc/ssh/sshd_config": "PermitRootLogin no\n",
		"etc/passwd":          "root:x:0:0::/root:/bin/sh\n",
		"etc/motd.orig":       "old motd\n",
		"usr/bin/deploy.sh":   "#!/bin/sh\necho hi\n",
		"usr/bin/turns-link":  "plain file\n",
		"var/lib/state":       "data\n",
	} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	if err := os.Symlink("deploy.sh", filepath.Join(root, "usr/bin/deploy")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	fingerprint = filepath.Join(t.TempDir(), "base.osfp")
	captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root, "-o", fingerprint); code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}
	return root, fingerprint
}

// TestCompareReportsExactlyTheMutations is the deliverable of this phase: a
// fingerprinted tree, one mutation per category, and a report that holds those
// lines and no others.
func TestCompareReportsExactlyTheMutations(t *testing.T) {
	root, fingerprint := baselineTree(t)

	// +D with a summary: a new tree that must be reported without being listed
	if err := os.MkdirAll(filepath.Join(root, "opt/myapp/sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, rel := range []string{"opt/myapp/a", "opt/myapp/b", "opt/myapp/sub/c"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("payload\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	// +F inside a directory the fingerprint already knows
	if err := os.WriteFile(filepath.Join(root, "etc/newfile"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// -F
	if err := os.Remove(filepath.Join(root, "etc/motd.orig")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	// ~F
	if err := os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config"), []byte("PermitRootLogin yes\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// %F
	if err := os.Chmod(filepath.Join(root, "var/lib/state"), 0o755); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// ~D
	if err := os.Chmod(filepath.Join(root, "usr/bin"), 0o700); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	// ~L
	if err := os.Remove(filepath.Join(root, "usr/bin/deploy")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Symlink("/usr/bin/deploy.sh", filepath.Join(root, "usr/bin/deploy")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// !T
	if err := os.Remove(filepath.Join(root, "usr/bin/turns-link")); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if err := os.Symlink("/dev/null", filepath.Join(root, "usr/bin/turns-link")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	// Nothing at all: only the date moves. §1.4 says this must be silent.
	if err := os.Chtimes(filepath.Join(root, "etc/passwd"), time.Unix(1, 0), time.Unix(1, 0)); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root"); code != exitOK {
		t.Fatalf("compare exited %d\n%s", code, out)
	}

	want := reportOrder([]string{
		"+F /etc/newfile",
		"-F /etc/motd.orig",
		"~F /etc/ssh/sshd_config",
		"+D /opt",
		"~D /usr/bin",
		"~L /usr/bin/deploy",
		"!T /usr/bin/turns-link",
		"%F /var/lib/state",
	})

	got := changeLines(out, root)
	// The detail is checked separately; compare the codes and paths first.
	codes := make([]string, len(got))
	for i, line := range got {
		f := strings.Fields(line)
		codes[i] = f[0] + " " + f[1]
	}
	if !slices.Equal(codes, want) {
		t.Errorf("report:\n  got  %v\n  want %v\n\nfull output:\n%s", codes, want, out)
	}

	t.Run("the new directory is summarized, not listed", func(t *testing.T) {
		for _, line := range got {
			if strings.Contains(line, "/opt/myapp") {
				t.Errorf("a file below the added directory was listed: %s", line)
			}
		}
		var summary string
		for _, line := range got {
			if strings.HasPrefix(line, "+D /opt") {
				summary = line
			}
		}
		for _, want := range []string{"3 files", "2 directories"} {
			if !strings.Contains(summary, want) {
				t.Errorf("summary %q is missing %q", summary, want)
			}
		}
	})

	t.Run("details name what moved", func(t *testing.T) {
		for _, want := range []string{
			"%F /var/lib/state mode 0644 → 0755",
			"~D /usr/bin mode 0755 → 0700",
			"~L /usr/bin/deploy deploy.sh → /usr/bin/deploy.sh",
			"!T /usr/bin/turns-link file → symlink",
		} {
			if !slices.Contains(got, want) {
				t.Errorf("missing line %q in:\n%v", want, got)
			}
		}
	})

	t.Run("a date change alone is silent", func(t *testing.T) {
		for _, line := range got {
			if strings.Contains(line, "/etc/passwd") {
				t.Errorf("touching a file produced %q; §1.4 says the mtime is never a criterion", line)
			}
		}
	})
}

func TestCompareOnAnUnchangedTree(t *testing.T) {
	_, fingerprint := baselineTree(t)

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--fail-on-diff"); code != exitOK {
		t.Fatalf("compare exited %d on an unchanged tree\n%s", code, out)
	}
	if got := changeLines(out, ""); len(got) != 0 {
		t.Errorf("an unchanged tree produced %v", got)
	}
	if !strings.Contains(out.String(), "SUMMARY") {
		t.Errorf("no summary was printed:\n%s", out)
	}
}

func TestCompareFailOnDiff(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/newfile"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root"); code != exitOK {
		t.Fatalf("compare without --fail-on-diff exited %d", code)
	}
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--fail-on-diff"); code != exitDiff {
		t.Fatalf("compare --fail-on-diff exited %d, want %d\n%s", code, exitDiff, out)
	}
}

func TestCompareNewDirModes(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.MkdirAll(filepath.Join(root, "opt/myapp"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, rel := range []string{"opt/myapp/a", "opt/myapp/b"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("payload\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	t.Run("summary counts without listing", func(t *testing.T) {
		out := captureStdout(t)
		runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--new-dir-mode", "summary")
		lines := changeLines(out, root)
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "+D /opt") {
			t.Fatalf("got %v, want one +D line", lines)
		}
		if !strings.Contains(lines[0], "2 files") {
			t.Errorf("summary is missing the counters: %q", lines[0])
		}
	})

	t.Run("skip reports nothing but the directory", func(t *testing.T) {
		out := captureStdout(t)
		runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--new-dir-mode", "skip")
		lines := changeLines(out, root)
		if len(lines) != 1 || lines[0] != "+D /opt" {
			t.Fatalf("got %v, want exactly \"+D /opt\"", lines)
		}
	})

	t.Run("deep lists everything below", func(t *testing.T) {
		out := captureStdout(t)
		runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--new-dir-mode", "deep")
		lines := changeLines(out, root)
		want := []string{"+D /opt", "+D /opt/myapp", "+F /opt/myapp/a", "+F /opt/myapp/b"}
		if !slices.Equal(lines, want) {
			t.Errorf("got %v, want %v", lines, want)
		}
	})

	t.Run("an unknown mode is refused", func(t *testing.T) {
		captureStdout(t)
		if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--new-dir-mode", "nope"); code != exitError {
			t.Errorf("exited %d, want %d", code, exitError)
		}
	})
}

func TestCompareShowAndIgnore(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/newfile"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config"), []byte("changed\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Run("show restricts the categories", func(t *testing.T) {
		out := captureStdout(t)
		runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--show", "~F")
		lines := changeLines(out, root)
		if len(lines) != 1 || !strings.HasPrefix(lines[0], "~F ") {
			t.Fatalf("got %v, want only the content change", lines)
		}
		if !strings.Contains(out.String(), "hidden by --show") {
			t.Errorf("the summary does not say how many lines were hidden:\n%s", out)
		}
	})

	t.Run("ignore rules are applied after classification", func(t *testing.T) {
		rules := filepath.Join(t.TempDir(), "ignore.txt")
		if err := os.WriteFile(rules, []byte("# noise\n~F:"+filepath.Join(root, "etc/ssh")+"\n"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		out := captureStdout(t)
		runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--ignore-from", rules)
		lines := changeLines(out, root)
		if !slices.Equal(lines, []string{"+F /etc/newfile"}) {
			t.Fatalf("got %v, want only the addition", lines)
		}
		if !strings.Contains(out.String(), "hidden by ignore rules") {
			t.Errorf("the summary does not count the ignored changes:\n%s", out)
		}
	})
}

func TestCompareRefusesAnotherSystem(t *testing.T) {
	root := t.TempDir()
	fingerprint := filepath.Join(t.TempDir(), "other.osfp")

	captureStdout(t)
	if code := runCmd(t, "baseline", "--allow-non-root", "--root", root,
		"-o", fingerprint, "--os-id", "solaris-11.4-sparc64"); code != exitOK {
		t.Fatalf("baseline exited %d", code)
	}

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root"); code != exitError {
		t.Fatalf("compare exited %d on a foreign fingerprint, want %d\n%s", code, exitError, out)
	}
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--allow-os-mismatch"); code != exitOK {
		t.Fatalf("compare --allow-os-mismatch exited %d", code)
	}
}

// TestCompareRefusesMismatchedPrivilege builds, by hand, the fingerprint a
// privileged scan would have produced, and checks that an unprivileged run
// refuses to compare against it. This is what makes --allow-non-root safe.
func TestCompareRefusesMismatchedPrivilege(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: the mismatch cannot be produced")
	}
	root := t.TempDir()
	info, err := osdetect.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}

	fingerprint := filepath.Join(t.TempDir(), "root.osfp")
	f, err := os.Create(fingerprint)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	w, err := store.NewWriter(f, &store.Meta{
		Tool: "osfp", ToolVersion: "test", CreatedAt: time.Now().UTC(),
		Key: info.Key(), System: *info,
		Privileged: true,
		Scan:       store.ScanOptions{Root: root, Mounts: "local", MaxDepth: 64, Jobs: 1},
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	e := scan.Entry{Path: root, Type: scan.TypeDir, Mode: 0o755}
	if err := w.Add(&e); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	f.Close()

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root"); code != exitPrivilege {
		t.Fatalf("compare exited %d, want %d\n%s", code, exitPrivilege, out)
	}
}

func TestCompareRejectsBadArguments(t *testing.T) {
	_, fingerprint := baselineTree(t)
	tests := [][]string{
		{"compare", "--allow-non-root"},                                           // no -b
		{"compare", "-b", "/nonexistent.osfp", "--allow-non-root"},                // missing file
		{"compare", "-b", fingerprint, "--allow-non-root", "--show", "nope"},      // unknown code
		{"compare", "-b", fingerprint, "--allow-non-root", "--ignore-from", "/x"}, // missing rules
		{"compare", "-b", fingerprint, "stray"},
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

func TestCompareInterrupted(t *testing.T) {
	_, fingerprint := baselineTree(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	captureStdout(t)
	if code := dispatch(ctx, []string{"compare", "-b", fingerprint, "--allow-non-root"}); code != exitInterrupted {
		t.Fatalf("interrupted compare exited %d, want %d", code, exitInterrupted)
	}
}

func TestCompareWritesTheReportToAFile(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/newfile"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Deliberately inside the tree being scanned: the report must exclude
	// itself, or it would report its own existence as a change.
	target := filepath.Join(root, "var", "drift.txt")

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "-o", target); code != exitOK {
		t.Fatalf("compare exited %d", code)
	}
	if out.Len() != 0 {
		t.Errorf("the report was also written to standard output:\n%s", out)
	}

	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "filesystem drift report") || !strings.Contains(text, "SUMMARY") {
		t.Errorf("the report file is incomplete:\n%s", text)
	}
	if !strings.Contains(text, "+F "+filepath.Join(root, "etc/newfile")) {
		t.Errorf("the report file is missing the change:\n%s", text)
	}
	for _, p := range []string{target, target + ".tmp"} {
		if strings.Contains(text, p+"\n") || strings.Contains(text, p+" ") {
			t.Errorf("the report reported itself: %s", p)
		}
	}
	if _, err := os.Stat(target + ".tmp"); err == nil {
		t.Error("the temporary report file was left behind")
	}
	if strings.Contains(text, "\033[") {
		t.Error("a report written to a file was colourised")
	}
}

func TestCompareJSONFormat(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/ssh/sshd_config"), []byte("changed\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--format", "json"); code != exitOK {
		t.Fatalf("compare exited %d", code)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want header + one change + summary:\n%s", len(lines), out)
	}
	var records []map[string]any
	for _, line := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		records = append(records, rec)
	}
	if records[0]["record"] != "header" || records[2]["record"] != "summary" {
		t.Errorf("stream is not header-change-summary: %v", records)
	}
	change := records[1]
	if change["op"] != "~F" {
		t.Errorf("op = %v, want ~F", change["op"])
	}
	old, ok := change["old"].(map[string]any)
	if !ok || old["mtime"] == "" || old["sha256"] == "" {
		t.Errorf("the old side lost its mtime or its digest: %v", change["old"])
	}
}

func TestCompareRejectsAnUnknownFormat(t *testing.T) {
	_, fingerprint := baselineTree(t)
	captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--format", "yaml"); code != exitError {
		t.Errorf("exited %d, want %d", code, exitError)
	}
}

func TestCompareRefusesAVanishedRoot(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("remove: %v", err)
	}

	out := captureStdout(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root"); code != exitError {
		t.Fatalf("compare exited %d, want %d", code, exitError)
	}
	// Nothing at all should have been written: a header with no body reads as
	// a system with no differences.
	if out.Len() != 0 {
		t.Errorf("a report was started before the failure:\n%s", out)
	}
}

// TestCompareFailOnDiffSaysNothingOnStderr covers a defect a porting pass
// found on FreeBSD: "differences found" is the outcome --fail-on-diff exists
// to produce, not a failure, and it was printing "osfp compare: <nil>".
func TestCompareFailOnDiffSaysNothingOnStderr(t *testing.T) {
	root, fingerprint := baselineTree(t)
	if err := os.WriteFile(filepath.Join(root, "etc/newfile"), []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	captureStdout(t)
	diagnostics := captureStderr(t)
	if code := runCmd(t, "compare", "-b", fingerprint, "--allow-non-root", "--fail-on-diff"); code != exitDiff {
		t.Fatalf("compare exited %d, want %d", code, exitDiff)
	}
	if got := diagnostics.String(); strings.Contains(got, "<nil>") || strings.Contains(got, "osfp compare:") {
		t.Errorf("stderr carries a spurious message:\n%s", got)
	}
}

// TestCodedErrorWithoutMessage guards the latent crash behind the same bug:
// Error() dereferenced a nil error.
func TestCodedErrorWithoutMessage(t *testing.T) {
	err := withExit(exitDiff, nil)
	if got := err.Error(); got == "" {
		t.Error("a coded error without a message produced an empty string")
	}
	var ec codedError
	if !errors.As(err, &ec) || ec.code != exitDiff {
		t.Errorf("errors.As lost the exit code: %v", err)
	}
}
