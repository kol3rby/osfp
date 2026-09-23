package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"osfp/internal/diff"
	"osfp/internal/osdetect"
	"osfp/internal/scan"
	"osfp/internal/store"
)

var update = flag.Bool("update", false, "rewrite the golden files")

func entry(path string, typ scan.Type, mutate ...func(*scan.Entry)) *scan.Entry {
	e := &scan.Entry{
		Path: path, Type: typ, Mode: 0o644, UID: 0, GID: 0,
		Size: 3174, MTime: 1740000000, Dev: 2049, Ino: 424242, Nlink: 1,
	}
	if typ == scan.TypeDir {
		e.Mode = 0o755
	}
	if typ == scan.TypeFile {
		for i := range e.Hash {
			e.Hash[i] = byte(i)
		}
		e.Hashed = true
	}
	for _, m := range mutate {
		m(e)
	}
	return e
}

// fixture is one report holding every category at least once, so that the
// golden files pin the whole layout rather than a happy path.
func fixture() (Header, []*diff.Change, Summary) {
	h := Header{
		Tool:         "osfp",
		ToolVersion:  "1.0",
		BaselinePath: "linux-debian-12-amd64.osfp",
		Baseline: &store.Meta{
			Tool: "osfp", ToolVersion: "1.0",
			CreatedAt: time.Date(2026, 3, 1, 9, 12, 44, 0, time.UTC),
			Key:       "linux-debian-12-amd64",
			System: osdetect.Info{
				OS: "linux", Distro: "debian", Version: "12", Arch: "amd64",
				Kernel: "6.1.0-18-amd64", Pretty: "Debian GNU/Linux 12 (bookworm)",
			},
			Privileged: true,
			Entries:    498233,
			Scan:       store.ScanOptions{Root: "/", Mounts: "local", MaxDepth: 64, Jobs: 8},
			Exclusions: []string{"/proc", "/sys", "/dev", "/tmp"},
		},
		SystemKey:       "linux-debian-12-amd64",
		SystemName:      "Debian GNU/Linux 12 (bookworm)",
		ScannedAt:       time.Date(2026, 9, 23, 14, 31, 2, 0, time.UTC),
		Privileged:      true,
		ExtraExclusions: []string{"/srv/backups"},
		IgnoreRules:     []string{"~F:/etc/adjtime"},
		NewDirMode:      "summary",
	}

	changes := []*diff.Change{
		{
			Op: diff.OpAddedDir, Path: "/opt/myapp",
			New:     entry("/opt/myapp", scan.TypeDir),
			Summary: &diff.DirSummary{Files: 412, Dirs: 18, Bytes: 88301568},
		},
		{
			Op: diff.OpRemovedDir, Path: "/etc/oldapp",
			Old: entry("/etc/oldapp", scan.TypeDir),
		},
		{
			Op: diff.OpChangedDir, Path: "/var/lib/myapp",
			Old:    entry("/var/lib/myapp", scan.TypeDir),
			New:    entry("/var/lib/myapp", scan.TypeDir, func(e *scan.Entry) { e.UID, e.GID = 998, 998 }),
			Detail: "uid 0 → 998, gid 0 → 998",
		},
		{
			Op: diff.OpAdded, Path: "/usr/local/bin/backdoor",
			New: entry("/usr/local/bin/backdoor", scan.TypeFile, func(e *scan.Entry) { e.Mode = 0o4755 }),
		},
		{
			Op: diff.OpRemoved, Path: "/etc/motd.orig",
			Old: entry("/etc/motd.orig", scan.TypeFile),
		},
		{
			Op: diff.OpChangedFile, Path: "/etc/ssh/sshd_config",
			Old:    entry("/etc/ssh/sshd_config", scan.TypeFile),
			New:    entry("/etc/ssh/sshd_config", scan.TypeFile, func(e *scan.Entry) { e.Size = 3481; e.Hash[0] = 0xff; e.MTime = 1758000000 }),
			Detail: "3.1 KiB → 3.4 KiB",
		},
		{
			Op: diff.OpChangedMeta, Path: "/usr/local/bin/deploy.sh",
			Old:    entry("/usr/local/bin/deploy.sh", scan.TypeFile),
			New:    entry("/usr/local/bin/deploy.sh", scan.TypeFile, func(e *scan.Entry) { e.Mode = 0o755 }),
			Detail: "mode 0644 → 0755",
		},
		{
			Op: diff.OpTypeChanged, Path: "/usr/bin/python3",
			Old:    entry("/usr/bin/python3", scan.TypeFile),
			New:    entry("/usr/bin/python3", scan.TypeSymlink, func(e *scan.Entry) { e.Link = "/tmp/payload"; e.Hashed = false }),
			Detail: "file → symlink",
		},
		{
			Op: diff.OpRetargeted, Path: "/etc/alternatives/editor",
			Old:    entry("/etc/alternatives/editor", scan.TypeSymlink, func(e *scan.Entry) { e.Link = "/usr/bin/nano"; e.Hashed = false }),
			New:    entry("/etc/alternatives/editor", scan.TypeSymlink, func(e *scan.Entry) { e.Link = "/usr/bin/vim.basic"; e.Hashed = false }),
			Detail: "/usr/bin/nano → /usr/bin/vim.basic",
		},
		{
			Op: diff.OpUnreadable, Path: "/var/lib/private/secret",
			Old:    entry("/var/lib/private/secret", scan.TypeFile),
			New:    entry("/var/lib/private/secret", scan.TypeFile, func(e *scan.Entry) { e.Hashed = false; e.Err = "permission denied" }),
			Detail: "permission denied",
		},
		{
			// A partial entry: no hash, so size and date are all there is.
			Op: diff.OpChangedMeta, Path: "/var/lib/vm/disk.img",
			Old:    entry("/var/lib/vm/disk.img", scan.TypeFile, func(e *scan.Entry) { e.Hashed = false; e.Partial = true; e.Size = 1 << 30 }),
			New:    entry("/var/lib/vm/disk.img", scan.TypeFile, func(e *scan.Entry) { e.Hashed = false; e.Partial = true; e.Size = 2 << 30 }),
			Detail: "size 1.0 GiB → 2.0 GiB (not hashed, so content was not verified)",
		},
		{
			// Volatile by nature: reported, but under its own heading.
			Op: diff.OpChangedFile, Path: "/var/log/auth.log",
			Old:    entry("/var/log/auth.log", scan.TypeFile),
			New:    entry("/var/log/auth.log", scan.TypeFile, func(e *scan.Entry) { e.Size = 91234; e.Hash[1] = 0xff }),
			Detail: "3.1 KiB → 89.1 KiB",
		},
	}

	s := Summary{
		Diff: diff.Stats{
			Counts: map[diff.Op]int64{
				diff.OpAddedDir: 1, diff.OpRemovedDir: 1, diff.OpChangedDir: 1,
				diff.OpAdded: 1, diff.OpRemoved: 1, diff.OpChangedFile: 2,
				diff.OpChangedMeta: 2, diff.OpTypeChanged: 1, diff.OpRetargeted: 1,
				diff.OpUnreadable: 1,
			},
			Ignored: 1240, Hidden: 3, Compared: 498220,
		},
		Scan: scan.Stats{
			Dirs: 45011, Files: 456012, Symlinks: 74, Errors: 3,
			Elapsed: 2*time.Minute + 14*time.Second,
		},
		Expected: 1, // /var/log/auth.log
	}
	return h, changes, s
}

// volatilePaths mimics the exclusion set's notion of expected churn.
func volatilePaths(path string) bool {
	return strings.HasPrefix(path, "/var/log/") || strings.HasPrefix(path, "/var/cache/")
}

func render(t *testing.T, format string, opts Options) string {
	t.Helper()
	h, changes, s := fixture()
	var buf bytes.Buffer
	r, err := New(format, &buf, opts)
	if err != nil {
		t.Fatalf("New(%q): %v", format, err)
	}
	if err := r.Header(h); err != nil {
		t.Fatalf("Header: %v", err)
	}
	for _, c := range changes {
		if err := r.Change(c); err != nil {
			t.Fatalf("Change: %v", err)
		}
	}
	if err := r.Close(s); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.String()
}

// golden compares against the recorded output, or rewrites it with -update.
func golden(t *testing.T, name, got string) {
	t.Helper()
	path := filepath.Join("testdata", name)
	if *update {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if got != string(want) {
		t.Errorf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, got, want)
	}
}

func TestTextReportGolden(t *testing.T) {
	golden(t, "report.text.golden", render(t, "text", Options{Volatile: volatilePaths}))
}

func TestJSONReportGolden(t *testing.T) {
	golden(t, "report.json.golden", render(t, "json", Options{}))
}

// TestTextReportNeverPrintsTimes is §11.3 made enforceable: the modification
// time is stored and exposed in JSON, but a date next to a diff line reads as
// the date of the change, and the mtime is a declaration an attacker can set.
func TestTextReportNeverPrintsTimes(t *testing.T) {
	out := render(t, "text", Options{Volatile: volatilePaths})

	// The entries in the fixture carry these timestamps.
	for _, forbidden := range []string{
		"2025-02-19", "1740000000", // the baseline mtime, both spellings
		"2025-09-16", "1758000000", // the live mtime
	} {
		if strings.Contains(out, forbidden) {
			t.Errorf("the text report contains the modification time %q", forbidden)
		}
	}
	// The header's own timestamps are legitimate and must stay.
	for _, wanted := range []string{"2026-03-01T09:12:44Z", "2026-09-23T14:31:02Z"} {
		if !strings.Contains(out, wanted) {
			t.Errorf("the header lost the timestamp %q", wanted)
		}
	}
}

// TestJSONReportCarriesTheTimes is the other half of §11.3.
func TestJSONReportCarriesTheTimes(t *testing.T) {
	out := render(t, "json", Options{})
	var changes int
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("line is not valid JSON: %v\n%s", err, line)
		}
		if rec["record"] != "change" {
			continue
		}
		changes++
		for _, side := range []string{"old", "new"} {
			e, ok := rec[side].(map[string]any)
			if !ok {
				continue
			}
			if _, ok := e["mtime"].(string); !ok {
				t.Errorf("%s side of %v has no mtime: %v", side, rec["path"], e)
			}
		}
	}
	if changes == 0 {
		t.Fatal("no change records were produced")
	}
}

func TestJSONReportIsOneObjectPerLine(t *testing.T) {
	out := render(t, "json", Options{})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	_, changes, _ := fixture()
	if got, want := len(lines), len(changes)+2; got != want {
		t.Fatalf("got %d lines, want %d (header, %d changes, summary)", got, want, len(changes))
	}

	var first, last map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("header: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil {
		t.Fatalf("summary: %v", err)
	}
	if first["record"] != "header" || last["record"] != "summary" {
		t.Errorf("the stream is not header-changes-summary: %v … %v", first["record"], last["record"])
	}
	if got := last["counts"].(map[string]any)["~F"]; got != float64(2) {
		t.Errorf("summary counts ~F = %v, want 2", got)
	}
}

func TestTextReportColor(t *testing.T) {
	plain := render(t, "text", Options{Volatile: volatilePaths})
	colored := render(t, "text", Options{Volatile: volatilePaths, Color: true})

	if strings.Contains(plain, "\033[") {
		t.Error("the plain report contains ANSI escapes")
	}
	for _, want := range []string{ansiGreen + "+D", ansiRed + "-F", ansiYellow + "~F", ansiMagenta + "?E"} {
		if !strings.Contains(colored, want) {
			t.Errorf("the coloured report is missing %q", strings.ReplaceAll(want, "\033", "ESC"))
		}
	}
	// Colour must not change anything else.
	if stripANSI(colored) != plain {
		t.Error("the coloured report differs from the plain one by more than its escapes")
	}
}

func stripANSI(s string) string {
	for _, code := range []string{ansiReset, ansiGreen, ansiRed, ansiYellow, ansiMagenta} {
		s = strings.ReplaceAll(s, code, "")
	}
	return s
}

func TestVolatileChangesAreGroupedApart(t *testing.T) {
	withGrouping := render(t, "text", Options{Volatile: volatilePaths})
	if !strings.Contains(withGrouping, "EXPECTED NOISE") {
		t.Fatal("no expected-noise section was produced")
	}
	noise := withGrouping[strings.Index(withGrouping, "EXPECTED NOISE"):]
	if !strings.Contains(noise, "/var/log/auth.log") {
		t.Error("the volatile change is not in the expected-noise section")
	}
	// It must still be reported, not dropped.
	if strings.Count(withGrouping, "/var/log/auth.log") != 1 {
		t.Error("the volatile change was dropped or duplicated")
	}

	without := render(t, "text", Options{})
	if strings.Contains(without, "EXPECTED NOISE") {
		t.Error("the section appeared although no volatile function was given")
	}
	if !strings.Contains(without, "/var/log/auth.log") {
		t.Error("the change vanished when grouping was disabled")
	}
}

func TestUnknownFormat(t *testing.T) {
	if _, err := New("yaml", &bytes.Buffer{}, Options{}); err == nil {
		t.Fatal("New accepted an unknown format")
	}
	for _, name := range append(Formats(), "", "jsonl") {
		if _, err := New(name, &bytes.Buffer{}, Options{}); err != nil {
			t.Errorf("New(%q) = %v", name, err)
		}
	}
}

func TestReportPropagatesWriteErrors(t *testing.T) {
	h, changes, s := fixture()
	for _, format := range Formats() {
		t.Run(format, func(t *testing.T) {
			r, err := New(format, failingWriter{}, Options{})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			_ = r.Header(h)
			for _, c := range changes {
				_ = r.Change(c)
			}
			if err := r.Close(s); err == nil {
				t.Error("a failing writer produced no error")
			}
		})
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

// TestSummaryNamesEverySkippedMount covers what a FreeBSD porting run showed:
// the summary counted the mount points it had not entered without naming them,
// so an operator could not tell which part of the system went unscanned. It
// also pins the wording, which read "1 pseudo filesystems".
func TestSummaryNamesEverySkippedMount(t *testing.T) {
	h, _, s := fixture()
	s.Scan.SkippedMounts = []scan.SkippedMount{
		{Path: "/dev", FSType: "devfs", Kind: scan.FSPseudo},
		{Path: "/srv/nas", FSType: "nfs", Kind: scan.FSNetwork},
		{Path: "/mnt/backup", FSType: "ext4", Kind: scan.FSLocal},
	}

	var buf bytes.Buffer
	r, err := New("text", &buf, Options{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := r.Header(h); err != nil {
		t.Fatalf("Header: %v", err)
	}
	if err := r.Close(s); err != nil {
		t.Fatalf("Close: %v", err)
	}

	for _, want := range []string{
		"1 pseudo filesystem not crossed: /dev (devfs)",
		"1 network filesystem not crossed: /srv/nas (nfs)",
		"1 local filesystem not crossed: /mnt/backup (ext4)",
	} {
		if !strings.Contains(buf.String(), want) {
			t.Errorf("summary does not contain %q:\n%s", want, buf.String())
		}
	}
}
