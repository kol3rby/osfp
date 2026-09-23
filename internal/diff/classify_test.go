package diff

import (
	"strings"
	"testing"

	"osfp/internal/scan"
)

// file returns a plausible regular-file entry; the options mutate it.
func file(mutate ...func(*scan.Entry)) *scan.Entry {
	e := &scan.Entry{
		Path:   "/etc/passwd",
		Type:   scan.TypeFile,
		Mode:   0o644,
		UID:    0,
		GID:    0,
		Size:   1024,
		MTime:  1700000000,
		Hash:   [32]byte{1, 2, 3},
		Hashed: true,
	}
	for _, m := range mutate {
		m(e)
	}
	return e
}

func dir(mutate ...func(*scan.Entry)) *scan.Entry {
	e := &scan.Entry{Path: "/etc", Type: scan.TypeDir, Mode: 0o755, MTime: 1700000000}
	for _, m := range mutate {
		m(e)
	}
	return e
}

func link(target string, mutate ...func(*scan.Entry)) *scan.Entry {
	e := &scan.Entry{Path: "/bin/sh", Type: scan.TypeSymlink, Mode: 0o777, Link: target, MTime: 1700000000}
	for _, m := range mutate {
		m(e)
	}
	return e
}

func TestClassify(t *testing.T) {
	tests := []struct {
		name       string
		old, live  *scan.Entry
		want       Op
		wantDetail string // substring
	}{
		{
			"identical", file(), file(), OpNone, "",
		},
		{
			// The decision of §1.4, locked: a file that was touched, restored
			// from a backup or reinstalled identically produces no line.
			"same hash, different mtime",
			file(),
			file(func(e *scan.Entry) { e.MTime = 1 }),
			OpNone, "",
		},
		{
			"different hash",
			file(),
			file(func(e *scan.Entry) { e.Hash = [32]byte{9}; e.Size = 2048 }),
			OpChangedFile, "1.0 KiB → 2.0 KiB",
		},
		{
			// A size change with the same content is impossible in practice,
			// but the rule is what matters: the hash decides, not the size.
			"same hash, different size",
			file(),
			file(func(e *scan.Entry) { e.Size = 4096 }),
			OpNone, "",
		},
		{
			"mode changed",
			file(),
			file(func(e *scan.Entry) { e.Mode = 0o755 }),
			OpChangedMeta, "mode 0644 → 0755",
		},
		{
			"ownership changed",
			file(),
			file(func(e *scan.Entry) { e.UID, e.GID = 998, 998 }),
			OpChangedMeta, "uid 0 → 998, gid 0 → 998",
		},
		{
			"content and mode changed reports the content",
			file(),
			file(func(e *scan.Entry) { e.Hash = [32]byte{9}; e.Mode = 0o755 }),
			OpChangedFile, "→",
		},
		{
			"directory mode changed",
			dir(),
			dir(func(e *scan.Entry) { e.Mode = 0o700 }),
			OpChangedDir, "mode 0755 → 0700",
		},
		{
			"directory unchanged",
			dir(), dir(), OpNone, "",
		},
		{
			"symlink retargeted",
			link("/bin/dash"),
			link("/bin/bash"),
			OpRetargeted, "/bin/dash → /bin/bash",
		},
		{
			"symlink unchanged",
			link("/bin/dash"), link("/bin/dash"), OpNone, "",
		},
		{
			"symlink ownership changed",
			link("/bin/dash"),
			link("/bin/dash", func(e *scan.Entry) { e.UID = 1000 }),
			OpChangedMeta, "uid 0 → 1000",
		},
		{
			"file became a symlink",
			file(),
			link("/dev/null"),
			OpTypeChanged, "file → symlink",
		},
		{
			"symlink became a file",
			link("/dev/null"),
			file(),
			OpTypeChanged, "symlink → file",
		},
		{
			"file became a directory",
			file(), dir(), OpTypeChanged, "file → directory",
		},
		{
			"unreadable now",
			file(),
			file(func(e *scan.Entry) { e.Hashed = false; e.Err = "permission denied" }),
			OpUnreadable, "permission denied",
		},
		{
			"was unreadable when the fingerprint was taken",
			file(func(e *scan.Entry) { e.Hashed = false; e.Err = "permission denied" }),
			file(),
			OpUnreadable, "unreadable when the fingerprint was taken",
		},
		{
			// §7.2: without a hash there is nothing but size and mtime, and
			// the category stays %F — no content change was ever verified.
			"partial entry, size changed",
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true; e.Size = 1 << 30 }),
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true; e.Size = 2 << 30 }),
			OpChangedMeta, "content was not verified",
		},
		{
			"partial entry, mtime changed",
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true }),
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true; e.MTime = 42 }),
			OpChangedMeta, "mtime changed",
		},
		{
			"partial entry, nothing changed",
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true }),
			file(func(e *scan.Entry) { e.Hashed = false; e.Partial = true }),
			OpNone, "",
		},
		{
			"fifo ownership changed",
			&scan.Entry{Type: scan.TypeFIFO, Mode: 0o644},
			&scan.Entry{Type: scan.TypeFIFO, Mode: 0o644, UID: 7},
			OpChangedMeta, "uid 0 → 7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			op, detail := Classify(tt.old, tt.live)
			if op != tt.want {
				t.Errorf("Classify = %s (%q), want %s", op, detail, tt.want)
			}
			if tt.wantDetail != "" && !strings.Contains(detail, tt.wantDetail) {
				t.Errorf("detail = %q, want it to contain %q", detail, tt.wantDetail)
			}
			if tt.want == OpNone && detail != "" {
				t.Errorf("an unchanged entry produced the detail %q", detail)
			}
		})
	}
}

// TestClassifyNeverReadsMTime is the structural guarantee behind §1.4: apart
// from the entries that have no hash, changing only the date must never change
// the verdict, whatever else the entry looks like.
func TestClassifyNeverReadsMTime(t *testing.T) {
	cases := []*scan.Entry{
		file(),
		file(func(e *scan.Entry) { e.Mode = 0o600 }),
		dir(),
		link("/bin/dash"),
		{Type: scan.TypeSocket, Mode: 0o755},
	}
	for _, base := range cases {
		t.Run(base.Type.String(), func(t *testing.T) {
			for _, mtime := range []int64{0, 1, 1 << 40, -1} {
				live := *base
				live.MTime = mtime
				op, detail := Classify(base, &live)
				if op != OpNone {
					t.Errorf("mtime %d alone produced %s (%s)", mtime, op, detail)
				}
			}
		})
	}
}

func TestOpCodes(t *testing.T) {
	for _, op := range AllOps {
		code := op.String()
		got, err := ParseOp(code)
		if err != nil || got != op {
			t.Errorf("ParseOp(%q) = %v, %v; want %v", code, got, err, op)
		}
		if op.Description() == "" {
			t.Errorf("%s has no description", code)
		}
	}
	if _, err := ParseOp("zz"); err == nil {
		t.Error("ParseOp accepted an unknown code")
	}
	if got := OpNone.String(); got != "=" {
		t.Errorf("OpNone.String() = %q, want =", got)
	}

	set, err := ParseOps("+D, -F ,~F")
	if err != nil {
		t.Fatalf("ParseOps: %v", err)
	}
	if len(set) != 3 || !set[OpAddedDir] || !set[OpRemoved] || !set[OpChangedFile] {
		t.Errorf("ParseOps returned %v", set)
	}
	if _, err := ParseOps(" , "); err == nil {
		t.Error("ParseOps accepted an empty list")
	}
	if _, err := ParseOps("+D,nope"); err == nil {
		t.Error("ParseOps accepted an unknown code")
	}
}
