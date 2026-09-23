package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"osfp/internal/canon"
	"osfp/internal/osdetect"
	"osfp/internal/scan"
)

func testMeta() *Meta {
	return &Meta{
		Tool:        "osfp",
		ToolVersion: "test",
		CreatedAt:   time.Date(2026, 3, 1, 9, 12, 44, 0, time.UTC),
		Key:         "linux-debian-12-amd64",
		System: osdetect.Info{
			OS: "linux", Distro: "debian", Version: "12", Arch: "amd64",
			Kernel: "6.1.0-18-amd64", Pretty: "Debian GNU/Linux 12 (bookworm)",
			Hostname: "audit-01", Source: "/etc/os-release",
		},
		Privileged: true,
		Scan: ScanOptions{
			Root: "/", Mounts: "local", MaxDepth: 64, Jobs: 8,
		},
		Exclusions: []string{"/proc", "/sys", "/dev", "/tmp"},
	}
}

// entryFor builds a deterministic entry for a path, so that half a million of
// them can be produced twice without being kept in memory.
//
// The hash is the SHA-256 of the path: deterministic, and as incompressible as
// a real digest, which is what makes the size measurement honest.
func entryFor(path string, i int) scan.Entry {
	e := scan.Entry{
		Path:  path,
		Mode:  0o644,
		UID:   0,
		GID:   0,
		Size:  int64(i%100000) * 13,
		MTime: 1700000000 + int64(i%1000000),
		Dev:   2049,
		Ino:   uint64(i) + 1,
		Nlink: 1,
	}
	switch {
	case strings.HasSuffix(path, "/"):
	case i%37 == 0:
		e.Type = scan.TypeSymlink
		e.Link = "../" + filepath.Base(path)
	case i%211 == 0:
		e.Type = scan.TypeDir
		e.Mode = 0o755
	default:
		e.Type = scan.TypeFile
		e.Hash = sha256.Sum256([]byte(path))
		e.Hashed = true
		if i%97 == 0 {
			e.Mode = 0o755
		}
		if i%1013 == 0 {
			e.UID, e.GID = 1000, 1000
		}
	}
	switch {
	case i%5003 == 0:
		e.Hashed = false
		e.Hash = [32]byte{}
		e.Err = "open " + path + ": permission denied"
	case i%7001 == 0:
		e.Hashed = false
		e.Hash = [32]byte{}
		e.Partial = true
		e.Size = 8 << 30
	}
	return e
}

// genPaths produces plausible absolute paths for a Debian-like system, sorted
// in canonical order and free of duplicates.
func genPaths(n int, seed int64) []string {
	rng := rand.New(rand.NewSource(seed))
	words := []string{
		"libssl", "libcrypto", "systemd", "python3.11", "perl", "gcc-12",
		"binutils", "coreutils", "dpkg", "apt", "grub", "linux-image",
		"fonts-dejavu", "ca-certificates", "openssh-server", "nginx",
	}
	seen := make(map[string]struct{}, n)
	out := make([]string, 0, n)
	for len(out) < n {
		var p string
		switch rng.Intn(6) {
		case 0:
			p = fmt.Sprintf("/usr/lib/x86_64-linux-gnu/%s.so.%d.%d.%d",
				words[rng.Intn(len(words))], rng.Intn(4), rng.Intn(40), rng.Intn(20))
		case 1:
			p = fmt.Sprintf("/usr/share/doc/%s-%d/changelog.Debian.%d.gz",
				words[rng.Intn(len(words))], rng.Intn(50), rng.Intn(1000))
		case 2:
			p = fmt.Sprintf("/usr/share/man/man%d/%s-%d.%d.gz",
				rng.Intn(9), words[rng.Intn(len(words))], rng.Intn(500), rng.Intn(9))
		case 3:
			p = fmt.Sprintf("/etc/%s/conf.d/%02d-%s.conf",
				words[rng.Intn(len(words))], rng.Intn(100), words[rng.Intn(len(words))])
		case 4:
			p = fmt.Sprintf("/var/lib/dpkg/info/%s-%d.%s",
				words[rng.Intn(len(words))], rng.Intn(2000),
				[]string{"list", "md5sums", "postinst", "conffiles"}[rng.Intn(4)])
		default:
			p = fmt.Sprintf("/usr/src/linux-headers-6.1.%d/include/linux/%s_%d.h",
				rng.Intn(60), words[rng.Intn(len(words))], rng.Intn(3000))
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	slices.SortFunc(out, canon.CompareKey)
	return out
}

// writeFingerprint writes n generated entries and returns the bytes.
func writeFingerprint(t testing.TB, n int, seed int64) ([]byte, []string) {
	t.Helper()
	paths := genPaths(n, seed)
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testMeta())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	for i, p := range paths {
		e := entryFor(p, i)
		if err := w.Add(&e); err != nil {
			t.Fatalf("Add(%s): %v", p, err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return buf.Bytes(), paths
}

func openBytes(t testing.TB, b []byte) *Reader {
	t.Helper()
	r, err := NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("NewReader: %v", err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func TestRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 2, 1000, 20000} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			raw, paths := writeFingerprint(t, n, 1)
			r := openBytes(t, raw)

			if got := r.Meta().Entries; got != int64(n) {
				t.Errorf("Meta().Entries = %d, want %d", got, n)
			}
			if err := r.Verify(); err != nil {
				t.Errorf("Verify: %v", err)
			}

			var i int
			err := r.Iterate(func(e *scan.Entry) error {
				if i >= len(paths) {
					return fmt.Errorf("read more entries than were written")
				}
				want := entryFor(paths[i], i)
				if *e != want {
					return fmt.Errorf("entry %d differs:\n got %+v\nwant %+v", i, *e, want)
				}
				i++
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if i != n {
				t.Fatalf("read %d entries, wrote %d", i, n)
			}
		})
	}
}

func TestRoundTripPreservesMetadata(t *testing.T) {
	raw, _ := writeFingerprint(t, 10, 1)
	got := openBytes(t, raw).Meta()
	want := testMeta()

	if got.Key != want.Key || got.Tool != want.Tool || got.ToolVersion != want.ToolVersion {
		t.Errorf("identity fields differ: %+v", got)
	}
	if !got.CreatedAt.Equal(want.CreatedAt) {
		t.Errorf("CreatedAt = %v, want %v", got.CreatedAt, want.CreatedAt)
	}
	if got.System != want.System {
		t.Errorf("System = %+v, want %+v", got.System, want.System)
	}
	if got.Scan != want.Scan {
		t.Errorf("Scan = %+v, want %+v", got.Scan, want.Scan)
	}
	if !slices.Equal(got.Exclusions, want.Exclusions) {
		t.Errorf("Exclusions = %v, want %v", got.Exclusions, want.Exclusions)
	}
	if !got.Privileged {
		t.Error("Privileged was not preserved")
	}
}

// TestRoundTripHalfAMillion is the phase's deliverable, and the measurement
// that decides whether the bespoke container was worth writing: §4.2 estimates
// 20–25 MB for 500 000 entries, against ~85 MB for SQLite and ~90–110 MB for
// bbolt.
func TestRoundTripHalfAMillion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped by -short")
	}
	const n = 500000

	start := time.Now()
	raw, paths := writeFingerprint(t, n, 42)
	writeTime := time.Since(start)

	r := openBytes(t, raw)
	if got := r.Meta().Entries; got != n {
		t.Fatalf("Meta().Entries = %d, want %d", got, n)
	}

	start = time.Now()
	var i int
	err := r.Iterate(func(e *scan.Entry) error {
		want := entryFor(paths[i], i)
		if *e != want {
			return fmt.Errorf("entry %d (%s) differs", i, e.Path)
		}
		i++
		return nil
	})
	readTime := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if i != n {
		t.Fatalf("read %d entries, wrote %d", i, n)
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var pathBytes int
	for _, p := range paths {
		pathBytes += len(p)
	}
	size := len(raw)
	t.Logf("%d entries → %.1f MB (%.1f bytes/entry), %d blocks",
		n, float64(size)/1e6, float64(size)/n, r.Meta().Blocks)
	t.Logf("raw input: %.1f MB of paths + %.1f MB of hashes = %.1f MB floor",
		float64(pathBytes)/1e6, float64(n)*32/1e6, float64(pathBytes+n*32)/1e6)
	t.Logf("written in %s, read back in %s", writeTime.Round(time.Millisecond), readTime.Round(time.Millisecond))

	if size > 40<<20 {
		t.Errorf("fingerprint is %.1f MB; §4.2 estimated 20–25 MB and the case for a "+
			"bespoke format rests on that", float64(size)/(1<<20))
	}
}

func TestWriterRejectsOutOfOrder(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, testMeta())
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	// Canonical order is /a < /a/b < /a.txt, so these two are in order.
	for _, p := range []string{"/a", "/a.txt"} {
		e := entryFor(p, 0)
		if err := w.Add(&e); err != nil {
			t.Fatalf("Add(%s): %v", p, err)
		}
	}
	// /a/b sorts before /a.txt, so it is out of order here — and this is
	// precisely the pair a plain byte comparison would get wrong.
	e := entryFor("/a/b", 0)
	if err := w.Add(&e); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("Add out of order returned %v, want ErrOutOfOrder", err)
	}
	// A duplicate key is equally fatal to a merge join.
	e = entryFor("/a.txt", 0)
	if err := w.Add(&e); !errors.Is(err, ErrOutOfOrder) {
		t.Fatalf("Add of a duplicate returned %v, want ErrOutOfOrder", err)
	}
}

func TestSeek(t *testing.T) {
	raw, paths := writeFingerprint(t, 20000, 7)
	r := openBytes(t, raw)
	if r.Meta().Blocks < 2 {
		t.Fatalf("the fingerprint has %d blocks; seeking is not exercised", r.Meta().Blocks)
	}

	t.Run("exact keys", func(t *testing.T) {
		for _, i := range []int{0, 1, 77, 5000, len(paths) - 1} {
			c, err := r.Seek(paths[i])
			if err != nil {
				t.Fatalf("Seek(%s): %v", paths[i], err)
			}
			e, err := c.Next()
			if err != nil {
				t.Fatalf("Next after Seek(%s): %v", paths[i], err)
			}
			if e.Path != paths[i] {
				t.Errorf("Seek(%s) landed on %s", paths[i], e.Path)
			}
			want := entryFor(paths[i], i)
			if *e != want {
				t.Errorf("Seek(%s) returned a different entry than a full pass", paths[i])
			}
		}
	})

	t.Run("key that does not exist lands on the next one", func(t *testing.T) {
		missing := paths[1000] + "-does-not-exist"
		c, err := r.Seek(missing)
		if err != nil {
			t.Fatalf("Seek: %v", err)
		}
		e, err := c.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if canon.CompareKey(e.Path, missing) < 0 {
			t.Errorf("Seek(%s) landed on %s, which sorts before it", missing, e.Path)
		}
	})

	t.Run("before the first key", func(t *testing.T) {
		c, err := r.Seek("/")
		if err != nil {
			t.Fatalf("Seek: %v", err)
		}
		e, err := c.Next()
		if err != nil {
			t.Fatalf("Next: %v", err)
		}
		if e.Path != paths[0] {
			t.Errorf("Seek(/) landed on %s, want the first entry %s", e.Path, paths[0])
		}
	})

	t.Run("past the last key", func(t *testing.T) {
		c, err := r.Seek("/zzzzzz")
		if err != nil {
			t.Fatalf("Seek: %v", err)
		}
		if _, err := c.Next(); err != io.EOF {
			t.Errorf("Next past the end returned %v, want io.EOF", err)
		}
	})

	t.Run("continues to the end", func(t *testing.T) {
		from := len(paths) - 2500
		c, err := r.Seek(paths[from])
		if err != nil {
			t.Fatalf("Seek: %v", err)
		}
		i := from
		for {
			e, err := c.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("Next: %v", err)
			}
			if e.Path != paths[i] {
				t.Fatalf("entry %d after seek: got %s, want %s", i, e.Path, paths[i])
			}
			i++
		}
		if i != len(paths) {
			t.Errorf("iteration after Seek stopped at %d of %d", i, len(paths))
		}
	})
}

func TestVerifyDetectsCorruption(t *testing.T) {
	raw, _ := writeFingerprint(t, 5000, 3)

	// A byte flipped in the middle of the data section: the file still parses,
	// which is exactly why the digest exists.
	damaged := slices.Clone(raw)
	damaged[len(damaged)/2] ^= 0x01

	r, err := NewReader(bytes.NewReader(damaged), int64(len(damaged)))
	if err != nil {
		// Parsing may also fail outright, which is an acceptable outcome.
		return
	}
	defer r.Close()
	if err := r.Verify(); !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("Verify on a damaged file returned %v, want ErrDigestMismatch", err)
	}
}

func TestOpenRejectsMalformedFiles(t *testing.T) {
	good, _ := writeFingerprint(t, 500, 5)

	tests := []struct {
		name string
		make func() []byte
		want error
	}{
		{"empty", func() []byte { return nil }, ErrCorrupt},
		{"too short", func() []byte { return make([]byte, 40) }, ErrCorrupt},
		{"bad magic", func() []byte {
			b := slices.Clone(good)
			b[0] = 'X'
			return b
		}, ErrBadMagic},
		{"future format version", func() []byte {
			b := slices.Clone(good)
			b[len(Magic)] = FormatVersion + 1
			return b
		}, ErrUnsupportedVersion},
		{"unknown compression", func() []byte {
			b := slices.Clone(good)
			b[len(Magic)+2] = 99
			return b
		}, ErrUnsupportedVersion},
		{"truncated tail", func() []byte { return good[:len(good)-16] }, ErrCorrupt},
		{"truncated body", func() []byte {
			b := slices.Clone(good)
			return append(b[:len(b)/2], b[len(b)-footerSize:]...)
		}, ErrCorrupt},
		{"section offset past the end", func() []byte {
			b := slices.Clone(good)
			// The first footer field is the metadata offset.
			binary.LittleEndian.PutUint64(b[len(b)-footerSize:], uint64(len(b)*4))
			return b
		}, ErrCorrupt},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := tt.make()
			r, err := NewReader(bytes.NewReader(b), int64(len(b)))
			if err == nil {
				r.Close()
				t.Fatal("NewReader accepted a malformed file")
			}
			if tt.want != nil && !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestOpenFile(t *testing.T) {
	raw, paths := writeFingerprint(t, 3000, 9)
	path := filepath.Join(t.TempDir(), "linux-debian-12-amd64.osfp")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	var n int
	if err := r.Iterate(func(*scan.Entry) error { n++; return nil }); err != nil {
		t.Fatalf("Iterate: %v", err)
	}
	if n != len(paths) {
		t.Errorf("read %d entries, want %d", n, len(paths))
	}

	if _, err := Open(filepath.Join(t.TempDir(), "missing.osfp")); err == nil {
		t.Error("Open accepted a missing file")
	}
}

func TestIterateStopsOnCallbackError(t *testing.T) {
	raw, _ := writeFingerprint(t, 5000, 11)
	r := openBytes(t, raw)

	want := errors.New("stop here")
	var seen int
	err := r.Iterate(func(*scan.Entry) error {
		seen++
		if seen == 42 {
			return want
		}
		return nil
	})
	if !errors.Is(err, want) {
		t.Fatalf("Iterate returned %v, want %v", err, want)
	}
	if seen != 42 {
		t.Errorf("callback ran %d times after stopping, want 42", seen)
	}
}

// TestFrontCodingSharesPrefixes checks the mechanism the size claim rests on.
func TestFrontCodingSharesPrefixes(t *testing.T) {
	const prev = "/usr/lib/x86_64-linux-gnu/libssl.so.3.0.11"
	const next = "/usr/lib/x86_64-linux-gnu/libssl.so.3.0.12"

	e := entryFor(next, 1)
	withPrev := appendEntry(nil, &e, prev)
	standalone := appendEntry(nil, &e, "")

	if len(withPrev) >= len(standalone) {
		t.Errorf("front coding saved nothing: %d bytes against %d", len(withPrev), len(standalone))
	}
	if saved := len(standalone) - len(withPrev); saved < 35 {
		t.Errorf("front coding saved only %d bytes on a 41-byte shared prefix", saved)
	}
}

func FuzzDecodeBlock(f *testing.F) {
	// Seed with real blocks, so the fuzzer starts from something decodable.
	for _, n := range []int{1, 5, 50} {
		paths := genPaths(n, int64(n))
		var block []byte
		prev := ""
		for i, p := range paths {
			e := entryFor(p, i)
			block = appendEntry(block, &e, prev)
			prev = p
		}
		f.Add(block)
	}
	f.Add([]byte{})
	f.Add([]byte{0x00})

	f.Fuzz(func(t *testing.T, block []byte) {
		// The contract is narrow and absolute: whatever the bytes, the
		// decoder returns entries or an error, and never panics.
		var d blockDecoder
		d.reset(block)
		prev := ""
		for i := 0; i < 10000; i++ {
			e, err := d.next()
			if err != nil {
				return
			}
			if e.Path == "" {
				t.Fatalf("decoded an entry with an empty path from %q", block)
			}
			if prev != "" && canon.CompareKey(prev, e.Path) >= 0 {
				t.Fatalf("decoded %q after %q, which breaks the canonical order", e.Path, prev)
			}
			prev = e.Path
		}
	})
}

func FuzzNewReader(f *testing.F) {
	for _, n := range []int{0, 1, 200} {
		raw, _ := writeFingerprint(f, n, int64(n+1))
		f.Add(raw)
	}
	f.Add([]byte(Magic))
	f.Add(make([]byte, headerSize+footerSize))

	f.Fuzz(func(t *testing.T, data []byte) {
		r, err := NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		defer r.Close()
		// A file that parses must also iterate without panicking, however
		// nonsensical its contents.
		var n int
		_ = r.Iterate(func(*scan.Entry) error {
			n++
			if n > 100000 {
				return io.EOF
			}
			return nil
		})
		_ = r.Verify()
		_, _ = r.Seek("/etc/passwd")
	})
}

func BenchmarkWriterAdd(b *testing.B) {
	paths := genPaths(50000, 1)
	entries := make([]scan.Entry, len(paths))
	for i, p := range paths {
		entries[i] = entryFor(p, i)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w, err := NewWriter(io.Discard, testMeta())
		if err != nil {
			b.Fatalf("NewWriter: %v", err)
		}
		for j := range entries {
			if err := w.Add(&entries[j]); err != nil {
				b.Fatalf("Add: %v", err)
			}
		}
		if err := w.Close(); err != nil {
			b.Fatalf("Close: %v", err)
		}
	}
	b.ReportMetric(float64(b.N*len(entries))/b.Elapsed().Seconds(), "entries/s")
}

func BenchmarkIterate(b *testing.B) {
	raw, paths := writeFingerprint(b, 50000, 1)
	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		r, err := NewReader(bytes.NewReader(raw), int64(len(raw)))
		if err != nil {
			b.Fatalf("NewReader: %v", err)
		}
		if err := r.Iterate(func(*scan.Entry) error { return nil }); err != nil {
			b.Fatalf("Iterate: %v", err)
		}
		r.Close()
	}
	b.ReportMetric(float64(b.N*len(paths))/b.Elapsed().Seconds(), "entries/s")
}

// TestReadRealFingerprint is the counterpart of TestScanRealTree: it opens a
// fingerprint produced by the real command and checks it end to end. Opt-in:
//
//	OSFP_FINGERPRINT=/path/to/linux-debian-13-arm64.osfp \
//	  go test ./internal/store/ -run TestReadRealFingerprint -v
func TestReadRealFingerprint(t *testing.T) {
	path := os.Getenv("OSFP_FINGERPRINT")
	if path == "" {
		t.Skip("set OSFP_FINGERPRINT to a fingerprint file to run this")
	}
	r, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer r.Close()
	if err := r.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	m := r.Meta()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}

	var n, hashed int64
	var last string
	if err := r.Iterate(func(e *scan.Entry) error {
		if last != "" && canon.CompareKey(last, e.Path) >= 0 {
			return fmt.Errorf("out of canonical order: %q then %q", last, e.Path)
		}
		last = e.Path
		if e.Hashed {
			hashed++
		}
		n++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n != m.Entries {
		t.Errorf("iterated %d entries, the footer announces %d", n, m.Entries)
	}

	t.Logf("%s — %s, %s, created %s by osfp %s",
		filepath.Base(path), m.Key, m.System.Pretty,
		m.CreatedAt.Format(time.RFC3339), m.ToolVersion)
	t.Logf("scope %s · %d exclusions · mounts=%s · privileged=%v",
		m.Scan.Root, len(m.Exclusions), m.Scan.Mounts, m.Privileged)
	t.Logf("%d entries (%d hashed, %d unreadable) in %d blocks",
		m.Entries, hashed, m.Errors, m.Blocks)
	t.Logf("file size %.1f MiB → %.1f bytes/entry; extrapolated to 500k entries: %.1f MB",
		float64(st.Size())/(1<<20), float64(st.Size())/float64(m.Entries),
		float64(st.Size())/float64(m.Entries)*500000/1e6)
}
