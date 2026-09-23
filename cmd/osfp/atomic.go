package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeBufferSize smooths the small writes the fingerprint writer makes — an
// eight-byte block header followed by a compressed block — into whole pages.
const writeBufferSize = 1 << 20

// atomicFile writes to a temporary file next to its destination and only moves
// it into place once it is complete and on disk.
//
// A fingerprint that exists must be whole: an interrupted scan that left a
// half-written file under the expected name would be compared months later
// against a system, and the report would be nonsense. Renaming within the same
// directory is atomic, so the file either is not there or is complete.
type atomicFile struct {
	final string
	tmp   string
	f     *os.File
	buf   *bufio.Writer
	done  bool
}

// createAtomic opens the temporary file for path. TempPath is exposed so that
// the scan can exclude it from its own walk.
func createAtomic(path string) (*atomicFile, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	tmp := abs + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &atomicFile{final: abs, tmp: tmp, f: f, buf: bufio.NewWriterSize(f, writeBufferSize)}, nil
}

// Writer returns the destination to write the fingerprint to.
func (a *atomicFile) Writer() io.Writer { return a.buf }

// Paths returns the final and temporary names, both of which the scan must
// exclude: a fingerprint that recorded itself would never compare equal.
func (a *atomicFile) Paths() []string { return []string{a.final, a.tmp} }

// Commit flushes, syncs and renames. The directory is synced too: without it,
// a crash could leave the rename unrecorded and the file under its temporary
// name — which is exactly the half-state the whole dance avoids.
func (a *atomicFile) Commit() error {
	if a.done {
		return nil
	}
	a.done = true
	if err := a.buf.Flush(); err != nil {
		a.f.Close()
		os.Remove(a.tmp)
		return err
	}
	if err := a.f.Sync(); err != nil {
		a.f.Close()
		os.Remove(a.tmp)
		return err
	}
	if err := a.f.Close(); err != nil {
		os.Remove(a.tmp)
		return err
	}
	if err := os.Rename(a.tmp, a.final); err != nil {
		os.Remove(a.tmp)
		return err
	}
	return syncDir(filepath.Dir(a.final))
}

// Abort discards the temporary file. It is safe to call after Commit, which is
// what makes "defer a.Abort()" the right way to use this type.
func (a *atomicFile) Abort() {
	if a.done {
		return
	}
	a.done = true
	a.f.Close()
	os.Remove(a.tmp)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", dir, err)
	}
	return nil
}
