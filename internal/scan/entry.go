// Package scan walks a filesystem and produces one Entry per path, in the
// canonical order of internal/canon, with regular files hashed in parallel.
//
// The same pipeline serves both commands: baseline writes the entries to a
// fingerprint, compare joins them with one. That is what guarantees the two
// see the same filesystem under the same rules.
package scan

import (
	"io/fs"
	"time"
)

// Type is the kind of a filesystem object. The values are the letters ls uses,
// which makes both a debug dump and the one-byte field of the fingerprint
// format readable without a lookup table.
type Type byte

const (
	TypeUnknown     Type = 0
	TypeDir         Type = 'd'
	TypeFile        Type = 'f'
	TypeSymlink     Type = 'l'
	TypeFIFO        Type = 'p'
	TypeSocket      Type = 's'
	TypeCharDevice  Type = 'c'
	TypeBlockDevice Type = 'b'
	// TypeError marks a path that could not be read. It is an entry of its
	// own rather than a dropped line: a file that becomes unreadable between
	// two scans is a finding, not an absence.
	TypeError Type = '!'
)

func (t Type) String() string {
	switch t {
	case TypeDir:
		return "directory"
	case TypeFile:
		return "file"
	case TypeSymlink:
		return "symlink"
	case TypeFIFO:
		return "fifo"
	case TypeSocket:
		return "socket"
	case TypeCharDevice:
		return "character device"
	case TypeBlockDevice:
		return "block device"
	case TypeError:
		return "unreadable"
	default:
		return "unknown"
	}
}

// Entry is one filesystem object. It is the unit of everything downstream: it
// is what the fingerprint stores, what the merge join compares, and what the
// report prints.
type Entry struct {
	Path string
	Type Type

	Mode uint32 // permission bits plus setuid, setgid and sticky
	UID  uint32
	GID  uint32
	Size int64
	// MTime is recorded and exposed in the JSONL output, but never compared:
	// see §1.4 of the plan. The one exception is a Partial entry, which has no
	// hash to compare instead.
	MTime int64

	Hash   [32]byte // SHA-256, valid only when Hashed is true
	Hashed bool
	// Partial marks a file that was not hashed because of --max-file-size.
	// Such an entry can only ever be compared on size and mtime, and the
	// report says so rather than claiming a content change it never verified.
	Partial bool

	Link string // target of a symlink, never followed

	Dev   uint64
	Ino   uint64
	Nlink uint32

	// Err is the reason a TypeError entry could not be read.
	Err string
}

// IsDir is a convenience for the walker and the merge join.
func (e *Entry) IsDir() bool { return e.Type == TypeDir }

// ModTime returns the recorded modification time.
func (e *Entry) ModTime() time.Time { return time.Unix(e.MTime, 0) }

// typeOf maps a Go file mode to a Type.
func typeOf(m fs.FileMode) Type {
	switch {
	case m.IsRegular():
		return TypeFile
	case m.IsDir():
		return TypeDir
	case m&fs.ModeSymlink != 0:
		return TypeSymlink
	case m&fs.ModeNamedPipe != 0:
		return TypeFIFO
	case m&fs.ModeSocket != 0:
		return TypeSocket
	case m&fs.ModeCharDevice != 0:
		return TypeCharDevice
	case m&fs.ModeDevice != 0:
		return TypeBlockDevice
	default:
		return TypeUnknown
	}
}

// unixMode extracts the twelve bits a chmod would set: the nine permission
// bits plus setuid, setgid and sticky.
//
// fs.FileMode is used rather than the raw st_mode because it is the same on
// every target, whereas the layout of syscall.Stat_t is not.
func unixMode(m fs.FileMode) uint32 {
	out := uint32(m.Perm())
	if m&fs.ModeSetuid != 0 {
		out |= 0o4000
	}
	if m&fs.ModeSetgid != 0 {
		out |= 0o2000
	}
	if m&fs.ModeSticky != 0 {
		out |= 0o1000
	}
	return out
}
