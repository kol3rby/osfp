//go:build unix

package scan

import (
	"io/fs"
	"syscall"
)

// fillStat copies the fields that io/fs does not expose: ownership, and the
// device and inode numbers the one-file-system guard and the hard link
// tracking need.
//
// Only field names are relied upon, never their types: syscall.Stat_t spells
// Dev as int32 on Darwin and uint64 on Linux, Nlink as uint16 here and uint32
// there. Widening conversions make one file enough for every target, and the
// times are taken from fs.FileInfo precisely because Mtim and Mtimespec are
// not spelled the same way everywhere.
func fillStat(e *Entry, info fs.FileInfo) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	e.UID = uint32(st.Uid)
	e.GID = uint32(st.Gid)
	e.Dev = uint64(st.Dev)
	e.Ino = uint64(st.Ino)
	e.Nlink = uint32(st.Nlink)
}
