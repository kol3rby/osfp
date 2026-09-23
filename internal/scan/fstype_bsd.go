//go:build darwin || dragonfly || freebsd

package scan

import (
	"golang.org/x/sys/unix"

	"osfp/internal/cstr"
)

// The BSDs and macOS report the filesystem type by name, which is both more
// readable and more stable than a magic number.
func fsTypeName(path string) (string, bool) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return "", false
	}
	return cstr.String(buf.Fstypename[:]), true
}
