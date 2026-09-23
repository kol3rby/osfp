//go:build solaris

package scan

import (
	"golang.org/x/sys/unix"

	"osfp/internal/cstr"
)

// Solaris and illumos expose the base type through statvfs(2).
func fsTypeName(path string) (string, bool) {
	var buf unix.Statvfs_t
	if err := unix.Statvfs(path, &buf); err != nil {
		return "", false
	}
	return cstr.String(buf.Basetype[:]), true
}
