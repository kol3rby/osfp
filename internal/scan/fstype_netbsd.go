//go:build netbsd

package scan

import (
	"golang.org/x/sys/unix"

	"osfp/internal/cstr"
)

// NetBSD offers statvfs(2) rather than statfs(2), and carries the type name in
// it.
func fsTypeName(path string) (string, bool) {
	var buf unix.Statvfs_t
	if err := unix.Statvfs(path, &buf); err != nil {
		return "", false
	}
	return cstr.String(buf.Fstypename[:]), true
}
