//go:build openbsd

package scan

import (
	"golang.org/x/sys/unix"

	"osfp/internal/cstr"
)

// OpenBSD spells the field F_fstypename, keeping the C name; the other BSDs
// dropped the prefix.
func fsTypeName(path string) (string, bool) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return "", false
	}
	return cstr.String(buf.F_fstypename[:]), true
}
