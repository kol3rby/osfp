//go:build linux

package scan

import (
	"errors"
	"os"
	"syscall"
)

// openForHash opens a file without disturbing its access time.
//
// Reading a file updates its atime, which would make the scan itself a
// modification of the system being audited. O_NOATIME prevents that, but the
// kernel only grants it to the file's owner or to a privileged process — which
// is the normal case, since baseline and compare require root. The fallback
// exists for --allow-non-root, where an inaccurate atime is a lesser evil than
// a failed scan.
func openForHash(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOATIME, 0)
	if err == nil {
		return f, nil
	}
	if errors.Is(err, syscall.EPERM) {
		return os.Open(path)
	}
	return nil, err
}
