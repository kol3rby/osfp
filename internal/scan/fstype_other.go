//go:build !aix && !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !solaris

package scan

// Every supported target has its own fsTypeName. This one only keeps the
// package building elsewhere: an unknown type is never crossed, which is the
// safe answer, and each mount point it stops at is named in the summary.
func fsTypeName(path string) (string, bool) { return "", false }
