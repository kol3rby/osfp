//go:build !linux

package scan

import "os"

// openForHash opens a file for hashing. Only Linux offers O_NOATIME, so on
// every other target the scan does update access times; the README says so.
func openForHash(path string) (*os.File, error) { return os.Open(path) }
