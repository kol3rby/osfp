//go:build !cgo

package main

// cgoEnabled reports how the binary was built. Releases are built with
// CGO_ENABLED=0 so that Solaris/illumos and AIX stay cross-compilable.
const cgoEnabled = false
