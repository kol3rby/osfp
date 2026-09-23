//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package osdetect

import (
	"golang.org/x/sys/unix"

	"osfp/internal/cstr"
)

// sysUname calls uname(2). It is the only part of this package that touches
// the system directly, which is why it is also the only part behind a build
// tag: every parser stays compiled, and tested, on every platform.
func sysUname() (utsname, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return utsname{}, err
	}
	return utsname{
		Sysname:  cstr.String(u.Sysname[:]),
		Nodename: cstr.String(u.Nodename[:]),
		Release:  cstr.String(u.Release[:]),
		Version:  cstr.String(u.Version[:]),
		Machine:  cstr.String(u.Machine[:]),
	}, nil
}
