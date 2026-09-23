package main

import (
	"fmt"
	"os"
)

// requireRoot refuses to scan as an unprivileged user.
//
// This is the first thing a scanning command does, before the OS is detected
// and before any file is opened. An unprivileged scan cannot read /etc/shadow,
// /root or /var/lib/private, nor traverse directories in mode 0700. It
// produces a silently incomplete fingerprint, or worse a comparison report
// full of spurious deletions — the worst possible outcome for an audit tool,
// because it looks correct. Producing nothing is better.
//
// os.Geteuid is portable across every target, so no x/sys is needed here. The
// effective uid is what is tested, not the real one, so that sudo and setuid
// behave as expected.
func requireRoot(allowNonRoot bool) error {
	euid := os.Geteuid()
	if euid == 0 {
		return nil
	}
	if !allowNonRoot {
		return withExit(exitPrivilege, fmt.Errorf(
			"must be run as root (effective uid %d); a scan run as an unprivileged "+
				"user cannot read large parts of the filesystem and would produce a "+
				"misleading report\n"+
				"       pass --allow-non-root to scan anyway; the result is marked "+
				"UNPRIVILEGED and cannot be compared with a privileged one", euid))
	}
	fmt.Fprintln(stderr, "WARNING: running unprivileged; the result is incomplete "+
		"and must not be used as an audit baseline")
	return nil
}

// privileged reports whether this process can read the whole filesystem.
func privileged() bool { return os.Geteuid() == 0 }
