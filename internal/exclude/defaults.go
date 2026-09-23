// Package exclude decides which paths a scan must not look at.
//
// Exclusions are cumulative and come from three layers (in this order): the
// built-in list for the operating system family, what the operator added on
// the command line, and the auto-exclusions osfp computes for itself. The
// effective list is recorded in the fingerprint so that a comparison can be
// run on exactly the same perimeter months later.
package exclude

// commonDefaults are excluded on every system: kernel interfaces, volatile
// runtime state and mount points for removable media. None of them is part of
// what an installed operating system is.
var commonDefaults = []string{
	"/proc",
	"/sys",
	"/dev",
	"/tmp",
	"/var/tmp",
	"/run",
	"/var/run",
	"/media",
	"/mnt",
	"/lost+found",
}

// osDefaults are the additions specific to an operating system family, keyed
// by GOOS.
//
// /home and /root are deliberately absent: on a freshly installed system they
// are nearly empty, and what appears in them afterwards — SSH keys, scripts,
// shell histories, cloned repositories — is precisely what an audit is looking
// for. Whoever audits a multi-user file server excludes them by hand.
var osDefaults = map[string][]string{
	"linux": {
		// /sys/fs/cgroup is covered by /sys and would only add a redundant
		// line to the exclusion list recorded in the fingerprint.
		"/var/lib/docker",
		"/swapfile",
	},
	"solaris": {
		"/devices",
		"/system/contract",
		"/system/object",
		"/system/volatile",
		"/rpool",
	},
	"freebsd": {
		"/compat/linux/proc",
		"/var/db/freebsd-update",
	},
	// OpenBSD and NetBSD have neither a Linux procfs nor freebsd-update, and
	// nothing of their own that commonDefaults misses. The entries exist so
	// that they do not borrow the FreeBSD list, which would be recorded in
	// their fingerprints as exclusions of paths they do not have.
	"openbsd": {},
	"netbsd":  {},
	"darwin": {
		"/Volumes",
		"/System/Volumes",
		"/private/var/vm",
		"/.Spotlight-V100",
		"/.fseventsd",
	},
}

// volatileDefaults are *not* excluded. They are scanned like everything else,
// but the report groups them in a foldable "expected noise" section: a package
// installation writes to /var/cache, and a running system writes to /var/log,
// so a difference there says much less than one in /etc.
//
// Marking them is more honest than excluding them silently: the operator still
// sees what changed, and still gets to decide it does not matter.
var volatileDefaults = []string{
	"/var/log",
	"/var/cache",
	"/var/spool",
}

// Defaults returns the built-in exclusions for an operating system, which is
// named by its GOOS value. illumos shares the Solaris list and DragonFly the
// FreeBSD one; OpenBSD and NetBSD have their own.
func Defaults(goos string) []string {
	out := make([]string, 0, len(commonDefaults)+8)
	out = append(out, commonDefaults...)
	out = append(out, osDefaults[family(goos)]...)
	return out
}

// osVolatile are the additions specific to an operating system family, keyed
// by GOOS like osDefaults.
var osVolatile = map[string][]string{
	"solaris": {
		// Solaris logs to /var/adm (messages, wtmpx, sulog…), and SMF gives
		// every service a log of its own.
		"/var/adm",
		"/var/svc/log",
		// The audit trail grows by design, and auditd is on by default on
		// Solaris 11.4. It stays scanned and reported: marking it volatile
		// only keeps it from deciding the exit code.
		"/var/audit",
		// Solaris 11 moved parts of /var to the rpool/VARSHARE dataset and
		// left symbolic links behind. The walk does not follow links, so the
		// files are reported under their real path, not the one above.
		"/var/share/adm",
		"/var/share/audit",
		// StatsStore, Solaris 11.4: time series whose file names carry their
		// time bounds, so they are renamed at every sample. A self-comparison
		// six minutes after a baseline reports a hundred of them.
		"/var/share/sstore",
	},
}

// Volatile returns the paths whose churn is expected on a running system.
func Volatile(goos string) []string {
	if family(goos) == "darwin" {
		return []string{"/private/var/log", "/private/var/folders"}
	}
	extra := osVolatile[family(goos)]
	out := make([]string, 0, len(volatileDefaults)+len(extra))
	out = append(out, volatileDefaults...)
	return append(out, extra...)
}

func family(goos string) string {
	switch goos {
	case "illumos":
		return "solaris"
	case "dragonfly":
		return "freebsd"
	default:
		return goos
	}
}
