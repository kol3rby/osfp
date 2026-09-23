package osdetect

import "strings"

// detectBSD covers FreeBSD, OpenBSD, NetBSD and DragonFly, where the version
// of the system is the version of the kernel: there is no separate userland
// distribution to name, so Distro stays empty and the key reads
// "freebsd-14.1-amd64".
func detectBSD(e env, info *Info) {
	if u, err := e.uname(); err == nil && u.Release != "" {
		info.Version = releaseBase(u.Release)
		info.Pretty = strings.TrimSpace(u.Sysname + " " + u.Release)
		info.Source = "uname(2)"
		return
	}

	if kv, path := readOSRelease(e); kv != nil && kv["VERSION_ID"] != "" {
		info.Version = kv["VERSION_ID"]
		info.Pretty = prettyName(kv)
		info.Source = path
		return
	}

	// Last resort: a helper binary. freebsd-version reports the userland
	// version, which is what matters after a freebsd-update; sysctl is the
	// equivalent on the other BSDs.
	for _, c := range []struct {
		name string
		args []string
	}{
		{"freebsd-version", nil},
		{"sysctl", []string{"-n", "kern.version"}},
	} {
		out, err := e.run(c.name, c.args...)
		if err != nil || out == "" {
			continue
		}
		line := firstLine([]byte(out))
		info.Pretty = line
		info.Source = strings.TrimSpace(c.name + " " + strings.Join(c.args, " "))
		if v := bsdVersionFromLine(line); v != "" {
			info.Version = v
		}
		return
	}
}

// releaseBase trims the build qualifiers FreeBSD appends to its release
// number: "14.1-RELEASE-p3" is the 14.1 line, and the patch level changes far
// too often to belong in a key.
func releaseBase(release string) string {
	base, _, _ := strings.Cut(release, "-")
	return base
}

// bsdVersionFromLine extracts a version from a line such as
// "FreeBSD 14.1-RELEASE-p3" or "OpenBSD 7.5 (GENERIC) #1: ...".
func bsdVersionFromLine(line string) string {
	for _, f := range strings.Fields(line) {
		if v := releaseBase(f); isNumericVersion(v) {
			return v
		}
	}
	return ""
}
