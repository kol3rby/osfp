package osdetect

import "strings"

// detectAIX assembles the version from uname(2), where AIX splits it in an
// unusual way: the major number is what uname calls the version, and the minor
// number is what it calls the release. AIX 7.3 therefore reports version 7 and
// release 3.
//
// oslevel -s adds the technology level, which is the part that actually moves:
// a TL update replaces thousands of files, so two systems on 7.3 with
// different technology levels must not share a fingerprint key.
func detectAIX(e env, info *Info) {
	if u, err := e.uname(); err == nil && u.Version != "" && u.Release != "" {
		info.Version = u.Version + "." + u.Release
		info.Kernel = info.Version
		info.Pretty = "AIX " + info.Version
		info.Source = "uname(2)"
	}

	out, err := e.run("oslevel", "-s")
	if err != nil || out == "" {
		return
	}
	// "7300-02-01-2346" is version 7.3.0.0, technology level 02.
	info.Kernel = out
	info.Source = strings.TrimSpace(info.Source + " + oslevel -s")
	fields := strings.Split(out, "-")
	if info.Version == "" {
		info.Version = oslevelVersion(fields[0])
	}
	if len(fields) > 1 && fields[1] != "" {
		info.Version += "-tl" + fields[1]
	}
	info.Pretty = "AIX " + out
}

// oslevelVersion turns the "7300" field of oslevel -s into "7.3".
func oslevelVersion(s string) string {
	if len(s) < 2 {
		return ""
	}
	return s[:1] + "." + s[1:2]
}
