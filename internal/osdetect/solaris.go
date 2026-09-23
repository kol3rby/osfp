package osdetect

import "strings"

// detectSolaris covers Oracle Solaris and the illumos distributions.
//
// /etc/release is the one file all of them ship, and its first line is the
// product banner: "Oracle Solaris 11.4 SPARC", "OmniOS v11 r151046",
// "OpenIndiana Hipster 2024.04 (powered by illumos)".
func detectSolaris(e env, info *Info) {
	if b, err := e.readFile("/etc/release"); err == nil {
		if line := firstLine(b); line != "" {
			info.Pretty = line
			info.Source = "/etc/release"
			info.Distro, info.Version = parseSolarisRelease(line)
			if info.Version != "" {
				return
			}
		}
	}

	// OmniOS and OpenIndiana also ship os-release(5).
	if kv, path := readOSRelease(e); kv != nil {
		if id := kv["ID"]; id != "" {
			info.Distro = id
		}
		if v := kv["VERSION_ID"]; v != "" {
			info.Version = v
		}
		if info.Pretty == "" {
			info.Pretty = prettyName(kv)
		}
		info.Source = path
		if info.Version != "" {
			return
		}
	}

	// uname -v reports the build, e.g. "11.4.42.111.0" on Solaris.
	if out, err := e.run("uname", "-v"); err == nil && out != "" {
		info.Version = out
		info.Source = "uname -v"
	}
}

// parseSolarisRelease identifies the product and its version in the banner
// line of /etc/release.
func parseSolarisRelease(line string) (distro, version string) {
	fields := strings.Fields(line)
	lower := strings.ToLower(line)

	switch {
	case strings.Contains(lower, "omnios"):
		// The release is the "r151046" token; "v11" is the illumos branch and
		// never changes.
		return "omnios", findField(fields, isOmniOSRevision)
	case strings.Contains(lower, "smartos"):
		return "smartos", findField(fields, isSmartOSBuild)
	case strings.Contains(lower, "openindiana"):
		return "openindiana", findField(fields, isNumericVersion)
	case strings.Contains(lower, "solaris"):
		return "solaris", findField(fields, isNumericVersion)
	}

	if len(fields) == 0 {
		return "", ""
	}
	return strings.ToLower(fields[0]), findField(fields, isNumericVersion)
}

func findField(fields []string, ok func(string) bool) string {
	for _, f := range fields {
		if ok(f) {
			return f
		}
	}
	return ""
}

// isOmniOSRevision matches "r151046".
func isOmniOSRevision(s string) bool {
	if len(s) < 2 || s[0] != 'r' {
		return false
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// isSmartOSBuild matches a build stamp such as "20240118T003834Z".
func isSmartOSBuild(s string) bool {
	if len(s) != 16 || s[8] != 'T' || s[15] != 'Z' {
		return false
	}
	for _, i := range []int{0, 1, 2, 3, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14} {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
