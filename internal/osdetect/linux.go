package osdetect

import "strings"

// detectLinux fills in the distribution and its version.
//
// os-release(5) is authoritative and present on every distribution released in
// the last decade. The /etc/*-release fallbacks exist for older systems and for
// the occasional appliance that ships a stripped /etc; the kernel series is the
// last resort, so that a key is always produced.
func detectLinux(e env, info *Info) {
	if kv, path := readOSRelease(e); kv != nil {
		info.Distro = kv["ID"]
		info.Version = kv["VERSION_ID"]
		info.Pretty = prettyName(kv)
		info.Source = path
		if info.Distro != "" {
			return
		}
	}

	// A rolling release has no VERSION_ID, and that is not a failure: the key
	// is simply "linux-arch-amd64". Only a missing ID sends us further down.
	for _, f := range []struct {
		path  string
		parse func(string, *Info)
	}{
		{"/etc/redhat-release", parseRedHatRelease},
		{"/etc/debian_version", parseDebianVersion},
		{"/etc/alpine-release", parseAlpineRelease},
	} {
		b, err := e.readFile(f.path)
		if err != nil {
			continue
		}
		line := firstLine(b)
		if line == "" {
			continue
		}
		f.parse(line, info)
		info.Source = f.path
		return
	}

	if series := kernelSeries(info.Kernel); series != "" {
		info.Version = series
		info.Source = "uname(2)"
	}
}

// prettyName prefers PRETTY_NAME, then NAME plus VERSION.
func prettyName(kv map[string]string) string {
	if p := kv["PRETTY_NAME"]; p != "" {
		return p
	}
	return strings.TrimSpace(kv["NAME"] + " " + kv["VERSION"])
}

// parseRedHatRelease reads lines such as
//
//	Red Hat Enterprise Linux release 9.4 (Plow)
//	CentOS Linux release 7.9.2009 (Core)
func parseRedHatRelease(line string, info *Info) {
	info.Pretty = line
	name, rest, ok := strings.Cut(line, " release ")
	if !ok {
		name = line
	}
	info.Distro = redHatFamily(name)
	if fields := strings.Fields(rest); len(fields) > 0 && isNumericVersion(fields[0]) {
		info.Version = fields[0]
	}
}

// redHatFamily maps a product name to the same short identifier os-release(5)
// would have used, so that a system with and without os-release produce the
// same key.
func redHatFamily(name string) string {
	lower := strings.ToLower(name)
	for _, c := range []struct{ needle, id string }{
		{"red hat enterprise", "rhel"},
		{"centos", "centos"},
		{"rocky", "rocky"},
		{"almalinux", "almalinux"},
		{"oracle", "ol"},
		{"scientific", "scientific"},
		{"fedora", "fedora"},
	} {
		if strings.Contains(lower, c.needle) {
			return c.id
		}
	}
	if fields := strings.Fields(lower); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// parseDebianVersion reads /etc/debian_version, which holds either a version
// ("12.5") or a codename pair for testing/unstable ("trixie/sid").
func parseDebianVersion(line string, info *Info) {
	info.Distro = "debian"
	info.Version = line
	info.Pretty = "Debian GNU/Linux " + line
}

func parseAlpineRelease(line string, info *Info) {
	info.Distro = "alpine"
	info.Version = line
	info.Pretty = "Alpine Linux v" + line
}

// kernelSeries reduces a kernel release such as "6.1.0-18-amd64" to "6.1".
// Anything more precise would change with every kernel update and make every
// fingerprint uncomparable to the next.
func kernelSeries(release string) string {
	dots := 0
	for i := 0; i < len(release); i++ {
		switch c := release[i]; {
		case c >= '0' && c <= '9':
		case c == '.':
			dots++
			if dots == 2 {
				return release[:i]
			}
		default:
			if i == 0 {
				return ""
			}
			return strings.TrimSuffix(release[:i], ".")
		}
	}
	return release
}
