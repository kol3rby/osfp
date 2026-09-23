package osdetect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// system describes a fake machine: the files it exposes, what uname(2) says,
// and what the helper binaries print. Detection is driven entirely through
// this, so the Solaris, AIX, macOS and BSD code paths are exercised on the
// Linux machine that runs CI.
type system struct {
	goos    string
	goarch  string
	files   map[string]string // absolute path → fixture file under testdata
	uname   utsname
	noUname bool
	cmds    map[string]string // "oslevel -s" → captured output
	host    string
}

func (s system) env(t *testing.T) env {
	t.Helper()
	return env{
		goos:   s.goos,
		goarch: s.goarch,
		readFile: func(name string) ([]byte, error) {
			fixture, ok := s.files[name]
			if !ok {
				return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
			}
			b, err := os.ReadFile(filepath.Join("testdata", fixture))
			if err != nil {
				t.Fatalf("fixture %s: %v", fixture, err)
			}
			return b, nil
		},
		uname: func() (utsname, error) {
			if s.noUname {
				return utsname{}, fmt.Errorf("uname is unavailable")
			}
			return s.uname, nil
		},
		hostname: func() (string, error) {
			if s.host == "" {
				return "", fmt.Errorf("no hostname")
			}
			return s.host, nil
		},
		run: func(name string, args ...string) (string, error) {
			cmd := strings.TrimSpace(name + " " + strings.Join(args, " "))
			out, ok := s.cmds[cmd]
			if !ok {
				return "", fmt.Errorf("%s: not found", name)
			}
			return out, nil
		},
	}
}

func detectIn(t *testing.T, s system) *Info {
	t.Helper()
	info, err := detect(s.env(t))
	if err != nil {
		t.Fatalf("detect: %v", err)
	}
	return info
}

// linuxWith returns a Linux system exposing one captured os-release file.
func linuxWith(fixture string) system {
	return system{
		goos:   "linux",
		goarch: "amd64",
		files:  map[string]string{"/etc/os-release": fixture},
		uname:  utsname{Sysname: "Linux", Release: "6.1.0-18-amd64", Machine: "x86_64"},
	}
}

func TestDetectLinuxDistributions(t *testing.T) {
	tests := []struct {
		fixture string
		distro  string
		version string
		key     string
		pretty  string
	}{
		{"os-release/debian-12.txt", "debian", "12", "linux-debian-12-amd64", "Debian GNU/Linux 12 (bookworm)"},
		{"os-release/ubuntu-24.04.txt", "ubuntu", "24.04", "linux-ubuntu-24.04-amd64", "Ubuntu 24.04.1 LTS"},
		{"os-release/alpine-3.20.txt", "alpine", "3.20.3", "linux-alpine-3.20.3-amd64", "Alpine Linux v3.20"},
		{"os-release/fedora-40.txt", "fedora", "40", "linux-fedora-40-amd64", "Fedora Linux 40 (Workstation Edition)"},
		{"os-release/rhel-9.4.txt", "rhel", "9.4", "linux-rhel-9.4-amd64", "Red Hat Enterprise Linux 9.4 (Plow)"},
		{"os-release/rocky-9.4.txt", "rocky", "9.4", "linux-rocky-9.4-amd64", "Rocky Linux 9.4 (Blue Onyx)"},
		{"os-release/almalinux-9.4.txt", "almalinux", "9.4", "linux-almalinux-9.4-amd64", "AlmaLinux 9.4 (Seafoam Ocelot)"},
		{"os-release/opensuse-leap-15.6.txt", "opensuse-leap", "15.6", "linux-opensuse-leap-15.6-amd64", "openSUSE Leap 15.6"},
		{"os-release/amazonlinux-2023.txt", "amzn", "2023", "linux-amzn-2023-amd64", "Amazon Linux 2023.5.20240916"},
		// A rolling release has no VERSION_ID, and the key says so rather
		// than inventing one.
		{"os-release/arch.txt", "arch", "", "linux-arch-amd64", "Arch Linux"},
	}
	for _, tt := range tests {
		t.Run(tt.distro, func(t *testing.T) {
			info := detectIn(t, linuxWith(tt.fixture))
			if info.Distro != tt.distro || info.Version != tt.version {
				t.Errorf("got distro %q version %q, want %q / %q", info.Distro, info.Version, tt.distro, tt.version)
			}
			if got := info.Key(); got != tt.key {
				t.Errorf("Key() = %q, want %q", got, tt.key)
			}
			if info.Pretty != tt.pretty {
				t.Errorf("Pretty = %q, want %q", info.Pretty, tt.pretty)
			}
			if info.Source != "/etc/os-release" {
				t.Errorf("Source = %q, want /etc/os-release", info.Source)
			}
			if info.Kernel != "6.1.0-18-amd64" {
				t.Errorf("Kernel = %q, want the uname release", info.Kernel)
			}
		})
	}
}

func TestDetectLinuxUsesVendorOSRelease(t *testing.T) {
	s := linuxWith("os-release/debian-12.txt")
	s.files = map[string]string{"/usr/lib/os-release": "os-release/debian-12.txt"}
	info := detectIn(t, s)
	if got, want := info.Key(), "linux-debian-12-amd64"; got != want {
		t.Errorf("Key() = %q, want %q", got, want)
	}
	if info.Source != "/usr/lib/os-release" {
		t.Errorf("Source = %q, want /usr/lib/os-release", info.Source)
	}
}

func TestDetectLinuxFallbacks(t *testing.T) {
	tests := []struct {
		name   string
		files  map[string]string
		key    string
		source string
	}{
		{
			"redhat-release on CentOS 7",
			map[string]string{"/etc/redhat-release": "legacy/redhat-release-centos-7.txt"},
			"linux-centos-7.9.2009-amd64", "/etc/redhat-release",
		},
		{
			"redhat-release on RHEL 6 maps to the os-release id",
			map[string]string{"/etc/redhat-release": "legacy/redhat-release-rhel-6.txt"},
			"linux-rhel-6.10-amd64", "/etc/redhat-release",
		},
		{
			"debian_version",
			map[string]string{"/etc/debian_version": "legacy/debian_version-12.5.txt"},
			"linux-debian-12.5-amd64", "/etc/debian_version",
		},
		{
			"debian_version on testing",
			map[string]string{"/etc/debian_version": "legacy/debian_version-testing.txt"},
			"linux-debian-trixie-sid-amd64", "/etc/debian_version",
		},
		{
			"alpine-release",
			map[string]string{"/etc/alpine-release": "legacy/alpine-release-3.20.3.txt"},
			"linux-alpine-3.20.3-amd64", "/etc/alpine-release",
		},
		{
			// Nothing identifies the distribution: the kernel series is still
			// a usable key, and far better than refusing to produce one.
			"nothing but the kernel",
			nil,
			"linux-6.1-amd64", "uname(2)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := linuxWith("")
			s.files = tt.files
			info := detectIn(t, s)
			if got := info.Key(); got != tt.key {
				t.Errorf("Key() = %q, want %q", got, tt.key)
			}
			if info.Source != tt.source {
				t.Errorf("Source = %q, want %q", info.Source, tt.source)
			}
		})
	}
}

func TestDetectBSD(t *testing.T) {
	tests := []struct {
		name   string
		system system
		key    string
		source string
	}{
		{
			"FreeBSD drops the patch level",
			system{goos: "freebsd", goarch: "amd64",
				uname: utsname{Sysname: "FreeBSD", Release: "14.1-RELEASE-p3", Machine: "amd64"}},
			"freebsd-14.1-amd64", "uname(2)",
		},
		{
			"OpenBSD",
			system{goos: "openbsd", goarch: "amd64",
				uname: utsname{Sysname: "OpenBSD", Release: "7.5", Machine: "amd64"}},
			"openbsd-7.5-amd64", "uname(2)",
		},
		{
			"NetBSD",
			system{goos: "netbsd", goarch: "amd64",
				uname: utsname{Sysname: "NetBSD", Release: "10.0", Machine: "amd64"}},
			"netbsd-10.0-amd64", "uname(2)",
		},
		{
			"FreeBSD falls back to os-release",
			system{goos: "freebsd", goarch: "amd64", noUname: true,
				files: map[string]string{"/etc/os-release": "os-release/freebsd-14.1.txt"}},
			"freebsd-14.1-amd64", "/etc/os-release",
		},
		{
			"FreeBSD falls back to freebsd-version",
			system{goos: "freebsd", goarch: "amd64", noUname: true,
				cmds: map[string]string{"freebsd-version": "14.1-RELEASE-p6"}},
			"freebsd-14.1-amd64", "freebsd-version",
		},
		{
			"OpenBSD falls back to sysctl",
			system{goos: "openbsd", goarch: "amd64", noUname: true,
				cmds: map[string]string{"sysctl -n kern.version": "OpenBSD 7.5 (GENERIC.MP) #82: Tue Mar 26 20:28:19 MDT 2024"}},
			"openbsd-7.5-amd64", "sysctl -n kern.version",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detectIn(t, tt.system)
			if got := info.Key(); got != tt.key {
				t.Errorf("Key() = %q, want %q", got, tt.key)
			}
			if info.Source != tt.source {
				t.Errorf("Source = %q, want %q", info.Source, tt.source)
			}
			if info.Distro != "" {
				t.Errorf("Distro = %q, want empty: a BSD has no separate distribution", info.Distro)
			}
		})
	}
}

func TestDetectSolaris(t *testing.T) {
	tests := []struct {
		name   string
		system system
		key    string
		source string
	}{
		{
			"Oracle Solaris 11.4",
			system{goos: "solaris", goarch: "sparc64",
				files: map[string]string{"/etc/release": "etc-release/solaris-11.4.txt"}},
			"solaris-11.4-sparc64", "/etc/release",
		},
		{
			"Oracle Solaris 10",
			system{goos: "solaris", goarch: "amd64",
				files: map[string]string{"/etc/release": "etc-release/solaris-10.txt"}},
			"solaris-10-amd64", "/etc/release",
		},
		{
			"OmniOS",
			system{goos: "illumos", goarch: "amd64",
				files: map[string]string{"/etc/release": "etc-release/omnios-r151046.txt"}},
			"illumos-omnios-r151046-amd64", "/etc/release",
		},
		{
			"OpenIndiana",
			system{goos: "illumos", goarch: "amd64",
				files: map[string]string{"/etc/release": "etc-release/openindiana-2024.04.txt"}},
			"illumos-openindiana-2024.04-amd64", "/etc/release",
		},
		{
			"SmartOS",
			system{goos: "illumos", goarch: "amd64",
				files: map[string]string{"/etc/release": "etc-release/smartos.txt"}},
			"illumos-smartos-20240118t003834z-amd64", "/etc/release",
		},
		{
			"OmniOS without /etc/release",
			system{goos: "illumos", goarch: "amd64",
				files: map[string]string{"/etc/os-release": "os-release/omnios-r151046.txt"}},
			"illumos-omnios-r151046-amd64", "/etc/os-release",
		},
		{
			"Solaris with neither file",
			system{goos: "solaris", goarch: "amd64",
				cmds: map[string]string{"uname -v": "11.4.42.111.0"}},
			"solaris-11.4.42.111.0-amd64", "uname -v",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detectIn(t, tt.system)
			if got := info.Key(); got != tt.key {
				t.Errorf("Key() = %q, want %q", got, tt.key)
			}
			if info.Source != tt.source {
				t.Errorf("Source = %q, want %q", info.Source, tt.source)
			}
		})
	}
}

func TestDetectDarwin(t *testing.T) {
	t.Run("SystemVersion.plist", func(t *testing.T) {
		info := detectIn(t, system{goos: "darwin", goarch: "arm64",
			files: map[string]string{systemVersionPlist: "plist/macos-14.5.plist"},
			uname: utsname{Sysname: "Darwin", Release: "23.5.0", Machine: "arm64"}})
		if got, want := info.Key(), "darwin-macos-14.5-arm64"; got != want {
			t.Errorf("Key() = %q, want %q", got, want)
		}
		if got, want := info.Pretty, "macOS 14.5 (23F79)"; got != want {
			t.Errorf("Pretty = %q, want %q", got, want)
		}
		if info.Kernel != "23.5.0" {
			t.Errorf("Kernel = %q, want the Darwin kernel release", info.Kernel)
		}
	})

	t.Run("sw_vers fallback", func(t *testing.T) {
		info := detectIn(t, system{goos: "darwin", goarch: "amd64",
			cmds: map[string]string{"sw_vers -productVersion": "13.6.7"}})
		if got, want := info.Key(), "darwin-macos-13.6.7-amd64"; got != want {
			t.Errorf("Key() = %q, want %q", got, want)
		}
	})
}

func TestDetectAIX(t *testing.T) {
	tests := []struct {
		name    string
		system  system
		key     string
		kernel  string
		version string
	}{
		{
			"uname and oslevel",
			system{goos: "aix", goarch: "ppc64",
				uname: utsname{Sysname: "AIX", Version: "7", Release: "3", Machine: "00F84C0C4C00"},
				cmds:  map[string]string{"oslevel -s": "7300-02-01-2346"}},
			"aix-7.3-tl02-ppc64", "7300-02-01-2346", "7.3-tl02",
		},
		{
			"uname alone",
			system{goos: "aix", goarch: "ppc64",
				uname: utsname{Sysname: "AIX", Version: "7", Release: "2"}},
			"aix-7.2-ppc64", "7.2", "7.2",
		},
		{
			"oslevel alone",
			system{goos: "aix", goarch: "ppc64", noUname: true,
				cmds: map[string]string{"oslevel -s": "7300-02-01-2346"}},
			"aix-7.3-tl02-ppc64", "7300-02-01-2346", "7.3-tl02",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := detectIn(t, tt.system)
			if got := info.Key(); got != tt.key {
				t.Errorf("Key() = %q, want %q", got, tt.key)
			}
			if info.Kernel != tt.kernel {
				t.Errorf("Kernel = %q, want %q", info.Kernel, tt.kernel)
			}
			if info.Version != tt.version {
				t.Errorf("Version = %q, want %q", info.Version, tt.version)
			}
		})
	}
}

func TestDetectUnsupportedOS(t *testing.T) {
	info, err := detect(system{goos: "plan9", goarch: "amd64", noUname: true}.env(t))
	if err == nil {
		t.Fatal("detect accepted an unsupported operating system")
	}
	// An Info is still returned: the caller may want to report what little is
	// known alongside the error.
	if info == nil || info.OS != "plan9" {
		t.Errorf("got %+v, want an Info describing the unsupported system", info)
	}
}

func TestDetectRecordsHostname(t *testing.T) {
	s := linuxWith("os-release/debian-12.txt")
	s.host = "audit-01"
	if got := detectIn(t, s).Hostname; got != "audit-01" {
		t.Errorf("Hostname = %q, want audit-01", got)
	}
}

func TestKey(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want string
	}{
		// The three examples the plan commits to.
		{"Debian", Info{OS: "linux", Distro: "debian", Version: "12", Arch: "amd64"}, "linux-debian-12-amd64"},
		{"Solaris", Info{OS: "solaris", Distro: "solaris", Version: "11.4", Arch: "sparc64"}, "solaris-11.4-sparc64"},
		{"FreeBSD", Info{OS: "freebsd", Version: "14.1", Arch: "amd64"}, "freebsd-14.1-amd64"},

		{"distro repeated in another case is still dropped", Info{OS: "solaris", Distro: "Solaris", Version: "11.4", Arch: "amd64"}, "solaris-11.4-amd64"},
		{"no version", Info{OS: "linux", Distro: "arch", Arch: "amd64"}, "linux-arch-amd64"},
		{"no distro and no version", Info{OS: "linux", Arch: "arm64"}, "linux-arm64"},
		{"noisy distro name", Info{OS: "linux", Distro: "Debian GNU/Linux", Version: "12", Arch: "amd64"}, "linux-debian-gnu-linux-12-amd64"},
		{"nothing at all", Info{}, "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.info.Key(); got != tt.want {
				t.Errorf("Key() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeKey(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"linux-debian-12-amd64", "linux-debian-12-amd64", false},
		{"Linux-Debian-12-AMD64", "linux-debian-12-amd64", false},
		{"linux--debian---12", "linux-debian-12", false},
		{"  linux-debian  ", "linux-debian", false},
		{"linux/debian:12", "linux-debian-12", false},
		{"", "", true},
		{"---", "", true},
		{"...", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := NormalizeKey(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("NormalizeKey(%q) error = %v, wantErr %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("NormalizeKey(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeComponent(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Debian", "debian"},
		{"11.4", "11.4"},
		{"Oracle Solaris", "oracle-solaris"},
		{"trixie/sid", "trixie-sid"},
		{"", ""},
		{"...", ""},
		{"--a--b--", "a-b"},
		{".1.", "1"},
		{"café", "caf"}, // non-ASCII bytes are separators, never transliterated
		{strings.Repeat("x", 40), strings.Repeat("x", maxComponent)},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := normalizeComponent(tt.in); got != tt.want {
				t.Errorf("normalizeComponent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	in := `# a comment
NAME="Debian GNU/Linux"
ID=debian
SINGLE='quoted value'
ESCAPED="a \"quoted\" word"
EMPTY=""
SPACED = value
not a pair
=novalue
`
	kv := parseOSRelease([]byte(in))
	for _, tt := range []struct{ key, want string }{
		{"NAME", "Debian GNU/Linux"},
		{"ID", "debian"},
		{"SINGLE", "quoted value"},
		{"ESCAPED", `a "quoted" word`},
		{"EMPTY", ""},
		{"SPACED", "value"},
	} {
		if got := kv[tt.key]; got != tt.want {
			t.Errorf("%s = %q, want %q", tt.key, got, tt.want)
		}
	}
	if _, ok := kv["not a pair"]; ok {
		t.Error("a line without '=' produced an entry")
	}
	if len(kv) != 6 {
		t.Errorf("parsed %d entries, want 6: %v", len(kv), kv)
	}
}

func TestKernelSeries(t *testing.T) {
	tests := []struct{ in, want string }{
		{"6.1.0-18-amd64", "6.1"},
		{"5.15.0", "5.15"},
		{"6.10", "6.10"},
		{"6", "6"},
		{"6.1-custom", "6.1"},
		{"linux", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := kernelSeries(tt.in); got != tt.want {
				t.Errorf("kernelSeries(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestDetectOnThisHost is the one test that touches the real machine: it
// proves the uname(2) wrapper and the wiring work, which no fixture can.
func TestDetectOnThisHost(t *testing.T) {
	info, err := Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	key := info.Key()
	if !strings.HasPrefix(key, info.OS+"-") {
		t.Errorf("Key() = %q, want it to start with the OS name %q", key, info.OS)
	}
	if info.Kernel == "" {
		t.Error("Kernel is empty: uname(2) did not answer")
	}
	if info.Arch == "" {
		t.Error("Arch is empty")
	}
	t.Logf("detected %s, kernel %s, source %s", info, info.Kernel, info.Source)
}
