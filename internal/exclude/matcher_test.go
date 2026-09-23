package exclude

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func newSet(t *testing.T, o Options) *Set {
	t.Helper()
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

func TestDefaultsPerOS(t *testing.T) {
	tests := []struct {
		goos       string
		mustHave   []string
		mustNotHav []string
	}{
		{"linux", []string{"/proc", "/sys", "/var/lib/docker", "/swapfile"}, []string{"/devices", "/Volumes"}},
		{"solaris", []string{"/proc", "/devices", "/system/contract", "/rpool"}, []string{"/var/lib/docker"}},
		{"illumos", []string{"/devices", "/system/volatile"}, []string{"/var/lib/docker"}},
		{"freebsd", []string{"/compat/linux/proc", "/var/db/freebsd-update"}, []string{"/devices"}},
		{"openbsd", []string{"/proc", "/tmp"}, []string{"/compat/linux/proc", "/var/db/freebsd-update", "/devices"}},
		{"netbsd", []string{"/proc", "/tmp"}, []string{"/compat/linux/proc", "/var/db/freebsd-update", "/devices"}},
		{"dragonfly", []string{"/compat/linux/proc"}, []string{"/devices"}},
		{"darwin", []string{"/Volumes", "/System/Volumes", "/.fseventsd"}, []string{"/var/lib/docker"}},
		{"aix", []string{"/proc", "/tmp"}, []string{"/devices", "/Volumes"}},
	}
	for _, tt := range tests {
		t.Run(tt.goos, func(t *testing.T) {
			got := Defaults(tt.goos)
			for _, want := range tt.mustHave {
				if !slices.Contains(got, want) {
					t.Errorf("Defaults(%q) is missing %q", tt.goos, want)
				}
			}
			for _, unwanted := range tt.mustNotHav {
				if slices.Contains(got, unwanted) {
					t.Errorf("Defaults(%q) unexpectedly contains %q", tt.goos, unwanted)
				}
			}
		})
	}
}

// TestHomeAndRootAreInScope locks decision 3 of the plan: what appears in a
// user's home directory after installation is exactly what an audit looks for.
func TestHomeAndRootAreInScope(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux"})
	for _, path := range []string{"/home", "/home/thomas/.ssh/authorized_keys", "/root", "/root/.bash_history"} {
		if s.Match(path) {
			t.Errorf("%s is excluded by default, it must be in scope", path)
		}
	}
}

func TestMatchPrefixesWholeComponents(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux"})
	excluded := []string{"/proc", "/proc/1/maps", "/var/tmp", "/var/tmp/deep/file", "/dev/null"}
	kept := []string{
		"/procfs",      // not /proc
		"/var/tmpfoo",  // not /var/tmp
		"/devices",     // not /dev on a Linux system
		"/etc/passwd",  // plainly in scope
		"/var/tmpfile", // the classic off-by-one of a naive prefix match
	}
	for _, p := range excluded {
		if !s.Match(p) {
			t.Errorf("%s should be excluded", p)
		}
	}
	for _, p := range kept {
		if s.Match(p) {
			t.Errorf("%s should not be excluded", p)
		}
	}
}

func TestMatchGlobs(t *testing.T) {
	s := newSet(t, Options{
		GOOS:       "linux",
		NoDefaults: true,
		Patterns:   []string{"/var/lib/*/cache", "*.swp", ".git", "/opt/app/log?"},
	})
	excluded := []string{
		"/var/lib/myapp/cache",
		"/etc/.file.swp",
		"/home/user/project/.git",
		"/opt/app/log1",
	}
	kept := []string{
		"/var/lib/myapp/data",
		// filepath.Match does not let '*' cross a separator, so a glob stays
		// anchored to the depth it was written at.
		"/var/lib/a/b/cache",
		"/etc/.file.swpx",
		"/opt/app/log12",
	}
	for _, p := range excluded {
		if !s.Match(p) {
			t.Errorf("%s should be excluded", p)
		}
	}
	for _, p := range kept {
		if s.Match(p) {
			t.Errorf("%s should not be excluded", p)
		}
	}
}

func TestNameGlobMatchesAtAnyDepth(t *testing.T) {
	s := newSet(t, Options{NoDefaults: true, Patterns: []string{"*.swp"}})
	for _, p := range []string{"/a.swp", "/very/deep/path/to/a.swp"} {
		if !s.Match(p) {
			t.Errorf("%s should be excluded by the name pattern", p)
		}
	}
}

func TestInvalidPatternIsRejected(t *testing.T) {
	_, err := New(Options{NoDefaults: true, Patterns: []string{"/var/[a-"}})
	if err == nil {
		t.Fatal("New accepted a malformed glob")
	}
	if !strings.Contains(err.Error(), "/var/[a-") {
		t.Errorf("error does not name the offending pattern: %v", err)
	}
}

func TestNoDefaultsStartsFromNothing(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux", NoDefaults: true})
	if s.Match("/proc/1") {
		t.Error("/proc is still excluded with NoDefaults")
	}
	if len(s.Patterns()) != 0 {
		t.Errorf("Patterns() = %v, want none", s.Patterns())
	}
}

func TestPatternsAreRecordedInOrder(t *testing.T) {
	s := newSet(t, Options{
		NoDefaults: true,
		Patterns:   []string{"/a", "/b"},
		Auto:       []string{"/usr/local/bin/osfp"},
	})
	want := []string{"/a", "/b", "/usr/local/bin/osfp"}
	if got := s.Patterns(); !slices.Equal(got, want) {
		t.Errorf("Patterns() = %v, want %v", got, want)
	}
}

func TestPatternsAreACopy(t *testing.T) {
	s := newSet(t, Options{NoDefaults: true, Patterns: []string{"/a"}})
	s.Patterns()[0] = "/mutated"
	if got := s.Patterns()[0]; got != "/a" {
		t.Errorf("Patterns() exposed its backing array: got %q", got)
	}
}

func TestBlankAndCommentPatternsAreIgnored(t *testing.T) {
	s := newSet(t, Options{
		NoDefaults: true,
		Patterns:   []string{"  ", "# a comment", " /opt "},
	})
	if got, want := s.Patterns(), []string{"/opt"}; !slices.Equal(got, want) {
		t.Errorf("Patterns() = %v, want %v", got, want)
	}
	if !s.Match("/opt/app") {
		t.Error("a pattern surrounded by spaces was not applied")
	}
}

func TestVolatile(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux"})
	for _, p := range []string{"/var/log", "/var/log/auth.log", "/var/cache/apt"} {
		if !s.Volatile(p) {
			t.Errorf("%s should be marked volatile", p)
		}
		if s.Match(p) {
			t.Errorf("%s must be scanned, not excluded", p)
		}
	}
	if s.Volatile("/etc/passwd") {
		t.Error("/etc/passwd must not be marked volatile")
	}

	for _, goos := range []string{"solaris", "illumos"} {
		sol := newSet(t, Options{GOOS: goos})
		for _, p := range []string{"/var/log/syslog", "/var/adm/messages", "/var/svc/log/system-cron:default.log",
			"/var/share/adm/lastlog", "/var/share/audit/20260923181029.not_terminated.solaris11",
			"/var/audit/20260923181029.not_terminated.omnios",
			"/var/share/sstore/repo/stats/11/0/1/1790187026743171:1790187625790729"} {
			if !sol.Volatile(p) {
				t.Errorf("%s: %s should be marked volatile", goos, p)
			}
		}
		if sol.Volatile("/var/share/pkg/repositories/solaris") {
			t.Errorf("%s: /var/share is volatile only where it holds logs", goos)
		}
		if sol.Volatile("/var/svc/manifest/system/cron.xml") {
			t.Errorf("%s: an SMF manifest must not be marked volatile", goos)
		}
	}
	if s.Volatile("/var/adm/messages") {
		t.Error("/var/adm is volatile on Solaris only")
	}

	quiet := newSet(t, Options{GOOS: "linux", NoVolatiles: true})
	if quiet.Volatile("/var/log") {
		t.Error("NoVolatiles did not disable the marking")
	}
}

func TestSelfPaths(t *testing.T) {
	paths := SelfPaths()
	if len(paths) == 0 {
		t.Fatal("SelfPaths returned nothing; the scan would fingerprint osfp itself")
	}
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			t.Errorf("SelfPaths returned a relative path %q", p)
		}
	}
}

// TestRootDefeatsCoveringPrefixes covers the case that made this rule
// necessary: scanning a subtree that a built-in exclusion sits above.
// --root /tmp/chroot must scan /tmp/chroot, not nothing at all.
func TestRootDefeatsCoveringPrefixes(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux", Root: "/tmp/chroot"})

	if s.Match("/tmp/chroot/etc/passwd") {
		t.Error("the default exclusion of /tmp emptied the requested root")
	}
	if slices.Contains(s.Patterns(), "/tmp") {
		t.Error("/tmp was recorded in the header although it was not applied")
	}
	if got := s.Dropped(); !slices.Contains(got, "/tmp") {
		t.Errorf("Dropped() = %v, want it to name /tmp", got)
	}

	// Everything that does not contain the root still applies.
	if !s.Match("/proc/1") {
		t.Error("/proc is no longer excluded")
	}
	if !s.Match("/var/tmp/x") {
		t.Error("/var/tmp is no longer excluded")
	}
}

func TestRootDoesNotDropUnrelatedOrNarrowerPrefixes(t *testing.T) {
	s := newSet(t, Options{
		NoDefaults: true,
		Root:       "/srv/data",
		Patterns:   []string{"/srv/data/cache", "/srv/other", "/srv"},
	})
	if !s.Match("/srv/data/cache/x") {
		t.Error("an exclusion inside the root must still apply")
	}
	if got := s.Dropped(); !slices.Equal(got, []string{"/srv"}) {
		t.Errorf("Dropped() = %v, want only /srv", got)
	}
	if got, want := s.Patterns(), []string{"/srv/data/cache", "/srv/other"}; !slices.Equal(got, want) {
		t.Errorf("Patterns() = %v, want %v", got, want)
	}
}

func TestRootSlashKeepsEveryDefault(t *testing.T) {
	s := newSet(t, Options{GOOS: "linux", Root: "/"})
	if len(s.Dropped()) != 0 {
		t.Errorf("scanning / dropped %v", s.Dropped())
	}
	if !s.Match("/proc/1") {
		t.Error("/proc is no longer excluded when scanning /")
	}
}
