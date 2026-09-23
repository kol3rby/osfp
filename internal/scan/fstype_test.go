package scan

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestClassifyFSOnThisHost checks the one thing a fixture cannot: that the
// system call is wired correctly on the machine running the tests.
func TestClassifyFSOnThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the well-known mount points below are Linux ones")
	}
	tests := []struct {
		path string
		want string
		kind FSKind
	}{
		{"/proc", "proc", FSPseudo},
		{"/sys", "sysfs", FSPseudo},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if _, err := os.Stat(tt.path); err != nil {
				t.Skipf("%s is not mounted here", tt.path)
			}
			name, kind := classifyFS(tt.path)
			if name != tt.want {
				t.Errorf("classifyFS(%s) named %q, want %q", tt.path, name, tt.want)
			}
			if kind != tt.kind {
				t.Errorf("classifyFS(%s) = %v, want %v", tt.path, kind, tt.kind)
			}
		})
	}
}

// TestRealFilesystemsAreLocal is the failure that would matter most: a
// container root is usually an overlay mount, and classifying it as anything
// but local would make osfp refuse to scan the system it was pointed at.
func TestRealFilesystemsAreLocal(t *testing.T) {
	for _, path := range []string{"/", t.TempDir()} {
		if name, kind := classifyFS(path); kind != FSLocal {
			t.Errorf("classifyFS(%s) = %q, %v; a real filesystem was not recognised as local", path, name, kind)
		}
	}
}

// TestUnknownPathIsNotCrossed locks the conservative answer: a query that
// fails leaves the filesystem unidentified, and an unidentified filesystem is
// not entered.
func TestUnknownPathIsNotCrossed(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	name, kind := classifyFS(missing)
	if kind != FSUnknown || name != "" {
		t.Errorf("classifyFS on an unreadable path = %q, %v; want an unidentified filesystem", name, kind)
	}
}

func TestFilesystemTables(t *testing.T) {
	for _, name := range []string{"proc", "sysfs", "tmpfs", "mfs", "autofs", "devtmpfs", "cgroup2", "objfs", "ctfs", "dev", "fd", "bootfs"} {
		if !pseudoFilesystems[name] {
			t.Errorf("%s should be a pseudo filesystem", name)
		}
	}
	for _, name := range []string{"nfs", "nfs4", "cifs", "smbfs", "sshfs"} {
		if !networkFilesystems[name] {
			t.Errorf("%s should be a network filesystem", name)
		}
	}
	// These hold real operating systems and must be crossed by default.
	for _, name := range []string{"ext4", "xfs", "btrfs", "zfs", "ufs", "apfs", "overlay", "squashfs", "erofs"} {
		if pseudoFilesystems[name] || networkFilesystems[name] {
			t.Errorf("%q must be treated as a local filesystem", name)
		}
	}
	// No name may appear in both tables.
	for name := range pseudoFilesystems {
		if networkFilesystems[name] {
			t.Errorf("%q is in both tables", name)
		}
	}
}

func TestFSKindString(t *testing.T) {
	for kind, want := range map[FSKind]string{
		FSLocal:   "local filesystem",
		FSPseudo:  "pseudo filesystem",
		FSNetwork: "network filesystem",
		FSUnknown: "unidentified filesystem",
	} {
		if got := kind.String(); got != want {
			t.Errorf("FSKind(%d).String() = %q, want %q", kind, got, want)
		}
	}
}

func TestParseMountPolicy(t *testing.T) {
	for in, want := range map[string]MountPolicy{
		"":      MountLocal,
		"local": MountLocal,
		"same":  MountSame,
		"all":   MountAll,
	} {
		got, err := ParseMountPolicy(in)
		if err != nil || got != want {
			t.Errorf("ParseMountPolicy(%q) = %v, %v; want %v", in, got, err, want)
		}
		if in != "" && got.String() != in {
			t.Errorf("round trip lost %q: got %q", in, got.String())
		}
	}
	if _, err := ParseMountPolicy("one-file-system"); err == nil {
		t.Error("ParseMountPolicy accepted an unknown value")
	}
}

// TestMountPolicyOnThisHost exercises the three policies against the real
// mount table. It is the only way to test them: a mount point cannot be
// fabricated in a temporary directory without privileges.
func TestMountPolicyOnThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("relies on / having pseudo filesystems mounted under it")
	}
	count := func(p MountPolicy) []SkippedMount {
		t.Helper()
		stats, err := Walk(context.Background(),
			Options{Root: "/", Mounts: p, MaxDepth: 1, NoHash: true},
			func(*Entry) error { return nil })
		if err != nil {
			t.Fatalf("Walk with mounts=%s: %v", p, err)
		}
		return stats.SkippedMounts
	}

	local := count(MountLocal)
	same := count(MountSame)
	all := count(MountAll)

	if len(all) != 0 {
		t.Errorf("mounts=all skipped %v", all)
	}
	if len(same) < len(local) {
		t.Errorf("mounts=same skipped %d mount points, fewer than mounts=local's %d", len(same), len(local))
	}
	for _, m := range local {
		if m.Kind == FSLocal {
			t.Errorf("mounts=local refused to cross a local filesystem: %+v", m)
		}
		if m.Path == "" {
			t.Errorf("a skipped mount has no path: %+v", m)
		}
	}
	t.Logf("local skipped %d, same skipped %d", len(local), len(same))
	for _, m := range local {
		t.Logf("  %s %s (%s)", m.Kind, m.Path, m.FSType)
	}
}
