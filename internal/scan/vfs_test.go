package scan

import (
	"slices"
	"testing"
)

// etcVFS has the shape of /etc/vfs on AIX 7. It was written from the AIX
// documentation, not captured on a machine; replace it with a real copy when
// one is available.
const etcVFS = `# @(#)vfs  comments
#
# name   vfs_number  mount_helper              filsys_helper
%defaultvfs jfs2 nfs
#
cdrfs    5    none                        none
procfs   6    none                        none
jfs      3    none                        /sbin/helpers/v3fshelper
jfs2     0    /sbin/helpers/jfs2          none
nfs      2    /sbin/helpers/nfsmnthelp    none      remote
nfs3     18   /sbin/helpers/nfsmnthelp    none      remote
nfs4     35   /sbin/helpers/nfs4mnthelp   none      remote
autofs   19   /usr/sbin/automount         none
ahafs    39   none                        none
mmfs     34   /usr/lpp/mmfs/bin/mmfsmount none      remote
broken
notanumber x  none                        none
`

func TestParseVFSTable(t *testing.T) {
	names, remote := parseVFSTable([]byte(etcVFS))

	for n, want := range map[int32]string{0: "jfs2", 2: "nfs", 3: "jfs", 6: "procfs", 18: "nfs3", 34: "mmfs", 39: "ahafs"} {
		if names[n] != want {
			t.Errorf("type %d is %q, want %q", n, names[n], want)
		}
	}
	if len(names) != 10 {
		t.Errorf("parsed %d types, want 10 (comments, directives and malformed lines skipped): %v", len(names), names)
	}
	for _, name := range []string{"nfs", "nfs3", "nfs4", "mmfs"} {
		if !slices.Contains(remote, name) {
			t.Errorf("%s is flagged remote in /etc/vfs but was not reported so", name)
		}
	}
	for _, name := range []string{"jfs2", "jfs", "procfs", "autofs"} {
		if slices.Contains(remote, name) {
			t.Errorf("%s was reported remote", name)
		}
	}
}

// TestBuiltinVFSClassification checks that every name of the fallback table
// lands in the category the mount policy needs.
func TestBuiltinVFSClassification(t *testing.T) {
	want := map[string]FSKind{
		"jfs2": FSLocal, "jfs": FSLocal, "cdrfs": FSLocal,
		"procfs": FSPseudo, "autofs": FSPseudo, "ahafs": FSPseudo,
		"nfs": FSNetwork, "nfs3": FSNetwork, "nfs4": FSNetwork, "cifs": FSNetwork, "namefs": FSNetwork,
	}
	for _, name := range builtinVFS {
		kind, listed := want[name]
		if !listed {
			t.Errorf("%s is in the built-in table but not in this test", name)
			continue
		}
		got := FSLocal
		switch {
		case pseudoFilesystems[name]:
			got = FSPseudo
		case networkFilesystems[name]:
			got = FSNetwork
		}
		if got != kind {
			t.Errorf("%s is classified %v, want %v", name, got, kind)
		}
	}
}
