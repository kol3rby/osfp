package scan

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// AIX reports the filesystem type as a number, statfs.f_vfstype, and keeps
// the table that names those numbers in /etc/vfs, one line per type:
//
//	# name   vfs_number  mount_helper              filsys_helper
//	%defaultvfs jfs2 nfs
//	jfs2     0           /sbin/helpers/jfs2        none
//	nfs      2           /sbin/helpers/nfsmnthelp  none          remote
//
// Reading the table on the machine is better than trusting a copy of it: it
// names whatever is installed there, GPFS included, and it says which types
// are remote. The parser lives outside the aix build tag so that it is tested
// on every platform.

// builtinVFS is the fallback when /etc/vfs cannot be read. It holds only the
// numbers of <sys/vmount.h> that matter to the mount policy. It was written
// from documentation, not checked on a machine: see docs/PORTING.md.
var builtinVFS = map[int32]string{
	0:  "jfs2",
	1:  "namefs",
	2:  "nfs",
	3:  "jfs",
	5:  "cdrfs",
	6:  "procfs",
	18: "nfs3",
	19: "autofs",
	35: "nfs4",
	37: "cifs",
	39: "ahafs",
}

// parseVFSTable reads /etc/vfs. It returns the name of every numbered type,
// and the names flagged remote. Comments, directives such as %defaultvfs and
// malformed lines are skipped.
func parseVFSTable(data []byte) (names map[int32]string, remote []string) {
	names = make(map[int32]string)
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '%' {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		n, err := strconv.ParseInt(fields[1], 10, 32)
		if err != nil {
			continue
		}
		names[int32(n)] = fields[0]
		for _, f := range fields[2:] {
			if f == "remote" {
				remote = append(remote, fields[0])
				break
			}
		}
	}
	return names, remote
}
