//go:build aix

package scan

import (
	"os"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	vfsOnce  sync.Once
	vfsNames map[int32]string
)

// loadVFS names the types from /etc/vfs on top of the built-in table, and
// treats every type the table flags remote as a network filesystem.
func loadVFS() {
	names := make(map[int32]string, len(builtinVFS))
	for n, name := range builtinVFS {
		names[n] = name
	}
	if data, err := os.ReadFile("/etc/vfs"); err == nil {
		parsed, remote := parseVFSTable(data)
		for n, name := range parsed {
			names[n] = name
		}
		// Written once, before the first classification returns: every read
		// of networkFilesystems follows a call to fsTypeName.
		for _, name := range remote {
			if !pseudoFilesystems[name] {
				networkFilesystems[name] = true
			}
		}
	}
	vfsNames = names
}

// AIX reports the type as a number, which /etc/vfs names. A number that
// neither /etc/vfs nor the built-in table knows is reported by its value and
// treated as unidentified, which means not crossed.
func fsTypeName(path string) (string, bool) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return "", false
	}
	vfsOnce.Do(loadVFS)
	if name, ok := vfsNames[buf.Vfstype]; ok {
		return name, true
	}
	return "vfs " + strconv.Itoa(int(buf.Vfstype)), false
}
