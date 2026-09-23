//go:build linux

package scan

import "golang.org/x/sys/unix"

// Linux reports a numeric magic rather than a name. The constants are spelled
// out here rather than taken from x/sys, so that the set osfp recognises
// cannot change under it when the dependency is updated.
//
// The key is uint32 on purpose. Statfs_t.Type is int64 on 64-bit targets and
// int32 on 32-bit ones, so a magic with the high bit set — CIFS is
// 0xff534d42 — would be a positive number on one and a negative number on the
// other. Truncating to 32 bits makes the table mean the same thing everywhere.
//
// Note what is deliberately absent: overlay, squashfs and erofs. A container
// root is very often an overlay mount, and treating it as a pseudo filesystem
// would make osfp refuse to scan the very system it was pointed at.
var linuxMagics = map[uint32]string{
	0x9fa0:     "proc",
	0x62656572: "sysfs",
	0x1cd1:     "devpts",
	0x1373:     "devfs",
	0x01021994: "tmpfs", // devtmpfs reports the same magic
	0x858458f6: "ramfs",
	0x0027e0eb: "cgroup",
	0x63677270: "cgroup2",
	0x64626720: "debugfs",
	0x74726163: "tracefs",
	0x73636673: "securityfs",
	0xf97cff8c: "selinuxfs",
	0x6165676c: "pstore",
	0xde5e81e4: "efivarfs",
	0xcafe4a11: "bpf",
	0x42494e4d: "binfmt_misc",
	0x62656570: "configfs",
	0x19800202: "mqueue",
	0x958458f6: "hugetlbfs",
	0x6969:     "nfs",
	0xff534d42: "cifs",
	0x517b:     "smbfs",
	0x0187:     "autofs",
	0x65735543: "fusectl",
}

// fsTypeName returns the name of the filesystem mounted at path, and whether
// it could be determined at all.
func fsTypeName(path string) (string, bool) {
	var buf unix.Statfs_t
	if err := unix.Statfs(path, &buf); err != nil {
		return "", false
	}
	name, known := linuxMagics[uint32(buf.Type)]
	if !known {
		// The filesystem exists but osfp has no name for it, which for this
		// decision means a real one.
		return "", true
	}
	return name, true
}
