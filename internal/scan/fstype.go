package scan

// FSKind is what osfp makes of a filesystem when it meets one at a mount
// point.
type FSKind uint8

const (
	// FSLocal is a filesystem that holds part of the installed system: ext4,
	// xfs, zfs, ufs, apfs, and also overlay, which is what a container root
	// usually is.
	FSLocal FSKind = iota
	// FSPseudo is a kernel interface or an in-memory tree. Nothing in it
	// belongs to the installed system and much of it changes on every read.
	FSPseudo
	// FSNetwork is a share served by another machine. Hashing one says
	// nothing about the system under audit and can take hours.
	FSNetwork
	// FSUnknown means the filesystem type could not be determined: statfs
	// failed, or AIX reported a type number that /etc/vfs does not name.
	FSUnknown
)

func (k FSKind) String() string {
	switch k {
	case FSPseudo:
		return "pseudo filesystem"
	case FSNetwork:
		return "network filesystem"
	case FSUnknown:
		return "unidentified filesystem"
	default:
		return "local filesystem"
	}
}

// pseudoFilesystems are kernel interfaces and in-memory trees.
//
// Note what is deliberately absent: overlay, squashfs and erofs. A container
// root is very often an overlay mount, and treating it as a pseudo filesystem
// would make osfp refuse to scan the very system it was pointed at.
var pseudoFilesystems = map[string]bool{
	// kernel interfaces
	"proc": true, "procfs": true, "linprocfs": true,
	"sysfs": true, "linsysfs": true,
	"devfs": true, "devtmpfs": true, "devpts": true, "ptyfs": true, "ptsfs": true,
	"kernfs": true, "fdescfs": true, "fdesc": true,
	"debugfs": true, "tracefs": true, "securityfs": true, "selinuxfs": true,
	"configfs": true, "binfmt_misc": true, "bpf": true, "pstore": true,
	"efivarfs": true, "mqueue": true, "hugetlbfs": true,
	"cgroup": true, "cgroup2": true, "fusectl": true,
	// Solaris and illumos; dev is /dev itself, fd is /dev/fd, and bootfs is
	// /system/boot, the boot archive as the loader put it in memory
	"objfs": true, "ctfs": true, "sharefs": true, "mntfs": true,
	"dev": true, "fd": true, "bootfs": true,
	// volatile in memory
	"tmpfs": true, "ramfs": true,
	"mfs": true, // OpenBSD and NetBSD, the only in-memory filesystem OpenBSD has left
	// an automounter: crossing it would mount whatever is behind it
	"autofs": true,
	// AIX event infrastructure, a kernel interface
	"ahafs": true,
}

// networkFilesystems are served by another machine.
var networkFilesystems = map[string]bool{
	"nfs": true, "nfs3": true, "nfs4": true, "nfsv4": true,
	"cifs": true, "smbfs": true, "smb2": true, "smb3": true,
	"afs": true, "9p": true, "ceph": true, "glusterfs": true, "sshfs": true,
	"lofs":   true, // Solaris loopback: the same tree under another name
	"namefs": true, // AIX, the same idea
}

// classifyFS names the filesystem mounted at path and says what to make of it.
func classifyFS(path string) (string, FSKind) {
	name, ok := fsTypeName(path)
	switch {
	case !ok:
		// The name, when there is one, says what could not be classified.
		return name, FSUnknown
	case pseudoFilesystems[name]:
		return name, FSPseudo
	case networkFilesystems[name]:
		return name, FSNetwork
	default:
		return name, FSLocal
	}
}
