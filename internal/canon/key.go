// Package canon defines the canonical order in which filesystem paths are
// produced, stored and compared.
//
// Everything else in osfp depends on this order. The comparison of a
// fingerprint with a live system is a merge join between two ordered streams —
// the fingerprint read sequentially, and the filesystem walked — which gives
// O(n) time, O(1) memory and no random access at all. That only works if both
// streams agree on the order, byte for byte, years apart and across operating
// systems. This file is that agreement.
package canon

// CompareKey orders paths the way a depth-first walk does: '/' sorts lower
// than any other byte. It returns -1, 0 or +1.
//
// A plain byte comparison of whole paths is not the same order. Given the
// directory "a" and the file "a.txt", a depth-first walk descends into "a" and
// emits "/a/b" before "/a.txt", because it compares the names "a" and "a.txt"
// one path component at a time. A byte comparison of the full strings puts
// "/a.txt" first, because '.' (0x2E) is lower than '/' (0x2F). Mapping '/' to
// 0x00 for the purpose of the comparison — which is what this function does,
// without allocating — restores the walk order:
//
//	/a  <  /a/b  <  /a.txt
//
// Paths are compared as raw bytes, not as text: filenames on the targeted
// systems are byte strings with no guaranteed encoding, and any normalisation
// here would make the order depend on a Unicode table that changes between Go
// releases.
//
// The mapping assumes paths contain no NUL byte, which POSIX guarantees for
// any path that actually came from a filesystem. A NUL in the input would
// collide with the mapped '/' and break the strict ordering; nothing in osfp
// can produce such a path.
func CompareKey(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		ca, cb := a[i], b[i]
		if ca == cb {
			continue
		}
		switch {
		case ca == '/':
			return -1
		case cb == '/':
			return 1
		case ca < cb:
			return -1
		default:
			return 1
		}
	}
	// One path is a prefix of the other, so the shorter one is its ancestor
	// or an earlier sibling; either way it comes first.
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
