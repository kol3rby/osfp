package diff

import (
	"fmt"
	"strings"

	"osfp/internal/humanize"
	"osfp/internal/scan"
)

// Classify compares the fingerprint entry and the live entry for one path, and
// returns the category plus the single fact that produced it.
//
// The decision table, in order:
//
//	either side unreadable      → ?E
//	types differ                → !T
//	symlink target differs      → ~L
//	SHA-256 differs             → ~F
//	no hash on either side      → %F on size (and mtime, which is all there is)
//	mode / uid / gid differ     → %F, or ~D for a directory
//	otherwise                   → no difference
//
// The modification time is never consulted, except on the "no hash" line.
func Classify(old, live *scan.Entry) (Op, string) {
	switch {
	case live.Err != "":
		return OpUnreadable, live.Err
	case old.Err != "":
		// It could not be read when the fingerprint was taken, so there is
		// nothing to compare against. Saying so is more useful than silently
		// reporting the entry as unchanged.
		return OpUnreadable, "unreadable when the fingerprint was taken: " + old.Err
	}

	if old.Type != live.Type {
		return OpTypeChanged, fmt.Sprintf("%s → %s", old.Type, live.Type)
	}

	if live.Type == scan.TypeSymlink && old.Link != live.Link {
		return OpRetargeted, fmt.Sprintf("%s → %s", old.Link, live.Link)
	}

	if live.Type == scan.TypeFile {
		switch {
		case old.Hashed && live.Hashed:
			if old.Hash != live.Hash {
				return OpChangedFile, fmt.Sprintf("%s → %s",
					humanize.Bytes(old.Size), humanize.Bytes(live.Size))
			}
		default:
			// At least one side was never hashed — --max-file-size, or a read
			// error recorded without one. Size and mtime are all there is, and
			// the category stays %F: no content change was ever verified.
			if d := compareUnhashed(old, live); d != "" {
				return OpChangedMeta, d
			}
		}
	}

	if d := compareAttributes(old, live); d != "" {
		if live.Type == scan.TypeDir {
			return OpChangedDir, d
		}
		return OpChangedMeta, d
	}
	return OpNone, ""
}

// compareUnhashed is the one place the modification time is a criterion, and
// only because there is no hash to use instead (§1.4 and §7.2).
func compareUnhashed(old, live *scan.Entry) string {
	var parts []string
	if old.Size != live.Size {
		parts = append(parts, fmt.Sprintf("size %s → %s",
			humanize.Bytes(old.Size), humanize.Bytes(live.Size)))
	}
	if old.MTime != live.MTime {
		parts = append(parts, "mtime changed")
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ", ") + " (not hashed, so content was not verified)"
}

// compareAttributes reports the ownership and permission changes, naming only
// what actually moved.
func compareAttributes(old, live *scan.Entry) string {
	var parts []string
	if old.Mode != live.Mode {
		parts = append(parts, fmt.Sprintf("mode %s → %s",
			humanize.Mode(old.Mode), humanize.Mode(live.Mode)))
	}
	if old.UID != live.UID {
		parts = append(parts, fmt.Sprintf("uid %d → %d", old.UID, live.UID))
	}
	if old.GID != live.GID {
		parts = append(parts, fmt.Sprintf("gid %d → %d", old.GID, live.GID))
	}
	return strings.Join(parts, ", ")
}

// opForMissing returns the category for an entry present on only one side.
func opForMissing(e *scan.Entry, added bool) Op {
	switch {
	case e.Type == scan.TypeDir && added:
		return OpAddedDir
	case e.Type == scan.TypeDir:
		return OpRemovedDir
	case added:
		return OpAdded
	default:
		return OpRemoved
	}
}
