// Package diff joins a fingerprint with a live filesystem and classifies what
// changed.
//
// The join is a merge join between two streams that are already in canonical
// order (see internal/canon): the fingerprint read sequentially and the
// filesystem walked. It runs in O(n) time and O(1) memory, with no random
// access and therefore no index to maintain.
//
// The classification never looks at the modification time. A file whose
// content and permissions are unchanged is unchanged, whatever its date; that
// single decision removes the largest source of noise in a drift report. The
// one exception is an entry that was never hashed, which has nothing else to
// compare — and it is reported as a metadata change, never as a content
// change, because no content was ever verified.
package diff

import (
	"fmt"
	"strings"
)

// Op is the category of a difference, using the codes of the plan's §1.1.
type Op uint8

const (
	OpNone        Op = iota // no difference; never reported
	OpAddedDir              // +D present on the system, absent from the fingerprint
	OpRemovedDir            // -D present in the fingerprint, absent from the system
	OpChangedDir            // ~D same path and type, but mode / uid / gid changed
	OpAdded                 // +F absent from the fingerprint
	OpRemoved               // -F absent from the system
	OpChangedFile           // ~F the SHA-256 differs
	OpChangedMeta           // %F same content, different mode / uid / gid
	OpTypeChanged           // !T a regular file became a symlink, or the reverse
	OpRetargeted            // ~L the target of a symlink changed
	OpUnreadable            // ?E permission denied, I/O error, vanished mid-scan
)

var opNames = map[Op]string{
	OpAddedDir:    "+D",
	OpRemovedDir:  "-D",
	OpChangedDir:  "~D",
	OpAdded:       "+F",
	OpRemoved:     "-F",
	OpChangedFile: "~F",
	OpChangedMeta: "%F",
	OpTypeChanged: "!T",
	OpRetargeted:  "~L",
	OpUnreadable:  "?E",
}

// AllOps lists every reportable category, in the order the report uses.
var AllOps = []Op{
	OpAddedDir, OpRemovedDir, OpChangedDir,
	OpAdded, OpRemoved, OpChangedFile, OpChangedMeta,
	OpTypeChanged, OpRetargeted, OpUnreadable,
}

func (o Op) String() string {
	if s, ok := opNames[o]; ok {
		return s
	}
	return "="
}

// Description is the long form used in report headings.
func (o Op) Description() string {
	switch o {
	case OpAddedDir:
		return "added directories"
	case OpRemovedDir:
		return "deleted directories"
	case OpChangedDir:
		return "modified directories"
	case OpAdded:
		return "added files"
	case OpRemoved:
		return "deleted files"
	case OpChangedFile:
		return "modified files — content"
	case OpChangedMeta:
		return "modified files — metadata"
	case OpTypeChanged:
		return "type changes"
	case OpRetargeted:
		return "retargeted symlinks"
	case OpUnreadable:
		return "unreadable"
	default:
		return "unchanged"
	}
}

// ParseOp reads one code, as --show accepts them.
func ParseOp(s string) (Op, error) {
	s = strings.TrimSpace(s)
	for op, name := range opNames {
		if strings.EqualFold(s, name) {
			return op, nil
		}
	}
	return OpNone, fmt.Errorf("unknown change code %q (known codes: %s)", s, strings.Join(OpCodes(), " "))
}

// OpCodes returns every code, for help and error messages.
func OpCodes() []string {
	out := make([]string, 0, len(AllOps))
	for _, op := range AllOps {
		out = append(out, op.String())
	}
	return out
}

// ParseOps reads a comma-separated list, as given to --show.
func ParseOps(list string) (map[Op]bool, error) {
	set := make(map[Op]bool)
	for _, field := range strings.Split(list, ",") {
		if strings.TrimSpace(field) == "" {
			continue
		}
		op, err := ParseOp(field)
		if err != nil {
			return nil, err
		}
		set[op] = true
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("no change code given")
	}
	return set, nil
}
