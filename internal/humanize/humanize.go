// Package humanize formats numbers for people rather than for machines.
//
// It exists so that the command, the classifier and the reporter all print a
// size the same way: a report that says "3.1 KiB" in one place and "3174" in
// another is a report whose lines cannot be compared by eye.
package humanize

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Count formats a number with thousands separators. Six-digit entry counts are
// the norm here and are unreadable without them.
func Count(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")

	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// Bytes formats a byte count in binary units.
func Bytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}

// Duration drops the sub-second noise from anything that ran for a while.
func Duration(d time.Duration) string {
	// A scan of a small tree finishes in microseconds; rounding it to the
	// nearest millisecond would report "0s", which reads as a failure.
	if d < 10*time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(100 * time.Millisecond).String()
}

// Mode formats a Unix permission word the way chmod and ls write it.
func Mode(m uint32) string { return "0" + strconv.FormatUint(uint64(m), 8) }

// Plural picks the wording for a count. A report that says "1 rules" is a
// report someone stopped proofreading; it lives here so that the command and
// the reporter cannot disagree about it.
func Plural(n int64, one, many string) string {
	if n == 1 || n == -1 {
		return one
	}
	return many
}
