// Package report turns a stream of classified changes into something a person
// or a program can read.
//
// Two formats, for two readers. The text report groups changes by category and
// is what an operator reads; it therefore has to know how many lines a section
// holds before it can print that section's heading, which means holding the
// changes until the end. The JSON Lines report streams: one object per line,
// nothing buffered, greppable by jq while it is still being written. That is
// the one to use when a report runs to hundreds of thousands of lines.
package report

import (
	"io"
	"time"

	"osfp/internal/diff"
	"osfp/internal/scan"
	"osfp/internal/store"
)

// Header describes what is being compared with what.
type Header struct {
	Tool        string
	ToolVersion string

	BaselinePath string
	Baseline     *store.Meta

	SystemKey  string
	SystemName string
	ScannedAt  time.Time
	Privileged bool

	// ExtraExclusions were given on the command line on top of the ones the
	// fingerprint records. They mechanically produce spurious deletions, so
	// the report says so rather than leaving the reader to work it out.
	ExtraExclusions []string
	IgnoreRules     []string
	NewDirMode      string
}

// Summary closes a report.
type Summary struct {
	Diff diff.Stats
	Scan scan.Stats
	// Expected is how many of the changes counted in Diff were filed as
	// expected noise, under a volatile directory.
	Expected int64
}

// Reporter consumes a comparison. Change is called once per reported
// difference, in canonical path order, and Close writes whatever the format
// keeps for the end.
type Reporter interface {
	Header(h Header) error
	Change(c *diff.Change) error
	Close(s Summary) error
}

// Options configures a reporter.
type Options struct {
	// Color enables ANSI colour in the text report.
	Color bool
	// Volatile reports whether a path sits in a directory whose churn is
	// expected — /var/log and friends. Those changes are grouped at the end
	// of the text report instead of being mixed with the rest. A nil function
	// disables the grouping.
	Volatile func(path string) bool
}

// New returns the reporter for a format name: "text" or "json".
func New(format string, w io.Writer, opts Options) (Reporter, error) {
	switch format {
	case "text", "":
		return newTextReporter(w, opts), nil
	case "json", "jsonl":
		return newJSONReporter(w), nil
	default:
		return nil, errUnknownFormat(format)
	}
}

// Formats lists the accepted format names, for help and error messages.
func Formats() []string { return []string{"text", "json"} }
