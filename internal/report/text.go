package report

import (
	"fmt"
	"io"
	"strings"

	"osfp/internal/diff"
	"osfp/internal/humanize"
	"osfp/internal/scan"
)

// formatMode is humanize.Mode, kept behind a local name so that the JSON and
// text reporters cannot drift apart on how a mode is spelled.
func formatMode(m uint32) string { return humanize.Mode(m) }

// errUnknownFormat is defined here so that the format names and their error
// live together.
func errUnknownFormat(name string) error {
	return fmt.Errorf("unknown report format %q (known formats: %s)",
		name, strings.Join(Formats(), ", "))
}

// pathColumn is the width paths are padded to before their detail. Longer
// paths push their detail out rather than being truncated: a truncated path in
// an audit report is worse than a ragged column.
const pathColumn = 38

// textReporter renders the report of §11.1.
//
// It holds the changes until the end because its sections carry a count in
// their heading, and a count is only known once the last change has arrived.
// That is the trade the format makes; the JSON Lines reporter is the one that
// streams.
type textReporter struct {
	w        io.Writer
	opts     Options
	header   Header
	sections map[diff.Op][]*diff.Change
	volatile []*diff.Change
	err      error
}

func newTextReporter(w io.Writer, opts Options) *textReporter {
	return &textReporter{w: w, opts: opts, sections: make(map[diff.Op][]*diff.Change)}
}

func (t *textReporter) Header(h Header) error {
	t.header = h
	b := h.Baseline

	t.printf("osfp %s — filesystem drift report\n", h.ToolVersion)
	t.printf("Baseline : %s   (created %s, %s %s)\n",
		h.BaselinePath, b.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		humanize.Count(b.Entries), humanize.Plural(b.Entries, "entry", "entries"))
	system := h.SystemKey
	if h.SystemName != "" {
		system = fmt.Sprintf("%s  %s", h.SystemKey, h.SystemName)
	}
	t.printf("System   : %s   (scanned %s)\n",
		system, h.ScannedAt.UTC().Format("2006-01-02T15:04:05Z"))

	scope := fmt.Sprintf("%s · %d %s", b.Scan.Root, len(b.Exclusions),
		humanize.Plural(int64(len(b.Exclusions)), "exclusion", "exclusions"))
	if b.Scan.Mounts != "" {
		scope += " · mounts=" + b.Scan.Mounts
	}
	if h.NewDirMode != "" {
		scope += " · new-dir-mode=" + h.NewDirMode
	}
	t.printf("Scope    : %s\n", scope)
	if !h.Privileged {
		t.printf("Warning  : UNPRIVILEGED scan; parts of the filesystem could not be read\n")
	}
	if n := len(h.ExtraExclusions); n > 0 {
		t.printf("Warning  : %d %s added on the command line (%s); "+
			"covered paths are reported as deleted\n",
			n, humanize.Plural(int64(n), "exclusion was", "exclusions were"), strings.Join(h.ExtraExclusions, " "))
	}
	if n := len(h.IgnoreRules); n > 0 {
		t.printf("Ignoring : %d %s\n", n, humanize.Plural(int64(n), "rule", "rules"))
	}
	return t.err
}

func (t *textReporter) Change(c *diff.Change) error {
	if t.opts.Volatile != nil && t.opts.Volatile(c.Path) {
		t.volatile = append(t.volatile, c)
		return t.err
	}
	t.sections[c.Op] = append(t.sections[c.Op], c)
	return t.err
}

func (t *textReporter) Close(s Summary) error {
	for _, op := range diff.AllOps {
		t.section(strings.ToUpper(op.Description()), t.sections[op])
	}
	// Churn in /var/log and friends is expected; it is reported, but at the
	// end and under its own heading, so that it does not dilute the rest.
	t.section("EXPECTED NOISE — VOLATILE DIRECTORIES", t.volatile)
	t.summary(s)
	return t.err
}

func (t *textReporter) section(title string, changes []*diff.Change) {
	if len(changes) == 0 {
		return
	}
	t.printf("\n%s (%s)\n", title, humanize.Count(int64(len(changes))))

	width := pathColumn
	for _, c := range changes {
		if n := len(c.Path); n > width && n <= 60 {
			width = n
		}
	}
	for _, c := range changes {
		detail := detailOf(c)
		code := t.colorize(c.Op)
		if detail == "" {
			t.printf("  %s %s\n", code, c.Path)
			continue
		}
		t.printf("  %s %-*s  %s\n", code, width, c.Path, detail)
	}
}

// detailOf renders the one fact that produced the classification.
func detailOf(c *diff.Change) string {
	if c.Summary != nil {
		return fmt.Sprintf("(%s %s, %s %s, %s)",
			humanize.Count(c.Summary.Files), humanize.Plural(c.Summary.Files, "file", "files"),
			humanize.Count(c.Summary.Dirs), humanize.Plural(c.Summary.Dirs, "directory", "directories"),
			humanize.Bytes(c.Summary.Bytes))
	}
	return c.Detail
}

func (t *textReporter) summary(s Summary) {
	group := func(ops ...diff.Op) string {
		var parts []string
		for _, op := range ops {
			parts = append(parts, fmt.Sprintf("%s %s", op, humanize.Count(s.Diff.Counts[op])))
		}
		return strings.Join(parts, "  ")
	}
	t.printf("\nSUMMARY  %s │ %s │ %s\n",
		group(diff.OpAddedDir, diff.OpRemovedDir, diff.OpChangedDir),
		group(diff.OpAdded, diff.OpRemoved, diff.OpChangedFile, diff.OpChangedMeta),
		group(diff.OpTypeChanged, diff.OpRetargeted, diff.OpUnreadable))

	var notes []string
	if s.Expected > 0 {
		notes = append(notes, fmt.Sprintf("%s of them expected noise", humanize.Count(s.Expected)))
	}
	if s.Diff.Ignored > 0 {
		notes = append(notes, fmt.Sprintf("%s %s hidden by ignore rules", humanize.Count(s.Diff.Ignored),
			humanize.Plural(s.Diff.Ignored, "difference", "differences")))
	}
	if s.Diff.Hidden > 0 {
		notes = append(notes, fmt.Sprintf("%s hidden by --show", humanize.Count(s.Diff.Hidden)))
	}
	notes = append(notes,
		fmt.Sprintf("%s %s scanned", humanize.Count(s.Scan.Total()),
			humanize.Plural(s.Scan.Total(), "entry", "entries")),
		"elapsed "+humanize.Duration(s.Scan.Elapsed))
	t.printf("         %s\n", strings.Join(notes, "  ·  "))

	// Mount points the walk stopped at are stated, not assumed: a reader must
	// be able to tell an absence of change from an absence of scanning.
	for _, line := range mountNotes(s.Scan.SkippedMounts) {
		t.printf("         %s\n", line)
	}
}

// ANSI styles, applied only when the destination is a terminal.
const (
	ansiReset   = "\033[0m"
	ansiGreen   = "\033[32m"
	ansiRed     = "\033[31m"
	ansiYellow  = "\033[33m"
	ansiMagenta = "\033[35m"
)

func (t *textReporter) colorize(op diff.Op) string {
	if !t.opts.Color {
		return op.String()
	}
	var c string
	switch op {
	case diff.OpAddedDir, diff.OpAdded:
		c = ansiGreen
	case diff.OpRemovedDir, diff.OpRemoved:
		c = ansiRed
	case diff.OpUnreadable:
		c = ansiMagenta
	default:
		c = ansiYellow
	}
	return c + op.String() + ansiReset
}

func (t *textReporter) printf(format string, args ...any) {
	if t.err != nil {
		return
	}
	_, t.err = fmt.Fprintf(t.w, format, args...)
}

// mountNotes renders one line per kind of filesystem the walk stopped at,
// naming the mount points and their type. Counting them would not be enough:
// the point is that the operator can see which part of the system was never
// looked at, and decide whether that is acceptable.
func mountNotes(mounts []scan.SkippedMount) []string {
	if len(mounts) == 0 {
		return nil
	}
	byKind := make(map[scan.FSKind][]string)
	order := make([]scan.FSKind, 0, 4)
	for _, m := range mounts {
		if _, seen := byKind[m.Kind]; !seen {
			order = append(order, m.Kind)
		}
		label := m.Path
		if m.FSType != "" {
			label += " (" + m.FSType + ")"
		}
		byKind[m.Kind] = append(byKind[m.Kind], label)
	}

	out := make([]string, 0, len(order))
	for _, kind := range order {
		paths := byKind[kind]
		noun := kind.String()
		if len(paths) != 1 {
			noun += "s"
		}
		out = append(out, fmt.Sprintf("%s %s not crossed: %s",
			humanize.Count(int64(len(paths))), noun, strings.Join(paths, " ")))
	}
	return out
}
