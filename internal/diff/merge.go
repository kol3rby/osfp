package diff

import (
	"fmt"
	"io"

	"osfp/internal/canon"
	"osfp/internal/scan"
)

// Source is the fingerprint side of the join: entries in canonical order,
// ending with io.EOF. The entry it returns need only stay valid until the next
// call, which is what a block-decoding cursor can promise.
//
// The interface is declared here, at the consumer, rather than exported by the
// package that implements it: that is the Go convention, and it is what lets a
// different fingerprint store be dropped in without store having to anticipate
// it. *store.Cursor satisfies it as written.
type Source interface {
	Next() (*scan.Entry, error)
}

// DirSummary counts what sits under a directory that is absent from the
// fingerprint, obtained without hashing anything.
type DirSummary struct {
	Files int64
	Dirs  int64
	Bytes int64
}

// Change is one difference: everything the report needs, and nothing it has to
// go back to the filesystem for.
type Change struct {
	Op   Op
	Path string
	// Old is the entry as the fingerprint recorded it, nil when the path was
	// added. New is the entry as the system holds it, nil when it was deleted.
	// Both are copies and outlive the streams they came from.
	Old *scan.Entry
	New *scan.Entry
	// Detail is the single fact that produced the classification: the sizes
	// for a content change, the attribute that moved for a metadata one.
	Detail string
	// Summary is filled for an added directory whose contents were counted
	// rather than listed.
	Summary *DirSummary
}

// Options configures a join.
type Options struct {
	// Show restricts the categories that reach the callback. A nil map shows
	// everything, which is the default: the extra categories fall out of the
	// same comparison and hiding them by default would only lose information.
	Show map[Op]bool
	// Ignore drops changes after classification.
	Ignore *Ignore
	// Summarize is called for an added directory whose contents are not being
	// listed. A nil function reports the directory alone.
	Summarize func(path string) *DirSummary
}

// Stats counts what a join produced.
type Stats struct {
	// Counts holds the number of reported changes per category.
	Counts map[Op]int64
	// Ignored and Hidden are the changes that were classified but not
	// reported, by the ignore rules and by --show respectively.
	Ignored int64
	Hidden  int64
	// Compared is the number of paths present on both sides.
	Compared int64
}

// Total returns the number of reported changes.
func (s Stats) Total() int64 {
	var n int64
	for _, v := range s.Counts {
		n += v
	}
	return n
}

// Joiner merges the fingerprint stream into the scan as it happens.
//
// The scan pushes entries and the fingerprint is pulled alongside, rather than
// both being pulled: the scanner already owns a pipeline and a walk order, so
// driving the join from its callback avoids a second goroutine and a channel
// per entry — and keeps the whole comparison in one goroutine, where the order
// is self-evident.
type Joiner struct {
	base  Source
	old   *scan.Entry // current fingerprint entry, nil once it is exhausted
	emit  func(*Change) error
	opts  Options
	stats Stats

	lastLive string
	started  bool
	done     bool
}

// NewJoiner starts a join over a fingerprint cursor.
func NewJoiner(base Source, opts Options, emit func(*Change) error) (*Joiner, error) {
	j := &Joiner{base: base, emit: emit, opts: opts}
	j.stats.Counts = make(map[Op]int64, len(AllOps))
	if err := j.advance(); err != nil {
		return nil, err
	}
	return j, nil
}

// Feed presents the next entry seen on the live system. Entries must arrive in
// canonical order, which is what the scanner guarantees.
func (j *Joiner) Feed(live *scan.Entry) error {
	if j.started && canon.CompareKey(j.lastLive, live.Path) >= 0 {
		return fmt.Errorf("diff: %q follows %q out of canonical order", live.Path, j.lastLive)
	}
	j.lastLive, j.started = live.Path, true

	// Everything in the fingerprint that sorts before the live entry is gone
	// from the system.
	for j.old != nil && canon.CompareKey(j.old.Path, live.Path) < 0 {
		if err := j.reportRemoved(); err != nil {
			return err
		}
	}

	if j.old != nil && j.old.Path == live.Path {
		j.stats.Compared++
		op, detail := Classify(j.old, live)
		if op != OpNone {
			if err := j.report(&Change{
				Op:     op,
				Path:   live.Path,
				Old:    copyOf(j.old),
				New:    copyOf(live),
				Detail: detail,
			}); err != nil {
				return err
			}
		}
		return j.advance()
	}

	// Absent from the fingerprint.
	return j.report(&Change{
		Op:   opForMissing(live, true),
		Path: live.Path,
		New:  copyOf(live),
	})
}

// Finish drains what is left of the fingerprint: paths the scan never reached,
// which are therefore gone.
func (j *Joiner) Finish() (Stats, error) {
	if j.done {
		return j.stats, nil
	}
	j.done = true
	for j.old != nil {
		if err := j.reportRemoved(); err != nil {
			return j.stats, err
		}
	}
	return j.stats, nil
}

// Stats returns the counters as they stand.
func (j *Joiner) Stats() Stats { return j.stats }

func (j *Joiner) reportRemoved() error {
	c := &Change{
		Op:   opForMissing(j.old, false),
		Path: j.old.Path,
		Old:  copyOf(j.old),
	}
	if err := j.report(c); err != nil {
		return err
	}
	return j.advance()
}

func (j *Joiner) advance() error {
	e, err := j.base.Next()
	if err == io.EOF {
		j.old = nil
		return nil
	}
	if err != nil {
		return err
	}
	j.old = e
	return nil
}

// report applies the two filters, counts what survives, and hands it over.
//
// The order matters: a change is classified first, then ignored or hidden.
// That is what lets the summary state how many differences were suppressed
// instead of quietly leaving them out.
func (j *Joiner) report(c *Change) error {
	if j.opts.Ignore.Match(c.Op, c.Path) {
		j.stats.Ignored++
		return nil
	}
	if j.opts.Show != nil && !j.opts.Show[c.Op] {
		j.stats.Hidden++
		return nil
	}
	if c.Op == OpAddedDir && j.opts.Summarize != nil {
		c.Summary = j.opts.Summarize(c.Path)
	}
	j.stats.Counts[c.Op]++
	return j.emit(c)
}

// copyOf detaches an entry from the buffer it was decoded or scanned into.
// Both streams reuse a single Entry, so a Change that outlives the callback
// must own its data.
func copyOf(e *scan.Entry) *scan.Entry {
	c := *e
	return &c
}
