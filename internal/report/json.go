package report

import (
	"encoding/json"
	"io"
	"time"

	"osfp/internal/diff"
	"osfp/internal/scan"
)

// jsonReporter writes JSON Lines: one self-describing object per line, a
// header first and a summary last.
//
// A single large JSON array would have to be closed before it could be parsed,
// which rules out reading a report while it is being produced and rules out jq
// on a report of half a million lines. One object per line costs a few bytes
// per record and keeps both.
type jsonReporter struct {
	enc *json.Encoder
	err error
}

func newJSONReporter(w io.Writer) *jsonReporter {
	return &jsonReporter{enc: json.NewEncoder(w)}
}

type headerRecord struct {
	Record   string         `json:"record"`
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Baseline baselineRecord `json:"baseline"`
	System   systemRecord   `json:"system"`
	Scope    scopeRecord    `json:"scope"`
}

type baselineRecord struct {
	Path       string    `json:"path"`
	Created    time.Time `json:"created"`
	Entries    int64     `json:"entries"`
	OSKey      string    `json:"os_key"`
	Privileged bool      `json:"privileged"`
	Tool       string    `json:"tool_version"`
}

type systemRecord struct {
	OSKey      string    `json:"os_key"`
	Name       string    `json:"name,omitempty"`
	Scanned    time.Time `json:"scanned"`
	Privileged bool      `json:"privileged"`
}

type scopeRecord struct {
	Root            string   `json:"root"`
	Mounts          string   `json:"mounts"`
	NewDirMode      string   `json:"new_dir_mode,omitempty"`
	Exclusions      []string `json:"exclusions"`
	ExtraExclusions []string `json:"extra_exclusions,omitempty"`
	IgnoreRules     []string `json:"ignore_rules,omitempty"`
}

func (j *jsonReporter) Header(h Header) error {
	b := h.Baseline
	j.write(headerRecord{
		Record:  "header",
		Tool:    h.Tool,
		Version: h.ToolVersion,
		Baseline: baselineRecord{
			Path: h.BaselinePath, Created: b.CreatedAt.UTC(), Entries: b.Entries,
			OSKey: b.Key, Privileged: b.Privileged, Tool: b.ToolVersion,
		},
		System: systemRecord{
			OSKey: h.SystemKey, Name: h.SystemName,
			Scanned: h.ScannedAt.UTC(), Privileged: h.Privileged,
		},
		Scope: scopeRecord{
			Root: b.Scan.Root, Mounts: b.Scan.Mounts,
			NewDirMode: h.NewDirMode, Exclusions: b.Exclusions,
			ExtraExclusions: h.ExtraExclusions, IgnoreRules: h.IgnoreRules,
		},
	})
	return j.err
}

type changeRecord struct {
	Record  string         `json:"record"`
	Op      string         `json:"op"`
	Path    string         `json:"path"`
	Detail  string         `json:"detail,omitempty"`
	Old     *entryRecord   `json:"old,omitempty"`
	New     *entryRecord   `json:"new,omitempty"`
	Summary *summaryRecord `json:"contents,omitempty"`
}

// entryRecord carries everything the fingerprint and the scan know about an
// entry, the modification time included.
//
// This is where the mtime belongs: a named field among others, with no claim
// about its role, usable to line a drift up with an incident timeline. It is
// absent from the text report for the opposite reason — a date printed next to
// a change reads as the date of that change, and the mtime is a declaration,
// not an observation (§11.3).
type entryRecord struct {
	Type    string `json:"type"`
	Mode    string `json:"mode"`
	UID     uint32 `json:"uid"`
	GID     uint32 `json:"gid"`
	Size    int64  `json:"size"`
	MTime   string `json:"mtime"`
	SHA256  string `json:"sha256,omitempty"`
	Link    string `json:"link,omitempty"`
	Partial bool   `json:"partial,omitempty"`
	Error   string `json:"error,omitempty"`
	Dev     uint64 `json:"dev,omitempty"`
	Ino     uint64 `json:"ino,omitempty"`
	Nlink   uint32 `json:"nlink,omitempty"`
}

type summaryRecord struct {
	Files int64 `json:"files"`
	Dirs  int64 `json:"directories"`
	Bytes int64 `json:"bytes"`
}

func (j *jsonReporter) Change(c *diff.Change) error {
	rec := changeRecord{
		Record: "change",
		Op:     c.Op.String(),
		Path:   c.Path,
		Detail: c.Detail,
		Old:    entryOf(c.Old),
		New:    entryOf(c.New),
	}
	if c.Summary != nil {
		rec.Summary = &summaryRecord{Files: c.Summary.Files, Dirs: c.Summary.Dirs, Bytes: c.Summary.Bytes}
	}
	j.write(rec)
	return j.err
}

func entryOf(e *scan.Entry) *entryRecord {
	if e == nil {
		return nil
	}
	r := &entryRecord{
		Type:    e.Type.String(),
		Mode:    formatMode(e.Mode),
		UID:     e.UID,
		GID:     e.GID,
		Size:    e.Size,
		MTime:   time.Unix(e.MTime, 0).UTC().Format(time.RFC3339),
		Link:    e.Link,
		Partial: e.Partial,
		Error:   e.Err,
		Dev:     e.Dev,
		Ino:     e.Ino,
		Nlink:   e.Nlink,
	}
	if e.Hashed {
		r.SHA256 = hex(e.Hash[:])
	}
	return r
}

type statsRecord struct {
	Record   string           `json:"record"`
	Counts   map[string]int64 `json:"counts"`
	Total    int64            `json:"total"`
	Expected int64            `json:"expected"`
	Ignored  int64            `json:"ignored"`
	Hidden   int64            `json:"hidden"`
	Compared int64            `json:"compared"`
	Scanned  int64            `json:"scanned"`
	Errors   int64            `json:"unreadable"`
	Mounts   []mountRecord    `json:"mounts_not_crossed,omitempty"`
	Elapsed  float64          `json:"elapsed_seconds"`
}

func (j *jsonReporter) Close(s Summary) error {
	counts := make(map[string]int64, len(diff.AllOps))
	for _, op := range diff.AllOps {
		counts[op.String()] = s.Diff.Counts[op]
	}
	j.write(statsRecord{
		Record: "summary", Counts: counts, Total: s.Diff.Total(), Expected: s.Expected,
		Ignored: s.Diff.Ignored, Hidden: s.Diff.Hidden, Compared: s.Diff.Compared,
		Scanned: s.Scan.Total(), Errors: s.Scan.Errors,
		Mounts:  mountRecords(s.Scan.SkippedMounts),
		Elapsed: s.Scan.Elapsed.Seconds(),
	})
	return j.err
}

func (j *jsonReporter) write(v any) {
	if j.err == nil {
		j.err = j.enc.Encode(v)
	}
}

const hexDigits = "0123456789abcdef"

// hex avoids pulling encoding/hex in for one fixed-size digest.
func hex(b []byte) string {
	out := make([]byte, len(b)*2)
	for i, c := range b {
		out[i*2] = hexDigits[c>>4]
		out[i*2+1] = hexDigits[c&0x0f]
	}
	return string(out)
}

// mountRecord names a mount point the walk did not enter. It is in the summary
// rather than among the changes because it is not a change: it is a statement
// about what the report does not cover.
type mountRecord struct {
	Path   string `json:"path"`
	FSType string `json:"fstype,omitempty"`
	Kind   string `json:"kind"`
}

func mountRecords(mounts []scan.SkippedMount) []mountRecord {
	if len(mounts) == 0 {
		return nil
	}
	out := make([]mountRecord, len(mounts))
	for i, m := range mounts {
		out[i] = mountRecord{Path: m.Path, FSType: m.FSType, Kind: m.Kind.String()}
	}
	return out
}
