package store

import (
	"time"

	"osfp/internal/osdetect"
)

// ScanOptions records how the scan that produced a fingerprint was run.
// compare reads it back to tell the operator when it is about to compare two
// different perimeters.
type ScanOptions struct {
	Root           string `json:"root"`
	Mounts         string `json:"mounts"`
	MaxDepth       int    `json:"max_depth"`
	MaxFileSize    int64  `json:"max_file_size,omitempty"`
	Jobs           int    `json:"jobs"`
	TrackHardlinks bool   `json:"track_hardlinks"`
}

// Meta is the self-describing header of a fingerprint. A fingerprint travels —
// scp'd to a laptop, attached to a ticket, read back a year later — so it
// carries everything needed to judge what it is worth, without any companion
// file.
type Meta struct {
	Tool        string    `json:"tool"`
	ToolVersion string    `json:"tool_version"`
	CreatedAt   time.Time `json:"created_at"`

	// Key is the fingerprint key compare checks against the live system. It is
	// stored rather than recomputed from System, so that a key forced with
	// --os-id survives.
	Key    string        `json:"os_key"`
	System osdetect.Info `json:"system"`

	// Privileged records whether the scan ran as root. A fingerprint taken
	// without privileges is silently incomplete, so it is marked here and
	// compare refuses to pair it with a privileged scan.
	Privileged bool `json:"privileged"`
	EUID       int  `json:"euid"`

	Scan       ScanOptions `json:"scan"`
	Exclusions []string    `json:"exclusions"`

	// The three fields below are results, not parameters: they are only known
	// once the last entry has been written, by which time this JSON is already
	// on disk. They live in the footer and are filled in when the file is
	// opened.
	Entries int64 `json:"-"`
	Errors  int64 `json:"-"`
	Blocks  int64 `json:"-"`
}
