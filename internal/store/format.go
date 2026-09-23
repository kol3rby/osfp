// Package store reads and writes the .osfp container: a sorted, immutable,
// block-compressed file — that is, an SSTable cut down to what osfp needs.
//
// The layout, from the start of the file:
//
//	HEADER   32 bytes: magic, format version, hash and compression algorithms
//	META     JSON: the system, the scan parameters and the exclusions used
//	DATA     blocks of front-coded entries, each block compressed on its own
//	INDEX    one record per block: its first key, its offset and its size
//	FOOTER   section offsets, counts, the digest of everything above, magic
//
// Two properties drive the design. Entries arrive already sorted (see
// internal/canon), so keys share long prefixes and front-coding turns a 60-byte
// path into a dozen bytes. And a SHA-256 is incompressible, so 32 bytes per
// regular file is a floor no format can go below — which is exactly why a
// general-purpose database loses here: it adds its own overhead on top of that
// floor.
package store

import "errors"

const (
	// Magic opens the file and is checked before anything else is believed.
	Magic = "OSFP\x00"
	// FooterMagic closes it, so that a truncated file is detected by reading
	// eight bytes rather than by failing somewhere in the middle.
	FooterMagic = "OSFP\x00END"

	// FormatVersion is bumped whenever a reader of an older osfp could
	// misinterpret a newer file. Readers refuse what they do not know.
	FormatVersion = 1
)

// Algorithm identifiers, recorded in the header so that a file always says how
// it was written.
const (
	HashSHA256 = 1

	CompressionNone = 0
	CompressionZstd = 1
)

const (
	headerSize = 32
	// footerSize is 9 uint64 fields, the digest and the closing magic.
	footerSize = 9*8 + 32 + len(FooterMagic)
	// blockHeaderSize prefixes every compressed block with its uncompressed
	// and compressed lengths, so the data section can be read start to finish
	// without the index.
	blockHeaderSize = 8

	// defaultBlockSize is the amount of uncompressed entry data gathered
	// before a block is flushed. Larger blocks compress better; smaller ones
	// make a seek cheaper. 64 KiB is the usual compromise.
	defaultBlockSize = 64 << 10
)

// Decoder limits. They exist for one reason: a .osfp file may be corrupt or
// hostile, and the decoder must fail rather than allocate a gigabyte because a
// length field says so.
const (
	maxBlockSize  = 64 << 20
	maxStringSize = 64 << 10
	// maxMetaSize bounds the JSON header. Ours is about a kilobyte; anything
	// past a few megabytes is a file worth refusing rather than parsing.
	maxMetaSize = 8 << 20
)

var (
	// ErrBadMagic means the file is not a fingerprint at all.
	ErrBadMagic = errors.New("not an osfp fingerprint file")
	// ErrUnsupportedVersion means it is one, written by a newer osfp.
	ErrUnsupportedVersion = errors.New("unsupported fingerprint format version")
	// ErrCorrupt covers every structural inconsistency found while parsing.
	ErrCorrupt = errors.New("corrupt fingerprint file")
	// ErrOutOfOrder is returned by the writer when entries do not arrive in
	// canonical order, which the whole format and the merge join depend on.
	ErrOutOfOrder = errors.New("entries must be added in canonical order")
	// ErrDigestMismatch means the file was damaged or truncated in transit.
	ErrDigestMismatch = errors.New("fingerprint digest does not match its contents")
)

// Entry flags, stored in one byte per entry.
//
// The plan wrote the hash as present "if the entry is a regular file", but
// that is not enough: a regular file that could not be read has no hash, and
// neither has one skipped by --max-file-size. One explicit byte removes the
// ambiguity; it costs 500 KB on half a million entries before compression, and
// almost nothing after, since the byte is nearly constant.
const (
	flagHashed   = 1 << 0
	flagPartial  = 1 << 1
	flagLink     = 1 << 2
	flagHardlink = 1 << 3
	flagError    = 1 << 4
)
