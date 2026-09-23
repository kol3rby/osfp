package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"hash"
	"io"

	"github.com/klauspost/compress/zstd"

	"osfp/internal/canon"
	"osfp/internal/scan"
)

// indexEntry locates one block.
type indexEntry struct {
	firstKey string
	offset   int64
	size     int64
}

// Writer streams entries into a .osfp file. Nothing is ever held in memory
// beyond the block being built and the block index, so the memory used is
// independent of the size of the filesystem.
type Writer struct {
	w      io.Writer
	digest hash.Hash
	off    int64
	enc    *zstd.Encoder

	block      []byte
	blockFirst string
	blockPrev  string
	blockCount int
	scratch    []byte

	index []indexEntry

	lastKey string
	hasLast bool
	entries int64
	errors  int64

	metaOffset, metaLength int64
	dataOffset             int64

	closed bool
	err    error
}

// NewWriter writes the header and the metadata, then stands ready for entries.
func NewWriter(w io.Writer, meta *Meta) (*Writer, error) {
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.SpeedDefault),
		zstd.WithEncoderConcurrency(1))
	if err != nil {
		return nil, err
	}

	fw := &Writer{
		w:      w,
		digest: sha256.New(),
		enc:    enc,
		block:  make([]byte, 0, defaultBlockSize+4096),
	}

	header := make([]byte, headerSize)
	copy(header, Magic)
	header[len(Magic)] = FormatVersion
	header[len(Magic)+1] = HashSHA256
	header[len(Magic)+2] = CompressionZstd
	if err := fw.write(header); err != nil {
		return nil, err
	}

	payload, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}
	fw.metaOffset = fw.off
	if err := fw.write(payload); err != nil {
		return nil, err
	}
	fw.metaLength = int64(len(payload))
	fw.dataOffset = fw.off
	return fw, nil
}

// write sends bytes to the file and to the digest at once, and keeps the
// running offset the index and footer need.
func (w *Writer) write(p []byte) error {
	if w.err != nil {
		return w.err
	}
	n, err := w.w.Write(p)
	w.off += int64(n)
	w.digest.Write(p[:n])
	if err != nil {
		w.err = err
	}
	return err
}

// Add appends an entry. Entries must arrive in canonical order; the check is
// not defensive pedantry but the invariant the whole format rests on, and
// breaking it would produce a file whose merge join silently loses entries.
func (w *Writer) Add(e *scan.Entry) error {
	if w.err != nil {
		return w.err
	}
	if w.closed {
		return fmt.Errorf("store: Add after Close")
	}
	if e.Path == "" {
		return fmt.Errorf("store: entry with an empty path")
	}
	if w.hasLast && canon.CompareKey(w.lastKey, e.Path) >= 0 {
		return fmt.Errorf("%w: %q after %q", ErrOutOfOrder, e.Path, w.lastKey)
	}

	if w.blockCount == 0 {
		w.blockFirst = e.Path
		w.blockPrev = ""
	}
	w.block = appendEntry(w.block, e, w.blockPrev)
	w.blockPrev = e.Path
	w.blockCount++

	w.lastKey = e.Path
	w.hasLast = true
	w.entries++
	if e.Err != "" {
		w.errors++
	}

	if len(w.block) >= defaultBlockSize {
		return w.flushBlock()
	}
	return nil
}

// Entries returns how many entries have been written so far.
func (w *Writer) Entries() int64 { return w.entries }

func (w *Writer) flushBlock() error {
	if w.blockCount == 0 {
		return nil
	}
	w.scratch = w.enc.EncodeAll(w.block, w.scratch[:0])

	var header [blockHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:], uint32(len(w.block)))
	binary.LittleEndian.PutUint32(header[4:], uint32(len(w.scratch)))

	offset := w.off
	if err := w.write(header[:]); err != nil {
		return err
	}
	if err := w.write(w.scratch); err != nil {
		return err
	}

	w.index = append(w.index, indexEntry{
		firstKey: w.blockFirst,
		offset:   offset,
		size:     w.off - offset,
	})
	w.block = w.block[:0]
	w.blockCount = 0
	return nil
}

// Close flushes the last block, writes the index and the footer, and seals the
// file with the digest of everything it contains.
func (w *Writer) Close() error {
	if w.closed {
		return nil
	}
	w.closed = true
	if w.err != nil {
		return w.err
	}
	if err := w.flushBlock(); err != nil {
		return err
	}
	dataLength := w.off - w.dataOffset

	indexOffset := w.off
	if err := w.writeIndex(); err != nil {
		return err
	}
	indexLength := w.off - indexOffset

	footer := make([]byte, 0, footerSize)
	for _, v := range []int64{
		w.metaOffset, w.metaLength,
		w.dataOffset, dataLength,
		indexOffset, indexLength,
		w.entries, w.errors, int64(len(w.index)),
	} {
		footer = binary.LittleEndian.AppendUint64(footer, uint64(v))
	}
	if err := w.write(footer); err != nil {
		return err
	}

	// The digest covers the file up to this point; it and the closing magic
	// are therefore written straight to the file, not through the hash.
	sum := w.digest.Sum(nil)
	if _, err := w.w.Write(sum); err != nil {
		return err
	}
	_, err := io.WriteString(w.w, FooterMagic)
	return err
}

func (w *Writer) writeIndex() error {
	buf := make([]byte, 0, len(w.index)*64)
	buf = binary.AppendUvarint(buf, uint64(len(w.index)))
	for _, ie := range w.index {
		buf = binary.AppendUvarint(buf, uint64(len(ie.firstKey)))
		buf = append(buf, ie.firstKey...)
		buf = binary.AppendUvarint(buf, uint64(ie.offset))
		buf = binary.AppendUvarint(buf, uint64(ie.size))
	}

	compressed := w.enc.EncodeAll(buf, nil)
	var header [blockHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:], uint32(len(buf)))
	binary.LittleEndian.PutUint32(header[4:], uint32(len(compressed)))
	if err := w.write(header[:]); err != nil {
		return err
	}
	return w.write(compressed)
}

// appendEntry encodes one entry, front-coded against the previous key of the
// same block. The first entry of a block has no shared prefix, which is what
// makes a block decodable on its own — and therefore what makes seeking
// possible.
func appendEntry(dst []byte, e *scan.Entry, prev string) []byte {
	shared := sharedPrefix(prev, e.Path)
	suffix := e.Path[shared:]

	dst = binary.AppendUvarint(dst, uint64(shared))
	dst = binary.AppendUvarint(dst, uint64(len(suffix)))
	dst = append(dst, suffix...)

	dst = append(dst, byte(e.Type))
	dst = append(dst, entryFlags(e))
	dst = binary.AppendUvarint(dst, uint64(e.Mode))
	dst = binary.AppendUvarint(dst, uint64(e.UID))
	dst = binary.AppendUvarint(dst, uint64(e.GID))
	dst = binary.AppendUvarint(dst, uint64(e.Size))
	// Signed: a modification time before 1970 is unusual but perfectly legal.
	dst = binary.AppendVarint(dst, e.MTime)

	if e.Hashed {
		dst = append(dst, e.Hash[:]...)
	}
	if e.Link != "" {
		dst = binary.AppendUvarint(dst, uint64(len(e.Link)))
		dst = append(dst, e.Link...)
	}
	if e.Dev != 0 || e.Ino != 0 || e.Nlink != 0 {
		dst = binary.AppendUvarint(dst, e.Dev)
		dst = binary.AppendUvarint(dst, e.Ino)
		dst = binary.AppendUvarint(dst, uint64(e.Nlink))
	}
	if e.Err != "" {
		dst = binary.AppendUvarint(dst, uint64(len(e.Err)))
		dst = append(dst, e.Err...)
	}
	return dst
}

func entryFlags(e *scan.Entry) byte {
	var f byte
	if e.Hashed {
		f |= flagHashed
	}
	if e.Partial {
		f |= flagPartial
	}
	if e.Link != "" {
		f |= flagLink
	}
	if e.Dev != 0 || e.Ino != 0 || e.Nlink != 0 {
		f |= flagHardlink
	}
	if e.Err != "" {
		f |= flagError
	}
	return f
}

// sharedPrefix returns the length of the common prefix of a and b, in bytes.
func sharedPrefix(a, b string) int {
	n := min(len(a), len(b))
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return i
}
