package store

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/klauspost/compress/zstd"

	"osfp/internal/canon"
	"osfp/internal/scan"
)

// Reader reads a .osfp file. Iteration is sequential and allocates one block
// at a time; Seek uses the block index, which is the only part of the file
// held in memory in full.
type Reader struct {
	r      io.ReaderAt
	closer io.Closer
	size   int64
	dec    *zstd.Decoder

	meta   *Meta
	index  []indexEntry
	digest [32]byte
}

// Open reads the fingerprint stored at path.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	r, err := NewReader(f, info.Size())
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	r.closer = f
	return r, nil
}

// NewReader parses a fingerprint from anything that can be read at an offset.
//
// Everything this function reads is treated as untrusted: a fingerprint is a
// file that travelled, and every offset and length it declares is checked
// against the real size before being used.
func NewReader(r io.ReaderAt, size int64) (*Reader, error) {
	if size < int64(headerSize+footerSize) {
		return nil, fmt.Errorf("%w: file is too short", ErrCorrupt)
	}

	header := make([]byte, headerSize)
	if _, err := r.ReadAt(header, 0); err != nil {
		return nil, err
	}
	if string(header[:len(Magic)]) != Magic {
		return nil, ErrBadMagic
	}
	if v := header[len(Magic)]; v != FormatVersion {
		return nil, fmt.Errorf("%w: version %d, this osfp writes and reads version %d",
			ErrUnsupportedVersion, v, FormatVersion)
	}
	if a := header[len(Magic)+1]; a != HashSHA256 {
		return nil, fmt.Errorf("%w: unknown hash algorithm %d", ErrUnsupportedVersion, a)
	}
	if a := header[len(Magic)+2]; a != CompressionZstd {
		return nil, fmt.Errorf("%w: unknown compression algorithm %d", ErrUnsupportedVersion, a)
	}

	footer := make([]byte, footerSize)
	if _, err := r.ReadAt(footer, size-int64(footerSize)); err != nil {
		return nil, err
	}
	if string(footer[len(footer)-len(FooterMagic):]) != FooterMagic {
		return nil, fmt.Errorf("%w: missing footer magic, the file is truncated", ErrCorrupt)
	}

	var f [9]int64
	for i := range f {
		f[i] = int64(binary.LittleEndian.Uint64(footer[i*8:]))
	}
	metaOffset, metaLength := f[0], f[1]
	dataOffset, dataLength := f[2], f[3]
	indexOffset, indexLength := f[4], f[5]
	entries, errCount, blocks := f[6], f[7], f[8]

	// The sections must all live between the header and the footer.
	limit := size - int64(footerSize)
	for _, s := range [][2]int64{
		{metaOffset, metaLength},
		{dataOffset, dataLength},
		{indexOffset, indexLength},
	} {
		if s[0] < int64(headerSize) || s[1] < 0 || s[0] > limit || s[0]+s[1] > limit {
			return nil, fmt.Errorf("%w: section at %d+%d lies outside the file", ErrCorrupt, s[0], s[1])
		}
	}
	if entries < 0 || errCount < 0 || blocks < 0 {
		return nil, fmt.Errorf("%w: negative counters in the footer", ErrCorrupt)
	}

	dec, err := zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderMaxMemory(maxBlockSize))
	if err != nil {
		return nil, err
	}

	fr := &Reader{r: r, size: size, dec: dec}
	copy(fr.digest[:], footer[9*8:])

	if metaLength > maxMetaSize {
		return nil, fmt.Errorf("%w: metadata section is %d bytes, which is implausible", ErrCorrupt, metaLength)
	}
	payload := make([]byte, metaLength)
	if _, err := r.ReadAt(payload, metaOffset); err != nil {
		return nil, err
	}
	var meta Meta
	if err := json.Unmarshal(payload, &meta); err != nil {
		return nil, fmt.Errorf("%w: metadata: %v", ErrCorrupt, err)
	}
	meta.Entries, meta.Errors, meta.Blocks = entries, errCount, blocks
	fr.meta = &meta

	if err := fr.readIndex(indexOffset, indexLength, dataOffset, dataOffset+dataLength); err != nil {
		return nil, err
	}
	if int64(len(fr.index)) != blocks {
		return nil, fmt.Errorf("%w: footer announces %d blocks, index holds %d", ErrCorrupt, blocks, len(fr.index))
	}
	return fr, nil
}

func (r *Reader) readIndex(offset, length, dataStart, dataEnd int64) error {
	if length == 0 {
		return nil
	}
	raw, err := r.readBlock(offset, length)
	if err != nil {
		return err
	}

	d := &byteReader{buf: raw}
	count := d.uvarint()
	// Every index record costs at least three bytes, so the announced count is
	// bounded by the section that holds it. Without that bound, a corrupt file
	// could ask for half a gigabyte of slice by writing one varint.
	if d.err != nil || count > uint64(len(raw)/3) {
		return fmt.Errorf("%w: unreadable block index", ErrCorrupt)
	}
	r.index = make([]indexEntry, 0, min(count, 4096))
	for i := uint64(0); i < count; i++ {
		key := d.str(maxStringSize)
		off := int64(d.uvarint())
		size := int64(d.uvarint())
		if d.err != nil {
			return fmt.Errorf("%w: unreadable block index", ErrCorrupt)
		}
		if off < dataStart || size <= 0 || off+size > dataEnd {
			return fmt.Errorf("%w: block %d at %d+%d lies outside the data section", ErrCorrupt, i, off, size)
		}
		r.index = append(r.index, indexEntry{firstKey: key, offset: off, size: size})
	}
	return nil
}

// readBlock reads and decompresses one block, checking every declared length
// before trusting it.
func (r *Reader) readBlock(offset, size int64) ([]byte, error) {
	if size < blockHeaderSize || offset+size > r.size {
		return nil, fmt.Errorf("%w: block at %d+%d", ErrCorrupt, offset, size)
	}
	raw := make([]byte, size)
	if _, err := r.r.ReadAt(raw, offset); err != nil {
		return nil, err
	}
	plainLen := int64(binary.LittleEndian.Uint32(raw[0:]))
	compLen := int64(binary.LittleEndian.Uint32(raw[4:]))
	if plainLen > maxBlockSize || compLen != size-blockHeaderSize {
		return nil, fmt.Errorf("%w: block at %d declares %d/%d bytes", ErrCorrupt, offset, plainLen, compLen)
	}
	// The declared length is only a hint for the initial allocation: it comes
	// from the file. The decoder grows the slice as it actually produces data,
	// and its own memory limit is the real guard.
	out, err := r.dec.DecodeAll(raw[blockHeaderSize:], make([]byte, 0, min(plainLen, 1<<20)))
	if err != nil {
		return nil, fmt.Errorf("%w: block at %d: %v", ErrCorrupt, offset, err)
	}
	if int64(len(out)) != plainLen {
		return nil, fmt.Errorf("%w: block at %d decompressed to %d bytes, expected %d",
			ErrCorrupt, offset, len(out), plainLen)
	}
	return out, nil
}

// Meta returns the fingerprint header.
func (r *Reader) Meta() *Meta { return r.meta }

// Digest returns the SHA-256 recorded in the footer.
func (r *Reader) Digest() [32]byte { return r.digest }

// Close releases the file, if this reader opened one.
func (r *Reader) Close() error {
	r.dec.Close()
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

// Verify recomputes the digest over the whole file and compares it with the
// one in the footer. This is what detects a truncated transfer or a damaged
// medium — the need a signature would not address any better.
func (r *Reader) Verify() error {
	h := sha256.New()
	covered := r.size - int64(32+len(FooterMagic))
	if _, err := io.Copy(h, io.NewSectionReader(r.r, 0, covered)); err != nil {
		return err
	}
	var got [32]byte
	h.Sum(got[:0])
	if got != r.digest {
		return ErrDigestMismatch
	}
	return nil
}

// Cursor returns a cursor over every entry, in canonical order.
func (r *Reader) Cursor() *Cursor { return &Cursor{r: r, block: -1} }

// Seek returns a cursor positioned on the first entry whose path is greater
// than or equal to path. It reads one block, found through the in-memory
// index, rather than scanning from the start.
func (r *Reader) Seek(path string) (*Cursor, error) {
	// The block that may contain path is the last one whose first key is not
	// greater than it.
	i := sort.Search(len(r.index), func(i int) bool {
		return canon.CompareKey(r.index[i].firstKey, path) > 0
	}) - 1
	if i < 0 {
		i = 0
	}
	c := &Cursor{r: r, block: i - 1}
	for {
		e, err := c.Next()
		if err != nil {
			if err == io.EOF {
				return c, nil
			}
			return nil, err
		}
		if canon.CompareKey(e.Path, path) >= 0 {
			c.pending = true
			return c, nil
		}
	}
}

// Iterate calls fn once per entry, in canonical order. The entry is only valid
// for the duration of the call.
func (r *Reader) Iterate(fn func(e *scan.Entry) error) error {
	c := r.Cursor()
	for {
		e, err := c.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if err := fn(e); err != nil {
			return err
		}
	}
}

// Cursor walks entries in canonical order.
type Cursor struct {
	r       *Reader
	block   int
	dec     blockDecoder
	pending bool
}

// Next returns the next entry, or io.EOF at the end of the file. The entry is
// only valid until the following call.
func (c *Cursor) Next() (*scan.Entry, error) {
	if c.pending {
		c.pending = false
		return &c.dec.e, nil
	}
	for {
		e, err := c.dec.next()
		if err == nil {
			return e, nil
		}
		if err != io.EOF {
			return nil, err
		}
		if c.block+1 >= len(c.r.index) {
			return nil, io.EOF
		}
		c.block++
		ie := c.r.index[c.block]
		buf, err := c.r.readBlock(ie.offset, ie.size)
		if err != nil {
			return nil, err
		}
		c.dec.reset(buf)
	}
}
