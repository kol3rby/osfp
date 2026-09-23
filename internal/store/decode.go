package store

import (
	"encoding/binary"
	"fmt"
	"io"

	"osfp/internal/canon"
	"osfp/internal/scan"
)

// byteReader decodes from a byte slice without ever panicking.
//
// This is the only code in osfp that parses binary data it did not just
// produce, and the data may be corrupt or hostile. Every accessor checks its
// bounds and latches the first error instead of returning it, so the decoding
// of an entry reads as a straight sequence of fields with a single check at
// the end — which is the only shape in which such a function stays correct.
type byteReader struct {
	buf []byte
	pos int
	err error
}

func (b *byteReader) fail(format string, args ...any) {
	if b.err == nil {
		b.err = fmt.Errorf("%w: %s", ErrCorrupt, fmt.Sprintf(format, args...))
	}
}

func (b *byteReader) done() bool { return b.err != nil || b.pos >= len(b.buf) }

func (b *byteReader) uvarint() uint64 {
	if b.err != nil {
		return 0
	}
	v, n := binary.Uvarint(b.buf[b.pos:])
	if n <= 0 {
		b.fail("truncated or overlong unsigned varint at offset %d", b.pos)
		return 0
	}
	b.pos += n
	return v
}

func (b *byteReader) varint() int64 {
	if b.err != nil {
		return 0
	}
	v, n := binary.Varint(b.buf[b.pos:])
	if n <= 0 {
		b.fail("truncated or overlong signed varint at offset %d", b.pos)
		return 0
	}
	b.pos += n
	return v
}

func (b *byteReader) u8() byte {
	if b.err != nil {
		return 0
	}
	if b.pos >= len(b.buf) {
		b.fail("unexpected end of block")
		return 0
	}
	v := b.buf[b.pos]
	b.pos++
	return v
}

// take returns the next n bytes of the underlying buffer, without copying.
func (b *byteReader) take(n int) []byte {
	if b.err != nil {
		return nil
	}
	if n < 0 || n > len(b.buf)-b.pos {
		b.fail("field of %d bytes runs past the end of the block", n)
		return nil
	}
	v := b.buf[b.pos : b.pos+n]
	b.pos += n
	return v
}

// str reads a length-prefixed string, refusing any length beyond max.
func (b *byteReader) str(max int) string {
	n := b.uvarint()
	if b.err != nil {
		return ""
	}
	if n > uint64(max) {
		b.fail("string of %d bytes exceeds the %d byte limit", n, max)
		return ""
	}
	return string(b.take(int(n)))
}

// blockDecoder turns one decompressed block back into entries.
type blockDecoder struct {
	br   byteReader
	prev string
	e    scan.Entry
}

func (d *blockDecoder) reset(buf []byte) {
	d.br = byteReader{buf: buf}
	d.prev = ""
}

// next decodes the entry at the current position, reusing the same Entry.
func (d *blockDecoder) next() (*scan.Entry, error) {
	if d.br.err != nil {
		return nil, d.br.err
	}
	if d.br.pos >= len(d.br.buf) {
		return nil, io.EOF
	}

	shared := d.br.uvarint()
	if d.br.err == nil && shared > uint64(len(d.prev)) {
		d.br.fail("shared prefix of %d bytes exceeds the previous key (%d bytes)", shared, len(d.prev))
	}
	suffix := d.br.str(maxStringSize)
	if d.br.err != nil {
		return nil, d.br.err
	}
	path := d.prev[:shared] + suffix
	// Two invariants the writer guarantees and a corrupt file may not: a path
	// is never empty, and keys inside a block strictly increase. Checking them
	// here turns a decodable but nonsensical file into an error, instead of a
	// merge join that silently loses entries.
	if path == "" {
		d.br.fail("entry with an empty path")
		return nil, d.br.err
	}
	if d.prev != "" && canon.CompareKey(d.prev, path) >= 0 {
		d.br.fail("key %q does not follow %q in canonical order", path, d.prev)
		return nil, d.br.err
	}

	e := &d.e
	*e = scan.Entry{Path: path}
	e.Type = scan.Type(d.br.u8())
	flags := d.br.u8()
	e.Mode = uint32(d.br.uvarint())
	e.UID = uint32(d.br.uvarint())
	e.GID = uint32(d.br.uvarint())
	e.Size = int64(d.br.uvarint())
	e.MTime = d.br.varint()

	if flags&flagHashed != 0 {
		copy(e.Hash[:], d.br.take(len(e.Hash)))
		e.Hashed = d.br.err == nil
	}
	e.Partial = flags&flagPartial != 0
	if flags&flagLink != 0 {
		e.Link = d.br.str(maxStringSize)
	}
	if flags&flagHardlink != 0 {
		e.Dev = d.br.uvarint()
		e.Ino = d.br.uvarint()
		e.Nlink = uint32(d.br.uvarint())
	}
	if flags&flagError != 0 {
		e.Err = d.br.str(maxStringSize)
	}

	if d.br.err != nil {
		return nil, d.br.err
	}
	d.prev = path
	return e, nil
}
