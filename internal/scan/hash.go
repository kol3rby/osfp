package scan

import (
	"context"
	"crypto/sha256"
	"hash"
	"io"
	"runtime"
	"sync"
)

// readBufferSize is the block size used to feed SHA-256. One buffer is
// allocated per worker and reused for the whole scan, which is simpler than a
// pool and allocates nothing per file.
const readBufferSize = 128 << 10

// maxJobs caps the default worker count. Past a handful of readers the disk
// runs out of IOPS long before the CPU runs out of cycles, and more goroutines
// only add seeking.
const maxJobs = 8

// DefaultJobs is the worker count used when --jobs is not given.
func DefaultJobs() int {
	if n := runtime.NumCPU(); n < maxJobs {
		return n
	}
	return maxJobs
}

// hasher is the pool of workers that turn regular files into SHA-256 sums.
type hasher struct {
	work    chan *slot
	wg      sync.WaitGroup
	maxSize int64
}

func startHasher(jobs int, maxSize int64) *hasher {
	h := &hasher{work: make(chan *slot), maxSize: maxSize}
	h.wg.Add(jobs)
	for i := 0; i < jobs; i++ {
		go h.run()
	}
	return h
}

func (h *hasher) run() {
	defer h.wg.Done()
	buf := make([]byte, readBufferSize)
	sum := sha256.New()
	for s := range h.work {
		hashEntry(&s.entry, h.maxSize, buf, sum)
		s.wg.Done()
	}
}

// submit queues an entry for hashing. The caller must have called
// s.wg.Add(1) first, so that the consumer cannot read the entry early.
func (h *hasher) submit(ctx context.Context, s *slot) error {
	select {
	case h.work <- s:
		return nil
	case <-ctx.Done():
		s.wg.Done()
		return ctx.Err()
	}
}

// stop closes the pool and waits for the workers to drain.
func (h *hasher) stop() {
	close(h.work)
	h.wg.Wait()
}

// hashEntry fills in the SHA-256 of a regular file.
//
// A read failure does not change the type of the entry: the file is still a
// file, and recording what it is plus why it could not be read says more than
// dropping it. The classifier turns a non-empty Err into a ?E line.
func hashEntry(e *Entry, maxSize int64, buf []byte, sum hash.Hash) {
	if maxSize > 0 && e.Size > maxSize {
		// No hash, so nothing but size and mtime will ever be comparable for
		// this entry — hence the explicit mark.
		e.Partial = true
		return
	}

	f, err := openForHash(e.Path)
	if err != nil {
		e.Err = err.Error()
		return
	}
	defer f.Close()

	sum.Reset()
	if _, err := io.CopyBuffer(sum, f, buf); err != nil {
		e.Err = err.Error()
		return
	}
	// Sum appends to the slice it is given; the array has exactly the right
	// capacity, so the digest lands in the entry without allocating.
	sum.Sum(e.Hash[:0])
	e.Hashed = true
}
