package scan

import (
	"context"
	"sync"
)

// slot is one cell of the reorder buffer: an entry, plus the means to wait for
// the worker that is hashing it.
type slot struct {
	entry Entry
	wg    sync.WaitGroup
}

// ring is the bounded reorder buffer of §7.3.
//
// The walk is sequential, so it already produces entries in canonical order;
// hashing them in parallel is what would scramble that order. The ring hands
// the walker a free cell, the walker commits cells in walk order, and the
// consumer reads them back in that same order, waiting on each one's worker.
//
// Two properties fall out of the fixed number of cells: memory is bounded
// whatever the size of the filesystem, and the walk blocks on its own when
// every cell is in flight. That back-pressure is free — no queue to tune, no
// sorting, and no global map.
type ring struct {
	free    chan *slot
	ordered chan *slot
}

func newRing(n int) *ring {
	r := &ring{
		free: make(chan *slot, n),
		// ordered holds at most every existing cell, so committing never
		// blocks and the walker can only ever wait on free.
		ordered: make(chan *slot, n),
	}
	for i := 0; i < n; i++ {
		r.free <- &slot{}
	}
	return r
}

// acquire takes a free cell, blocking — and thereby throttling the walk —
// until the consumer releases one.
func (r *ring) acquire(ctx context.Context) (*slot, error) {
	select {
	case s := <-r.free:
		s.entry = Entry{}
		return s, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// commit places a cell in the output sequence. It never blocks.
func (r *ring) commit(s *slot) { r.ordered <- s }

// release returns a consumed cell to the pool.
func (r *ring) release(s *slot) { r.free <- s }

// close ends the output sequence.
func (r *ring) close() { close(r.ordered) }
