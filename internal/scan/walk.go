package scan

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"osfp/internal/exclude"
)

// DefaultMaxDepth bounds the descent. Recursive bind mounts and directory
// loops that survive the one-file-system guard end here rather than in an
// unbounded walk.
const DefaultMaxDepth = 64

// MountPolicy decides what the walk does when it reaches a mount point.
//
// The default crosses into another local filesystem. That is not the obvious
// choice — "one file system" is the familiar behaviour of du, tar and rsync —
// but it is the correct one here, and a porting run on FreeBSD is what showed
// why: on a stock ZFS install, /home, /var/log, /var/audit, /usr/src and four
// more are separate datasets. Stopping at every mount point silently reversed
// the plan's explicit decision to keep /home in scope, and left the audit
// trail itself out of the fingerprint.
//
// What stopping at mount points was really for — not hashing a four-terabyte
// share mounted on /srv — is expressed directly by looking at the filesystem
// type instead, which is what MountLocal does.
type MountPolicy uint8

const (
	// MountLocal descends into local filesystems and stops at pseudo and
	// network ones. It is the zero value, and the default.
	MountLocal MountPolicy = iota
	// MountSame stops at every mount point, whatever it holds.
	MountSame
	// MountAll crosses everything, including network shares.
	MountAll
)

// ParseMountPolicy reads the value of the --mounts flag.
func ParseMountPolicy(s string) (MountPolicy, error) {
	switch s {
	case "local", "":
		return MountLocal, nil
	case "same":
		return MountSame, nil
	case "all":
		return MountAll, nil
	default:
		return MountLocal, fmt.Errorf("unknown mount policy %q (local, same or all)", s)
	}
}

func (p MountPolicy) String() string {
	switch p {
	case MountSame:
		return "same"
	case MountAll:
		return "all"
	default:
		return "local"
	}
}

// SkippedMount records a mount point the walk did not enter, and why. An audit
// report has to be able to distinguish "nothing changed here" from "nothing
// was looked at here", which means naming these rather than counting them.
type SkippedMount struct {
	Path   string
	FSType string // empty when the type could not be determined
	Kind   FSKind
}

// Options configures a scan.
type Options struct {
	Root        string       // subtree to scan, "/" by default
	Exclude     *exclude.Set // may be nil: scan everything
	Mounts      MountPolicy  // what to do at a mount point; zero value is MountLocal
	MaxDepth    int          // 0 selects DefaultMaxDepth
	Jobs        int          // 0 selects min(NumCPU, 8)
	MaxFileSize int64        // 0 means no limit: hash every file
	// NoHash walks and stats everything but opens nothing. It is what
	// --new-dir-mode=summary uses to count what sits under a directory that
	// is absent from the fingerprint, without hashing an entire new tree.
	NoHash bool

	// Descend is asked, for each directory that is about to be entered,
	// whether the walk should enter it. compare uses it to prune directories
	// absent from the fingerprint: they are reported as added, and their
	// contents are never listed or hashed. A nil Descend enters everything.
	//
	// The entry passed is only valid for the duration of the call.
	Descend func(e *Entry) bool
}

func (o *Options) setDefaults() {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.MaxDepth <= 0 {
		o.MaxDepth = DefaultMaxDepth
	}
	if o.Jobs <= 0 {
		o.Jobs = DefaultJobs()
	}
}

// Stats summarises a scan.
type Stats struct {
	Dirs     int64
	Files    int64
	Symlinks int64
	Others   int64
	Errors   int64 // entries carrying a read error
	Hashed   int64
	Partial  int64
	Pruned   int64 // directories emitted but not descended into
	// SkippedMounts names the mount points the walk did not enter. It is
	// capped, because a machine with a thousand automounts should not turn its
	// report into a mount table.
	SkippedMounts []SkippedMount
	Bytes         int64 // bytes actually hashed
	Elapsed       time.Duration
}

// Total returns the number of entries produced.
func (s Stats) Total() int64 { return s.Dirs + s.Files + s.Symlinks + s.Others }

// Walk scans opts.Root and calls emit once per entry, in canonical order.
//
// The entry handed to emit points into the reorder buffer and is only valid
// for the duration of the call: copy whatever must outlive it. An error
// returned by emit stops the scan and is what Walk returns.
func Walk(ctx context.Context, opts Options, emit func(e *Entry) error) (Stats, error) {
	opts.setDefaults()
	start := time.Now()

	root := filepath.Clean(opts.Root)
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return Stats{}, fmt.Errorf("scan root %s: %w", root, err)
	}
	if !rootInfo.IsDir() {
		return Stats{}, fmt.Errorf("scan root %s is not a directory", root)
	}
	var probe Entry
	fillStat(&probe, rootInfo)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	w := &walker{
		opts:   opts,
		root:   root,
		ring:   newRing(4 * opts.Jobs),
		hasher: startHasher(opts.Jobs, opts.MaxFileSize),
	}

	var walkErr error
	go func() {
		// The hasher is stopped before the sequence is closed, so that every
		// committed cell has been through a worker by the time the consumer
		// reaches the end of the stream.
		defer w.ring.close()
		defer w.hasher.stop()
		walkErr = w.visit(ctx, root, rootInfo, 0, probe.Dev)
	}()

	var stats Stats
	var emitErr error
	for s := range w.ring.ordered {
		s.wg.Wait()
		if emitErr == nil {
			stats.count(&s.entry)
			if err := emit(&s.entry); err != nil {
				emitErr = err
				// Stop the walk and keep draining: the walker is likely
				// blocked on a free cell and would never notice otherwise.
				cancel()
			}
		}
		w.ring.release(s)
	}
	stats.Pruned = w.pruned
	stats.SkippedMounts = w.skipped
	stats.Elapsed = time.Since(start)

	switch {
	case emitErr != nil:
		return stats, emitErr
	case walkErr != nil:
		return stats, walkErr
	}
	return stats, nil
}

func (s *Stats) count(e *Entry) {
	switch e.Type {
	case TypeDir:
		s.Dirs++
	case TypeFile:
		s.Files++
	case TypeSymlink:
		s.Symlinks++
	default:
		s.Others++
	}
	if e.Err != "" {
		s.Errors++
	}
	if e.Hashed {
		s.Hashed++
		s.Bytes += e.Size
	}
	if e.Partial {
		s.Partial++
	}
}

type walker struct {
	opts   Options
	root   string
	ring   *ring
	hasher *hasher
	pruned int64

	skipped []SkippedMount
}

// visit emits the entry for path and, when it is a directory the walk may
// enter, its children in name order.
//
// The recursion is written here rather than delegated to filepath.WalkDir for
// one reason: WalkDir reports a directory it cannot list by calling back a
// second time with the same path, which would put two entries at the same key
// into a stream that the merge join requires to be strictly increasing. Doing
// the listing first lets the failure be recorded on the directory's own entry,
// where it also reads better: "?E /var/lib/private  permission denied".
func (w *walker) visit(ctx context.Context, path string, info fs.FileInfo, depth int, parentDev uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	s, err := w.ring.acquire(ctx)
	if err != nil {
		return err
	}
	e := &s.entry
	e.Path = path
	e.Type = typeOf(info.Mode())
	e.Mode = unixMode(info.Mode())
	e.Size = info.Size()
	e.MTime = info.ModTime().Unix()
	fillStat(e, info)

	if e.Type == TypeSymlink {
		// The target is read, never followed: a retargeted link is a change,
		// and following links would create loops and duplicate entries.
		if target, err := os.Readlink(path); err == nil {
			e.Link = target
		} else {
			e.Err = err.Error()
		}
	}

	var children []fs.DirEntry
	descend := e.Type == TypeDir && w.mayDescend(e, depth, parentDev)
	if descend {
		children, err = os.ReadDir(path)
		if err != nil {
			// Unreadable directory: the scan records why and carries on. This
			// is the single most common finding of an unprivileged scan, and
			// the reason baseline and compare demand root.
			e.Err = err.Error()
			descend = false
		}
	}

	if e.Type == TypeFile && !w.opts.NoHash {
		s.wg.Add(1)
		if err := w.hasher.submit(ctx, s); err != nil {
			return err
		}
	}
	// From here on the cell belongs to the consumer and must not be read.
	w.ring.commit(s)

	for _, c := range children {
		child := filepath.Join(path, c.Name())
		if w.opts.Exclude != nil && w.opts.Exclude.Match(child) {
			continue
		}
		ci, err := c.Info()
		if err != nil {
			// The entry vanished between the listing and the stat. That is a
			// finding of its own, not a reason to stop.
			if err := w.emitError(ctx, child, err); err != nil {
				return err
			}
			continue
		}
		if err := w.visit(ctx, child, ci, depth+1, e.Dev); err != nil {
			return err
		}
	}
	return nil
}

// mayDescend applies the three reasons not to enter a directory that has
// nonetheless been emitted. The scan root is always entered.
func (w *walker) mayDescend(e *Entry, depth int, parentDev uint64) bool {
	if depth == 0 {
		return true
	}
	switch {
	// A different device than the parent's means a mount point, and only
	// there is the filesystem type worth asking for: one statfs per mount
	// rather than one per directory.
	case e.Dev != parentDev && !w.crossMount(e.Path):
	case depth >= w.opts.MaxDepth:
	case w.opts.Descend != nil && !w.opts.Descend(e):
	default:
		return true
	}
	w.pruned++
	return false
}

// crossMount decides whether to enter the filesystem newly reached at path,
// and records it when it does not.
//
// A filesystem whose type cannot be determined — which on the supported
// targets means an AIX type number missing from /etc/vfs — is not entered.
// That is the conservative answer: the cost of wrongly crossing is hours spent
// hashing a remote share, the cost of wrongly stopping is a gap, and a gap
// that is named in the summary is one the operator can act on.
func (w *walker) crossMount(path string) bool {
	if w.opts.Mounts == MountAll {
		return true
	}
	name, kind := classifyFS(path)
	if w.opts.Mounts == MountLocal && kind == FSLocal {
		return true
	}
	w.noteMount(path, name, kind)
	return false
}

// maxSkippedMounts caps what the summary reports by name.
const maxSkippedMounts = 20

func (w *walker) noteMount(path, fsType string, kind FSKind) {
	if len(w.skipped) < maxSkippedMounts {
		w.skipped = append(w.skipped, SkippedMount{Path: path, FSType: fsType, Kind: kind})
	}
}

// emitError records a path that could not be stat'ed at all.
func (w *walker) emitError(ctx context.Context, path string, cause error) error {
	s, err := w.ring.acquire(ctx)
	if err != nil {
		return err
	}
	s.entry.Path = path
	s.entry.Type = TypeError
	s.entry.Err = cause.Error()
	w.ring.commit(s)
	return nil
}
