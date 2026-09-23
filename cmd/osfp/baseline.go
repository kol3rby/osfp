package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"osfp/internal/exclude"
	"osfp/internal/humanize"
	"osfp/internal/osdetect"
	"osfp/internal/scan"
	"osfp/internal/store"
)

func runBaseline(ctx context.Context, args []string) error {
	fs := newFlagSet("baseline")
	out := fs.String("o", "", "write the fingerprint to `FILE` (default: <os-key>.osfp)")
	var excludes stringSlice
	fs.Var(&excludes, "exclude", "exclude a `PATH` prefix or glob (repeatable)")
	excludeFrom := fs.String("exclude-from", "", "read exclusion patterns from `FILE`, one per line")
	noDefaults := fs.Bool("no-default-excludes", false, "start from an empty exclusion list")
	root := fs.String("root", "/", "scan this `DIR` instead of the whole filesystem")
	jobs := fs.Int("jobs", 0, "use `N` hashing workers (default: min(NumCPU, 8))")
	mounts := fs.String("mounts", "local", "what to do at a mount point, `POLICY` being local (cross local filesystems, stop at pseudo and network ones), same (stop at every one) or all (cross everything)")
	maxFileSize := fs.Int64("max-file-size", 0, "record size and mtime instead of hashing files larger than `N` bytes")
	maxDepth := fs.Int("max-depth", scan.DefaultMaxDepth, "refuse to descend deeper than `N` levels")
	allowNonRoot := fs.Bool("allow-non-root", false, "scan without root privileges (marks the fingerprint UNPRIVILEGED)")
	osID := fs.String("os-id", "", "force the fingerprint `KEY` instead of detecting it")
	force := fs.Bool("force", false, "overwrite an existing fingerprint")
	verbose := false
	fs.BoolVar(&verbose, "v", false, "report progress while scanning")
	fs.BoolVar(&verbose, "verbose", false, "report progress while scanning")
	if err := fs.Parse(args); err != nil {
		return usageErr(fs, err)
	}
	if fs.NArg() != 0 {
		return usageErr(fs, errUsage)
	}

	mountPolicy, err := scan.ParseMountPolicy(*mounts)
	if err != nil {
		return err
	}

	// Step 0: privileges, before anything is detected, opened or written.
	if err := requireRoot(*allowNonRoot); err != nil {
		return err
	}

	info, key, err := identify(*osID)
	if err != nil {
		return err
	}

	target := *out
	if target == "" {
		target = key + ".osfp"
	}
	if !*force {
		if _, err := os.Stat(target); err == nil {
			return fmt.Errorf("%s already exists; pass --force to overwrite it", target)
		}
	}

	file, err := createAtomic(target)
	if err != nil {
		return err
	}
	defer file.Abort()

	// The exclusion set is built last, because two of its auto-exclusions are
	// the files this very command is about to write.
	auto := append(exclude.SelfPaths(), file.Paths()...)
	patterns := []string(excludes)
	if *excludeFrom != "" {
		fromFile, err := exclude.LoadPatterns(*excludeFrom)
		if err != nil {
			return fmt.Errorf("--exclude-from: %w", err)
		}
		patterns = append(patterns, fromFile...)
	}
	set, err := exclude.New(exclude.Options{
		GOOS:       info.OS,
		Root:       *root,
		NoDefaults: *noDefaults,
		Patterns:   patterns,
		Auto:       auto,
	})
	if err != nil {
		return err
	}
	if dropped := set.Dropped(); len(dropped) > 0 {
		n := int64(len(dropped))
		fmt.Fprintf(stderr, "note: %d %s under --root %s and %s not recorded: %s\n",
			n, humanize.Plural(n, "exclusion does not apply", "exclusions do not apply"),
			*root, humanize.Plural(n, "was", "were"), strings.Join(dropped, " "))
	}

	opts := scan.Options{
		Root:        *root,
		Exclude:     set,
		Mounts:      mountPolicy,
		MaxDepth:    *maxDepth,
		Jobs:        *jobs,
		MaxFileSize: *maxFileSize,
	}
	if opts.Jobs <= 0 {
		opts.Jobs = scan.DefaultJobs()
	}

	toolVersion, _ := buildStamps()
	meta := &store.Meta{
		Tool:        "osfp",
		ToolVersion: toolVersion,
		CreatedAt:   time.Now().UTC(),
		Key:         key,
		System:      *info,
		Privileged:  privileged(),
		EUID:        os.Geteuid(),
		Scan: store.ScanOptions{
			Root:        filepath.Clean(opts.Root),
			Mounts:      opts.Mounts.String(),
			MaxDepth:    opts.MaxDepth,
			MaxFileSize: opts.MaxFileSize,
			Jobs:        opts.Jobs,
		},
		Exclusions: set.Patterns(),
	}

	writer, err := store.NewWriter(file.Writer(), meta)
	if err != nil {
		return err
	}

	progress := newProgress(verbose)
	stats, err := scan.Walk(ctx, opts, func(e *scan.Entry) error {
		progress.tick(e)
		return writer.Add(e)
	})
	if err != nil {
		if ctx.Err() != nil {
			return withExit(exitInterrupted, errors.New("interrupted; no fingerprint was written"))
		}
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := file.Commit(); err != nil {
		return err
	}
	progress.done()

	size := fileSize(target)
	fmt.Fprintf(stdout, "wrote %s\n", target)
	fmt.Fprintf(stdout, "  system   %s\n", key)
	fmt.Fprintf(stdout, "  scope    %s · %d %s%s%s\n",
		meta.Scan.Root, len(meta.Exclusions),
		humanize.Plural(int64(len(meta.Exclusions)), "exclusion", "exclusions"),
		" · mounts="+opts.Mounts.String(),
		optional(!meta.Privileged, " · UNPRIVILEGED"))
	fmt.Fprintf(stdout, "  entries  %s (%s %s, %s %s, %s %s, %s other)\n",
		humanize.Count(stats.Total()),
		humanize.Count(stats.Dirs), humanize.Plural(stats.Dirs, "directory", "directories"),
		humanize.Count(stats.Files), humanize.Plural(stats.Files, "file", "files"),
		humanize.Count(stats.Symlinks), humanize.Plural(stats.Symlinks, "symlink", "symlinks"),
		humanize.Count(stats.Others))
	fmt.Fprintf(stdout, "  hashed   %s %s, %s\n", humanize.Count(stats.Hashed),
		humanize.Plural(stats.Hashed, "file", "files"), humanize.Bytes(stats.Bytes))
	if stats.Errors > 0 || stats.Partial > 0 || stats.Pruned > 0 {
		fmt.Fprintf(stdout, "  skipped  %s unreadable, %s not hashed (too large), %s %s not descended\n",
			humanize.Count(stats.Errors), humanize.Count(stats.Partial),
			humanize.Count(stats.Pruned), humanize.Plural(stats.Pruned, "directory", "directories"))
	}
	for _, m := range stats.SkippedMounts {
		label := m.Path
		if m.FSType != "" {
			label += " (" + m.FSType + ")"
		}
		fmt.Fprintf(stdout, "  mount    %s not crossed: %s\n", m.Kind, label)
	}
	fmt.Fprintf(stdout, "  size     %s in %s\n", humanize.Bytes(size), humanize.Duration(stats.Elapsed))
	return nil
}

// identify resolves the fingerprint key, either from the running system or
// from --os-id for a distribution osfp does not recognise.
func identify(override string) (*osdetect.Info, string, error) {
	info, err := osdetect.Detect()
	if err != nil && override == "" {
		return nil, "", err
	}
	key := info.Key()
	if override != "" {
		key, err = osdetect.NormalizeKey(override)
		if err != nil {
			return nil, "", err
		}
	}
	return info, key, nil
}

func fileSize(path string) int64 {
	if st, err := os.Stat(path); err == nil {
		return st.Size()
	}
	return 0
}

func optional(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

// progress reports what a long scan is doing, at most once a second, on
// stderr — so that piping the summary elsewhere stays clean.
type progress struct {
	enabled  bool
	terminal bool
	next     time.Time
	entries  int64
	bytes    int64
	started  time.Time
	width    int // widest line drawn, in runes: what done has to erase
}

// progressWidth keeps the progress line on one row of an 80-column terminal.
// A line that wraps cannot be redrawn in place: the carriage return only goes
// back to the start of the last row.
const progressWidth = 79

func newProgress(enabled bool) *progress {
	now := time.Now()
	// Only a terminal can redraw a line in place. Redirected to a file, the
	// carriage returns would glue every update into one unreadable line, so
	// each update becomes a line of its own instead.
	terminal := false
	if st, err := os.Stderr.Stat(); err == nil {
		terminal = st.Mode()&os.ModeCharDevice != 0
	}
	return &progress{enabled: enabled, terminal: terminal, next: now.Add(time.Second), started: now}
}

func (p *progress) tick(e *scan.Entry) {
	if !p.enabled {
		return
	}
	p.entries++
	if e.Hashed {
		p.bytes += e.Size
	}
	if p.entries%512 != 0 {
		return
	}
	now := time.Now()
	if now.Before(p.next) {
		return
	}
	p.next = now.Add(time.Second)
	if p.terminal {
		line := []rune(fmt.Sprintf("  %s entries, %s hashed, %s  %s",
			humanize.Count(p.entries), humanize.Bytes(p.bytes), humanize.Duration(now.Sub(p.started)), e.Path))
		if len(line) > progressWidth {
			line = line[:progressWidth]
		}
		// Pad to the widest line drawn so far, or the tail of a longer
		// previous one would stay on screen.
		p.width = max(p.width, len(line))
		fmt.Fprintf(stderr, "\r%-*s", p.width, string(line))
		return
	}
	fmt.Fprintf(stderr, "  %s entries, %s hashed, %s\n",
		humanize.Count(p.entries), humanize.Bytes(p.bytes), humanize.Duration(now.Sub(p.started)))
}

func (p *progress) done() {
	if p.enabled && p.terminal && p.width > 0 {
		fmt.Fprintf(stderr, "\r%*s\r", p.width, "")
	}
}
