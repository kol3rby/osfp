package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"osfp/internal/diff"
	"osfp/internal/exclude"
	"osfp/internal/osdetect"
	"osfp/internal/report"
	"osfp/internal/scan"
	"osfp/internal/store"
)

// newDirMode decides what happens below a directory that is absent from the
// fingerprint (§1.3).
type newDirMode string

const (
	newDirSummary newDirMode = "summary" // report the directory plus counters
	newDirDeep    newDirMode = "deep"    // list and hash everything below it
	newDirSkip    newDirMode = "skip"    // report the directory and nothing else
)

func runCompare(ctx context.Context, args []string) error {
	fs := newFlagSet("compare")
	base := fs.String("b", "", "compare against the fingerprint in `FILE` (required)")
	format := fs.String("format", "text", "report `FORMAT`: text or json")
	out := fs.String("o", "", "write the report to `FILE` instead of standard output")
	show := fs.String("show", "", "report only these change `CODES`, comma separated (default: all)")
	newDirs := fs.String("new-dir-mode", string(newDirSummary), "what to report below an added directory, `MODE` being summary, deep or skip")
	ignoreFrom := fs.String("ignore-from", "", "read ignore rules from `FILE`")
	var excludes stringSlice
	fs.Var(&excludes, "exclude", "exclude a `PATH` on top of the fingerprint's own exclusions (repeatable)")
	jobs := fs.Int("jobs", 0, "use `N` hashing workers (default: min(NumCPU, 8))")
	noColor := fs.Bool("no-color", false, "never colourise the text report")
	allowMismatch := fs.Bool("allow-os-mismatch", false, "compare even if the system is not the one the fingerprint describes")
	allowNonRoot := fs.Bool("allow-non-root", false, "scan without root privileges")
	failOnDiff := fs.Bool("fail-on-diff", false, "exit with code 1 when differences are found")
	verbose := false
	fs.BoolVar(&verbose, "v", false, "report progress while scanning")
	fs.BoolVar(&verbose, "verbose", false, "report progress while scanning")
	if err := fs.Parse(args); err != nil {
		return usageErr(fs, err)
	}
	if fs.NArg() != 0 || *base == "" {
		return usageErr(fs, errUsage)
	}
	mode := newDirMode(*newDirs)
	switch mode {
	case newDirSummary, newDirDeep, newDirSkip:
	default:
		return fmt.Errorf("--new-dir-mode must be summary, deep or skip, not %q", *newDirs)
	}

	// Step 0: privileges, before anything is opened.
	if err := requireRoot(*allowNonRoot); err != nil {
		return err
	}

	reader, err := store.Open(*base)
	if err != nil {
		return err
	}
	defer reader.Close()
	if err := reader.Verify(); err != nil {
		return fmt.Errorf("%s: %w", *base, err)
	}
	meta := reader.Meta()

	// The mount policy comes from the fingerprint, like the rest of the
	// perimeter: comparing a scan that crossed mount points with one that did
	// not would report an entire filesystem as deleted (§6.2).
	mountPolicy, err := scan.ParseMountPolicy(meta.Scan.Mounts)
	if err != nil {
		return fmt.Errorf("%s: %w", *base, err)
	}

	info, err := osdetect.Detect()
	if err != nil && !*allowMismatch {
		return err
	}
	if err := checkComparable(meta, info, *allowMismatch); err != nil {
		return err
	}

	// The report file, when there is one, is created before the exclusion set
	// so that the scan can be told to ignore it and its temporary twin.
	dest, autoExclude, err := openReportFile(*out)
	if err != nil {
		return err
	}
	defer dest.abort()

	// Step 3: the set of directories the fingerprint knows about. It answers
	// in O(1), during the walk, the question that makes the pruning possible:
	// is this a directory we have ever seen?
	dirs, err := loadDirs(reader)
	if err != nil {
		return err
	}

	// Step 4: the perimeter is the fingerprint's, not the command line's, so
	// that the two scans are comparable at all (§6.2).
	set, err := exclude.New(exclude.Options{
		GOOS:       meta.System.OS,
		Root:       meta.Scan.Root,
		NoDefaults: true,
		Patterns:   append(append([]string{}, meta.Exclusions...), []string(excludes)...),
		Auto:       append(exclude.SelfPaths(), autoExclude...),
	})
	if err != nil {
		return err
	}
	// The exclusion set carries the volatile list, which is what lets the text
	// report group expected churn under its own heading.
	reporter, err := report.New(*format, dest.w, report.Options{
		Color:    useColor(*format, *out, *noColor),
		Volatile: set.Volatile,
	})
	if err != nil {
		return err
	}

	opts := scan.Options{
		Root:        meta.Scan.Root,
		Exclude:     set,
		Mounts:      mountPolicy,
		MaxDepth:    meta.Scan.MaxDepth,
		MaxFileSize: meta.Scan.MaxFileSize,
		Jobs:        *jobs,
		Descend: func(e *scan.Entry) bool {
			if _, known := dirs[e.Path]; known {
				return true
			}
			return mode == newDirDeep
		},
	}

	joinOpts := diff.Options{}
	if *show != "" {
		if joinOpts.Show, err = diff.ParseOps(*show); err != nil {
			return err
		}
	}
	if *ignoreFrom != "" {
		if joinOpts.Ignore, err = diff.LoadIgnore(*ignoreFrom); err != nil {
			return fmt.Errorf("--ignore-from: %w", err)
		}
	}
	if mode == newDirSummary {
		joinOpts.Summarize = func(path string) *diff.DirSummary {
			return summarizeDir(ctx, opts, path)
		}
	}

	// The scan root is checked before a single line is written: a report whose
	// header is printed and whose body then fails is worse than no report.
	if st, err := os.Stat(meta.Scan.Root); err != nil {
		return fmt.Errorf("the fingerprint covers %s, which cannot be read now: %w", meta.Scan.Root, err)
	} else if !st.IsDir() {
		return fmt.Errorf("the fingerprint covers %s, which is no longer a directory", meta.Scan.Root)
	}

	if err := reporter.Header(report.Header{
		Tool:            "osfp",
		ToolVersion:     toolVersion(),
		BaselinePath:    *base,
		Baseline:        meta,
		SystemKey:       info.Key(),
		SystemName:      info.Pretty,
		ScannedAt:       time.Now().UTC(),
		Privileged:      privileged(),
		ExtraExclusions: []string(excludes),
		IgnoreRules:     joinOpts.Ignore.Rules(),
		NewDirMode:      string(mode),
	}); err != nil {
		return err
	}

	// Expected noise is reported like any other change, but counted apart:
	// a log that grew between two scans must not make --fail-on-diff fail on
	// every running system.
	var expected int64
	joiner, err := diff.NewJoiner(reader.Cursor(), joinOpts, func(c *diff.Change) error {
		if set.Volatile(c.Path) {
			expected++
		}
		return reporter.Change(c)
	})
	if err != nil {
		return err
	}
	progress := newProgress(verbose)
	stats, err := scan.Walk(ctx, opts, func(e *scan.Entry) error {
		progress.tick(e)
		return joiner.Feed(e)
	})
	if err != nil {
		if ctx.Err() != nil {
			return withExit(exitInterrupted, errors.New("interrupted; the report is incomplete"))
		}
		return err
	}
	diffStats, err := joiner.Finish()
	if err != nil {
		return err
	}
	progress.done()

	if err := reporter.Close(report.Summary{Diff: diffStats, Scan: stats, Expected: expected}); err != nil {
		return err
	}
	if err := dest.commit(); err != nil {
		return err
	}

	if diffStats.Total() > expected && *failOnDiff {
		return withExit(exitDiff, nil)
	}
	return nil
}

// reportDest is either standard output or a file written atomically.
type reportDest struct {
	w    io.Writer
	file *atomicFile
}

// openReportFile returns where the report goes, plus the paths the scan must
// exclude so that it does not fingerprint the report it is producing.
func openReportFile(path string) (*reportDest, []string, error) {
	if path == "" {
		return &reportDest{w: stdout}, nil, nil
	}
	f, err := createAtomic(path)
	if err != nil {
		return nil, nil, err
	}
	return &reportDest{w: f.Writer(), file: f}, f.Paths(), nil
}

func (d *reportDest) commit() error {
	if d.file == nil {
		return nil
	}
	return d.file.Commit()
}

func (d *reportDest) abort() {
	if d.file != nil {
		d.file.Abort()
	}
}

// useColor decides whether the text report is colourised: only for the text
// format, only on a terminal, and never when NO_COLOR is set.
func useColor(format, out string, noColor bool) bool {
	if noColor || format == "json" || out != "" {
		return false
	}
	if _, set := os.LookupEnv("NO_COLOR"); set {
		return false
	}
	st, err := os.Stdout.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func toolVersion() string {
	v, _ := buildStamps()
	return v
}

// checkComparable refuses the two comparisons that would produce a report full
// of differences that are not differences at all.
func checkComparable(meta *store.Meta, info *osdetect.Info, allowMismatch bool) error {
	if key := info.Key(); key != meta.Key && !allowMismatch {
		return fmt.Errorf("this system is %s but the fingerprint describes %s; "+
			"comparing them would report most of the filesystem as changed\n"+
			"       pass --allow-os-mismatch if that is really what you want", key, meta.Key)
	}
	// A privileged fingerprint against an unprivileged scan turns every
	// unreadable path into a deletion. This check is what makes
	// --allow-non-root safe to offer at all.
	if meta.Privileged != privileged() {
		return withExit(exitPrivilege, fmt.Errorf(
			"the fingerprint was taken %s but this scan is %s; the comparison would "+
				"report thousands of spurious deletions",
			privilegeWord(meta.Privileged), privilegeWord(privileged())))
	}
	return nil
}

func privilegeWord(p bool) string {
	if p {
		return "as root"
	}
	return "unprivileged"
}

// loadDirs reads the fingerprint once and keeps every directory path.
func loadDirs(r *store.Reader) (map[string]struct{}, error) {
	dirs := make(map[string]struct{}, 1+r.Meta().Entries/8)
	err := r.Iterate(func(e *scan.Entry) error {
		if e.IsDir() {
			dirs[e.Path] = struct{}{}
		}
		return nil
	})
	return dirs, err
}

// summarizeDir counts what sits under an added directory without hashing a
// single byte of it — the point of --new-dir-mode=summary.
func summarizeDir(ctx context.Context, base scan.Options, path string) *diff.DirSummary {
	sub := base
	sub.Root = path
	sub.NoHash = true
	sub.Descend = nil

	var s diff.DirSummary
	_, err := scan.Walk(ctx, sub, func(e *scan.Entry) error {
		switch {
		case e.Type == scan.TypeDir && e.Path != path:
			s.Dirs++
		case e.Type == scan.TypeFile:
			s.Files++
			s.Bytes += e.Size
		}
		return nil
	})
	if err != nil {
		return nil
	}
	return &s
}
