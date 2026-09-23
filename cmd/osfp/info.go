package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"osfp/internal/humanize"
	"osfp/internal/store"
)

// info and verify read a fingerprint and nothing else, so neither requires any
// privilege (§7.5): there is no filesystem to be unable to read.

func runInfo(_ context.Context, args []string) error {
	fs := newFlagSet("info")
	base := fs.String("b", "", "describe the fingerprint in `FILE` (required)")
	asJSON := fs.Bool("json", false, "print the metadata as JSON")
	if err := fs.Parse(args); err != nil {
		return usageErr(fs, err)
	}
	if fs.NArg() != 0 || *base == "" {
		return usageErr(fs, errUsage)
	}

	r, err := store.Open(*base)
	if err != nil {
		return err
	}
	defer r.Close()
	meta := r.Meta()

	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(meta)
	}

	size := fileSize(*base)
	fmt.Fprintf(stdout, "%s\n", *base)
	fmt.Fprintf(stdout, "  tool         %s %s\n", meta.Tool, meta.ToolVersion)
	fmt.Fprintf(stdout, "  created      %s\n", meta.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"))
	fmt.Fprintf(stdout, "  key          %s\n", meta.Key)
	if meta.System.Pretty != "" {
		fmt.Fprintf(stdout, "  system       %s\n", meta.System.Pretty)
	}
	if host := describeHost(meta); host != "" {
		fmt.Fprintf(stdout, "  host         %s\n", host)
	}

	// The privilege level is the first thing that decides whether this
	// fingerprint is usable as an audit baseline, so it is stated plainly.
	if meta.Privileged {
		fmt.Fprintf(stdout, "  privileged   yes\n")
	} else {
		fmt.Fprintf(stdout, "  privileged   no — UNPRIVILEGED (effective uid %d); incomplete, "+
			"and not comparable with a privileged scan\n", meta.EUID)
	}

	scope := []string{meta.Scan.Root}
	if meta.Scan.Mounts != "" {
		scope = append(scope, "mounts="+meta.Scan.Mounts)
	}
	scope = append(scope, fmt.Sprintf("max-depth %d", meta.Scan.MaxDepth))
	if meta.Scan.MaxFileSize > 0 {
		scope = append(scope, "max-file-size "+humanize.Bytes(meta.Scan.MaxFileSize))
	}
	scope = append(scope, fmt.Sprintf("%d %s", meta.Scan.Jobs, humanize.Plural(int64(meta.Scan.Jobs), "job", "jobs")))
	fmt.Fprintf(stdout, "  scope        %s\n", strings.Join(scope, " · "))

	fmt.Fprintf(stdout, "  entries      %s", humanize.Count(meta.Entries))
	if meta.Errors > 0 {
		fmt.Fprintf(stdout, " (%s unreadable)", humanize.Count(meta.Errors))
	}
	fmt.Fprintf(stdout, " in %s %s\n", humanize.Count(meta.Blocks), humanize.Plural(meta.Blocks, "block", "blocks"))
	fmt.Fprintf(stdout, "  size         %s (%.1f bytes per entry)\n",
		humanize.Bytes(size), perEntry(size, meta.Entries))
	fmt.Fprintf(stdout, "  digest       %x\n", r.Digest())

	fmt.Fprintf(stdout, "  exclusions   %d\n", len(meta.Exclusions))
	for _, p := range meta.Exclusions {
		fmt.Fprintf(stdout, "                 %s\n", p)
	}
	return nil
}

func runVerify(_ context.Context, args []string) error {
	fs := newFlagSet("verify")
	base := fs.String("b", "", "check the fingerprint in `FILE` (required)")
	quiet := fs.Bool("quiet", false, "print nothing; report the result through the exit code")
	if err := fs.Parse(args); err != nil {
		return usageErr(fs, err)
	}
	if fs.NArg() != 0 || *base == "" {
		return usageErr(fs, errUsage)
	}

	r, err := store.Open(*base)
	if err != nil {
		return err
	}
	defer r.Close()

	// Verify recomputes the digest over the whole file, which is what detects
	// a truncated transfer or a damaged medium — the need the plan decided a
	// signature would not address any better (§16, decision 4).
	if err := r.Verify(); err != nil {
		return fmt.Errorf("%s: %w", *base, err)
	}
	if !*quiet {
		fmt.Fprintf(stdout, "%s: OK\n", *base)
		fmt.Fprintf(stdout, "  sha256   %x\n", r.Digest())
		fmt.Fprintf(stdout, "  entries  %s\n", humanize.Count(r.Meta().Entries))
	}
	return nil
}

// describeHost joins whatever is known about the machine the fingerprint was
// taken on, skipping what the detection could not establish.
func describeHost(meta *store.Meta) string {
	var parts []string
	if h := meta.System.Hostname; h != "" {
		parts = append(parts, h)
	}
	if k := meta.System.Kernel; k != "" {
		parts = append(parts, "kernel "+k)
	}
	return strings.Join(parts, ", ")
}

func perEntry(size, entries int64) float64 {
	if entries == 0 {
		return 0
	}
	return float64(size) / float64(entries)
}
