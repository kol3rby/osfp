package main

import (
	"context"
	"fmt"
	"runtime"
	"runtime/debug"

	"osfp/internal/osdetect"
)

// Build information. version and commit are set at link time by the Makefile:
//
//	-ldflags "-X main.version=1.0.0 -X main.commit=abcdef1"
//
// When they are empty — a plain "go build" or "go run" — they fall back to the
// VCS stamps the toolchain embeds on its own.
var (
	version = ""
	commit  = ""
)

const unknownVersion = "devel"

func runVersion(_ context.Context, args []string) error {
	fs := newFlagSet("version")
	short := fs.Bool("short", false, "print only the version number")
	if err := fs.Parse(args); err != nil {
		return usageErr(fs, err)
	}
	if fs.NArg() != 0 {
		return usageErr(fs, errUsage)
	}

	v, c := buildStamps()
	if *short {
		fmt.Fprintln(stdout, v)
		return nil
	}

	fmt.Fprintf(stdout, "osfp %s\n", v)
	if c != "" {
		fmt.Fprintf(stdout, "commit:  %s\n", c)
	}
	fmt.Fprintf(stdout, "go:      %s\n", runtime.Version())
	fmt.Fprintf(stdout, "target:  %s/%s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(stdout, "cgo:     %s\n", boolString(cgoEnabled))

	// The fingerprint key is what names the fingerprint file and what compare
	// refuses to cross, so "osfp version" is the place to check it before
	// trusting a baseline.
	info, err := osdetect.Detect()
	fmt.Fprintf(stdout, "system:  %s\n", info.Key())
	switch {
	case err != nil:
		fmt.Fprintf(stdout, "         detection incomplete: %v\n", err)
	case info.Pretty != "":
		fmt.Fprintf(stdout, "         %s (from %s)\n", info.Pretty, info.Source)
	}
	return nil
}

// buildStamps resolves the version and commit to report, preferring the values
// injected at link time.
func buildStamps() (ver, rev string) {
	ver, rev = version, commit
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if ver == "" {
			ver = unknownVersion
		}
		return ver, rev
	}
	if ver == "" {
		ver = info.Main.Version
		if ver == "" || ver == "(devel)" {
			ver = unknownVersion
		}
	}
	if rev == "" {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				rev = s.Value
			case "vcs.modified":
				if s.Value == "true" && rev != "" {
					rev += "-dirty"
				}
			}
		}
	}
	return ver, rev
}

func boolString(b bool) string {
	if b {
		return "enabled"
	}
	return "disabled"
}
