package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"osfp/internal/osdetect"
)

func TestLookupCoversEveryCommand(t *testing.T) {
	for _, c := range commands {
		if got := lookup(c.name); got != c {
			t.Errorf("lookup(%q) did not return the registered command", c.name)
		}
		if c.run == nil {
			t.Errorf("command %q has no run function", c.name)
		}
		if !strings.HasPrefix(c.usage, c.name) {
			t.Errorf("command %q: usage line %q does not start with the command name", c.name, c.usage)
		}
	}
	if lookup("nope") != nil {
		t.Error("lookup returned a command for an unknown name")
	}
}

func TestDispatchExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no arguments", nil, exitError},
		{"unknown command", []string{"frobnicate"}, exitError},
		{"help", []string{"help"}, exitOK},
		{"help for a command", []string{"help", "compare"}, exitOK},
		{"help for an unknown command", []string{"help", "frobnicate"}, exitError},
		{"version", []string{"version"}, exitOK},
		{"version short", []string{"version", "--short"}, exitOK},
		{"version with a stray argument", []string{"version", "stray"}, exitError},
		{"version with an unknown flag", []string{"version", "--nope"}, exitError},
		{"unimplemented command", []string{"info"}, exitError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := dispatch(context.Background(), tt.args); got != tt.want {
				t.Errorf("dispatch(%q) = %d, want %d", tt.args, got, tt.want)
			}
		})
	}
}

func TestExitCodesAreDistinct(t *testing.T) {
	seen := map[int]string{}
	for name, code := range map[string]int{
		"exitOK":          exitOK,
		"exitDiff":        exitDiff,
		"exitError":       exitError,
		"exitPrivilege":   exitPrivilege,
		"exitInterrupted": exitInterrupted,
	} {
		if other, dup := seen[code]; dup {
			t.Errorf("%s and %s share exit code %d", name, other, code)
		}
		seen[code] = name
	}
}

func TestBuildStampsAlwaysReportAVersion(t *testing.T) {
	if v, _ := buildStamps(); v == "" {
		t.Error("buildStamps returned an empty version")
	}
}

// captureStdout redirects the writer the commands print to, and restores it
// when the test ends.
func captureStdout(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	saved := stdout
	stdout = &buf
	t.Cleanup(func() { stdout = saved })
	return &buf
}

// TestVersionReportsTheFingerprintKey locks the deliverable of the OS
// detection phase: the key osfp would use for a fingerprint must be visible
// without running a scan.
func TestVersionReportsTheFingerprintKey(t *testing.T) {
	out := captureStdout(t)
	if got := dispatch(context.Background(), []string{"version"}); got != exitOK {
		t.Fatalf("dispatch(version) = %d, want %d", got, exitOK)
	}

	info, err := osdetect.Detect()
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if want := "system:  " + info.Key() + "\n"; !strings.Contains(out.String(), want) {
		t.Errorf("version output does not contain %q:\n%s", want, out)
	}
	for _, want := range []string{"osfp ", "go:      ", "target:  ", "cgo:     "} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("version output does not contain %q:\n%s", want, out)
		}
	}
}

func TestVersionShortPrintsOnlyTheVersion(t *testing.T) {
	out := captureStdout(t)
	if got := dispatch(context.Background(), []string{"version", "--short"}); got != exitOK {
		t.Fatalf("dispatch(version --short) = %d, want %d", got, exitOK)
	}
	v, _ := buildStamps()
	if got, want := out.String(), v+"\n"; got != want {
		t.Errorf("version --short printed %q, want %q", got, want)
	}
}

// TestHelpListsTheOptions guards against a regression that is easy to miss:
// the flag set only exists inside a command's run function, so the help text
// has to reach it through the usage error.
func TestHelpListsTheOptions(t *testing.T) {
	out := captureStdout(t)
	if got := dispatch(context.Background(), []string{"help", "baseline"}); got != exitOK {
		t.Fatalf("help baseline exited %d", got)
	}
	for _, want := range []string{"usage: osfp baseline", "options:", "-allow-non-root", "-exclude-from", "-mounts"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("help output is missing %q:\n%s", want, out)
		}
	}
}

// captureStderr redirects the diagnostics writer for the duration of a test.
// Reading what a command did *not* print is how a spurious message is caught.
func captureStderr(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	saved := stderr
	stderr = &buf
	t.Cleanup(func() { stderr = saved })
	return &buf
}
