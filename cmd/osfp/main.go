// Command osfp fingerprints the filesystem of a freshly installed operating
// system and reports how a live system has drifted from that fingerprint.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"text/tabwriter"
)

// Exit codes. They are part of the tool's contract with calling scripts and
// must not be reused for anything else.
const (
	exitOK          = 0   // no differences, or a command that only reports
	exitDiff        = 1   // differences found (compare, with --fail-on-diff)
	exitError       = 2   // runtime failure
	exitPrivilege   = 3   // insufficient privileges, or mismatched scan privileges
	exitInterrupted = 130 // SIGINT / SIGTERM
)

// errUsage makes a command fail with its own usage text instead of an error
// message.
var errUsage = errors.New("usage")

// usageError carries the command.s own flag set alongside a usage failure, so
// that the options can be listed. A command defines its flags inside its run
// function, which is where they belong; this is how they reach the printer.
type usageError struct {
	fs  *flag.FlagSet
	err error
}

func (e usageError) Error() string { return e.err.Error() }
func (e usageError) Unwrap() error { return e.err }

// usageErr tags a parsing failure with the flag set that produced it.
func usageErr(fs *flag.FlagSet, err error) error { return usageError{fs: fs, err: err} }

// printUsage writes the invocation line and, when the error carries a flag
// set, the options with their defaults.
func printUsage(w io.Writer, cmd *command, err error) {
	fmt.Fprintf(w, "usage: osfp %s\n", cmd.usage)
	var ue usageError
	if errors.As(err, &ue) && ue.fs != nil {
		fmt.Fprintf(w, "\n%s\n\noptions:\n", cmd.summary)
		ue.fs.SetOutput(w)
		ue.fs.PrintDefaults()
	}
}

// command is one osfp subcommand. run receives the arguments that follow the
// subcommand name and returns the process exit code.
type command struct {
	name    string
	usage   string
	summary string
	run     func(ctx context.Context, args []string) error
}

// commands is the subcommand table; it also drives the top-level usage text.
var commands = []*command{
	{
		name:    "baseline",
		usage:   "baseline [-o FILE] [--exclude PATH]... [--root DIR] [--jobs N]",
		summary: "record a fingerprint of the current filesystem",
		run:     runBaseline,
	},
	{
		name:    "compare",
		usage:   "compare -b FINGERPRINT [--show CODES] [--new-dir-mode MODE] [--ignore-from FILE]",
		summary: "report how the filesystem drifted from a fingerprint",
		run:     runCompare,
	},
	{
		name:    "info",
		usage:   "info -b FINGERPRINT",
		summary: "print the metadata of a fingerprint",
		run:     runInfo,
	},
	{
		name:    "verify",
		usage:   "verify -b FINGERPRINT",
		summary: "check the internal checksum of a fingerprint",
		run:     runVerify,
	},
	{
		name:    "version",
		usage:   "version [--short]",
		summary: "print version and build information",
		run:     runVersion,
	},
}

// stdout and stderr are the destinations of everything the tool prints: the
// result on one, diagnostics on the other. They are variables so that tests
// can read what a command actually produced — including what it did *not*
// produce, which is how a spurious message gets caught.
var (
	stdout io.Writer = os.Stdout
	stderr io.Writer = os.Stderr
)

func main() {
	// A scan can run for minutes; an interrupt must unwind it cleanly, remove
	// the partial file and report exit code 130 rather than leave a truncated
	// fingerprint behind.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(dispatch(ctx, os.Args[1:]))
}

// dispatch routes to a subcommand. It is separate from main so that tests can
// exercise the router without spawning a process.
func dispatch(ctx context.Context, args []string) int {
	if len(args) == 0 {
		usage(stderr)
		return exitError
	}

	name := args[0]
	switch name {
	case "-h", "-help", "--help", "help":
		return help(ctx, args[1:])
	case "-V", "--version":
		name = "version"
		args = args[:1]
	}

	cmd := lookup(name)
	if cmd == nil {
		fmt.Fprintf(stderr, "osfp: unknown command %q\n", name)
		usage(stderr)
		return exitError
	}

	err := cmd.run(ctx, args[1:])
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
		printUsage(stderr, cmd, err)
		return exitError
	default:
		var ec codedError
		if errors.As(err, &ec) {
			if ec.err != nil {
				fmt.Fprintf(stderr, "osfp %s: %v\n", cmd.name, ec.err)
			}
			return ec.code
		}
		fmt.Fprintf(stderr, "osfp %s: %v\n", cmd.name, err)
		return exitError
	}
}

// codedError carries an exit code alongside an error, for the cases where the
// contract demands something other than exitError.
//
// Its error may be nil, and that is not an oversight: "compare --fail-on-diff
// found differences" is exit code 1 with nothing to report. It is the outcome
// the flag exists to produce, not a failure, so it must not print anything.
type codedError struct {
	code int
	err  error
}

func (e codedError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit status %d", e.code)
	}
	return e.err.Error()
}

func (e codedError) Unwrap() error { return e.err }

// withExit tags err with the exit code the caller must return. A nil err means
// "use this exit code and say nothing".
func withExit(code int, err error) error { return codedError{code: code, err: err} }

func lookup(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

// help implements "osfp help [command]".
func help(ctx context.Context, args []string) int {
	if len(args) == 0 {
		usage(stdout)
		return exitOK
	}
	cmd := lookup(args[0])
	if cmd == nil {
		fmt.Fprintf(stderr, "osfp: unknown command %q\n", args[0])
		return exitError
	}
	// The command itself is asked to describe its flags: -h makes its own
	// flag set surface through the error, which is the only place it exists.
	printUsage(stdout, cmd, cmd.run(ctx, []string{"-h"}))
	return exitOK
}

func usage(w io.Writer) {
	fmt.Fprint(w, "osfp fingerprints a filesystem and reports how it drifted.\n\nusage: osfp <command> [options]\n\ncommands:\n")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, c := range commands {
		fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
	}
	tw.Flush()
	fmt.Fprint(w, "\nrun \"osfp help <command>\" for the options of one command.\n")
}

// newFlagSet returns a flag set that reports errors through dispatch rather
// than printing a second, redundant usage block of its own. It takes the
// command name rather than the command itself: a subcommand must not reach
// back into the commands table, of which it is itself an entry.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}
