# osfp — OS FingerPrint

`osfp` records a fingerprint of a freshly installed operating system, then
reports how a live system has drifted from it: files and directories added,
removed, modified in content, or modified in ownership and permissions.

It is a single static binary with no runtime dependency, built without cgo so
that it runs on Linux, the BSDs, Solaris/illumos, macOS and AIX alike.

## Commands

| Command | What it does |
|---|---|
| `osfp baseline` | record a fingerprint of the current filesystem |
| `osfp compare` | report how the filesystem drifted from a fingerprint |
| `osfp info` | print what a fingerprint holds: system, scope, counts, digest |
| `osfp verify` | recompute the internal digest, to detect a damaged transfer |
| `osfp version` | version, build and the fingerprint key of this system |

`info`, `verify` and `version` read no filesystem and need no privileges.

The manual pages, `osfp(1)`, `osfp-baseline(1)` and `osfp-compare(1)`, are in
`docs/man/` and ship with the release binaries; `man ./docs/man/osfp.1` reads
one without installing it. Changes are recorded in `CHANGELOG.md`.

## Usage

```sh
# Record a fingerprint of a freshly installed system.
# Written to <os-key>.osfp in the current directory unless -o says otherwise.
sudo osfp baseline

# Narrow the scope, and drop what churns by design.
sudo osfp baseline --root /usr --exclude /var/lib/docker --exclude-from excludes.txt

# Months later, report how the system drifted from it.
sudo osfp compare -b linux-debian-12-amd64.osfp

# Either command, with a progress line while it scans.
sudo osfp compare -b linux-debian-12-amd64.osfp -v

# Only content changes, ignoring what churns by design.
sudo osfp compare -b linux-debian-12-amd64.osfp --show "~F,!T" --ignore-from ignore.txt

# What a fingerprint holds, and whether it survived the trip.
osfp info -b linux-debian-12-amd64.osfp
osfp verify -b linux-debian-12-amd64.osfp

# One JSON object per line, for a large report or for further processing.
sudo osfp compare -b linux-debian-12-amd64.osfp --format json -o drift.jsonl
sudo jq -r 'select(.record=="change" and .op=="~F") | "\(.path) \(.new.mtime)"' drift.jsonl
```

`baseline` and `compare` require root and exit with code `3` otherwise. The
escape hatch, `--allow-non-root`, marks the fingerprint `UNPRIVILEGED`; such a
fingerprint can never be compared with a privileged one, because the difference
would show up as thousands of spurious deletions.

The fingerprint is written to a temporary file and renamed into place once it
is complete and synced, so a file under the final name is always whole. It is
created mode `0600`: it lists every path on the system. So is a report written
with `compare -o`, for the same reason.

`-v` (or `--verbose`) reports progress on standard error, at most once a
second: entries seen, bytes hashed, time elapsed. On a terminal the line is
redrawn in place and erased before the report is printed; redirected, each
update becomes a line of its own. Standard output is untouched, so `-v` can be
combined with a report piped elsewhere.

`compare` reuses the perimeter recorded in the fingerprint — the same root, the
same exclusions, the same mount-point rule — so that the two scans are
comparable at all. A directory that is absent from the fingerprint is reported
once, with counters, and its contents are never listed or hashed;
`--new-dir-mode` changes that to `deep` or `skip`.

The modification time is recorded but never compared. A `touch`, a restore from
backup, a `cp` without `-p` or an identical package reinstall produce no line at
all. Only an entry that was never hashed, because of `--max-file-size`, falls
back to size and date — and it is reported as a metadata change, never as a
content change, because no content was verified.

### Change codes

```
+D / -D / ~D   directory added / deleted / mode or ownership changed
+F / -F        path added / deleted
~F             file content changed (SHA-256)
%F             same content, different mode, uid or gid
!T             type changed, e.g. a file became a symlink
~L             symlink retargeted
?E             could not be read
```

`--show` restricts the report to some of them; `--ignore-from` drops rules
after classification, so the summary can still say how many differences were
hidden.

### Report formats

The default text report groups changes by category, one section per code, and
ends with a summary. Changes under `/var/log`, `/var/cache` and `/var/spool`,
plus the logs, audit trail and statistics of Solaris and illumos (`/var/adm`,
`/var/svc/log`, `/var/audit`, and their `/var/share` homes on Solaris 11),
are reported under their own heading rather than mixed with the rest: they are
expected churn, not findings. They are counted in the summary, which says how
many of them there are, but they never make `--fail-on-diff` exit with `1`: on
a running system a log grows between any two scans. Colour is used when
standard output is a terminal, and disabled by `--no-color` or by `NO_COLOR`.

`--format json` writes JSON Lines instead: a header object, one object per
change, then a summary object, whose `expected` field is the part of `total`
filed as expected noise. It streams, so it stays usable on a report of
hundreds of thousands of lines, and on standard output it can be piped to `jq`
while the scan runs; with `-o`, the file appears under its name only once
complete. The text report has to hold its changes until the end, because its
section headings carry a count.

The `old` and `new` objects of a JSON change carry everything the fingerprint
and the scan know about the entry, including the modification time. That is
where a date belongs: a named field, with no claim about its role. It is absent
from the text report because a date printed next to a change reads as the date
of that change, and the modification time is a declaration anyone can set.

The following are excluded by default and recorded in the fingerprint header:
`/proc`, `/sys`, `/dev`, `/tmp`, `/var/tmp`, `/run`, `/var/run`, `/media`,
`/mnt`, `/lost+found`, plus a per-OS list. `/home` and `/root` are **not**
excluded: what appears there after installation is what an audit is looking
for.

### Mount points

`--mounts` decides what happens at a mount point:

| Value | Behaviour |
|---|---|
| `local` (default) | descend into another local filesystem, stop at pseudo and network ones |
| `same` | stop at every mount point, whatever it holds |
| `all` | cross everything, network shares included |

The default is not the familiar one — `du`, `tar` and `rsync -x` all stop at
every mount point — and it is deliberate. On a stock FreeBSD ZFS install,
`/home`, `/var/log`, `/var/audit` and `/usr/src` are separate datasets; the
same is true of btrfs subvolumes and of many LVM layouts. Stopping at every
mount point would leave all of them out of the fingerprint, including the audit
trail, and would silently reverse the decision to keep `/home` in scope.

What stopping at mount points was really for — not hashing a four-terabyte
share mounted on `/srv` — is expressed directly by looking at the filesystem
type, which is what `local` does. Whatever is not crossed is named in the
summary, with its type: an audit report has to let you tell "nothing changed
here" from "nothing was looked at here".

AIX reports the type as a number, which `osfp` names from `/etc/vfs`; a
number that table does not know is treated as unidentified and not crossed,
and the summary says so. This path has never run on a real AIX system: see
below.

## Build

```sh
make build      # host binary
make lint test  # gofmt, go vet, tests
make race       # the tests under the race detector (needs cgo)
make fuzz       # every fuzz target, FUZZTIME=30s by default
make cross      # build every supported GOOS/GOARCH
make vet-all    # vet every supported GOOS/GOARCH, build tags included
make man-lint   # check the manual pages (needs mandoc)
make release    # release binaries, manual pages and SHA256SUMS in dist/
```

The build requires Go 1.23 or later. `CGO_ENABLED=0` is forced by the
`Makefile` and by CI. There are two external dependencies: `golang.org/x/sys`
for `uname(2)` and `statfs(2)`, and `github.com/klauspost/compress` for the
zstd used inside the fingerprint file.

The `Makefile` is a convenience, not the build: `go build ./cmd/osfp` produces
the binary and `go test ./...` runs the suite. It is written to avoid GNU make
extensions so that it also works under the BSD `make` the target systems ship
and the GNU make 3.81 that macOS still ships;
if it ever does not, those two commands always will.

## Detected systems

The fingerprint key identifies the system a fingerprint belongs to, and
`compare` refuses to cross two different keys:

```
linux-debian-12-amd64            freebsd-14.1-amd64
linux-opensuse-leap-15.6-amd64   openbsd-7.5-amd64
linux-arch-amd64                 solaris-11.4-sparc64
darwin-macos-14.5-arm64          illumos-omnios-r151046-amd64
aix-7.3-tl02-ppc64
```

Detection reads `/etc/os-release`, `/etc/release`, `SystemVersion.plist` and
`uname(2)` before it considers running a helper binary, so it still works on a
system that is only half alive. Run `osfp version` to see the key for the
current machine.

## Supported targets

`linux/amd64`, `linux/arm64`, `linux/386`, `linux/arm`, `freebsd/amd64`,
`freebsd/arm64`, `openbsd/amd64`, `netbsd/amd64`, `solaris/amd64`,
`illumos/amd64`, `darwin/amd64`, `darwin/arm64`, `aix/ppc64`.

`aix/ppc64` is built and vetted, but it has never been run: no AIX machine
was available for the manual pass. Treat it as untested.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | success, or no differences found |
| `1` | differences found (`compare --fail-on-diff`), expected noise aside |
| `2` | runtime error, or invalid invocation |
| `3` | insufficient privileges, or mismatched scan privilege levels |
| `130` | interrupted (`SIGINT` / `SIGTERM`) |

`baseline` and `compare` require root: a scan run as an unprivileged user
cannot read large parts of the filesystem and would produce a fingerprint that
looks complete but is not.

## Portability

Every target is built and vetted on each change; the test suite runs on Linux
and macOS, and against real Debian, Ubuntu, Alpine, Rocky and Fedora container
images. The targets with no runner — the BSDs, Solaris and illumos — are
exercised by hand before a release, following `docs/PORTING.md`; AIX is the
exception, built and vetted but never run.

## Licence

MIT — see [LICENSE](LICENSE).

osfp links two third-party modules and the Go standard library, all under
permissive licences. Because the binary is static, their copyright notices are
compiled into every copy, so [THIRD-PARTY-LICENSES](THIRD-PARTY-LICENSES)
travels with each release and lists them verbatim:

| Component | Licence |
|---|---|
| The Go standard library and runtime | BSD-3-Clause |
| `golang.org/x/sys/unix` | BSD-3-Clause, with a patent grant |
| `github.com/klauspost/compress` | BSD-3-Clause, portions Apache-2.0 |
| `…/internal/snapref` | BSD-3-Clause (Snappy-Go) |
| `…/zstd/internal/xxhash` | MIT |
