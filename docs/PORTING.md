# Porting checklist

`osfp` targets thirteen GOOS/GOARCH pairs. Continuous integration builds and
vets every one of them, and runs the test suite on the two operating systems
GitHub offers natively. The rest has to be exercised by hand before a release,
and this file is that procedure.

## What CI already covers

| Check | Where |
|---|---|
| `gofmt`, `go vet`, unit tests, race detector | Linux and macOS runners |
| Real distributions, end to end | Debian 12 and trixie, Ubuntu 24.04, Alpine 3.20, Rocky 9, Fedora 40 containers |
| JSON Lines report read back with `jq` | Linux runner |
| Fuzzing of the `.osfp` decoders | Linux runner |
| Build **and vet** for all thirteen targets | Linux runner, cross-compiled |

Cross-compiling proves the code compiles. It does not prove that `statfs`
returns what this code expects, that `uname` fills the fields it reads, or that
a fingerprint taken on one release can be compared on the next. That is what
the manual pass is for.

## What has to be done by hand

The targets with no runner: FreeBSD, OpenBSD, NetBSD, Solaris, illumos and AIX.
A virtual machine or a jail is enough; none of the steps needs more than a few
hundred megabytes of filesystem.

### Procedure, per platform

Nothing is built on the target. `osfp` is a static binary with no runtime
dependency, so the machine under test needs neither Go nor make — that is the
whole point of `CGO_ENABLED=0`, and testing the binary you will actually ship
is better than testing one rebuilt on the spot.

**On a machine that has Go:**

```sh
make release                              # all thirteen targets into dist/
scp dist/osfp-*-freebsd-amd64 target:/tmp/osfp
```

Or, for one target without the Makefile:

```sh
CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64 go build -o osfp-freebsd ./cmd/osfp
```

**On the target, as root:**

```sh
chmod +x /tmp/osfp
/tmp/osfp version                         # the key must name the real system
/tmp/osfp baseline -o /tmp/base.osfp -v
/tmp/osfp info -b /tmp/base.osfp
/tmp/osfp verify -b /tmp/base.osfp
/tmp/osfp compare -b /tmp/base.osfp -v    # must be quiet, or close to it

mkdir -p /opt/planted && echo payload > /opt/planted/file
chmod 0755 /etc/motd
/tmp/osfp compare -b /tmp/base.osfp --fail-on-diff ; echo "exit $?"
```

### If you do want to build on the target

You need Go, and you do not need this repository's `Makefile`:

```sh
pkg install go          # FreeBSD; pkg_add go on OpenBSD, pkgin install go on NetBSD
go build ./cmd/osfp     # this is the entire build
go test ./...           # and this is the entire test suite
```

The `Makefile` is written to avoid GNU make extensions, but it is a developer
convenience, not part of the build. If it misbehaves under a BSD `make`, use
the two commands above, or install GNU make (`pkg install gmake`) and run
`gmake`. Report the misbehaviour: a Makefile that only works under GNU make in
a project whose selling point is portability is a defect, not a fact of life.

### What to look at, and why

1. **The fingerprint key** (`osfp version`). Each platform reads a different
   source: `/etc/release` on Solaris and illumos, `uname(2)` on the BSDs and
   AIX, `oslevel -s` for the AIX technology level. A wrong key is not fatal —
   `--os-id` overrides it — but it means the parser needs a fixture.
2. **The filesystem types.** This needs a separate run. The built-in
   exclusions already cover `/dev`, `/proc`, `/sys` and `/tmp` by name, so the
   walk never reaches them unless `--no-default-excludes` is given, and the
   type is only asked for when the walk *stops* at a mount point:
   `--mounts=all` crosses without asking, so it can never show anything.
   `--mounts=same` stops at every mount point and names each one:

   ```sh
   /tmp/osfp baseline -o /tmp/probe.osfp --force \
       --no-default-excludes --mounts=same --max-depth 3
   ```

   The summary then prints one line per mount point, for instance
   `mount    pseudo filesystem not crossed: /dev (devfs)`. On FreeBSD expect
   `devfs`, `procfs` if it is mounted, and `zfs` for every dataset. On Solaris
   expect `dev` on `/dev`, `devfs` on `/devices`, `proc`, `tmpfs`, `autofs` on
   `/home`, `/net` and `/nfs4`, and `zfs` for the datasets, `/system` among
   them — which is why `ctfs` and `objfs`, mounted below it, never show up.
   Neither do `mntfs` and `sharefs`: they are mounted on files, `/etc/mnttab`
   and `/etc/dfs/sharetab`, and the type is only asked for at a directory.
   Those two files are hashed like any other. On illumos (OmniOS) `/system`
   is an ordinary directory, so `ctfs` and `objfs` do show up, along with
   `bootfs` on `/system/boot` and `tmpfs` on `/etc/svc/volatile`; `/home`,
   `/usr` and `/var` are datasets. On OpenBSD `/dev` is an ordinary
   directory of the root filesystem and there is no procfs, so expect only
   `ffs` for the separate partitions (`/home`, `/usr`, `/var`…), and `mfs` if
   one is configured. On AIX the type is a number named from `/etc/vfs`:
   expect `jfs2` for `/usr`, `/var`, `/opt` and `/home`, `procfs` on `/proc`,
   and `ahafs` on `/aha` if the event infrastructure is mounted. A line that
   says `unidentified filesystem (vfs N)` is a number `/etc/vfs` does not name.

   If the lines are there but the type names are empty or garbled, `statfs`
   is not returning what this platform's `fsTypeName` expects — that is a
   finding. If a type that is plainly a pseudo or network filesystem shows up
   as `local filesystem`, it is missing from the tables in
   `internal/scan/fstype.go`.

   Note what the *default* flags tell you: `--mounts=local` prints a line only
   for what it refuses to enter, so no line means the hard-coded exclusions
   already covered every pseudo filesystem mounted on the machine. The
   detection exists for the mount nobody listed — an NFS share under `/srv`,
   a tmpfs under `/var/lib` — not for `/proc`.
3. **Access times.** `O_NOATIME` exists only on Linux. Elsewhere the scan does
   update access times; check that a second `baseline` still produces the same
   entry count, i.e. that the scan did not disturb what it was measuring in a
   way that shows up as drift.
4. **Fingerprint size.** `osfp info` prints bytes per entry. It should sit near
   45; a much larger figure means the front-coding is not working on that
   platform's path layout and is worth investigating.
5. **Exit codes.** `0` when clean, `1` with `--fail-on-diff` after the
   mutation, `3` when run as a normal user without `--allow-non-root`.

### Results, to fill in before 1.0

The *fingerprint key* is the string on the `system:` line of `osfp version`,
also printed as `key` by `osfp info`. It names the fingerprint file and it is
what `compare` refuses to cross, so it is the first thing to check: everything
else is only meaningful once the machine has identified itself correctly.

What each target is expected to report, in shape if not in version — these are
the values the unit tests in `internal/osdetect` assert against captured
fixtures:

```
freebsd/amd64    freebsd-14.1-amd64            from uname(2), build qualifiers dropped
openbsd/amd64    openbsd-7.5-amd64             from uname(2)
netbsd/amd64     netbsd-10.0-amd64             from uname(2)
solaris/amd64    solaris-11.4-amd64            from the banner line of /etc/release
illumos/amd64    illumos-omnios-r151046-amd64  distribution named: OmniOS, OpenIndiana, SmartOS
aix/ppc64        aix-7.3-tl02-ppc64            uname(2) for 7.3, oslevel -s for the technology level
```

A key that does not match this shape is not fatal — `--os-id` overrides it —
but it means the parser for that platform needs a fixture. Capture the file or
command output that confused it, drop it in `internal/osdetect/testdata/`, and
the case can be written without access to the machine.

| Target | OS version tested | Fingerprint key reported | Entries | Bytes/entry | Notes |
|---|---|---|---|---|---|
| freebsd/amd64 | 15.0-RELEASE-p2 | `freebsd-15.0-amd64` ✓ | 132,758 | **39.9** | see the note below |
| openbsd/amd64 | 7.8 | `openbsd-7.8-amd64` ✓ | 38,806 | **41.8** | all five checks pass; see the note below |
| netbsd/amd64 | 10.1 | `netbsd-10.1-amd64` ✓ | 165,016 | **39.3** | all five checks pass; `Statvfs` names `kernfs` and `tmpfs` with default flags; see the note below |
| solaris/amd64 | 11.4 GA (August 2018, no SRU) | `solaris-11.4-amd64` ✓ | 174,970 | **38.8** | all five checks pass; see the note below |
| illumos/amd64 | OmniOS r151056 | `illumos-omnios-r151056-amd64` ✓ | 136,786 | **34.7** | all five checks pass; see the note below |
| aix/ppc64 | — | — | — | — | **not run**: no machine available; see the note below |

## If a platform fails

The parsers are pure functions over bytes and are all reachable from a test:
capture the file or the command output that confused the detection, add it to
`internal/osdetect/testdata/`, and write the case. Nothing in `osdetect`
requires the platform to be present in order to be tested — that is the reason
it is built that way.

## What the FreeBSD pass found

FreeBSD 15.0-RELEASE-p2, ZFS root, September 2026. The five checks passed:
the key is read from `uname(2)` with the build qualifiers dropped, `statfs`
names `devfs` through `Fstypename`, two consecutive scans agree on the entry
count, the fingerprint costs 39.9 bytes per entry, and the exit codes are 0, 1
and 3 as documented. `devfs` is the only pseudo filesystem found: procfs is
not mounted on a stock install. The scan hashed 5.4 GiB in 29.3 s on 2 jobs.

The pass also changed the design, which is why it is worth running on every
platform rather than trusting the cross-compiler:

- **The default mount policy was wrong, and wrong by half.** With
  `--one-file-system` on, as the plan specified, the fingerprint held 66,260
  entries. With the type-aware default that replaced it, the same system gives
  **132,758** — the old behaviour covered 49.9 % of the machine. What it left
  out was `/home`, `/var/audit`, `/var/log`, `/usr/src`, `/usr/ports`,
  `/var/mail`, `/var/crash` and `/zroot`: on a stock ZFS install these are
  separate datasets, so stopping at every mount point stopped at all of them.
  A Linux test on a single ext4 filesystem could not have shown this.
- **The summary counted what it skipped without naming it.** "8 directories
  not descended" gave no way to tell which half of the system had not been
  looked at. Skipped mount points are now listed with their filesystem type.
- **`--fail-on-diff` printed `osfp compare: <nil>` on its nominal path**, and
  the error type behind it would have panicked on a nil error. Both fixed.
- Three plural bugs, and two wrong commands in this very file.


## What the OpenBSD pass found

OpenBSD 7.8, `ffs` root with separate `/home` and `/usr`, September 2026. The
five checks passed: the key is `openbsd-7.8-amd64`, `statfs` names `ffs`
through `F_fstypename` for both separate partitions, the fingerprint costs
41.8 bytes per entry, the exit codes are 0, 1 and 3, and the self-comparison
is empty.

This pass settled what FreeBSD could not. Every ZFS dataset there was mounted
`noatime`, so the claim that a scan does not disturb what it measures had not
actually been put to the test. Here the root is mounted without it: the access
time of `/etc/services` moved from 19:36:21 to 19:38:35 during a `baseline`,
yet a second `baseline` found the same 38,806 entries and `compare` reported
nothing.

And again, the pass corrected things a cross-compiler cannot see:

- **The probe for filesystem types in this file could never work.** It used
  `--mounts=all`, which crosses every mount point without asking for its type.
  It now uses `--mounts=same`.
- **OpenBSD and NetBSD borrowed FreeBSD's exclusions**, so their fingerprints
  recorded `/compat/linux/proc` and `/var/db/freebsd-update`. They now have
  their own, empty, list.
- **`mfs` was missing from the pseudo filesystems.** It is the only in-memory
  filesystem OpenBSD has left since tmpfs was removed; a `/tmp` on `mfs` would
  have been hashed as part of the installed system.
- More plural bugs: `1 jobs`, `1 blocks`, `1 symlinks`.

## What the NetBSD pass found

NetBSD 10.1, `ffs` root, September 2026. The five checks passed: the key is
`netbsd-10.1-amd64`, the fingerprint costs 39.3 bytes per entry — the lowest
so far, on the largest system (165,016 entries) — the exit codes are 0, 1 and
3, and the access time of `/etc/services` moved during a `baseline` (17:55:05
to 17:57:05) while a second `baseline` found the same entry count.

NetBSD is the only target that reads the filesystem type through `statvfs(2)`
rather than `statfs(2)`, and it proved it with the default flags, without the
probe: the walk stopped at `/kern (kernfs)` and `/var/shm (tmpfs)`. Neither is
in the built-in exclusions. This is the first real system on which the
type-aware mount policy caught something nobody had listed; without it,
`/var/shm` would have been hashed as part of the installed system. `ptyfs` does
not show up because it is mounted under `/dev`, which is excluded by name.

It is also the first pass on which the self-comparison was not empty:
`/var/log/cron` grew from 2.7 to 2.9 KiB in under four minutes, and the report
filed it under *expected noise*, as designed, rather than among the findings.

What the pass changed:

- **The progress line left debris behind.** Past about 150,000 entries the line
  was wider than the 80 columns `done` erased, and a stray character stayed at
  the end of `wrote …`. The line is now capped at 79 columns and erased to the
  width it actually reached.
- **`-v` was undocumented**, on `compare` especially, where the progress line
  already existed. It is now in the `README` and in the procedure above.
- **Expected noise made `--fail-on-diff` fail.** The `/var/log/cron` line was
  filed apart but still counted, so on any running system the exit code would
  have been `1` with nothing changed. Expected noise is still reported and
  counted in the summary (`1 of them expected noise`), but no longer decides
  the exit code. The machine then made the case on its own: by the time the
  fixed binary ran, `newsyslog` had rotated the logs at 18:00, and the same
  fingerprint gave twelve changes under `/var/log` — rotated archives, `wtmp`
  and `wtmpx` truncated to zero — all filed as expected noise, with exit `0`.
  Before the fix, `--fail-on-diff` would have failed on an untouched system.

## What the Solaris pass found

Oracle Solaris 11.4 GA (assembled August 2018, no SRU), ZFS root, September
2026. The five checks passed: the key is `solaris-11.4-amd64`, read from the
banner line of `/etc/release` despite its leading spaces; the fingerprint costs
38.8 bytes per entry, the lowest so far on the largest system (174,970
entries); the exit codes are 0, 1 and 3; and with `atime=on` the access time
of `/etc/inet/services` moved during a `baseline` (20:44 to 20:51) while the
second `baseline` differed only by 81 files, all written by StatsStore.

Whether the key survives an SRU is not settled by this machine, which has
none: the banner line is expected to stay `Oracle Solaris 11.4 X86`, with the
update level in `uname -v` only.

`statvfs(2)` names every mount through `Basetype`. The default walk stops at
`autofs` on `/home`, `/net` and `/nfs4` — `/home` only automounts
`/export/home`, a ZFS dataset that is scanned — and crosses the separate
datasets `/var`, `/export`, `/opt`, `/root`, `/system` and `/platform`, which
stopping at every mount point would have left out, as on FreeBSD. `mntfs` and
`sharefs` are mounted on files, `/etc/mnttab` and `/etc/dfs/sharetab`, so they
are hashed rather than classified; neither changed between two reads.

This is the pass that tested the expected-noise design hardest. A stock
Solaris 11.4 is never quiet: six minutes after the `baseline`, a hundred files
had been renamed, and thirty-six minutes after it the noise stood at 162 lines. With
the planted directory and the `chmod`, the two real changes still came first
in the report, and they alone made `--fail-on-diff` exit with `1`.

What the pass changed:

- **StatsStore, new in 11.4, renames its time series at every sample.**
  `/var/share/sstore` is now marked volatile.
- **Solaris logs to `/var/adm` and `/var/svc/log`, not `/var/log`**, and
  `auditd` is on by default. These are volatile too, and so is the audit
  trail: it grows by design, and marking it volatile keeps it scanned and
  reported, but a deletion there no longer fails `--fail-on-diff`. That is a
  deliberate trade-off, recorded in the plan.
- **Solaris 11 moved parts of `/var` to the VARSHARE dataset** and left
  symbolic links behind: `/var/audit` is a link to `/var/share/audit`,
  `/var/adm/lastlog` to `/var/share/adm/lastlog`. The walk does not follow
  links, so files are reported under their real path, and the volatile list
  names both.
- **The list of volatile directories became per-OS**, like the exclusions.
- **`dev`, the type of `/dev`, was missing from the pseudo filesystems** and
  was classified as local; `fd`, the type of `/dev/fd`, is added with it.
- **What this file expected of Solaris was wrong.** `ctfs` and `objfs` sit
  below `/system`, a dataset of its own, and `mntfs` and `sharefs` are mounted
  on files: none of the four can show up in the probe.

## What the illumos pass found

OmniOS r151056, ZFS root, September 2026. The five checks passed: the key is
`illumos-omnios-r151056-amd64`, the release token taken from the banner line
of `/etc/release` and the constant `v11` left out, as the fixtures for r151046
had pinned; the fingerprint costs 34.7 bytes per entry, the lowest of the
pass, because 17 % of the entries are symbolic links, which carry no hash; the
exit codes are 0, 1 and 3; and with `atime=on` the access time of
`/etc/inet/services` moved during a `baseline` (21:10 to 21:12) while the
second `baseline` was identical to the first, entry for entry.

OmniOS is the quiet counterpart of Solaris 11.4 on the same SunOS kernel: the
self-comparison was empty, and so was the report after the planted mutation,
save for the two planted changes. The noise on Solaris came from StatsStore and
the audit daemon, which Oracle added, not from the family. None of the
volatile paths added for Solaris exists here but `/var/adm` and
`/var/svc/log`, and neither changed.

`statvfs(2)` names every mount through `Basetype`. Here `/system` is an
ordinary directory, so `ctfs` and `objfs` show up below it, and the type-aware
default stops at a second mount nobody had listed: `tmpfs` on
`/etc/svc/volatile`, which on Solaris 11 is a symbolic link to the excluded
`/system/volatile`.

What the pass changed:

- **`bootfs` was missing from the pseudo filesystems.** It is the boot archive
  as the loader put it in memory, mounted on `/system/boot`, and the default
  walk had crossed it. It held one file, so the harm was one entry, but a
  fingerprint taken before the fix and compared after it would report that
  file as deleted: any change to the type tables changes what a scan covers.
- **The probe in this file ran at depth 1**, which reaches neither
  `/system/boot`, nor `/system/contract`, nor `/etc/svc/volatile`. It now runs
  at depth 3.
- **The last plural bugs**, found by review rather than one system at a time:
  `1 directories not descended` showed up here, and seven more counts in the
  summaries and the report had the same flaw. A test now pins the singular.

## AIX: not run

No AIX machine was available for this pass, so `aix/ppc64` ships built and
vetted but never executed. What follows is what is known to be at risk, for
whoever runs it first.

Reading the code for this pass found the target in worse shape than "untested":
`fsTypeName` returned *unknown* on AIX, on the stated grounds that `x/sys`
offers no way to read the type there. That was wrong — `unix.Statfs` exists for
`aix/ppc64` and carries `f_vfstype` — and it was costly. An unknown type is
never crossed, and a stock AIX puts `/usr`, `/var`, `/opt`, `/home` and `/tmp`
on logical volumes of their own: a default fingerprint would have held the
root filesystem and little else, the FreeBSD mistake again, only worse.

The type is now read as `f_vfstype` and named from `/etc/vfs`, the table every
AIX system keeps; a type that table flags `remote`, GPFS included, is treated
as a network filesystem. When `/etc/vfs` cannot be read, a built-in table of
the `<sys/vmount.h>` numbers takes over. Neither has met a real machine: the
table was written from documentation, and the test fixture for `/etc/vfs` was
written the same way.

What to check first, in this order:

1. **The key**, from `uname(2)` and `oslevel -s`: `aix-7.3-tl02-ppc64` in
   shape. If it is wrong, capture `oslevel -s` into
   `internal/osdetect/testdata/`.
2. **The filesystem types**, with the probe of point 2: every separate logical
   volume should show as `jfs2`. Copy the machine's `/etc/vfs` over the
   fixture in `internal/scan/vfs_test.go`.
3. **The entry count** of a default `baseline`, against `df` for `/`, `/usr`,
   `/var`, `/opt` and `/home`: it is the direct measure of whether the mount
   policy now covers the system.

`statfs` needs no privileges, so the first two steps, and the rest of the
procedure with `--allow-non-root`, can be run from an ordinary account — on
the GCC Compile Farm, for instance, which has lent AIX machines to free software
developers (check its current machine list).
