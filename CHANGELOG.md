# Changelog

All notable changes to `osfp` are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). For `osfp`, the
public interface is the command line, the exit codes, the JSON Lines report and
the `.osfp` file format.

## [1.0.0] - 2026-09-23

The first release.

### Added

- `osfp baseline` records a fingerprint of a filesystem: path, type, mode,
  owner, group, size and modification time of every entry, SHA-256 of every
  regular file, target of every symbolic link. The file is written atomically,
  mode `0600`, and records its own perimeter: root, exclusions, mount policy,
  depth limit.
- `osfp compare` scans the same perimeter again and reports ten kinds of
  change (`+D -D ~D +F -F ~F %F !T ~L ?E`) in a single merged pass. A directory
  absent from the fingerprint is reported once with counters, unless
  `--new-dir-mode` says otherwise. The modification time is never compared.
- `osfp info`, `osfp verify` and `osfp version`, which need no privileges.
- A text report grouped by change code, and a streaming JSON Lines report
  (`--format json`).
- `--show` to restrict the report to some codes, and `--ignore-from` for rules
  applied after classification, so that the summary still counts what they
  hide.
- Expected noise: changes under the volatile directories — `/var/log`,
  `/var/cache`, `/var/spool`, and per system the logs, audit trail and
  statistics of Solaris and illumos — are reported under their own heading and
  counted apart. They never make `--fail-on-diff` exit with `1`, and the JSON
  summary gives their number as `expected`.
- A mount policy that looks at the filesystem type: `--mounts=local`, the
  default, crosses local filesystems and stops at pseudo and network ones,
  naming each mount point it does not cross.
- A fingerprint key per operating system, release and architecture, detected
  on Linux, the BSDs, Solaris, illumos, macOS and AIX; `compare` refuses to
  cross two keys unless told to.
- Root is required for `baseline` and `compare`; `--allow-non-root` marks a
  fingerprint `UNPRIVILEGED`, never comparable with a privileged one.
- `-v` progress on standard error.
- Manual pages: `osfp(1)`, `osfp-baseline(1)`, `osfp-compare(1)`.
- Static binaries for thirteen targets, built without cgo, with `SHA256SUMS`
  and the third-party notices.

### Known limitations

- `aix/ppc64` is built and vetted but has never been run on a real system.
  Its filesystem types are read from `/etc/vfs`, unverified. See
  `docs/PORTING.md`.
- Outside Linux, a scan updates the access times of what it reads. They are
  never compared, so this does not show in a report.
- A change to the filesystem type tables between two versions changes what a
  scan covers: a fingerprint taken with an older version may then report the
  contents of a newly excluded mount point as deleted.
