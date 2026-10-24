# HTTP2Shell / CVE-2026-111497 — Exposure Checker

`http2shell-check.sh` is a read-only bash checker for **CVE-2026-111497 ("HTTP2Shell")**, a
vulnerability in the C decoder of [brotli](https://github.com/google/brotli). Any binary that
embeds an unpatched copy of the decoder is potentially exploitable over HTTP/2.

The script inspects a host (or its containers/images) and reports every brotli artifact it can
see — system packages, pip packages, Node/Bun/Envoy, and embedded (vendored) decoders inside
running processes — with a `VULN` / `WARN` / `OK` / `SKIP` line each and a final verdict.

No root required for basic host mode; no writes, no network calls.

## Quick start

```bash
bash http2shell-check.sh              # host mode (default)
bash http2shell-check.sh --deep      # also scan ELF files on disk (I/O heavy)
bash http2shell-check.sh --containers  # read running containers' filesystems (needs root)
bash http2shell-check.sh --images    # scan local docker images (executes code in each image!)
```

`--deep` and `--containers`/`--images` are opt-in and can be combined. `--deep` scans
`/usr /opt /srv /app /home` by default; override with `DEEP_PATHS="/var/lib/docker/overlay2 ..."`
(as root this covers image layers on disk without executing anything).

**Exit codes:** `0` clean · `1` VULNERABLE · `2` warnings only · `3` internal error.

## How detection works

### Marker-based, version-independent

Any copy of brotli's C decoder contains its error-string table, so the string
`_ERROR_FORMAT_EXUBERANT_NIBBLE` marks a decoder; the upstream fix adds a new error code, so
`_ERROR_FORMAT_BLOCK_SWITCH` marks a *fixed* copy — including distro backports and
cherry-picked fixes that keep the old version number. Fixed Node builds still report the old
`process.versions.brotli`, so version strings alone are not reliable for vendored copies; the
marker is. (Limit: a static build whose linker dropped the error strings has neither marker and
is not detected.)

### Fail-closed policy

Any `libbrotli` version in the affected range (1.0.3–1.2.0) is reported **VULN** unless its exact
revision is listed as a confirmed distro security fix in `confirmed_dist_fixed()`. Distro backports
keep the old upstream number, so they must be listed explicitly; a stale revision (e.g. a 2020
USN) is never treated as a fix. When Ubuntu/RHEL/Alpine publish fixes, add the exact fixed
revisions to that function.

### What is checked (host mode)

| # | Check |
|---|-------|
| 0 | Pending distro updates (`apt list --upgradable` matching brotli) |
| 1 | System libbrotli via `dpkg` / `apk` / `rpm` + fix-marker check of the installed `libbrotlidec` |
| 2 | Processes still holding a *deleted* (old) libbrotli in memory — running the vulnerable decoder |
| 3 | Python `Brotli` / `brotlicffi` from `pip list` (distro-built bindings that link the system lib are resolved via `ldd`) |
| 4 | Node.js (official builds by version; distro builds follow the system lib verdict) |
| 5 | Bun |
| 6 | Envoy (exposed only if a Brotli decompressor is configured) |
| 7 | Embedded (vendored) decoders in every running process, read through `/proc/PID/exe`, `/proc/PID/map_files`, `/proc/PID/root` — covers containers too when run as root |
| 8 | `--containers`: brotli packages + all ELF files in every *running* container's filesystem (Docker, containerd/K8s, CRI-O, Podman) — read-only, no exec |
| 9 | `--images`: per-image probe inside each local docker image (best effort, 30 s/image) |

Known-app recognition names common vendor binaries (Node, Bun, Envoy, DuckDB, ClickHouse,
Playwright, wheels, etc.) for readable output.

## Affected / fixed versions (as of 2026-10-24)

| Artifact | Affected | Fixed |
|---|---|---|
| libbrotli (C decoder) | 1.0.3 – 1.2.0 | 1.0.10 / 1.1.1 / 1.2.1 |
| Debian backports (2026-10-23) | | 12 → `1.0.9-2+deb12u1`, 13 → `1.1.0-2+deb13u1` |
| PyPI `Brotli` | ≤ 1.2.0 | 1.2.1 |
| PyPI `brotlicffi` | ≤ 1.2.0.x | 1.2.1.0 |
| Node.js | < 22.23.4 / 24.22.1 / 26.12.1; odd lines (23, 25) and pre-22 (incl. 20) EOL, no fix | 22.23.4 / 24.22.1 / 26.12.1 |
| Bun | ≤ 1.4.3 | 1.4.4 |
| Envoy | < per-line fixes; older lines EOL | 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0 |

Vendored copies **fixed upstream**: Node.js, Bun, Chromium, Firefox, brotlicffi, ngx_brotli,
Brotli4j, Ghostscript, SumatraPDF, CatBoost, YTsaurus.
**No fixed release yet** (as of 2026-10-24): .NET runtime (`BrotliDecoder`/`HttpClient`), PHP brotli
extension, Ruby brotli gem, DuckDB, ClickHouse, Apache Arrow (bundled), libjxl, GraalJS, v8-jsi,
7-Zip forks (NanaZip, 7-Zip-zstd, p7zip), MuPDF, EDK II, UEFITool, YDB.
**Not affected** (separate implementations): Java/JS/C# ports, Rust `brotli-decompressor`; Go
`andybalholm/brotli` could only crash (fixed 2026-10-23).

## Remediation (printed with a VULN verdict)

```
system lib:  apt-get update && apt-get install --only-upgrade 'libbrotli*'   (rebuild base images)
python:      pip install -U 'Brotli>=1.2.1' 'brotlicffi>=1.2.1.0'   (or uninstall if unused)
node:        22.23.4 / 24.22.1 / 26.12.1
bun:         1.4.4
envoy:       1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0
```

Then **restart all affected processes** — a running process keeps the old decoder in memory
(section 2 of the script checks exactly this). Envoy is exposed only if a Brotli decompressor is
configured (`curl -s localhost:9901/config_dump | grep -c envoy.compression.brotli.decompressor`).

## Safety

- **Host mode**: read-only, no root, no writes. `pip` self-check is disabled
  (`PIP_DISABLE_PIP_VERSION_CHECK=1`) so `pip list` makes no network calls; the script `cd`s to `/`
  before any interpreter runs (a planted `pip/__main__.py` / `_brotli.py` in the CWD cannot
  execute); the `_brotli` import check runs in `-I` isolated mode.
- **`--images`**: requires the docker socket (root-equivalent) and **executes code inside each
  scanned image with default networking**. Do NOT run it on hosts where you do not fully trust
  every local image. For fleet use, an SBOM/vulnerability scanner is the better tool once its
  database maps this CVE.
- **`--deep`**: read-only but I/O heavy (minutes on a cold cache); runs under `nice`/`ionice`.
- **`--containers`**: needs root and the host PID namespace; reads filesystems through
  `/proc/PID/root` — no docker socket, no exec into the container, nothing is started. Mounted
  volumes are not scanned (`-xdev`).

## Coverage gaps (stated so nobody over-trusts the output)

- Vendored copies are only seen if a running process loads them, or with `--deep` if they sit
  under `DEEP_PATHS`; copies inside archives (jars, zips, unpacked wheels) are not seen.
- Unprivileged runs only see the invoking user's processes.
- virtualenvs / pipx / conda envs not on `PATH` are not seen (activate the env before running).
- Distroless images yield `SKIP` in `--images` mode.

## Example output

```
== HTTP2Shell / CVE-2026-111497 — web-01 — 2026-10-24T12:00:00Z ==
WARN  libbrotli(system)                 1.1.0-2 (distro fix update pending: ...)
VULN  processes                         holding an OLD (deleted) libbrotli in memory - restart now: pids 1234
OK    node                             24.22.1
VULN  embedded: Node.js                /usr/lib/node_modules/... [pid 1234 node] (Brotli decoder without the fix)
...
=== VERDICT: VULNERABLE (exit 1) ===
```

## Requirements

bash and standard userland (`awk`, `find`, `grep`, `dd`/`od`, `stat`). `dpkg`/`apk`/`rpm` are
used when present. `--containers` needs root; `--images` needs the `docker` CLI + socket.
