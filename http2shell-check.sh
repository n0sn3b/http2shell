#!/usr/bin/env bash
# http2shell-check.sh v8 — check exposure to CVE-2026-111497 (HTTP2Shell)
#
# MODES / SAFETY:
#   host mode (default): read-only, no root, no writes. pip self-check is
#   disabled (PIP_DISABLE_PIP_VERSION_CHECK=1) so pip list makes no network
#   calls; the script cd's to / before any interpreter runs, so a planted
#   pip/__main__.py or _brotli.py in the CWD cannot execute; the _brotli
#   import check additionally runs in -I isolated mode.
#   --images mode: REQUIRES the docker socket (root-equivalent) and EXECUTES
#   code inside each scanned image with default networking. Do NOT run it on
#   hosts where you do not fully trust every local image. For fleet use, an
#   SBOM / vulnerability scanner is the better tool once its database maps
#   this CVE.
#   --deep: also scan ELF files on disk (default: /usr /opt /srv /app /home,
#   override with DEEP_PATHS="..."), not just what running processes load.
#   Read-only but I/O heavy (minutes on a cold cache); runs under nice/ionice.
#   As root, DEEP_PATHS=/var/lib/docker/overlay2 also covers image layers
#   on disk without running any container.
#   --containers: for every RUNNING container (Docker, containerd/Kubernetes,
#   CRI-O, Podman), read its filesystem through /proc/PID/root: check its
#   distro brotli packages (parsed from the dpkg/apk databases, or host rpm
#   --root) and scan every ELF file in it with the embedded decoder check.
#   Needs root and the host PID namespace. No docker socket, no exec into the
#   container, nothing is started. Mounted volumes are not scanned (-xdev).
#
# EMBEDDED DECODER CHECK (version-independent):
#   Any binary that contains Brotli's C decoder also contains its error-string
#   table, so the string _ERROR_FORMAT_EXUBERANT_NIBBLE marks a decoder. The
#   upstream fix (google/brotli 0ed4268 and its 1.0/1.1 branch equivalents)
#   adds a new error code to that table, so _ERROR_FORMAT_BLOCK_SWITCH marks a
#   fixed copy, including cherry-picked fixes that keep the old version number.
#   Verified 2026-10-24 on official Node.js 22.23.3 / 24.22.0 (no marker) vs
#   22.23.4 / 24.22.1 (marker), PyPI Brotli 1.2.0 vs 1.2.1, brotlicffi 1.2.0.1
#   vs 1.2.1.0, and Ubuntu 24.04 libbrotlidec 1.1.0 (no marker). Fixed Node
#   builds still report the OLD version in process.versions.brotli, so version
#   strings are not a reliable test for vendored copies; the marker is.
#   By default the check reads the executable and every file-backed library of
#   every running process it can see (through /proc/PID/root, so processes
#   inside containers are covered when run as root).
#   Limit: a static build whose linker dropped the error-string function has
#   neither marker and is not detected; the version checks below still apply.
#
# Vendored copies known as of 2026-10-24 (broccoli2shell.com):
#   fixed upstream: Node.js, Bun, Chromium, Firefox, brotlicffi, ngx_brotli,
#     Brotli4j, Ghostscript, SumatraPDF, CatBoost, YTsaurus
#   no fixed release yet: .NET runtime (BrotliDecoder/HttpClient), PHP brotli
#     extension, Ruby brotli gem, DuckDB, ClickHouse, Apache Arrow (bundled
#     build), libjxl, GraalJS, v8-jsi, 7-Zip forks (NanaZip, 7-Zip-zstd, p7zip),
#     MuPDF, EDK II, UEFITool, YDB
#   not affected (separate implementations): Java/JS/C# ports, Rust
#     brotli-decompressor; Go andybalholm/brotli could only crash, fixed 2026-10-23
#
# FAIL-CLOSED POLICY: any libbrotli version in the affected range (1.0.3-1.2.0)
# is reported VULN unless it is in confirmed_dist_fixed() below. Distro security
# backports keep the old upstream number, so they must be listed explicitly;
# when Ubuntu/RHEL/Alpine publish their fixes, add the exact fixed revisions
# to that list. An old revision (e.g. a 2020 USN) is never treated as a fix
# for this CVE.
#
# Exit codes: 0 = clean, 1 = VULNERABLE, 2 = warnings only, 3 = internal error
#
# Coverage gaps (stated so nobody over-trusts the output):
#   - vendored copies are only seen if a running process loads them, or with
#     --deep if they sit under DEEP_PATHS; copies inside archives (jar, zip,
#     wheels not yet unpacked) are not seen
#   - unprivileged runs only see the invoking user's processes
#   - virtualenvs, pipx, conda envs not on PATH are not seen (host mode
#     checks the default interpreter; activate the env before running if needed)
#   - distroless images yield SKIP in --images mode
#   - the stale-process check without root only sees the invoking user's processes
#
# Reference (as of 2026-10-24):
#   libbrotli   affected 1.0.3-1.2.0, fixed upstream in 1.0.10 / 1.1.1 / 1.2.1
#               Debian backports (2026-10-23): 12 -> 1.0.9-2+deb12u1,
#               13 -> 1.1.0-2+deb13u1. No Ubuntu/RHEL/Alpine fix revisions
#               confirmed as of this version.
#   Brotli (PyPI)     <=1.2.0 vuln -> 1.2.1
#   brotlicffi (PyPI) <=1.2.0.x vuln -> 1.2.1.0
#   Node.js   fixed 22.23.4 / 24.22.1 / 26.12.1; official odd lines (23, 25)
#               and pre-22 lines (incl. 20) EOL, no fix. Distro builds
#               (e.g. Debian's nodejs package) link the SYSTEM libbrotli, in
#               which case the system lib verdict governs.
#   Bun     <=1.4.3 vuln -> 1.4.4 (GHSA-663w-cv8g-jj2p)
#   Envoy   fixed 1.36.12 / 1.37.8 / 1.38.6 / 1.39.3 / 1.40.0 (GHSA-3wvj-j6qm-62mr);
#           older lines are EOL with no fix. Exposed only if a Brotli
#           decompressor is configured; to check a running Envoy:
#           curl -s localhost:9901/config_dump | grep -c envoy.compression.brotli.decompressor
#   Advisory DBs: GitHub's GHSA-9v8h-qqgm-4m35 (2026-10-22) lists the PyPI
#   brotli and brotlicffi packages, so Dependabot can flag them. pip-audit and
#   Safety coverage not verified.

set -u
cd / || exit 3

IMAGES=0; DEEP=0; CONTAINERS=0
for a in "$@"; do
  case "$a" in
    --images) IMAGES=1 ;;
    --deep)   DEEP=1 ;;
    --containers) CONTAINERS=1 ;;
    *) echo "unknown option: $a (use --images, --deep, --containers)" >&2; exit 3 ;;
  esac
done
DEC_MARK='_ERROR_FORMAT_EXUBERANT_NIBBLE'   # present in any copy of the C decoder
FIX_MARK='_ERROR_FORMAT_BLOCK_SWITCH'       # present only in fixed copies
export PIP_DISABLE_PIP_VERSION_CHECK=1
VULN=0; WARN=0
SYS_LIB_FIXED=0   # 1 if a confirmed-fixed system libbrotli was seen
APT_PENDING=0

ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

report() {
  case "$1" in
    VULN) printf 'VULN  %-36s %s\n' "$2" "$3"; VULN=1 ;;
    WARN) printf 'WARN  %-36s %s\n' "$2" "$3"; WARN=1 ;;
    OK)   printf 'OK    %-36s %s\n' "$2" "$3" ;;
    SKIP) printf 'SKIP  %-36s %s\n' "$2" "$3" ;;
  esac
}

# upstream libbrotli verdict for a bare version (1.0.9, 1.2.1, ...)
# NOTAF = below the affected range (<=1.0.2 or 0.x), not vulnerable
libbrotli_verdict() {
  local up="$1" major
  major=$(printf '%s' "$up" | cut -d. -f1)
  case "$major" in
    0) echo NOTAF ;;
    1)
      minor=$(printf '%s' "$up" | cut -d. -f2 2>/dev/null)
      case "$minor" in
        0)
          if ver_ge "$up" "1.0.10"; then echo FIXED
          elif ver_ge "$up" "1.0.3"; then echo VULN
          else echo NOTAF; fi ;;
        1)
          if ver_ge "$up" "1.1.1"; then echo FIXED; else echo VULN; fi ;;
        2)
          if ver_ge "$up" "1.2.1"; then echo FIXED; else echo VULN; fi ;;
        3|4) echo FIXED ;;
        *) echo UNKNOWN ;;
      esac ;;
    *) echo UNKNOWN ;;
  esac
}

# Distro security revisions CONFIRMED as the brotli fix (as of 2026-10-24).
# Add Ubuntu/RHEL/Alpine fixed revisions here as they publish.
confirmed_dist_fixed() {
  case "$1" in
    1.0.9-2+deb12u1|1.1.0-2+deb13u1) return 0 ;;
  esac
  return 1
}

# $1=name  $2=distro  $3=full version  $4=fix marker in the installed
# libbrotlidec (present|absent|unknown; host only, images pass nothing)
check_syslib() {
  local name="$1" ver="$3" mark="${4:-unknown}" up rv
  up=$(printf '%s' "$ver" | sed 's/[-+].*//')
  if [ "$mark" = present ]; then
    SYS_LIB_FIXED=1
    report OK "$name" "$ver (fix marker present in the installed libbrotlidec)"
    return
  fi
  if confirmed_dist_fixed "$ver"; then
    if [ "$mark" = absent ]; then
      report WARN "$name" "$ver (listed as fixed, but the installed libbrotlidec has no fix marker; check the file)"
      return
    fi
    SYS_LIB_FIXED=1
    report OK "$name" "$ver (confirmed distro security fix)"
    return
  fi
  rv=$(libbrotli_verdict "$up")
  case "$rv" in
    FIXED)  SYS_LIB_FIXED=1; report OK "$name" "$ver" ;;
    NOTAF)  report OK "$name" "$ver (below affected range 1.0.3-1.2.0)" ;;
    VULN)   report VULN "$name" "$ver (fix: 1.0.10 / 1.1.1 / 1.2.1; if this is a distro package, check its security tracker for a pending backport)" ;;
    *)      report WARN "$name" "$ver (branch not in known fix matrix)" ;;
  esac
}

is_elf() { [ "$(dd if="$1" bs=4 count=1 2>/dev/null | od -An -tx1 | tr -d ' \n')" = 7f454c46 ]; }

# name a file by the project known to vendor Brotli into it (display only)
known_app() {
  case "$1" in
    *curl_cffi*)                    echo "Python curl_cffi" ;;
    *brotlicffi*)                   echo "Python brotlicffi" ;;
    */_brotli*.so)                  echo "Python Brotli" ;;
    *pillow.libs/*|*/PIL/*)         echo "Pillow (vendored lib)" ;;
    *.libs/libbrotli*)              echo "Python wheel (vendored lib)" ;;
    *playwright*)                   echo "Playwright (bundled Node)" ;;
    *libbrotlidec*)                 echo "libbrotli (non-system copy)" ;;
    */node|*/nodejs)                echo "Node.js" ;;
    */bun)                          echo "Bun" ;;
    */envoy|*/envoy-*)              echo "Envoy" ;;
    *System.IO.Compression.Native*) echo ".NET runtime" ;;
    *php*brotli*)                   echo "PHP brotli ext" ;;
    */gems/*brotli*)                echo "Ruby brotli gem" ;;
    *duckdb*)                       echo "DuckDB" ;;
    *clickhouse*)                   echo "ClickHouse" ;;
    *arrow*|*parquet*)              echo "Apache Arrow" ;;
    *libjxl*)                       echo "libjxl" ;;
    *7z*|*NanaZip*)                 echo "7-Zip fork" ;;
    *mupdf*)                        echo "MuPDF" ;;
    *ydb*)                          echo "YDB" ;;
    *graal*)                        echo "GraalJS" ;;
    *brotli4j*)                     echo "Brotli4j" ;;
    *ngx_http_brotli*|*nginx*)      echo "nginx (ngx_brotli)" ;;
    *signal-desktop*)               echo "Signal Desktop" ;;
    *electron*|*chrom*)             echo "Chromium/Electron" ;;
    *firefox*|*libxul*)             echo "Firefox" ;;
    */gs|*libgs*)                   echo "Ghostscript" ;;
    *curl*)                         echo "curl" ;;
    *)                              echo "unknown app" ;;
  esac
}

# container id (first 12 hex) of a pid, from its cgroup; empty if not in a
# container. Docker, containerd, CRI-O and Podman all use 64-hex ids there.
container_of() { grep -oE '[0-9a-f]{64}' "/proc/$1/cgroup" 2>/dev/null | head -n1 | cut -c1-12; }

# fix marker in the libbrotlidec under root $1 ("" = host). Sets LIBMARK to
# present|absent|unknown and LIBFILE to the file read. Only regular files are
# read: absolute symlinks inside a container would resolve on the host.
lib_mark() {
  local r="$1" f good="" bad=""
  LIBMARK=unknown; LIBFILE=""
  # every architecture's copy (amd64, i386, ...); one copy without the fix is enough for "absent"
  for f in "$r"/usr/lib/*/libbrotlidec.so.* "$r"/usr/lib64/libbrotlidec.so.* "$r"/usr/lib/libbrotlidec.so.* "$r"/lib/*/libbrotlidec.so.*; do
    [ -f "$f" ] && [ ! -L "$f" ] || continue
    # covered by the package check, so the embedded scan skips these exact files
    EMB_SEEN="$EMB_SEEN$(stat -L -c '%d:%i' "$f" 2>/dev/null) "
    if grep -qaF "$FIX_MARK" "$f"; then good=${good:-$f}
    elif grep -qaF "$DEC_MARK" "$f"; then bad=${bad:-$f}; fi
  done
  if [ -n "$bad" ]; then LIBMARK=absent; LIBFILE=$bad
  elif [ -n "$good" ]; then LIBMARK=present; LIBFILE=$good; fi
}

# brotli packages in a dpkg database under root $1 ("" = host): only binaries
# built from the brotli source package (libbrotli1, brotli, libbrotli-dev,
# python3-brotli), printed as "name[:arch] version". Reads status (installed
# entries only) and status.d/ (distroless images keep one file per package).
dpkg_brotli_pkgs() {
  local r="$1" prog
  # shellcheck disable=SC2016
  prog='BEGIN { RS = "" }
    { p = v = src = st = a = ""; n = split($0, L, "\n")
      for (i = 1; i <= n; i++) {
        if (L[i] ~ /^Package: /) p = substr(L[i], 10)
        else if (L[i] ~ /^Version: /) v = substr(L[i], 10)
        else if (L[i] ~ /^Source: /) src = substr(L[i], 9)
        else if (L[i] ~ /^Status: /) st = substr(L[i], 9)
        else if (L[i] ~ /^Architecture: /) a = substr(L[i], 15)
      }
      sub(/ .*/, "", src)
      if (need && st !~ / installed$/) next
      if (p == "brotli" || src == "brotli" || p ~ /^libbrotli(1|-dev)$/) print p ((a != "" && a != "all") ? ":" a : "") " " v }'
  [ -f "$r/var/lib/dpkg/status" ] && awk -v need=1 "$prog" "$r/var/lib/dpkg/status"
  [ -d "$r/var/lib/dpkg/status.d" ] && find "$r/var/lib/dpkg/status.d" -maxdepth 1 -type f ! -name '*.md5sums' -exec cat {} + 2>/dev/null | awk -v need=0 "$prog"
  return 0
}

# $1=file to read  $2=path to display  $3=context
EMB_SEEN=" "; EMB_FOUND=0
scan_embedded() {
  local f="$1" shown="$2" ctx="$3" id
  [ -f "$f" ] || return 0
  id=$(stat -L -c '%d:%i' "$f" 2>/dev/null) || return 0
  case "$EMB_SEEN" in *" $id "*) return 0 ;; esac
  EMB_SEEN="$EMB_SEEN$id "
  is_elf "$f" || return 0
  grep -qaF "$DEC_MARK" "$f" 2>/dev/null || return 0
  EMB_FOUND=1
  if grep -qaF "$FIX_MARK" "$f" 2>/dev/null; then
    report OK "embedded: $(known_app "$shown")" "$shown$ctx (fix marker present)"
  else
    report VULN "embedded: $(known_app "$shown")" "$shown$ctx (Brotli decoder without the fix)"
  fi
}

echo "== HTTP2Shell / CVE-2026-111497 — $(hostname) — $(date -u +%FT%TZ) =="

# ---------- 0. pending distro updates (dpkg) ----------
if command -v apt >/dev/null 2>&1 && apt list --upgradable 2>/dev/null | grep -qi brotli; then
  APT_PENDING=1
  report WARN "libbrotli(system)" "distro fix update pending: apt-get update && apt-get install --only-upgrade 'libbrotli*'"
fi

# ---------- 1. system libbrotli ----------
# the fix marker in the installed library overrides the version string, so a
# distro backport is recognised even before its revision is listed above
lib_mark ""; SYSLIB_MARK=$LIBMARK
if command -v dpkg >/dev/null 2>&1; then
  # state codes: ii (installed), hi (installed, held) - both matter
  pkgs=$(dpkg_brotli_pkgs "" | sort -u)
  if [ -n "$pkgs" ]; then
    while read -r n v; do check_syslib "libbrotli($n)" "dpkg" "$v" "$SYSLIB_MARK"; done <<< "$pkgs"
  else
    report SKIP "libbrotli(system)" "no package found (dpkg)"
  fi
elif command -v apk >/dev/null 2>&1; then
  # apk info -v prints single tokens: "brotli-libs-1.1.0-r2"; strip the
  # subpackage prefix (libs, dev, static, doc, ...) up to the version
  pkgs=$(apk info -v 2>/dev/null | awk '$1 ~ /^brotli/ {v=$1; sub(/^[a-z-]*-/, "", v); print "brotli "v}' | sort -u)
  if [ -n "$pkgs" ]; then
    while read -r n v; do check_syslib "libbrotli($n)" "apk" "$v" "$SYSLIB_MARK"; done <<< "$pkgs"
  else
    report SKIP "libbrotli(system)" "no package found (apk)"
  fi
elif command -v rpm >/dev/null 2>&1; then
  pkgs=$(rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' libbrotli brotli 2>/dev/null | awk 'NF==2 && $2 ~ /^[0-9]/')
  if [ -n "$pkgs" ]; then
    while read -r n v; do check_syslib "libbrotli($n)" "rpm" "$v" "$SYSLIB_MARK"; done <<< "$pkgs"
  else
    report SKIP "libbrotli(system)" "no package found (rpm)"
  fi
fi

# ---------- 2. processes still holding the old (deleted) library ----------
# A process mapped to a deleted libbrotli is RUNNING the vulnerable decoder: VULN.
if [ -d /proc ]; then
  stale=$(grep -l 'libbrotli.*\.so[.0-9]* (deleted)' /proc/[0-9]*/maps 2>/dev/null | head -n5)
  if [ -n "$stale" ]; then
    pids=$(printf '%s\n' "$stale" | sed 's|/proc/||; s|/maps||' | tr '\n' ' ')
    report VULN "processes" "holding an OLD (deleted) libbrotli in memory - restart now: pids $pids"
  else
    report SKIP "processes" "no deleted libbrotli mappings visible ($([ "$(id -u)" = 0 ] && echo "all processes checked" || echo "unprivileged: own processes only"))"
  fi
fi

# ---------- 3. Python PyPI packages ----------
pipout=""
for p in "pip list" "pip3 list" "python3 -m pip list"; do
  out=$($p 2>/dev/null)
  [ -n "$out" ] && pipout="$pipout$out"$'\n'
done
if [ -n "$pipout" ]; then
  pipout=$(printf '%s\n' "$pipout" | sort -u)
  b=$(printf '%s\n' "$pipout" | awk 'tolower($1)=="brotli" && NF>=2 {print $2; exit}')
  c=$(printf '%s\n' "$pipout" | awk 'tolower($1)=="brotlicffi" && NF>=2 {print $2; exit}')
  if [ -n "$b" ]; then
    # -I: isolated mode, CWD is not on sys.path (no planted-module execution)
    moddir=$(python3 -I -c "import _brotli,os;print(os.path.dirname(_brotli.__file__))" 2>/dev/null)
    if [ -n "$moddir" ] && ldd "$moddir"/_brotli*.so 2>/dev/null | grep -q libbrotli; then
      # distro-built binding (apt python3-brotli shows up in pip list): follows
      # the system libbrotli, not the PyPI version
      if [ "$SYS_LIB_FIXED" = 1 ]; then
        report OK "python Brotli" "$b (distro binding, follows fixed system lib)"
      else
        report VULN "python Brotli" "$b (distro binding, follows unpatched system lib)"
      fi
    else
      if ver_ge "$b" "1.2.1"; then report OK "python Brotli" "$b"
      else report VULN "python Brotli" "$b (< 1.2.1, fix: 1.2.1)"; fi
    fi
  fi
  if [ -n "$c" ]; then
    if ver_ge "$c" "1.2.1.0"; then report OK "python brotlicffi" "$c"
    else report VULN "python brotlicffi" "$c (< 1.2.1.0, fix: 1.2.1.0)"; fi
  fi
  if [ -n "$b$c" ]; then
    auto=$(printf '%s\n' "$pipout" | awk 'tolower($1) ~ /^(requests|httpx|aiohttp|urllib3)$/ {print $1}' | tr '\n' ' ')
    if [ -n "$auto" ]; then
      echo "      -> auto-decode path active: $auto"
    else
      echo "      -> no requests/httpx/aiohttp/urllib3 detected (exposure only via direct import)"
    fi
  fi
else
  report SKIP "python" "no pip found"
fi

# ---------- 4. Node.js ----------
node_verdict() { # $1=display name, $2=version
  local name="$1" v="$2" m="$3"
  case "$m" in
    20|23|25) report VULN "$name" "$v - EOL official line, no fix exists; migrate to 22/24/26" ;;
    ''|*[^0-9]*) report WARN "$name" "$v (unparseable major version)" ;;
    *)
      if [ "$m" -lt 22 ] 2>/dev/null; then
        report VULN "$name" "$v - EOL official line, no fix exists"
      elif [ "$m" = 22 ]; then
        ver_ge "$v" "22.23.4" && report OK "$name" "$v" || report VULN "$name" "$v (< 22.23.4)"
      elif [ "$m" = 24 ]; then
        ver_ge "$v" "24.22.1" && report OK "$name" "$v" || report VULN "$name" "$v (< 24.22.1)"
      elif [ "$m" = 26 ]; then
        ver_ge "$v" "26.12.1" && report OK "$name" "$v" || report VULN "$name" "$v (< 26.12.1)"
      else
        report WARN "$name" "$v (line not in known fix matrix)"
      fi ;;
  esac
}
if command -v node >/dev/null 2>&1; then
  v=$(node -v 2>/dev/null | tr -d 'v')
  m=${v%%.*}
  links_sys=$(ldd "$(command -v node)" 2>/dev/null | grep -c brotli)
  if [ "$links_sys" -gt 0 ]; then
    # distro build: the system libbrotli is what actually runs
    if [ "$SYS_LIB_FIXED" = 1 ]; then
      report OK "node" "$v (distro build linked to system libbrotli, which is fixed)"
    elif [ "$APT_PENDING" = 1 ]; then
      report WARN "node" "$v (distro build; system libbrotli fix pending)"
    else
      report WARN "node" "$v (distro build linked to system libbrotli; check the system lib verdict above)"
    fi
    case "$m" in 20|23|25|1[89]|21) echo "      -> note: official line $m is EOL (no upstream fix), but this distro build is governed by the system lib" ;; esac
  else
    node_verdict "node" "$v" "$m"
  fi
else
  report SKIP "node" "not installed"
fi

# ---------- 5. Bun ----------
if command -v bun >/dev/null 2>&1; then
  v=$(bun -v 2>/dev/null)
  if [ -z "$v" ]; then
    report SKIP "bun" "version not parseable"
  elif ver_ge "$v" "1.4.4"; then report OK "bun" "$v"
  else report VULN "bun" "$v (<= 1.4.3, fix: 1.4.4)"; fi
else
  report SKIP "bun" "not installed"
fi

# ---------- 6. Envoy (exposure requires a br decompressor in the filter chain) ----------
if command -v envoy >/dev/null 2>&1; then
  v=$(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)
  if [ -z "$v" ]; then
    report SKIP "envoy" "version not parseable"
  else
    mm=${v#*.}; mm=${mm%%.*}
    case "$mm" in
      36) ver_ge "$v" "1.36.12" && report OK "envoy" "$v" || report VULN "envoy" "$v (< 1.36.12)" ;;
      37) ver_ge "$v" "1.37.8"  && report OK "envoy" "$v" || report VULN "envoy" "$v (< 1.37.8)" ;;
      38) ver_ge "$v" "1.38.6"  && report OK "envoy" "$v" || report VULN "envoy" "$v (< 1.38.6)" ;;
      39) ver_ge "$v" "1.39.3"  && report OK "envoy" "$v" || report VULN "envoy" "$v (< 1.39.3)" ;;
      40|41|42) report OK "envoy" "$v (fixed line)" ;;
      ''|*[!0-9]*) report WARN "envoy" "$v (unparseable minor version)" ;;
      *)
        if [ "$mm" -lt 36 ]; then
          report VULN "envoy" "$v (EOL line, no fix; exposed only if a Brotli decompressor is configured)"
        else
          report WARN "envoy" "$v (line not in known fix matrix)"
        fi ;;
    esac
  fi
else
  report SKIP "envoy" "not installed"
fi

# ---------- 7. embedded (vendored / static) Brotli decoders ----------
# running processes: executable + file-backed mappings, read through the
# process's own root so container filesystems resolve correctly
# Files are opened through /proc/PID/exe and /proc/PID/map_files/<range>
# (root only), which reach the exact file the process runs even inside a
# container or after the file was replaced or deleted. Without root,
# /proc/PID/root/<path> is used for the invoking user's own processes.
for pd in /proc/[0-9]*; do
  [ -r "$pd/maps" ] || continue
  pid=${pd#/proc/}; comm=$(cat "$pd/comm" 2>/dev/null)
  cid=$(container_of "$pid"); [ -n "$cid" ] && comm="$comm, container $cid"
  scan_embedded "$pd/exe" "$(readlink "$pd/exe" 2>/dev/null)" " [pid $pid $comm]"
  while read -r range path; do
    if stat -L "$pd/map_files/$range" >/dev/null 2>&1; then
      scan_embedded "$pd/map_files/$range" "$path" " [pid $pid $comm]"
    else
      case "$path" in *" (deleted)") continue ;; esac
      scan_embedded "$pd/root$path" "$path" " [pid $pid $comm]"
    fi
  done < <(awk '$6 ~ /^\// && $6 !~ /^\/(dev|proc|sys)\// && !seen[$6]++ {p = $6; for (i = 7; i <= NF; i++) p = p " " $i; print $1, p}' "$pd/maps" 2>/dev/null)
done
if [ "$DEEP" = 1 ]; then
  echo "      -> --deep: scanning ELF files under ${DEEP_PATHS:-/usr /opt /srv /app /home}"
  # shellcheck disable=SC2086
  while IFS= read -r -d '' f; do
    scan_embedded "$f" "$f" ""
  done < <(nice -n 19 ionice -c3 find ${DEEP_PATHS:-/usr /opt /srv /app /home} -xdev -type f -size +32k -print0 2>/dev/null \
           | nice -n 19 ionice -c3 xargs -0 -r grep -laFZ "$DEC_MARK" 2>/dev/null)
fi
[ "$EMB_FOUND" = 0 ] && report SKIP "embedded decoders" "none found in visible processes$([ "$DEEP" = 1 ] && echo ' or scanned paths')"

# ---------- 8. running containers (opt-in; root, read-only, no exec) ----------
if [ "$CONTAINERS" = 1 ]; then
  echo ""
  echo "== running containers (filesystems read through /proc/PID/root) =="
  if [ "$(id -u)" != 0 ]; then
    report SKIP "containers" "needs root to read other processes' filesystems"
  else
    selfns=$(readlink /proc/self/ns/mnt)
    # names and images, if a container CLI is available (cosmetic, read-only)
    cnames=""
    for cli in docker podman; do
      command -v "$cli" >/dev/null 2>&1 && cnames="$cnames$($cli ps --no-trunc --format '{{.ID}} {{.Names}} {{.Image}}' 2>/dev/null)"$'\n'
    done
    done_ids=" "; ncont=0
    for pd in /proc/[0-9]*; do
      pid=${pd#/proc/}
      cid=$(container_of "$pid"); [ -n "$cid" ] || continue
      case "$done_ids" in *" $cid "*) continue ;; esac
      # same mount namespace as us = same filesystem, already covered
      [ "$(readlink "$pd/ns/mnt" 2>/dev/null)" = "$selfns" ] && continue
      r="$pd/root"
      [ -d "$r/" ] || continue
      done_ids="$done_ids$cid "; ncont=$((ncont + 1))
      cname=$(printf '%s\n' "$cnames" | awk -v id="$cid" 'index($1, id) == 1 {print $2 " (" $3 ")"; exit}')
      echo "-- container $cid ${cname:+$cname }[pid $pid $(cat "$pd/comm" 2>/dev/null)]"
      # list everything in this container, even files already reported by the process scan
      EMB_SEEN=" "
      lib_mark "$r"
      cpkgs=""; cpm=""
      if [ -f "$r/var/lib/dpkg/status" ] || [ -d "$r/var/lib/dpkg/status.d" ]; then
        cpm=dpkg
        cpkgs=$(dpkg_brotli_pkgs "$r" | sort -u)
      elif [ -f "$r/lib/apk/db/installed" ]; then
        cpm=apk
        cpkgs=$(awk '/^P:/ {p = substr($0, 3)} /^V:/ {v = substr($0, 3)}
                     /^$/ {if (p ~ /^brotli/) print "brotli " v; p = ""; v = ""}
                     END  {if (p ~ /^brotli/) print "brotli " v}' "$r/lib/apk/db/installed" | sort -u)
      elif [ -d "$r/var/lib/rpm" ] && command -v rpm >/dev/null 2>&1; then
        cpm=rpm
        cpkgs=$(rpm --root "$r" -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' libbrotli brotli 2>/dev/null | awk 'NF==2 && $2 ~ /^[0-9]/')
      fi
      if [ -n "$cpkgs" ]; then
        while read -r n v; do check_syslib "ctr:$cid $n" "$cpm" "$v" "$LIBMARK"; done <<< "$cpkgs"
      elif [ "$LIBMARK" = absent ]; then
        report VULN "ctr:$cid libbrotli" "${LIBFILE#"$r"} (no package record; library has no fix marker)"
      elif [ "$LIBMARK" = present ]; then
        report OK "ctr:$cid libbrotli" "${LIBFILE#"$r"} (fix marker present)"
      fi
      while IFS= read -r -d '' f; do
        scan_embedded "$f" "${f#"$r"}" " [container $cid]"
      done < <(nice -n 19 ionice -c3 find "$r/" -xdev -type f -size +32k -print0 2>/dev/null \
               | nice -n 19 ionice -c3 xargs -0 -r grep -laFZ "$DEC_MARK" 2>/dev/null)
    done
    [ "$ncont" = 0 ] && report SKIP "containers" "no running containers found"
  fi
fi

# ---------- 9. docker images (opt-in; needs docker socket, runs code in images) ----------
if [ "$IMAGES" = 1 ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo ""
    echo "SKIP  --images requested but no docker binary"
  else
    echo ""
    echo "== docker images (WARNING: needs docker socket, executes code inside each image; best effort, 30s/image) =="
    probe='export PIP_DISABLE_PIP_VERSION_CHECK=1;
          (dpkg -l 2>/dev/null | awk "\$1 ~ /^.i/ && \$2 ~ /brotli/ {print \"SYSLIB dpkg \" \$2\" \"\$3}");
          (apk info -v 2>/dev/null | awk "\$1 ~ /^brotli/ {v=\$1; sub(/^[a-z-]*-/,\"\",v); print \"SYSLIB apk brotli \"v}" | sort -u);
          (rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE}\\n" libbrotli brotli 2>/dev/null | awk "NF==2 && \$2 ~ /^[0-9]/ {print \"SYSLIB rpm \" \$1\" \"\$2}");
          for p in "pip list" "pip3 list" "python3 -m pip list"; do $p 2>/dev/null | awk "tolower(\$1) ~ /^(brotli|brotlicffi|requests|httpx|aiohttp|urllib3)\$/ {print \"PY \" \$1\" \"\$2}"; done;
          command -v node >/dev/null 2>&1 && { node -v 2>/dev/null | sed "s/^/NODE /"; n=$(ldd $(command -v node) 2>/dev/null | grep -c brotli); [ "$n" -gt 0 ] && echo "NODELINK 1"; };
          command -v bun  >/dev/null 2>&1 && bun -v 2>/dev/null | sed "s/^/BUN /";'
    for img in $(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u); do
      out=$(timeout 30 docker run --rm --entrypoint sh "$img" -c "$probe" 2>/dev/null)
      if [ -z "$out" ]; then
        echo "SKIP  image $img (no shell or no output; distroless images land here)"
        continue
      fi
      found=0
      # pre-scan: does this image have a confirmed-fixed / fixed system lib?
      imgsysfixed=0
      for sv in $(printf '%s\n' "$out" | grep '^SYSLIB' | awk '{print $NF}'); do
        if confirmed_dist_fixed "$sv"; then imgsysfixed=1; continue; fi
        case "$(libbrotli_verdict "$(printf '%s' "$sv" | sed 's/[-+].*//')")" in
          FIXED) imgsysfixed=1 ;;
        esac
      done
      while read -r line; do
        [ -z "$line" ] && continue
        case "$line" in
          "SYSLIB dpkg "*) check_syslib "img:$img $(echo "$line" | awk '{print $3}')" "dpkg" "$(echo "$line" | awk '{print $4}')"; found=1 ;;
          "SYSLIB apk "*)  check_syslib "img:$img brotli" "apk" "$(echo "$line" | awk '{print $4}')"; found=1 ;;
          "SYSLIB rpm "*)  check_syslib "img:$img $(echo "$line" | awk '{print $3}')" "rpm" "$(echo "$line" | awk '{print $4}')"; found=1 ;;
          "PY Brotli "*)
            b=$(echo "$line" | awk '{print $3}')
            if [ -n "$b" ]; then
              if ver_ge "$b" "1.2.1"; then report OK "img:$img py:Brotli" "$b"; else report VULN "img:$img py:Brotli" "$b (< 1.2.1)"; fi
            fi
            found=1 ;;
          "PY brotlicffi "*)
            c=$(echo "$line" | awk '{print $3}')
            if [ -n "$c" ]; then
              if ver_ge "$c" "1.2.1.0"; then report OK "img:$img py:brotlicffi" "$c"; else report VULN "img:$img py:brotlicffi" "$c (< 1.2.1.0)"; fi
            fi
            found=1 ;;
          "PY "*) found=1 ;;
          "NODELINK 1") ;;
          "NODE "*)
            v=$(echo "$line" | awk '{print $2}' | tr -d 'v'); m=${v%%.*}
            nodelink=$(printf '%s\n' "$out" | grep -c '^NODELINK 1')
            if [ "$nodelink" -gt 0 ]; then
              if [ "$imgsysfixed" = 1 ]; then
                report OK "img:$img node" "$v (distro build, linked system lib is fixed)"
              else
                report VULN "img:$img node" "$v (distro build, linked system lib not confirmed fixed)"
              fi
            else
              node_verdict "img:$img node" "$v" "$m"
            fi
            found=1 ;;
          "BUN "*)
            v=$(echo "$line" | awk '{print $2}')
            if [ -n "$v" ]; then
              ver_ge "$v" "1.4.4" && report OK "img:$img bun" "$v" || report VULN "img:$img bun" "$v (<= 1.4.3)"
            fi
            found=1 ;;
        esac
      done <<< "$out"
      [ "$found" = 0 ] && echo "OK    image $img (no brotli artifacts found)"
    done
  fi
fi

# ---------- coverage note ----------
echo ""
echo "note: embedded decoders are found in running processes$([ "$DEEP" = 1 ] && echo ', scanned paths')$([ "$CONTAINERS" = 1 ] && echo ', running container filesystems') only; static builds"
echo "      without Brotli's error strings and copies inside archives are not seen. See header."

# ---------- verdict ----------
echo ""
if [ "$VULN" = 1 ]; then
  echo "=== VERDICT: VULNERABLE (exit 1) ==="
  echo "Fix: system lib (apt: apt-get update && apt-get install --only-upgrade 'libbrotli*'; rebuild base images)"
  echo "     Python (pip install -U 'Brotli>=1.2.1' 'brotlicffi>=1.2.1.0', or uninstall if unused)"
  echo "     Node (22.23.4 / 24.22.1 / 26.12.1), Bun (1.4.4), Envoy (1.36.12/1.37.8/1.38.6/1.39.3/1.40.0)"
  echo "     Then RESTART all affected processes - a running process keeps the old decoder in memory (section 2 checks this)."
  echo "     Envoy is exposed only if a Brotli decompressor is configured (check /config_dump on the admin port)."
elif [ "$WARN" = 1 ]; then
  echo "=== VERDICT: WARNINGS ONLY (exit 2) ==="
else
  echo "=== VERDICT: CLEAN (exit 0) ==="
fi
[ "$VULN" = 1 ] && exit 1
[ "$WARN" = 1 ] && exit 2
exit 0
