#!/usr/bin/env bash
# Re-run under bash if started with sh/dash (macOS /bin/sh is not bash 4+).
if [ -z "${BASH_VERSION:-}" ]; then exec bash "$0" "$@"; fi
# cats-portscan 0.2.0 - TCP connect scanner
#
# Scan only systems you own or have explicit written authorization to test.
#
# Exit status: 0 scan completed, 1 runtime error, 2 usage error, 130/143 interrupted.
# Results go to stdout. Progress and the summary go to stderr, so output pipes cleanly.

# Bash 4.3+ is needed for associative arrays, mapfile, and `wait -n`.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 3) )); then
  printf 'error: bash 4.3 or newer required (found %s; macOS: brew install bash)\n' "$BASH_VERSION" >&2
  exit 1
fi

set -uo pipefail

readonly VERSION=0.2.0
readonly PROG=${0##*/}
readonly DEFAULT_PORTS='21,22,23,25,53,80,110,111,135,139,143,389,443,445,587,993,995,1433,1521,2049,3306,3389,5432,5900,6379,8080,8443,9200,27017'
readonly BANNER_MAX=200
readonly MAX_PROBES=2000000

declare -A SERVICE=(
  [21]=ftp [22]=ssh [23]=telnet [25]=smtp [53]=dns [80]=http [110]=pop3
  [111]=rpcbind [135]=msrpc [139]=netbios [143]=imap [389]=ldap [443]=https
  [445]=smb [587]=submission [993]=imaps [995]=pop3s [1433]=mssql [1521]=oracle
  [2049]=nfs [3306]=mysql [3389]=rdp [5432]=postgres [5900]=vnc [6379]=redis
  [8080]=http-alt [8443]=https-alt [9200]=elasticsearch [27017]=mongodb
)

HOST_SPEC=''
PORT_SPEC=''
PORT_GIVEN=0
TIMEOUT=2
RETRIES=0
MAXJOBS=64
GRAB_BANNER=0
PROBE=''
SHOW_CLOSED=0
FORMAT=text
OUTFILE=''
VERBOSE=0
QUIET=0
START=0
TOTAL_QUEUED=0
TIMEOUT_BIN=''
TMP_SCAN=''
HOSTS=()
PORTS=()

# ---------------------------------------------------------------- helpers
log()  { (( QUIET )) || printf '%s\n' "$*" >&2; }
vlog() { (( VERBOSE )) && printf '%s\n' "$*" >&2; return 0; }
die()  { printf '%s: error: %s\n' "$PROG" "$*" >&2; exit 2; }

usage() {
  cat <<HELP
$PROG $VERSION - TCP connect scanner
(c) Kondo Solutions 1999-2026

Scan only systems you own or are authorized to test.

Usage: $PROG -h TARGET [options]

Target:
  -h TARGET    hostname, IPv4, IPv4 last-octet range (10.0.0.1-50), or CIDR /24-/32

Ports:
  -p PORTS     ports and ranges, comma or space separated (default: built-in common list)

Options:
  -t SEC       connect timeout in seconds, 1-999 (default 2)
  -r N         retries after a timeout, 0-9 (default 0)
  -c N         maximum parallel connections, 1-512 (default 64)
  -b           grab service banners
  -P STR       send STR before reading the banner; \\r\\n escapes allowed (implies -b)
  -a           include closed and filtered ports in the output
  -f FORMAT    output format: text, json, or csv (default text)
  -o FILE      also write results to FILE
  -q           quiet: no progress or summary on stderr
  -v           verbose progress
      --version  print version and exit
      --help     print this help and exit
  --           end of options; the next argument is the target

Port states: open (connect succeeded), closed (refused), filtered (timed out).

Exit status: 0 completed, 1 runtime error, 2 usage error, 130/143 interrupted.

Example: $PROG -h 127.0.0.1 -p 22,80,8000-8010 -b -f json
HELP
}

valid_ipv4() {
  local ip=$1 x
  local -a oct
  [[ $ip =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || return 1
  IFS=. read -r -a oct <<< "$ip"
  for x in "${oct[@]}"; do (( 10#$x <= 255 )) || return 1; done
}

# Expands a host spec to one address per line, written to stdout.
expand_hosts() {
  local spec=$1 prefix lo hi i ip mask block start last
  if [[ $spec =~ ^([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\.([0-9]{1,3})-([0-9]{1,3})$ ]]; then
    prefix=${BASH_REMATCH[1]}
    lo=$((10#${BASH_REMATCH[2]})); hi=$((10#${BASH_REMATCH[3]}))
    valid_ipv4 "$prefix.0" || die "invalid IPv4 prefix: $prefix"
    (( lo <= hi && hi <= 255 )) || die "invalid host range: $spec"
    for ((i=lo;i<=hi;i++)); do printf '%s.%d\n' "$prefix" "$i"; done
  elif [[ $spec == */* ]]; then
    ip=${spec%/*}; mask=${spec#*/}
    valid_ipv4 "$ip" || die "invalid IPv4 CIDR address: $ip"
    [[ $mask =~ ^(2[4-9]|3[0-2])$ ]] || die 'CIDR mask must be /24 through /32'
    prefix=${ip%.*}; last=$((10#${ip##*.}))
    block=$((1 << (32 - mask))); start=$((last / block * block))
    for ((i=start;i<start+block;i++)); do printf '%s.%d\n' "$prefix" "$i"; done
  elif [[ $spec == *.* && $spec =~ ^[0-9.]+$ ]]; then
    valid_ipv4 "$spec" || die "invalid IPv4 address: $spec"
    printf '%s\n' "$spec"
  elif [[ $spec =~ ^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$ ]]; then
    (( ${#spec} <= 253 )) || die "hostname too long: $spec"
    printf '%s\n' "$spec"
  else
    die "invalid host: $spec"
  fi
}

# Expands a port spec to sorted, unique ports, one per line, written to stdout.
expand_ports() {
  local spec=$1 part lo hi p
  local -a parts found=()
  [[ -n $spec ]] || die 'empty port specification'
  spec=${spec//[[:space:]]/,}
  while [[ $spec == *,,* ]]; do spec=${spec//,,/,}; done
  spec=${spec#,}; spec=${spec%,}
  [[ -n $spec ]] || die 'empty port specification'
  IFS=, read -r -a parts <<< "$spec"
  for part in "${parts[@]}"; do
    if [[ $part =~ ^([0-9]{1,5})-([0-9]{1,5})$ ]]; then
      lo=$((10#${BASH_REMATCH[1]})); hi=$((10#${BASH_REMATCH[2]}))
      (( lo >= 1 && hi <= 65535 && lo <= hi )) || die "invalid port range: $part"
      for ((p=lo;p<=hi;p++)); do found+=("$p"); done
    elif [[ $part =~ ^[0-9]{1,5}$ ]]; then
      p=$((10#$part)); (( p >= 1 && p <= 65535 )) || die "invalid port: $part"
      found+=("$p")
    else
      die "invalid port specification: $part"
    fi
  done
  printf '%s\n' "${found[@]}" | sort -nu
}

service_for() {
  local port=$1 name=''
  if [[ -n ${SERVICE[$port]:-} ]]; then
    printf '%s' "${SERVICE[$port]}"
    return 0
  fi
  if command -v getent >/dev/null 2>&1; then
    name=$(getent services "$port/tcp" 2>/dev/null | awk 'NR==1{print $1}')
  fi
  printf '%s' "${name:-unknown}"
}

# Protocol-appropriate probe for well-known plaintext HTTP ports.
default_probe() {
  case $1 in
    80|8000|8008|8080|8888) printf '%s' 'HEAD / HTTP/1.0\r\n\r\n' ;;
    *) ;;
  esac
}

# Reads one line from the service, optionally after sending a probe.
# The probe is passed as a positional argument, so it never reaches the shell parser.
grab_banner() {
  local host=$1 port=$2 probe=$3
  "$TIMEOUT_BIN" "$TIMEOUT" bash -c '
    exec 3<>/dev/tcp/"$1"/"$2" || exit 1
    if [[ -n $3 ]]; then printf "%b" "$3" >&3; fi
    IFS= read -r -t "$4" line <&3 || true
    printf "%s" "$line"
  ' _ "$host" "$port" "$probe" "$TIMEOUT" 2>/dev/null \
    | tr -cd '\11\12\40-\176' | head -c "$BANNER_MAX" | tr '\n\t' '  '
}

json_str() {
  local s=$1
  s=${s//\\/\\\\}
  s=${s//\"/\\\"}
  s=${s//$'\t'/\\t}
  s=${s//$'\r'/\\r}
  s=${s//$'\n'/\\n}
  printf '"%s"' "$s"
}

csv_field() {
  printf '"%s"' "${1//\"/\"\"}"
}

# ---------------------------------------------------------------- scanning
# Probes one host:port and writes a TSV record (host, port, state, service, banner)
# to $TMP_SCAN/r.<idx>. Open ports are always recorded; closed and filtered ports only with -a.
scan_one() {
  local host=$1 port=$2 idx=$3
  local out state=closed rc=0 attempt probe banner='' svc
  out=$TMP_SCAN/r.$idx

  for (( attempt = 0; attempt <= RETRIES; attempt++ )); do
    rc=0
    "$TIMEOUT_BIN" "$TIMEOUT" bash -c 'exec 3<>/dev/tcp/"$1"/"$2"' _ "$host" "$port" 2>/dev/null || rc=$?
    case $rc in
      0)   state=open; break ;;
      124) state=filtered ;;
      *)   state=closed ;;
    esac
  done

  if [[ $state == open ]]; then
    svc=$(service_for "$port")
    if (( GRAB_BANNER )); then
      probe=$PROBE
      [[ -n $probe ]] || probe=$(default_probe "$port")
      banner=$(grab_banner "$host" "$port" "$probe")
      banner=${banner%"${banner##*[![:space:]]}"}
      banner=${banner#"${banner%%[![:space:]]*}"}
    fi
    printf '%s\t%s\t%s\t%s\t%s\n' "$host" "$port" open "$svc" "$banner" > "$out"
  elif (( SHOW_CLOSED )); then
    printf '%s\t%s\t%s\t%s\t\n' "$host" "$port" "$state" "$(service_for "$port")" > "$out"
  fi
  return 0
}

# Launches every probe, keeping at most MAXJOBS running.
dispatch() {
  local host port rc idx=0 running=0
  for host in "${HOSTS[@]}"; do
    for port in "${PORTS[@]}"; do
      while (( running >= MAXJOBS )); do
        rc=0
        wait -n 2>/dev/null || rc=$?
        # 127 means no children were left to reap, so the count is already correct.
        if (( rc == 127 )); then running=0; else running=$((running - 1)); fi
      done
      scan_one "$host" "$port" "$idx" &
      running=$((running + 1))
      idx=$((idx + 1))
      if (( VERBOSE && idx % 5000 == 0 )); then vlog "queued $idx probes"; fi
    done
  done
  TOTAL_QUEUED=$idx
  wait
}

# Concatenates per-probe records in queue order.
collect() {
  local i f
  for ((i = 0; i < TOTAL_QUEUED; i++)); do
    f=$TMP_SCAN/r.$i
    [[ -f $f ]] && cat -- "$f"
  done
  return 0
}

# ---------------------------------------------------------------- output
# Reads TSV records on stdin and renders them in the selected format.
emit() {
  local host port state svc banner first=1
  case $FORMAT in
    json) printf '[' ;;
    csv)  printf 'host,port,state,service,banner\n' ;;
  esac
  while IFS=$'\t' read -r host port state svc banner; do
    case $FORMAT in
      text)
        case $state in
          open)
            printf '[OPEN] %s:%s %s\n' "$host" "$port" "$svc"
            [[ -n $banner ]] && printf '       %s\n' "$banner"
            ;;
          filtered) printf '[FILT] %s:%s %s\n' "$host" "$port" "$svc" ;;
          *)        printf '[----] %s:%s %s\n' "$host" "$port" "$svc" ;;
        esac
        ;;
      json)
        if (( first )); then printf '\n  '; else printf ',\n  '; fi
        first=0
        printf '{"host":%s,"port":%s,"state":"%s","service":%s,"banner":%s}' \
          "$(json_str "$host")" "$port" "$state" "$(json_str "$svc")" "$(json_str "$banner")"
        ;;
      csv)
        printf '%s,%s,%s,%s,%s\n' \
          "$(csv_field "$host")" "$port" "$state" "$(csv_field "$svc")" "$(csv_field "$banner")"
        ;;
    esac
  done
  if [[ $FORMAT == json ]]; then
    (( first )) || printf '\n'
    printf ']\n'
  fi
}

# ---------------------------------------------------------------- setup
parse_args() {
  while (( $# )); do
    case $1 in
      -h|-p|-t|-c|-r|-P|-o|-f)
        (( $# >= 2 )) || die "option $1 needs a value (run --help for the list)"
        case $1 in
          -h) HOST_SPEC=$2 ;;
          -p) PORT_SPEC=$2; PORT_GIVEN=1 ;;
          -t) TIMEOUT=$2 ;;
          -c) MAXJOBS=$2 ;;
          -r) RETRIES=$2 ;;
          -P) PROBE=$2; GRAB_BANNER=1 ;;
          -o) OUTFILE=$2 ;;
          -f) FORMAT=$2 ;;
        esac
        shift 2
        ;;
      -b) GRAB_BANNER=1; shift ;;
      -a) SHOW_CLOSED=1; shift ;;
      -q) QUIET=1; shift ;;
      -v) VERBOSE=1; shift ;;
      --version) printf '%s %s\n' "$PROG" "$VERSION"; exit 0 ;;
      --help) usage; exit 0 ;;
      --)
        shift
        (( $# == 1 )) || die 'expected exactly one target after --'
        [[ -z $HOST_SPEC ]] || die 'target specified twice'
        HOST_SPEC=$1; shift
        ;;
      -?*) die "unknown option: $1" ;;
      *)
        [[ -z $HOST_SPEC ]] || die "unexpected argument: $1"
        HOST_SPEC=$1; shift
        ;;
    esac
  done

  [[ -n $HOST_SPEC ]] || { usage >&2; die 'target required (-h)'; }
  [[ $TIMEOUT =~ ^[1-9][0-9]{0,2}$ ]] || die 'timeout must be 1-999 seconds'
  [[ $MAXJOBS =~ ^[1-9][0-9]{0,2}$ ]] && (( MAXJOBS <= 512 )) || die 'concurrency must be 1-512'
  [[ $RETRIES =~ ^[0-9]$ ]] || die 'retries must be 0-9'
  case $FORMAT in
    text|json|csv) ;;
    *) die "format must be text, json, or csv (got: $FORMAT)" ;;
  esac
}

check_deps() {
  local c tool
  for c in timeout gtimeout; do
    if command -v "$c" >/dev/null 2>&1; then TIMEOUT_BIN=$c; break; fi
  done
  [[ -n $TIMEOUT_BIN ]] || die 'GNU timeout required (macOS: brew install coreutils)'
  for tool in sort tr head mktemp awk; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
  done
}

cleanup() {
  local p
  trap - EXIT INT TERM
  if [[ -n $TMP_SCAN && -d $TMP_SCAN ]]; then
    jobs -p > "$TMP_SCAN/pids" 2>/dev/null || true
    while read -r p; do kill "$p" 2>/dev/null || true; done < "$TMP_SCAN/pids"
    rm -rf -- "$TMP_SCAN"
  fi
}

main() {
  local total open_count dir

  parse_args "$@"
  check_deps
  (( PORT_GIVEN )) || PORT_SPEC=$DEFAULT_PORTS

  TMP_SCAN=$(mktemp -d) || die 'cannot create temporary directory'
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM

  expand_hosts "$HOST_SPEC" > "$TMP_SCAN/hosts"
  expand_ports "$PORT_SPEC" > "$TMP_SCAN/ports"
  mapfile -t HOSTS < "$TMP_SCAN/hosts"
  mapfile -t PORTS < "$TMP_SCAN/ports"
  (( ${#HOSTS[@]} > 0 && ${#PORTS[@]} > 0 )) || die 'empty host or port list'

  total=$(( ${#HOSTS[@]} * ${#PORTS[@]} ))
  (( total <= MAX_PROBES )) || die "$total probes exceeds the limit of $MAX_PROBES; narrow the target or ports"

  if [[ -n $OUTFILE ]]; then
    if [[ $OUTFILE == */* ]]; then dir=${OUTFILE%/*}; else dir=.; fi
    [[ -d $dir ]] || die "no such directory: $dir"
    : > "$OUTFILE" 2>/dev/null || die "cannot write output: $OUTFILE"
  fi

  log "$PROG $VERSION: ${#HOSTS[@]} host(s) x ${#PORTS[@]} port(s), timeout ${TIMEOUT}s, retries $RETRIES, jobs $MAXJOBS"
  (( total <= 100000 )) || log "note: $total probes queued, this will take a while"

  START=$SECONDS
  dispatch
  collect > "$TMP_SCAN/all.tsv"

  if [[ -n $OUTFILE ]]; then
    emit < "$TMP_SCAN/all.tsv" | tee -- "$OUTFILE" || die "failed writing results to $OUTFILE"
  else
    emit < "$TMP_SCAN/all.tsv"
  fi

  open_count=$(awk -F'\t' '$3 == "open" { n++ } END { print n + 0 }' "$TMP_SCAN/all.tsv")
  log "$open_count open of $total probed in $((SECONDS - START))s"
  [[ -z $OUTFILE ]] || log "results written to $OUTFILE"
  exit 0
}

main "$@"
