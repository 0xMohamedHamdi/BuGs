#!/usr/bin/env bash

# BuGs - Bug Bounty Recon  (Bash edition)
# =======================================================
# Implements the Bug Bounty methodology as a single bash
# pipeline: URL discovery -> merge/dedupe -> categorize -> params ->
# JS secrets -> directory fuzzing -> port discovery.
#
# REQUIRES an input file of alive subdomains (one per line) - see -i below.
# Every external tool is optional: if it's not installed, that step is
# skipped with a warning and the pipeline keeps going. The categorize and
# params stages are pure grep/sed/awk, so they always work once AllURLs.txt
# exists, even with zero recon tools installed.
#
# Usage:
#   ./BuGs.sh -i AliveSubs.txt -d example.com [-o outdir] [-s stage]
#
#   -i FILE     Required. File with alive subdomains, one per line.
#   -d DOMAIN   Root domain (used by waymore / paramspider). Optional.
#   -o DIR      Output directory (default: BuGs_out)
#   -s STAGE    Run only one stage instead of the full pipeline:
#                 discover | merge | categorize | params | jsscan |
#                 secrets | fuzz | ports | tools
#   -u URL      Target URL for the 'fuzz' stage
#   -w WORDLIST Wordlist for the 'fuzz' stage
#   -t TOOL     Fuzz tool: ffuf|gobuster|feroxbuster|dirsearch|dirb (default ffuf)
#   -g ORG      GitHub org for the 'secrets' stage (TruffleHog)
#   -h          Show this help
#
# Examples:
#   ./BuGs.sh -i AliveSubs.txt -d example.com                 # full pipeline
#   ./BuGs.sh -i AliveSubs.txt -s discover -d example.com      # one stage
#   ./BuGs.sh -o results -s categorize                         # just classify AllURLs.txt
#   ./BuGs.sh -s fuzz -u https://example.com -w wordlist.txt -t ffuf
#   ./BuGs.sh -s ports -i AliveSubs.txt
#   ./BuGs.sh -s tools                                         # check what's installed
#
# Intended for targets you are authorized to test (your own assets or
# in-scope bug bounty programs). You are responsible for complying with
# the applicable program rules and the law.

set -uo pipefail
cat << "EOF" 
 ____         ____     
| __ ) _   _ / ___|___ 
|  _ \| | | | |  _/ __|
| |_) | |_| | |_| \__ \       ⚡︎⚡︎⚡︎⚡︎⚡︎⚡︎
|____/ \__,_|\____|___/   

 「 ✦ Helper code by AI ✦ 」

EOF
# ---------------------------------------------------------------------
# Defaults / argument parsing
# ---------------------------------------------------------------------
INPUT=""
DOMAIN=""
OUTDIR="BuGs_out"
STAGE="all"
FUZZ_URL=""
FUZZ_WORDLIST=""
FUZZ_TOOL="ffuf"
GH_ORG=""

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "i:d:o:s:u:w:t:g:h" opt; do
  case "$opt" in
    i) INPUT="$OPTARG" ;;
    d) DOMAIN="$OPTARG" ;;
    o) OUTDIR="$OPTARG" ;;
    s) STAGE="$OPTARG" ;;
    u) FUZZ_URL="$OPTARG" ;;
    w) FUZZ_WORDLIST="$OPTARG" ;;
    t) FUZZ_TOOL="$OPTARG" ;;
    g) GH_ORG="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

mkdir -p "$OUTDIR"

ALLURLS="$OUTDIR/AllURLs.txt"

log()  { echo "[*] $*"; }
warn() { echo "  [!] $*"; }
have() { command -v "$1" >/dev/null 2>&1; }

need_input() {
  if [[ -z "$INPUT" ]]; then
    echo "Error: this stage requires -i FILE (alive subdomains list)" >&2
    exit 1
  fi
  if [[ ! -f "$INPUT" ]]; then
    echo "Error: input file not found: $INPUT" >&2
    exit 1
  fi
}

# ---------------------------------------------------------------------
# Stage: tool check
# ---------------------------------------------------------------------
stage_tools() {
  log "Checking recon toolchain availability"
  local tools=(waybackurls waymore gau gauplus hakrawler katana gospider
               paramspider x8 anew qsreplace mantra jsecret jsleak
               trufflehog arjun sqlmap nuclei ffuf gobuster feroxbuster
               dirsearch dirb naabu nmap kr gitdorker bfac)
  for t in "${tools[@]}"; do
    if have "$t"; then
      printf "  [ok]      %s\n" "$t"
    else
      printf "  [missing] %s\n" "$t"
    fi
  done
}

# ---------------------------------------------------------------------
# Stage: discover
# ---------------------------------------------------------------------
stage_discover() {
  need_input
  log "URL Discovery"

  if have waybackurls; then
    log "  waybackurls"
    cat "$INPUT" | waybackurls > "$OUTDIR/WB1.txt"
  else warn "waybackurls not found - skipping"; fi

  if have waymore && [[ -n "$DOMAIN" ]]; then
    log "  waymore"
    waymore -i "$INPUT" -mode U -l 1000 -from 2021 -oU "$OUTDIR/WM1.txt"
  else warn "waymore not found (or -d not given) - skipping"; fi

  if have gau; then
    log "  gau"
    cat "$INPUT" | gau --threads 200 > "$OUTDIR/GAU1.txt"
  else warn "gau not found - skipping"; fi

  if have gauplus; then
    log "  gauplus"
    gauplus -t 200 -random-agent < "$INPUT" > "$OUTDIR/GAU2.txt"
  else warn "gauplus not found - skipping"; fi

  if have hakrawler; then
    log "  hakrawler"
    cat "$INPUT" | hakrawler -subs -u -insecure > "$OUTDIR/HK1.txt"
  else warn "hakrawler not found - skipping"; fi

  if have katana; then
    log "  katana"
    katana -u "$INPUT" -jc -kf all -d 5 -headless -fx -aff -fs rdn -f url -silent > "$OUTDIR/KTN1.txt"
  else warn "katana not found - skipping"; fi

  if have gospider; then
    log "  gospider"
    gospider -S "$INPUT" -t 20 -d 3 --js --sitemap --robots -o "$OUTDIR/gospider_out" >/dev/null 2>&1
    find "$OUTDIR/gospider_out" -type f -exec cat {} \; 2>/dev/null \
      | grep -oE 'https?://[^ ]+' > "$OUTDIR/GS1.txt" || true
  else warn "gospider not found - skipping"; fi

  if have paramspider && [[ -n "$DOMAIN" ]]; then
    log "  paramspider"
    paramspider -d "$DOMAIN" -o "$OUTDIR/PS1.txt"
  else warn "paramspider not found (or -d not given) - skipping"; fi

  if have x8; then
    log "  x8"
    x8 -u "$INPUT" -o "$OUTDIR/X81.txt"
  else warn "x8 not found - skipping"; fi

  log "Discovery complete. Run -s merge next (or -s all)."
}

# ---------------------------------------------------------------------
# Stage: merge  (anew-style manual dedupe, no external dependency needed)
# ---------------------------------------------------------------------
stage_merge() {
  log "Merging + deduping URLs -> $ALLURLS"
  local sources=(WB1.txt WM1.txt GAU1.txt GAU2.txt KTN1.txt HK1.txt GS1.txt GS2.txt PS1.txt X81.txt)
  touch "$ALLURLS"
  local before after added
  before=$(wc -l < "$ALLURLS" 2>/dev/null || echo 0)
  for f in "${sources[@]}"; do
    if [[ -f "$OUTDIR/$f" ]]; then
      cat "$OUTDIR/$f" "$ALLURLS" | sort -u -o "$ALLURLS"
    fi
  done
  after=$(wc -l < "$ALLURLS")
  log "AllURLs.txt now has $after unique URLs"
}

# ---------------------------------------------------------------------
# Stage: categorize  (pure grep/sed - always works once AllURLs.txt exists)
# ---------------------------------------------------------------------
stage_categorize() {
  if [[ ! -s "$ALLURLS" ]]; then
    echo "Error: $ALLURLS is empty or missing - run -s discover then -s merge first," >&2
    echo "       or drop your own AllURLs.txt into $OUTDIR/" >&2
    exit 1
  fi
  log "Categorizing $ALLURLS"

  grep -iE '\.jsx?(\?.*)?$'  "$ALLURLS" | grep -ivE '\.json' | sort -u > "$OUTDIR/js.txt"
  grep -iE '\.asp(\?.*)?$'   "$ALLURLS" | sort -u > "$OUTDIR/asp.txt"
  grep -iE '\.php(\?.*)?$'   "$ALLURLS" | sort -u > "$OUTDIR/php.txt"
  grep -iE '\.jsp(\?.*)?$'   "$ALLURLS" | sort -u > "$OUTDIR/jsp.txt"
  grep -iE '\.jspx(\?.*)?$'  "$ALLURLS" | sort -u > "$OUTDIR/jspx.txt"
  grep -iE '\.aspx(\?.*)?$'  "$ALLURLS" | sort -u > "$OUTDIR/aspx.txt"
  grep '='                   "$ALLURLS" | sort -u > "$OUTDIR/injection.txt"

  grep -iE '(/api/v[0-9]|\.(json|xml|graphql|gql|swagger|openapi))(\?.*)?$' \
    "$ALLURLS" | sort -u > "$OUTDIR/api_urls.txt"

  grep -iE '\.(php|asp|aspx|jsp|jspx|cfm|cgi|pl|rb|py)(\?.*)?$' \
    "$ALLURLS" | sort -u > "$OUTDIR/backend_files.txt"

  grep -iE '(login|signin|signup|register|auth|oauth|sso|token|reset|password|account|session)' \
    "$ALLURLS" | sort -u > "$OUTDIR/login_flows.txt"

  grep -iE '(upload|file|download|image|media|avatar|import|export|attachment|doc)' \
    "$ALLURLS" | sort -u > "$OUTDIR/file_uploads.txt"

  grep -iE '(admin|dashboard|internal|manage|manager|root|controlpanel|cpanel|portal|sysadmin)' \
    "$ALLURLS" | sort -u > "$OUTDIR/admin_panels.txt"

  grep -iE '\.(env|bak|config|conf|sql|log|swp|git|yaml|yml|json|db|tar|gz|zip)(\?.*)?$' \
    "$ALLURLS" | sort -u > "$OUTDIR/sensitive_files.txt"

  grep -iE '(/|=)[0-9]{1,10}(/|\?|&|$)|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
    "$ALLURLS" | sort -u > "$OUTDIR/idor_targets.txt"

  grep -iE '(admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest=|next=|target=|path=|file=|page=|fetch=|proxy=)' \
    "$ALLURLS" | sort -u > "$OUTDIR/interesting.txt"

  grep -iE '(aws|s3|bucket|gcp|azure|vault|token|apikey|secret|key|bearer|access_token|private)' \
    "$ALLURLS" | sort -u > "$OUTDIR/cloud_leaks.txt"

  for f in js asp php jsp jspx aspx injection api_urls backend_files login_flows \
           file_uploads admin_panels sensitive_files idor_targets interesting cloud_leaks; do
    printf "  %-20s %s\n" "$f.txt" "$(wc -l < "$OUTDIR/$f.txt")"
  done
}

# ---------------------------------------------------------------------
# Stage: params
# ---------------------------------------------------------------------
stage_params() {
  if [[ ! -s "$ALLURLS" ]]; then
    echo "Error: $ALLURLS is empty or missing - run -s discover / -s merge first" >&2
    exit 1
  fi
  log "Extracting parameterized URLs"

  grep '=' "$ALLURLS" | sort -u > "$OUTDIR/params.txt"

  # Parameter key stripping: value after '=' up to next '&' becomes empty
  grep '=' "$ALLURLS" | sed -E 's/=[^&]*/=/g' | sort -u > "$OUTDIR/param.txt"

  if have qsreplace; then
    grep '=' "$ALLURLS" | qsreplace "FUZZ" | sort -u > "$OUTDIR/ParamURLs.txt"
  else
    warn "qsreplace not found - using native sed fallback for FUZZ templating"
    grep '=' "$ALLURLS" | sed -E 's/=[^&]*/=FUZZ/g' | sort -u > "$OUTDIR/ParamURLs.txt"
  fi

  printf "  params.txt: %s  param.txt: %s  ParamURLs.txt: %s\n" \
    "$(wc -l < "$OUTDIR/params.txt")" "$(wc -l < "$OUTDIR/param.txt")" "$(wc -l < "$OUTDIR/ParamURLs.txt")"
}

# ---------------------------------------------------------------------
# Stage: jsscan
# ---------------------------------------------------------------------
stage_jsscan() {
  local js="$OUTDIR/js.txt"
  if [[ ! -s "$js" ]]; then
    echo "Error: $js not found - run -s categorize first" >&2
    exit 1
  fi
  log "JS Secret Discovery"

  local ran=0
  if have mantra;  then log "  mantra";  cat "$js" | mantra  > "$OUTDIR/mantra_output.txt";  ran=1; fi
  if have jsecret; then log "  jsecret"; cat "$js" | jsecret > "$OUTDIR/jsecret_output.txt"; ran=1; fi
  if have jsleak;  then
    log "  jsleak"
    cat "$js" | xargs -P 20 -I {} jsleak -s -l -k -e {} >> "$OUTDIR/jsleak_output.txt"
    ran=1
  fi

  if [[ "$ran" -eq 0 ]]; then
    warn "none of mantra/jsecret/jsleak found - falling back to native regex scan"
    : > "$OUTDIR/regex_secrets.txt"
    while IFS= read -r entry; do
      [[ -f "$entry" ]] && grep -nE 'api[_-]?key|token|secret|password' "$entry" \
        | sed "s#^#$entry:#" >> "$OUTDIR/regex_secrets.txt"
    done < "$js"
    log "regex_secrets.txt: $(wc -l < "$OUTDIR/regex_secrets.txt") hits"
  fi
}

# ---------------------------------------------------------------------
# Stage: secrets (TruffleHog)
# ---------------------------------------------------------------------
stage_secrets() {
  if ! have trufflehog; then
    warn "trufflehog not found on PATH - skipping"
    return
  fi
  log "TruffleHog Secret Scan"
  if [[ -n "$GH_ORG" ]]; then
    trufflehog github --org="$GH_ORG" --results=verified
  fi
  if [[ -f "$OUTDIR/js.txt" ]]; then
    trufflehog filesystem "$OUTDIR/js.txt" --json > "$OUTDIR/trufflehog_results.json"
  fi
}

# ---------------------------------------------------------------------
# Stage: fuzz
# ---------------------------------------------------------------------
stage_fuzz() {
  if [[ -z "$FUZZ_URL" || -z "$FUZZ_WORDLIST" ]]; then
    echo "Error: -s fuzz requires -u URL and -w WORDLIST" >&2
    exit 1
  fi
  log "Directory Fuzzing ($FUZZ_TOOL)"
  case "$FUZZ_TOOL" in
    ffuf)
      have ffuf && ffuf -u "$FUZZ_URL/FUZZ" -w "$FUZZ_WORDLIST" -t 200 -mc 200 \
        -o "$OUTDIR/ffuf_results.json" || warn "ffuf not found"
      ;;
    gobuster)
      have gobuster && gobuster dir -u "$FUZZ_URL" -w "$FUZZ_WORDLIST" -k \
        -o "$OUTDIR/gobuster_results.txt" || warn "gobuster not found"
      ;;
    feroxbuster)
      have feroxbuster && feroxbuster -u "$FUZZ_URL" -w "$FUZZ_WORDLIST" -t 300 -k -d 3 \
        -e -x php,html,json,js,log,txt,bak,old,zip,tar,gz \
        -o "$OUTDIR/feroxbuster_results.txt" || warn "feroxbuster not found"
      ;;
    dirsearch)
      have dirsearch && dirsearch -u "$FUZZ_URL" -w "$FUZZ_WORDLIST" -i 200 --full-url \
        -o "$OUTDIR/dirsearch_results.txt" || warn "dirsearch not found"
      ;;
    dirb)
      have dirb && dirb "$FUZZ_URL" | tee "$OUTDIR/dirb_results.txt" || warn "dirb not found"
      ;;
    *)
      echo "Error: unknown fuzz tool '$FUZZ_TOOL'" >&2; exit 1 ;;
  esac
}

# ---------------------------------------------------------------------
# Stage: ports
# ---------------------------------------------------------------------
stage_ports() {
  need_input
  log "Port Discovery"
  if have naabu; then
    naabu -list "$INPUT" -p - -rate 2000 -o "$OUTDIR/ports.txt"
  elif have nmap; then
    nmap -iL "$INPUT" -T4 -Pn -oN "$OUTDIR/nmap_results.txt"
  else
    warn "neither naabu nor nmap found - skipping"
  fi
}

# ---------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------
case "$STAGE" in
  tools)      stage_tools ;;
  discover)   stage_discover ;;
  merge)      stage_merge ;;
  categorize) stage_categorize ;;
  params)     stage_params ;;
  jsscan)     stage_jsscan ;;
  secrets)    stage_secrets ;;
  fuzz)       stage_fuzz ;;
  ports)      stage_ports ;;
  all)
    need_input
    stage_discover
    stage_merge
    stage_categorize
    stage_params
    stage_jsscan
    ;;
  *)
    echo "Unknown stage: $STAGE" >&2
    usage
    ;;
esac
