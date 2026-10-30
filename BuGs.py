#!/usr/bin/env python3

"""
BuGs - Bug Bounty Recon 
=========================================
Implements the Bug Bounty  methodology:
  1. URL Discovery (waybackurls, waymore, gau, gauplus, hakrawler, katana, gospider, paramspider, x8)
  2. Merge + Dedupe -> AllURLs.txt
  3. Categorize (JS, backend files, API, auth, uploads, admin, sensitive files, IDOR, SSRF/redirect, cloud leaks)
  4. Parameter extraction (qsreplace/anew style)
  5. JS secret discovery (mantra, jsecret, jsleak, trufflehog)
  6. Directory fuzzing (ffuf, gobuster, feroxbuster, dirsearch, dirb)
  7. Port discovery (naabu, nmap)

Design notes:
  - External tools are invoked via subprocess ONLY if found on PATH (shutil.which).
    Missing tools are skipped with a warning, never silently faked.
  - Categorization (the regex-based classification stage) is pure Python and always
    works even with zero external tools installed - it's the core value of this script.
  - All stage outputs are written to an --outdir (default ./BuGs_out) exactly like
    the .txt artifacts in the original methodology (WB1.txt, GAU1.txt, AllURLs.txt, etc.)

Usage:
  python3 BuGs.py discover -i AliveSubs.txt -d example.com
  python3 BuGs.py merge
  python3 BuGs.py categorize
  python3 BuGs.py params
  python3 BuGs.py jsscan
  python3 BuGs.py secrets --github-org example-org
  python3 BuGs.py fuzz -u https://example.com -w wordlist.txt --tool ffuf
  python3 BuGs.py ports -i AliveSubs.txt
  python3 BuGs.py all -i AliveSubs.txt -d example.com     # run the full pipeline

This is intended for use against targets you are authorized to test
(your own assets or in-scope bug bounty programs). You are responsible
for complying with the applicable program rules and the law.
"""
print (r"""
 ____         ____     
| __ ) _   _ / ___|___ 
|  _ \| | | | |  _/ __|
| |_) | |_| | |_| \__ \       ⚡︎⚡︎⚡︎⚡︎⚡︎⚡︎
|____/ \__,_|\____|___/   

 「 ✦ Helper code by AI ✦ 」

""")
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def which(tool: str) -> bool:
    return shutil.which(tool) is not None


def run(cmd, outfile=None, input_file=None, quiet=False):
    """Run a shell-style command list. Optionally pipe a file in / redirect stdout to a file."""
    if not quiet:
        print(f"  $ {' '.join(cmd)}" + (f"  > {outfile}" if outfile else ""))
    stdin = open(input_file, "rb") if input_file else None
    stdout = open(outfile, "wb") if outfile else subprocess.PIPE
    try:
        result = subprocess.run(cmd, stdin=stdin, stdout=stdout, stderr=subprocess.PIPE)
        if result.returncode != 0 and not outfile:
            sys.stderr.write(result.stderr.decode(errors="ignore"))
        return result
    except FileNotFoundError:
        print(f"  [!] tool not found: {cmd[0]} - skipping")
        return None
    finally:
        if stdin:
            stdin.close()
        if stdout is not subprocess.PIPE:
            stdout.close()


def anew(new_lines, existing_path: Path):
    """Append only unique lines to existing_path, mirroring tomnomnom/anew."""
    existing = set()
    if existing_path.exists():
        existing = set(existing_path.read_text(errors="ignore").splitlines())
    added = 0
    with existing_path.open("a") as f:
        for line in new_lines:
            line = line.strip()
            if line and line not in existing:
                f.write(line + "\n")
                existing.add(line)
                added += 1
    return added


def read_lines(path: Path):
    if not path.exists():
        return []
    return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]


# --------------------------------------------------------------------------
# Stage 1: URL Discovery
# --------------------------------------------------------------------------

DISCOVERY_TOOLS = ["waybackurls", "waymore", "gau", "gauplus", "hakrawler",
                    "katana", "gospider", "paramspider", "x8"]


def stage_discover(args, outdir: Path):
    print("[*] Stage: URL Discovery")
    subs = args.input
    ran_any = False

    if which("waybackurls"):
        run(["waybackurls"], input_file=subs, outfile=str(outdir / "WB1.txt"))
        ran_any = True
    else:
        print("  [!] waybackurls not found - skipping")

    if which("waymore"):
        if args.domain:
            run(["waymore", "-i", subs, "-mode", "U", "-l", "1000", "-from", "2021",
                 "-oU", str(outdir / "WM1.txt")])
            ran_any = True
        else:
            print("  [!] waymore found but -d/--domain not given - skipping")
    else:
        print("  [!] waymore not found - skipping")

    if which("gau"):
        run(["gau", "--threads", "200"], input_file=subs, outfile=str(outdir / "GAU1.txt"))
        ran_any = True
    else:
        print("  [!] gau not found - skipping")

    if which("gauplus"):
        run(["gauplus", "-t", "200", "-random-agent"], input_file=subs,
            outfile=str(outdir / "GAU2.txt"))
        ran_any = True
    else:
        print("  [!] gauplus not found - skipping")

    if which("hakrawler"):
        run(["hakrawler", "-subs", "-u", "-insecure"], input_file=subs,
            outfile=str(outdir / "HK1.txt"))
        ran_any = True
    else:
        print("  [!] hakrawler not found - skipping")

    if which("katana"):
        run(["katana", "-u", subs, "-jc", "-kf", "all", "-d", "5", "-headless",
             "-fx", "-aff", "-fs", "rdn", "-f", "url", "-silent",
             "-o", str(outdir / "KTN1.txt")])
        ran_any = True
    else:
        print("  [!] katana not found - skipping")

    if which("gospider"):
        run(["gospider", "-S", subs, "-t", "20", "-d", "3", "--js", "--sitemap",
             "--robots", "-o", str(outdir)])
        ran_any = True
    else:
        print("  [!] gospider not found - skipping")

    if which("paramspider"):
        if args.domain:
            run(["paramspider", "-d", args.domain, "-o", str(outdir / "PS1.txt")])
            ran_any = True
        else:
            print("  [!] paramspider found but -d/--domain not given - skipping")
    else:
        print("  [!] paramspider not found - skipping")

    if which("x8"):
        run(["x8", "-u", subs, "-o", str(outdir / "X81.txt")])
        ran_any = True
    else:
        print("  [!] x8 not found - skipping")

    if not ran_any:
        print("\n  [!] NONE of the discovery tools were found on your PATH.")
        print("      Run 'python3 BuGs.py tools' to see what's missing,")
        print("      and see REQUIREMENTS.md for install commands.")

    print("[*] Discovery complete. Run 'merge' next.")


# --------------------------------------------------------------------------
# Stage 2: Merge
# --------------------------------------------------------------------------

MERGE_SOURCES = ["WB1.txt", "WM1.txt", "GAU1.txt", "GAU2.txt", "KTN1.txt", "HK1.txt",
                  "GS1.txt", "GS2.txt", "PS1.txt", "X81.txt"]


def stage_merge(args, outdir: Path):
    print("[*] Stage: Merge URLs")
    all_urls = outdir / "AllURLs.txt"
    total = 0
    for name in MERGE_SOURCES:
        p = outdir / name
        if p.exists():
            added = anew(read_lines(p), all_urls)
            total += added
            print(f"  + {name}: {added} new")
    print(f"[*] AllURLs.txt now has {len(read_lines(all_urls))} unique URLs")


# --------------------------------------------------------------------------
# Stage 3: Categorize (pure Python - always works)
# --------------------------------------------------------------------------

CATEGORIES = {
    "js.txt":            r"\.jsx?(\?.*)?$",
    "asp.txt":            r"\.asp(\?.*)?$",
    "php.txt":            r"\.php(\?.*)?$",
    "jsp.txt":            r"\.jsp(\?.*)?$",
    "jspx.txt":           r"\.jspx(\?.*)?$",
    "aspx.txt":           r"\.aspx(\?.*)?$",
    "injection.txt":      r"=",
    "api_urls.txt":       r"(/api/v[0-9]|\.(json|xml|graphql|gql|swagger|openapi))(\?.*)?$",
    "backend_files.txt":  r"\.(php|asp|aspx|jsp|jspx|cfm|cgi|pl|rb|py)(\?.*)?$",
    "login_flows.txt":    r"(login|signin|signup|register|auth|oauth|sso|token|reset|password|account|session)",
    "file_uploads.txt":   r"(upload|file|download|image|media|avatar|import|export|attachment|doc)",
    "admin_panels.txt":   r"(admin|dashboard|internal|manage|manager|root|controlpanel|cpanel|portal|sysadmin)",
    "sensitive_files.txt": r"\.(env|bak|config|conf|sql|log|swp|git|yaml|yml|json|db|tar|gz|zip)(\?.*)?$",
    "idor_targets.txt":   r"([/=][0-9]{1,10}([/?&]|$))|([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    "interesting.txt":    r"(admin|login|signup|redirect|callback|auth|dev|test|beta|debug|staging|url=|r=|u=|goto=|return=|dest=|next=|target=|path=|file=|page=|fetch=|proxy=)",
    "cloud_leaks.txt":    r"(aws|s3|bucket|gcp|azure|vault|token|apikey|secret|key|bearer|access_token|private)",
}

# JS files needs the extra exclusion of static .json (from the "Advanced Regex" section)
JS_STRICT_PATTERN = re.compile(r"\.jsx?(\?.*)?$", re.IGNORECASE)
JSON_EXCLUDE_PATTERN = re.compile(r"\.json", re.IGNORECASE)


def stage_categorize(args, outdir: Path):
    print("[*] Stage: Categorize / Extract Interesting Data")
    all_urls = read_lines(outdir / "AllURLs.txt")
    if not all_urls:
        print("  [!] AllURLs.txt is empty or missing - run 'discover' + 'merge' first, "
              "or point --outdir at a folder that already has one.")
        return

    counts = {}
    for fname, pattern in CATEGORIES.items():
        rx = re.compile(pattern, re.IGNORECASE)
        matches = [u for u in all_urls if rx.search(u)]
        if fname == "js.txt":
            matches = [u for u in matches if not JSON_EXCLUDE_PATTERN.search(u)]
        out_path = outdir / fname
        added = anew(matches, out_path)
        counts[fname] = len(read_lines(out_path))

    for fname, total in counts.items():
        print(f"  {fname:<22} {total}")


# --------------------------------------------------------------------------
# Stage 4: Parameter extraction
# --------------------------------------------------------------------------

def stage_params(args, outdir: Path):
    print("[*] Stage: Parameter Extraction")
    all_urls = read_lines(outdir / "AllURLs.txt")
    param_urls = [u for u in all_urls if "=" in u]
    anew(param_urls, outdir / "params.txt")

    # Parameter key stripping: value after '=' up to next '&' becomes empty
    strip_rx = re.compile(r"=[^&]*")
    stripped = [strip_rx.sub("=", u) for u in param_urls]
    anew(stripped, outdir / "param.txt")

    # FUZZ replace (qsreplace-style) if qsreplace is installed; else do it natively
    if which("qsreplace"):
        tmp_in = outdir / "_param_urls_tmp.txt"
        tmp_in.write_text("\n".join(param_urls))
        run(["qsreplace", "FUZZ"], input_file=str(tmp_in), outfile=str(outdir / "_fuzz_tmp.txt"))
        fuzz_lines = read_lines(outdir / "_fuzz_tmp.txt")
        (outdir / "_fuzz_tmp.txt").unlink(missing_ok=True)
        tmp_in.unlink(missing_ok=True)
    else:
        fuzz_lines = [strip_rx.sub("=FUZZ", u) for u in param_urls]

    anew(fuzz_lines, outdir / "ParamURLs.txt")
    print(f"  params.txt: {len(read_lines(outdir/'params.txt'))}  "
          f"param.txt: {len(read_lines(outdir/'param.txt'))}  "
          f"ParamURLs.txt: {len(read_lines(outdir/'ParamURLs.txt'))}")


# --------------------------------------------------------------------------
# Stage 5: JS secret discovery
# --------------------------------------------------------------------------

SECRET_PATTERN = re.compile(r"api[_-]?key|token|secret|password", re.IGNORECASE)


def stage_jsscan(args, outdir: Path):
    print("[*] Stage: JS Secret Discovery")
    js_urls_file = outdir / "js.txt"
    if not js_urls_file.exists():
        print("  [!] js.txt not found - run 'categorize' first")
        return

    if which("mantra"):
        run(["mantra"], input_file=str(js_urls_file), outfile=str(outdir / "mantra_output.txt"))
    if which("jsecret"):
        run(["jsecret"], input_file=str(js_urls_file), outfile=str(outdir / "jsecret_output.txt"))
    if which("jsleak"):
        for url in read_lines(js_urls_file):
            run(["jsleak", "-s", "-l", "-k", "-e", url], outfile=str(outdir / "jsleak_output.txt"))

    if not any(which(t) for t in ("mantra", "jsecret", "jsleak")):
        print("  [!] none of mantra/jsecret/jsleak found on PATH.")
        print("  [i] Falling back to native regex secret scan on any downloaded JS files "
              "listed as local paths in js.txt (skips remote URLs).")
        found = []
        for entry in read_lines(js_urls_file):
            p = Path(entry)
            if p.exists() and p.is_file():
                text = p.read_text(errors="ignore")
                for m in SECRET_PATTERN.finditer(text):
                    line_no = text.count("\n", 0, m.start()) + 1
                    found.append(f"{p}:{line_no}: {m.group(0)}")
        anew(found, outdir / "regex_secrets.txt")
        print(f"  regex_secrets.txt: {len(read_lines(outdir/'regex_secrets.txt'))} hits")


def stage_secrets(args, outdir: Path):
    print("[*] Stage: TruffleHog Secret Scan")
    if not which("trufflehog"):
        print("  [!] trufflehog not found on PATH - skipping")
        return
    if args.github_org:
        run(["trufflehog", "github", f"--org={args.github_org}", "--results=verified"])
    js_urls_file = outdir / "js.txt"
    if js_urls_file.exists():
        run(["trufflehog", "filesystem", str(js_urls_file), "--json"],
            outfile=str(outdir / "trufflehog_results.json"))
    if args.git_repo:
        run(["trufflehog", "git", args.git_repo])


# --------------------------------------------------------------------------
# Stage 6: Directory fuzzing
# --------------------------------------------------------------------------

def stage_fuzz(args, outdir: Path):
    print("[*] Stage: Directory Fuzzing")
    tool = args.tool
    url, wordlist = args.url, args.wordlist

    if tool == "ffuf" and which("ffuf"):
        run(["ffuf", "-u", f"{url}/FUZZ", "-w", wordlist, "-t", "200", "-mc", "200",
             "-o", str(outdir / "ffuf_results.json")])
    elif tool == "gobuster" and which("gobuster"):
        run(["gobuster", "dir", "-u", url, "-w", wordlist, "-k",
             "-o", str(outdir / "gobuster_results.txt")])
    elif tool == "feroxbuster" and which("feroxbuster"):
        run(["feroxbuster", "-u", url, "-w", wordlist, "-t", "300", "-k", "-d", "3",
             "-e", "-x", "php,html,json,js,log,txt,bak,old,zip,tar,gz",
             "-o", str(outdir / "feroxbuster_results.txt")])
    elif tool == "dirsearch" and which("dirsearch"):
        run(["dirsearch", "-u", url, "-w", wordlist, "-i", "200", "--full-url",
             "-o", str(outdir / "dirsearch_results.txt")])
    elif tool == "dirb" and which("dirb"):
        run(["dirb", url], outfile=str(outdir / "dirb_results.txt"))
    else:
        print(f"  [!] '{tool}' not found on PATH or not supported - install it and retry")


# --------------------------------------------------------------------------
# Stage 7: Port discovery
# --------------------------------------------------------------------------

def stage_ports(args, outdir: Path):
    print("[*] Stage: Port Discovery")
    if which("naabu"):
        run(["naabu", "-list", args.input, "-p", "-", "-rate", "2000",
             "-o", str(outdir / "ports.txt")])
    elif which("nmap"):
        run(["nmap", "-iL", args.input, "-T4", "-Pn", "-oN", str(outdir / "nmap_results.txt")])
    else:
        print("  [!] neither naabu nor nmap found on PATH - skipping")


# --------------------------------------------------------------------------
# Stage: tool check
# --------------------------------------------------------------------------

ALL_TOOLS = ["waybackurls", "waymore", "gau", "gauplus", "hakrawler", "katana",
             "gospider", "paramspider", "x8", "anew", "qsreplace", "mantra",
             "jsecret", "jsleak", "trufflehog", "arjun", "sqlmap", "nuclei",
             "ffuf", "gobuster", "feroxbuster", "dirsearch", "dirb", "naabu",
             "nmap", "kr", "bfac"]


def stage_tools(args, outdir: Path):
    print("[*] Checking recon toolchain availability")
    for t in ALL_TOOLS:
        status = "ok" if which(t) else "missing"
        print(f"  [{status:^7}] {t}")


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------

def stage_all(args, outdir: Path):
    stage_discover(args, outdir)
    stage_merge(args, outdir)
    stage_categorize(args, outdir)
    stage_params(args, outdir)
    stage_jsscan(args, outdir)
    if getattr(args, "run_ports", False):
        stage_ports(args, outdir)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        prog="BuGs",
        description="BuGs - Bug Bounty Recon Orchestrator (URL discovery -> categorization -> secrets -> fuzzing)")
    parser.add_argument("--outdir", default="BuGs_out", help="Working/output directory (default: BuGs_out)")
    sub = parser.add_subparsers(dest="command", required=True)

    p_discover = sub.add_parser("discover", help="Run URL discovery tools against a subdomain list")
    p_discover.add_argument("-i", "--input", required=True, help="File with alive subdomains (one per line)")
    p_discover.add_argument("-d", "--domain", help="Root domain (needed by waymore/paramspider)")
    p_discover.set_defaults(func=stage_discover)

    p_merge = sub.add_parser("merge", help="Merge + dedupe all discovery outputs into AllURLs.txt")
    p_merge.set_defaults(func=stage_merge)

    p_cat = sub.add_parser("categorize", help="Regex-classify AllURLs.txt into topical files")
    p_cat.set_defaults(func=stage_categorize)

    p_params = sub.add_parser("params", help="Extract parameterized URLs / FUZZ templates")
    p_params.set_defaults(func=stage_params)

    p_js = sub.add_parser("jsscan", help="Scan js.txt for secrets (mantra/jsecret/jsleak or regex fallback)")
    p_js.set_defaults(func=stage_jsscan)

    p_secrets = sub.add_parser("secrets", help="Run TruffleHog against GitHub org / git repo / local JS files")
    p_secrets.add_argument("--github-org", help="GitHub org to scan")
    p_secrets.add_argument("--git-repo", help="Git repo URL to scan")
    p_secrets.set_defaults(func=stage_secrets)

    p_fuzz = sub.add_parser("fuzz", help="Directory/file fuzzing")
    p_fuzz.add_argument("-u", "--url", required=True)
    p_fuzz.add_argument("-w", "--wordlist", required=True)
    p_fuzz.add_argument("--tool", choices=["ffuf", "gobuster", "feroxbuster", "dirsearch", "dirb"], default="ffuf")
    p_fuzz.set_defaults(func=stage_fuzz)

    p_ports = sub.add_parser("ports", help="Port discovery via naabu/nmap")
    p_ports.add_argument("-i", "--input", required=True, help="File with alive subdomains/IPs")
    p_ports.set_defaults(func=stage_ports)

    p_all = sub.add_parser("all", help="Run the full pipeline: discover -> merge -> categorize -> params -> jsscan")
    p_all.add_argument("-i", "--input", required=True)
    p_all.add_argument("-d", "--domain", help="Root domain (needed by waymore/paramspider)")
    p_all.add_argument("--run-ports", action="store_true", help="Also run the port discovery stage")
    p_all.set_defaults(func=stage_all)

    p_tools = sub.add_parser("tools", help="Check which recon tools are installed on your PATH")
    p_tools.set_defaults(func=stage_tools)

    args = parser.parse_args()
    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    args.func(args, outdir)


if __name__ == "__main__":
    main()
