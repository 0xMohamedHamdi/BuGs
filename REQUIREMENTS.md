# BuGs — Requirements & Install Guide

`BuGs.sh` (and `BuGs.py`) are orchestrators: they call these external
tools via subprocess if found on your `PATH`, and skip anything missing with
a warning. Nothing is *hard-required* except the base system utilities below —
but the more of these you install, the more stages actually produce output.

Run `./BuGs.sh -s tools` any time to see which of these are currently
installed on your machine.

---

## 0. Base requirements (needed no matter what)

| Requirement | Why | Install |
|---|---|---|
| Bash 4+ | runs `BuGs.sh` | pre-installed on Linux/macOS; on Windows use WSL |
| Python 3.8+ | runs `BuGs.py` (if you use that version) | `sudo apt install python3` / `brew install python3` |
| coreutils (`grep`, `sed`, `awk`, `sort`, `xargs`) | categorize/merge/params stages | pre-installed on Linux/macOS |
| Go 1.21+ | needed to install most tools below | `sudo apt install golang-go` or https://go.dev/doc/install |
| Rust + Cargo | needed for `x8`, optionally `feroxbuster` | https://rustup.rs |
| Git | cloning tool repos | `sudo apt install git` |

After installing Go tools, make sure `$HOME/go/bin` is on your `PATH`:
```bash
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc && source ~/.bashrc
```

---

## 1. URL Discovery stage

| Tool | Install |
|---|---|
| waybackurls | `go install github.com/tomnomnom/waybackurls@latest` |
| waymore | `pip install waymore` |
| gau | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| gauplus | `go install github.com/bp0lr/gauplus@latest` |
| hakrawler | `go install github.com/hakluke/hakrawler@latest` |
| katana | `go install github.com/projectdiscovery/katana/cmd/katana@latest` (needs Go 1.21+; add `CGO_ENABLED=1` if headless mode fails to build) |
| gospider | `go install github.com/jaeles-project/gospider@latest` |
| paramspider | `git clone https://github.com/devanshbatham/paramspider && cd paramspider && pip install .` |
| x8 | `cargo install x8` |

## 2. Merge / dedupe

| Tool | Install |
|---|---|
| anew | `go install github.com/tomnomnom/anew@latest` |

(`BuGs.sh` does its own `sort -u` merge natively, so `anew` is optional —
only needed if you want to reuse its exact one-liners yourself.)

## 3. Categorize / Extract Interesting Data

No extra tools needed — this stage is pure `grep`/`sed` and always works.

## 4. Parameter Extraction

| Tool | Install |
|---|---|
| qsreplace | `go install github.com/tomnomnom/qsreplace@latest` |

(Optional — the script falls back to a native `sed` FUZZ templater if
`qsreplace` isn't installed.)

## 5. JS Secret Discovery

| Tool | Install |
|---|---|
| mantra | `git clone https://github.com/MrSudoX/mantra && cd mantra && pip install -r requirements.txt` (check the repo's README for the exact entry point) |
| jsecret | `git clone https://github.com/Rsthn/jsecret` — follow the repo's README (no package manager release) |
| jsleak | `git clone https://github.com/chaitin/jsleak && cd jsleak && go build` |
| TruffleHog | `curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin` or `brew install trufflehog` |

## 6. Parameter Discovery & SQLi

| Tool | Install |
|---|---|
| Arjun | `pip install arjun` |
| sqlmap | `sudo apt install sqlmap` or `git clone https://github.com/sqlmapproject/sqlmap.git` |

## 7. Full Vulnerability Scan

| Tool | Install |
|---|---|
| Nuclei | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` then `nuclei -update-templates` |
| Param Miner | Burp Suite BApp Store, or `git clone https://github.com/PortSwigger/param-miner` and load manually in Burp's Extender tab |

## 8. Fuzzing (directories/files)

| Tool | Install |
|---|---|
| ffuf | `go install github.com/ffuf/ffuf/v2@latest` |
| gobuster | `go install github.com/OJ/gobuster/v3@latest` |
| feroxbuster | `cargo install feroxbuster` or `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash` |
| dirsearch | `git clone https://github.com/maurosoria/dirsearch.git && cd dirsearch && pip install -r requirements.txt` |
| dirb | `sudo apt install dirb` |
| Kiterunner | `git clone https://github.com/assetnote/kiterunner.git && cd kiterunner && make build` (binary ends up at `./dist/kr` — put it on your PATH as `kr`) |

## 9. Port Discovery

| Tool | Install |
|---|---|
| naabu | needs libpcap first: `sudo apt install libpcap-dev`, then `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| nmap | `sudo apt install nmap` / `brew install nmap` |

## 10. Sensitive File / Secrets OSINT (not wired into pegpont.sh yet, but referenced in the methodology doc)

| Tool | Install |
|---|---|
| GitDorker | `git clone https://github.com/obheda12/GitDorker && cd GitDorker && pip install -r requirements.txt` (needs a GitHub personal access token in a token file) |
| BFAC | `pip install bfac` or `git clone https://github.com/mazen160/bfac && cd bfac && pip install -r requirements.txt` |

---

## Quick "install everything Go-based" script

If you have Go and Cargo already set up, this one-liner grabs most of the
Go/Rust tools in one go:

```bash
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/bp0lr/gauplus@latest
go install github.com/hakluke/hakrawler@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/jaeles-project/gospider@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
cargo install x8
cargo install feroxbuster
pip install waymore arjun bfac
```

Then check the result with:
```bash
./BuGs.sh -s tools
```

---

**Note:** Some of these tools (sqlmap, Nuclei against live targets, TruffleHog
against org GitHub repos, GitDorker) send real traffic or query real
services. Only point them at assets/programs you're authorized to test.
