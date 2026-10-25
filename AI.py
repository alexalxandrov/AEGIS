#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╭──────────────────────────────────────────────────────────────────────╮
│  ⚡  L O C A L   G G U F   A G E N T                                  │
│  local inference · tool calling · colourised & fast · v2.4.3         │
│  + network reconnaissance toolkit (nmap, sqlmap, gobuster, …)        │
│                                                                      │
│  v2.4.3 fixes:                                                       │
│    • tool name sanitizer: "ip_addr()" → "ip_addr"                    │
│    • LocalTools.execute tolerates stray parens / whitespace          │
│    • prompt: explicit rule that tool name has no parentheses         │
╰──────────────────────────────────────────────────────────────────────╯
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import textwrap
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════════════
#  COLOUR & GLYPH LAYER
# ══════════════════════════════════════════════════════════════════════

_COLOR_ON = (os.environ.get("NO_COLOR") is None) and sys.stdout.isatty()

def _fg(n: int) -> str: return f"\033[38;5;{n}m" if _COLOR_ON else ""

class C:
    R = "\033[0m" if _COLOR_ON else ""
    B = "\033[1m" if _COLOR_ON else ""
    D = "\033[2m" if _COLOR_ON else ""
    I = "\033[3m" if _COLOR_ON else ""

    primary   = _fg(51)
    secondary = _fg(45)
    accent    = _fg(213)
    success   = _fg(46)
    warning   = _fg(220)
    error     = _fg(196)
    info      = _fg(39)
    muted     = _fg(244)
    dim       = _fg(240)
    reason    = _fg(141)
    tool      = _fg(208)
    user      = _fg(117)
    ai        = _fg(158)
    gold      = _fg(220)

class G:
    bolt      = "⚡"
    spark     = "✦"
    diamond   = "◆"
    circle    = "◈"
    arrow     = "❯"
    tri       = "▸"
    tool      = "⌬"
    brain     = "⟡"
    eye       = "◉"
    check     = "✔"
    cross     = "✘"
    warn      = "⚠"
    file      = "⧉"
    dir       = "⬡"
    ghost     = "⎔"

# ══════════════════════════════════════════════════════════════════════
#  DEPENDENCY BOOTSTRAP
# ══════════════════════════════════════════════════════════════════════

def _ensure_llama_cpp() -> bool:
    try:
        import llama_cpp  # noqa
        return True
    except ImportError:
        print(f"{C.warning}{G.warn} llama-cpp-python not found — installing…{C.R}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "llama-cpp-python"])
            import llama_cpp  # noqa
            return True
        except Exception as exc:
            print(f"{C.error}{G.cross} install failed: {exc}{C.R}")
            print(f"{C.muted}Install manually: pip install llama-cpp-python{C.R}")
            return False

if not _ensure_llama_cpp():
    sys.exit(1)

from llama_cpp import Llama  # type: ignore  # noqa: E402

# ══════════════════════════════════════════════════════════════════════
#  CONSTANTS & PROTOCOL
# ══════════════════════════════════════════════════════════════════════

APP_NAME  = "LOCAL GGUF AGENT"
VERSION   = "2.4.3"
DEFAULT_TIMEOUT        = 120
DEFAULT_MAX_TOKENS     = 1024
DEFAULT_CONTEXT_SIZE   = 16384
DEFAULT_THREADS        = max(1, (os.cpu_count() or 2) - 1)
DEFAULT_CONFIRM_LIMIT  = 15
DEFAULT_TEMPERATURE    = 0.7

TOOL_BEGIN = "<<<QWEN_TOOL_CALL>>>"
TOOL_END   = "<<<END_QWEN_TOOL_CALL>>>"

TOOL_TIMEOUTS: Dict[str, int] = {
    "nmap":       1800,
    "masscan":     900,
    "sqlmap":     1800,
    "hydra":      1800,
    "john":       3600,
    "hashcat":    3600,
    "gobuster":    900,
    "dirb":        900,
    "ffuf":        900,
    "nikto":       900,
    "wpscan":      900,
    "nuclei":     1200,
    "dnsrecon":    300,
    "dnsenum":     300,
    "amass":      1200,
    "subfinder":   300,
    "enum4linux":  300,
    "httpx":       300,
    "traceroute":  120,
    "ping":         60,
}
DEFAULT_TOOL_TIMEOUT = 180

NETWORK_TOOLS = [
    "bash", "curl", "ping", "traceroute", "dig", "whois", "ip", "ss",
    "nmap", "masscan", "arp-scan",
    "gobuster", "dirb", "ffuf", "nikto", "whatweb", "wafw00f",
    "sqlmap", "wpscan", "nuclei", "httpx",
    "dnsrecon", "dnsenum", "amass", "subfinder",
    "enum4linux", "smbclient", "smbmap",
    "hydra", "john", "hashcat", "searchsploit",
]

CORE_TOOLS = [
    "bash", "read_file", "write_file", "list_directory", "python", "git",
    "ip_addr", "ip_route", "ping", "dig", "whois", "nmap", "curl",
    "web_fetch", "web_headers",
    "list_tools", "nmap_cheatsheet",
]

PROTOCOL_PROMPT = f"""You are a local autonomous assistant.

## REASONING
You may think privately inside <think>…</think> before answering.
Anything inside <think> will NOT be shown to the user as the final answer.
Write the actual answer OUTSIDE the tags.
Never put a tool call inside <think>…</think>.

## TOOL CALLING — STRICT
To invoke a tool you MUST emit this exact block, both markers on their own lines:

{TOOL_BEGIN}
{{"tool": "NAME", "arguments": {{ ... }}}}
{TOOL_END}

NON-NEGOTIABLE:
• Both markers MUST appear, verbatim, character-for-character.
• The JSON body MUST be a single-line object without markdown fences.
• The "tool" value MUST be the BARE NAME — no parentheses, no spaces:
  write "ip_addr", NOT "ip_addr()". Write "nmap", NOT "nmap(target=…)".
• Do NOT place a tool call inside <think>…</think> reasoning.
• Exactly ONE tool call per assistant turn.
• Never claim a tool ran unless you received a "TOOL RESULT".
• If you don't need a tool, just answer normally — no JSON, no markers.

Common failure modes to AVOID:
✗ Writing raw JSON without the two markers.
✗ Forgetting {TOOL_END}.
✗ Wrapping the JSON in ``` fences.
✗ Emitting the call inside your private reasoning block.
✗ Putting parentheses in "tool": "ip_addr()" is WRONG; use "ip_addr".
"""

# ══════════════════════════════════════════════════════════════════════
#  PRECOMPILED REGEX
# ══════════════════════════════════════════════════════════════════════

_RE_THINK_XML   = re.compile(r"<think(?:ing)?>\s*(.*?)\s*</think(?:ing)?>", re.DOTALL | re.I)
_RE_THINK_TAG   = re.compile(r"</?think(?:ing)?>", re.I)
_RE_REASON_MD   = re.compile(r"```(?:thinking|reasoning)\s*(.*?)\s*```", re.DOTALL | re.I)
_RE_FENCE_OPEN  = re.compile(r"^```(?:json)?\s*", re.I)
_RE_FENCE_CLOSE = re.compile(r"\s*```$")
_RE_FENCE_JSON  = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL | re.I)
_RE_TOOLCALL    = re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", re.DOTALL | re.I)
_RE_URL         = re.compile(r"^https?://", re.I)
_RE_MODEL_SIZE  = re.compile(r"(\d+(?:\.\d+)?)\s*[Bb](?![A-Za-z])")
_RE_TOOL_PARENS = re.compile(r"\s*\(.*\)\s*$", re.DOTALL)

# ══════════════════════════════════════════════════════════════════════
#  OUTPUT HELPERS
# ══════════════════════════════════════════════════════════════════════

def _emit(icon: str, tag: str, msg: str, colour: str) -> None:
    sys.stdout.write(f"{colour}{C.B}{icon} {tag}{C.R} {msg}\n")
    sys.stdout.flush()

def info(m: str) -> None: _emit(G.circle,   "INFO",  m, C.info)
def ok(m: str)   -> None: _emit(G.check,    " OK ",  m, C.success)
def warn(m: str) -> None: _emit(G.warn,     "WARN",  m, C.warning)
def err(m: str)  -> None: _emit(G.cross,    "FAIL",  m, C.error)
def step(m: str) -> None: _emit(G.tri,      "STEP",  m, C.secondary)
def dbg(m: str, on: bool) -> None:
    if on:
        _emit(G.ghost, "DBG ", m, C.dim)

def read_line(prompt_text: str) -> str:
    sys.stdout.write(prompt_text)
    sys.stdout.flush()
    raw = sys.stdin.buffer.readline()
    if not raw:
        raise EOFError
    return raw.decode("utf-8", errors="replace").rstrip("\r\n")

def banner() -> None:
    inner_w = 62
    top    = "╭" + "─" * inner_w + "╮"
    bottom = "╰" + "─" * inner_w + "╯"
    title  = f"{G.bolt}  L O C A L   G G U F   A G E N T"
    sub    = f"offensive recon · tool calling · v{VERSION}"

    def line(text: str, colour: str) -> str:
        pad = inner_w - len(text) - 1
        return f"{C.primary}│{C.R} {colour}{text}{C.R}" + " " * max(0, pad) + f"{C.primary}│{C.R}"

    print()
    print(f"{C.primary}{top}{C.R}")
    print(line(title, C.gold + C.B))
    print(line(sub,   C.muted + C.I))
    print(f"{C.primary}{bottom}{C.R}")
    print()

def box(title: str, text: str, colour: str = "", icon: str = "") -> None:
    if not text:
        return
    colour = colour or C.primary
    icon   = icon or G.diamond
    text   = str(text)
    width  = 76

    print()
    print(f"{colour}╭─ {icon} {C.B}{title}{C.R}{colour} "
          f"{'─' * max(1, width - len(title) - 5)}{C.R}")
    for raw_line in text.splitlines() or [""]:
        for sub in textwrap.wrap(raw_line, width=width - 2, replace_whitespace=False) or [""]:
            print(f"{colour}│{C.R} {sub}")
    print(f"{colour}╰{'─' * (width + 2)}{C.R}")

def user_echo(text: str) -> None:
    print(f"\n{C.user}{C.B}{G.arrow} you{C.R}  {C.user}{text}{C.R}")

def ai_label() -> None:
    sys.stdout.write(f"\n{C.ai}{C.B}{G.spark} ai{C.R}  ")
    sys.stdout.flush()

def check_internet(timeout: float = 3.0) -> bool:
    for host, port in (("1.1.1.1", 443), ("8.8.8.8", 53)):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except OSError:
            pass
    return False

def find_gguf_model() -> Optional[Path]:
    script_dir = Path(__file__).resolve().parent
    for f in script_dir.iterdir():
        if f.suffix.lower() == ".gguf":
            return f
    return None

def safe_json(v: Any) -> str:
    return json.dumps(v, ensure_ascii=False, indent=2)

def _first_which(names: List[str]) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None

def detect_model_size_b(model_path: str) -> Optional[float]:
    m = _RE_MODEL_SIZE.search(Path(model_path).stem)
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None

def sanitize_tool_name(name: str) -> str:
    """'ip_addr()' → 'ip_addr'; ' nmap ' → 'nmap'."""
    if not isinstance(name, str):
        return ""
    s = name.strip()
    s = _RE_TOOL_PARENS.sub("", s).strip()
    return s

# ══════════════════════════════════════════════════════════════════════
#  LIVE STATUS TICKER
# ══════════════════════════════════════════════════════════════════════

_TICKER_WIDTH = 40

def _waiting_ticker(stop_event: threading.Event, start_time: float) -> None:
    if not sys.stderr.isatty():
        return
    while not stop_event.wait(0.4):
        elapsed = time.monotonic() - start_time
        msg = f"… generating {elapsed:6.1f}s"
        sys.stderr.write("\r" + msg.ljust(_TICKER_WIDTH))
        sys.stderr.flush()

def _clear_ticker() -> None:
    if sys.stderr.isatty():
        sys.stderr.write("\r" + (" " * _TICKER_WIDTH) + "\r")
        sys.stderr.flush()

# ══════════════════════════════════════════════════════════════════════
#  STARTUP TOOL CHECK
# ══════════════════════════════════════════════════════════════════════

@dataclass(slots=True)
class ToolAudit:
    available: List[str]
    missing:   List[str]

def audit_network_tools() -> ToolAudit:
    available, missing = [], []
    for t in NETWORK_TOOLS:
        (available if shutil.which(t) else missing).append(t)
    return ToolAudit(available, missing)

_INSTALL_HINTS = {
    "debian": "sudo apt update && sudo apt install -y {pkgs}",
    "arch":   "sudo pacman -S --needed {pkgs}",
    "fedora": "sudo dnf install -y {pkgs}",
    "mac":    "brew install {pkgs}",
}

def report_tool_audit(audit: ToolAudit) -> bool:
    if audit.available:
        head = ", ".join(audit.available[:10])
        more = "" if len(audit.available) <= 10 else f" (+{len(audit.available)-10} more)"
        ok(f"network tools available ({len(audit.available)}): {C.muted}{head}{more}{C.R}")

    if not audit.missing:
        ok("all requested network tools are present")
        return True

    warn(f"missing {len(audit.missing)} network tool(s):")
    print(f"  {C.error}{', '.join(audit.missing)}{C.R}")

    pkgs = " ".join(audit.missing)
    print(f"\n{C.muted}Suggested install commands:{C.R}")
    print(f"  {C.dim}Debian/Ubuntu :{C.R} {_INSTALL_HINTS['debian'].format(pkgs=pkgs)}")
    print(f"  {C.dim}Arch          :{C.R} {_INSTALL_HINTS['arch'].format(pkgs=pkgs)}")
    print(f"  {C.dim}Fedora        :{C.R} {_INSTALL_HINTS['fedora'].format(pkgs=pkgs)}")
    print(f"  {C.dim}macOS         :{C.R} {_INSTALL_HINTS['mac'].format(pkgs=pkgs)}")

    try:
        ans = read_line(
            f"\n{C.warning}{G.warn} continue anyway? {C.muted}(missing tools will fail on call) [y/N]{C.R} "
        ).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return ans in ("y", "yes")

# ══════════════════════════════════════════════════════════════════════
#  TOOL POLICY
# ══════════════════════════════════════════════════════════════════════

class ToolPolicy:
    DENY_FRAGMENTS = (
        "rm -rf /", "rm -rf /*", "mkfs", "dd if=", ":(){", "fork bomb",
        "> /dev/sd", "shutdown -h", "reboot", "poweroff", "halt",
    )

    def classify_bash(self, command: str) -> str:
        raw = command.strip()
        if not raw:
            return "DENY"
        low = raw.lower()
        for frag in self.DENY_FRAGMENTS:
            if frag in low:
                return "DENY"
        try:
            parts = shlex.split(raw)
        except ValueError:
            return "SAFE"
        if not parts:
            return "DENY"
        if parts[0] in ("sudo", "su"):
            return "ASK"
        return "SAFE"

@dataclass(slots=True)
class ToolResult:
    ok: bool
    output: str
    error: str = ""

    def as_dict(self) -> dict:
        return {"ok": self.ok, "output": self.output, "error": self.error}

# ══════════════════════════════════════════════════════════════════════
#  NMAP PROFILES / CHEATSHEET
# ══════════════════════════════════════════════════════════════════════

NMAP_PROFILES: Dict[str, List[str]] = {
    "ping":       ["-sn"],
    "discovery":  ["-sn", "-PE", "-PS443", "-PA80", "-PP", "-T4"],
    "sweep":      ["-sn", "-T4"],
    "quick":      ["-T4", "-F"],
    "full":       ["-T4", "-p-"],
    "service":    ["-sV", "-T4", "-p-", "--version-intensity", "5"],
    "os":         ["-O", "--osscan-guess", "-T4"],
    "aggressive": ["-A", "-T4"],
    "stealth":    ["-sS", "-T4", "-Pn"],
    "udp":        ["-sU", "--top-ports", "100", "-T4"],
    "vuln":       ["-sV", "--script", "vuln", "-T4"],
    "default":    ["-sV", "-sC", "-T4"],
    "http":       ["-p", "80,443,8080,8443,8000,8888,3000,5000,9000", "-sV", "-T4"],
    "smb":        ["-p", "139,445",
                   "--script", "smb-os-discovery,smb-enum-shares,smb-enum-users", "-T4"],
}
NMAP_SAFE_PROFILES = {"ping", "discovery", "sweep"}

NMAP_CHEATSHEET = """\
NMAP PROFILES (call nmap with {"target": "...", "profile": "NAME"}):

  ping        -sn                                 host discovery only
  discovery   -sn -PE -PS443 -PA80 -PP -T4        thorough host discovery
  sweep       -sn -T4                             CIDR ping sweep
  quick       -T4 -F                              top-100 TCP ports
  full        -T4 -p-                             all 65535 TCP ports
  service     -sV -T4 -p- --version-intensity 5   service/version detection
  os          -O --osscan-guess -T4               OS fingerprint
  aggressive  -A -T4                              OS+ver+NSE+traceroute
  stealth     -sS -T4 -Pn                         SYN scan (root), no ICMP
  udp         -sU --top-ports 100 -T4             UDP top-100
  vuln        -sV --script vuln -T4               known CVE NSE scripts
  default     -sV -sC -T4                         default NSE scripts
  http        -p 80,443,8080,8443,8000,8888,3000,5000,9000 -sV -T4
  smb         -p 139,445 --script smb-os-discovery,smb-enum-shares,smb-enum-users -T4

EXTRAS
  • Custom NSE script:  {"script": "http-enum"}
  • Arbitrary flags:    {"options": ["-Pn", "-v", "-oN", "scan.txt"]}
  • Target formats:     IP | hostname | CIDR (e.g. 10.0.0.0/24) | range

BIG-NET RECON WORKFLOW
  1) nmap profile="discovery" over the CIDR         → live hosts
  2) nmap profile="quick" per host                  → open TCP ports
  3) nmap profile="service" on interesting hosts    → versions
  4) whatweb / httpx / nikto on web ports
  5) gobuster / dirb / ffuf to enumerate content
  6) nmap profile="vuln" or nuclei on web/DB
  7) sqlmap / wpscan on the specific apps
  8) searchsploit against found versions
"""

# ══════════════════════════════════════════════════════════════════════
#  LOCAL TOOLS
# ══════════════════════════════════════════════════════════════════════

class LocalTools:
    def __init__(self, policy: ToolPolicy, cwd: Path, mode: str = "confirm-dangerous",
                 max_confirm: int = DEFAULT_CONFIRM_LIMIT):
        self.policy = policy
        self.mode = mode
        self.max_confirm = max_confirm
        self.confirm_count = 0
        self.cwd = cwd

        self.handlers: Dict[str, Callable[[dict], ToolResult]] = {
            "bash":           self.bash,
            "read_file":      self.read_file,
            "write_file":     self.write_file,
            "list_directory": self.list_directory,
            "processes":      self.processes,
            "systemctl":      self.systemctl,
            "git":            self.git,
            "python":         self.python,
            "curl":           self.curl,
            "ip_addr":        self.ip_addr,
            "ip_route":       self.ip_route,
            "ip_neigh":       self.ip_neigh,
            "ss":             self.ss,
            "ping":           self.ping,
            "traceroute":     self.traceroute,
            "dig":            self.dig,
            "whois":          self.whois,
            "nmap":           self.nmap,
            "masscan":        self._simple("masscan", intrusive=True),
            "arp_scan":       self._simple("arp-scan", intrusive=True),
            "web_fetch":      self.web_fetch,
            "web_headers":    self.web_headers,
            "gobuster":       self._simple("gobuster", intrusive=True),
            "dirb":           self._simple("dirb", intrusive=True),
            "ffuf":           self._simple("ffuf", intrusive=True),
            "nikto":          self._simple("nikto", intrusive=True),
            "whatweb":        self._simple("whatweb", intrusive=False),
            "wafw00f":        self._simple("wafw00f", intrusive=False),
            "sqlmap":         self._simple("sqlmap", intrusive=True),
            "wpscan":         self._simple("wpscan", intrusive=True),
            "nuclei":         self._simple("nuclei", intrusive=True),
            "httpx":          self._simple("httpx", intrusive=False),
            "dnsrecon":       self._simple("dnsrecon", intrusive=False),
            "dnsenum":        self._simple("dnsenum", intrusive=False),
            "amass":          self._simple("amass", intrusive=False),
            "subfinder":      self._simple("subfinder", intrusive=False),
            "enum4linux":     self._simple("enum4linux", intrusive=True),
            "smbclient":      self._simple("smbclient", intrusive=True),
            "smbmap":         self._simple("smbmap", intrusive=True),
            "searchsploit":   self._simple("searchsploit", intrusive=False),
            "hydra":          self._simple("hydra", intrusive=True),
            "john":           self._simple("john", intrusive=True),
            "hashcat":        self._simple("hashcat", intrusive=True),
            "nmap_cheatsheet": self.nmap_cheatsheet,
            "list_tools":     self.list_tools,
        }

    def specs(self) -> dict:
        return {
            "bash":           {"arguments": {"command": "string"},
                               "description": "Run a local shell command subject to policy."},
            "read_file":      {"arguments": {"path": "string", "max_bytes": "integer?"},
                               "description": "Read a UTF-8 text file."},
            "write_file":     {"arguments": {"path": "string", "content": "string"},
                               "description": "Write a text file; confirmation required."},
            "list_directory": {"arguments": {"path": "string?"},
                               "description": "List a directory."},
            "processes":      {"arguments": {},
                               "description": "Show a process snapshot."},
            "systemctl":      {"arguments": {"args": "array[string]"},
                               "description": "Run systemctl."},
            "git":            {"arguments": {"args": "array[string]"},
                               "description": "Run git in the current working directory."},
            "python":         {"arguments": {"code": "string"},
                               "description": "Run Python code; confirmation required."},
            "curl":           {"arguments": {"args": "array[string]"},
                               "description": "Run curl with safe defaults."},
            "ip_addr":        {"arguments": {},
                               "description": "List network interfaces & addresses."},
            "ip_route":       {"arguments": {},
                               "description": "Show the kernel routing table."},
            "ip_neigh":       {"arguments": {},
                               "description": "Show ARP/neighbour table."},
            "ss":             {"arguments": {"options": "array[string]?"},
                               "description": "Socket statistics (default: -tulnp)."},
            "ping":           {"arguments": {"target": "string", "count": "integer?"},
                               "description": "ICMP echo to a host."},
            "traceroute":     {"arguments": {"target": "string", "max_hops": "integer?"},
                               "description": "Trace the route to a host."},
            "dig":            {"arguments": {"target": "string", "record": "string?", "args": "array[string]?"},
                               "description": "DNS lookup (A/AAAA/MX/TXT/NS/…)."},
            "whois":          {"arguments": {"target": "string"},
                               "description": "WHOIS lookup for a domain or IP."},
            "nmap": {
                "arguments": {
                    "target":  "string IP/host/CIDR/range",
                    "profile": "string? ping|discovery|sweep|quick|full|service|os|aggressive|stealth|udp|vuln|default|http|smb",
                    "script":  "string? NSE script e.g. 'http-enum'",
                    "options": "array[string]? extra nmap flags",
                },
                "description": "Nmap port/service/OS/vuln scanner with profiles.",
            },
            "masscan":        {"arguments": {"args": "array[string]"},
                               "description": "Masscan fast port scanner."},
            "arp_scan":       {"arguments": {"args": "array[string]?"},
                               "description": "ARP scan of the local subnet."},
            "web_fetch":      {"arguments": {"url": "string", "max_bytes": "integer?", "timeout": "number?"},
                               "description": "Fetch a URL; returns status + headers + body (page source)."},
            "web_headers":    {"arguments": {"url": "string"},
                               "description": "Fetch only HTTP headers of a URL."},
            "gobuster":       {"arguments": {"args": "array[string]"},
                               "description": "gobuster dir/dns/vhost brute-force."},
            "dirb":           {"arguments": {"args": "array[string]"},
                               "description": "dirb web content scanner."},
            "ffuf":           {"arguments": {"args": "array[string]"},
                               "description": "ffuf fast web fuzzer."},
            "nikto":          {"arguments": {"args": "array[string]"},
                               "description": "nikto web server vulnerability scanner."},
            "whatweb":        {"arguments": {"args": "array[string]"},
                               "description": "whatweb web tech fingerprinting."},
            "wafw00f":        {"arguments": {"args": "array[string]"},
                               "description": "wafw00f WAF detection."},
            "sqlmap":         {"arguments": {"args": "array[string]"},
                               "description": "sqlmap SQL injection detection/exploitation."},
            "wpscan":         {"arguments": {"args": "array[string]"},
                               "description": "wpscan WordPress vulnerability scanner."},
            "nuclei":         {"arguments": {"args": "array[string]"},
                               "description": "nuclei template-based vulnerability scanner."},
            "httpx":          {"arguments": {"args": "array[string]"},
                               "description": "httpx HTTP probing (title, tech, status)."},
            "dnsrecon":       {"arguments": {"args": "array[string]"},
                               "description": "dnsrecon DNS enumeration."},
            "dnsenum":        {"arguments": {"args": "array[string]"},
                               "description": "dnsenum DNS enumeration."},
            "amass":          {"arguments": {"args": "array[string]"},
                               "description": "amass subdomain / attack-surface enumeration."},
            "subfinder":      {"arguments": {"args": "array[string]"},
                               "description": "subfinder passive subdomain discovery."},
            "enum4linux":     {"arguments": {"args": "array[string]"},
                               "description": "enum4linux SMB/Windows enumeration."},
            "smbclient":      {"arguments": {"args": "array[string]"},
                               "description": "smbclient SMB client."},
            "smbmap":         {"arguments": {"args": "array[string]"},
                               "description": "smbmap SMB share enumeration."},
            "searchsploit":   {"arguments": {"args": "array[string]"},
                               "description": "searchsploit offline Exploit-DB search."},
            "hydra":          {"arguments": {"args": "array[string]"},
                               "description": "hydra online password brute-force (authorised use only)."},
            "john":           {"arguments": {"args": "array[string]"},
                               "description": "john the Ripper hash cracker."},
            "hashcat":        {"arguments": {"args": "array[string]"},
                               "description": "hashcat GPU/CPU hash cracker."},
            "nmap_cheatsheet": {"arguments": {},
                                "description": "Return nmap profile / big-network recon cheatsheet."},
            "list_tools":     {"arguments": {"category": "string?"},
                               "description": "List ALL registered tools (optionally filter by category substring)."},
        }

    def _confirm(self, title: str, details: str) -> bool:
        if self.confirm_count >= self.max_confirm:
            warn(f"confirm limit ({self.max_confirm}) reached — auto-deny")
            return False
        print(f"\n{C.warning}{G.warn} [CONFIRM]{C.R} {C.B}{title}{C.R}")
        for ln in details.splitlines():
            print(f"  {C.dim}│{C.R} {ln}")
        try:
            ans = read_line(f"{C.warning}execute? {C.muted}[y/N]{C.R} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if ans in ("y", "yes"):
            self.confirm_count += 1
            return True
        return False

    def _net_confirm(self, name: str, command: str, intrusive: bool) -> bool:
        if self.mode == "auto-safe":
            if intrusive:
                warn(f"{name}: blocked in auto-safe mode (intrusive)")
                return False
            return True
        if self.mode == "manual-all":
            return self._confirm(f"{name} request", command)
        if intrusive:
            return self._confirm(f"{name} request", command)
        return True

    def _timeout_for(self, tool: str) -> int:
        return TOOL_TIMEOUTS.get(tool, DEFAULT_TOOL_TIMEOUT)

    def _run_argv(self, tool: str, argv: List[str],
                  cwd: Optional[Path] = None,
                  timeout: Optional[int] = None) -> ToolResult:
        exe = shutil.which(tool)
        if not exe:
            return ToolResult(False, "", f"{tool} is not installed")
        to = timeout if timeout is not None else self._timeout_for(tool)
        try:
            proc = subprocess.run(
                [exe, *argv],
                cwd=str(cwd or self.cwd),
                capture_output=True,
                text=True,
                timeout=to,
                env=os.environ.copy(),
            )
        except subprocess.TimeoutExpired:
            return ToolResult(False, "", f"{tool} timed out after {to}s")
        except Exception as exc:
            return ToolResult(False, "", f"{type(exc).__name__}: {exc}")
        out = proc.stdout or ""
        if proc.stderr:
            out += ("\n" if out else "") + proc.stderr
        return ToolResult(proc.returncode == 0, out[-60_000:],
                          f"exit={proc.returncode}" if proc.returncode else "")

    def _simple(self, tool: str, intrusive: bool) -> Callable[[dict], ToolResult]:
        def handler(args: dict) -> ToolResult:
            raw = args.get("args", [])
            if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
                return ToolResult(False, "", "args must be an array of strings")
            cmd_display = tool + " " + " ".join(shlex.quote(x) for x in raw)
            if not self._net_confirm(tool, cmd_display, intrusive):
                return ToolResult(False, "", "denied by mode/policy")
            return self._run_argv(tool, raw)
        return handler

    def execute(self, name: str, arguments: Any) -> ToolResult:
        # tolerate stray parentheses / whitespace around the name
        key = sanitize_tool_name(str(name))
        handler = self.handlers.get(key) or self.handlers.get(str(name).strip())
        if not handler:
            return ToolResult(False, "", f"unknown tool: {name} (did you mean '{key}'?)")
        if not isinstance(arguments, dict):
            return ToolResult(False, "", "tool arguments must be a JSON object")
        try:
            return handler(arguments)
        except subprocess.TimeoutExpired:
            return ToolResult(False, "", "tool timed out")
        except Exception as exc:
            return ToolResult(False, "", f"{type(exc).__name__}: {exc}")

    def bash(self, args: dict) -> ToolResult:
        command = str(args.get("command", ""))
        cls = self.policy.classify_bash(command)
        if cls == "DENY":
            return ToolResult(False, "", "denied by safety policy")
        if self.mode == "manual-all" or cls == "ASK":
            if not self._confirm("bash request", command):
                return ToolResult(False, "", "user denied")
        shell = shutil.which("bash") or shutil.which("sh")
        if not shell:
            return ToolResult(False, "", "no POSIX shell found")
        flag = "-lc" if Path(shell).name == "bash" else "-c"
        proc = subprocess.run([shell, flag, command], cwd=str(self.cwd),
                              capture_output=True, text=True,
                              timeout=DEFAULT_TIMEOUT, env=os.environ.copy())
        out = proc.stdout or ""
        if proc.stderr:
            out += ("\n" if out else "") + proc.stderr
        return ToolResult(proc.returncode == 0, out[-20_000:],
                          f"exit={proc.returncode}" if proc.returncode else "")

    def _resolve(self, path: str) -> Path:
        p = Path(path).expanduser()
        if not p.is_absolute():
            p = self.cwd / p
        return p.resolve()

    def read_file(self, args: dict) -> ToolResult:
        p = self._resolve(str(args.get("path", "")))
        if not p.is_file():
            return ToolResult(False, "", f"not a file: {p}")
        max_bytes = int(args.get("max_bytes", 200_000))
        return ToolResult(True, p.read_bytes()[:max_bytes].decode("utf-8", errors="replace"))

    def write_file(self, args: dict) -> ToolResult:
        p = self._resolve(str(args.get("path", "")))
        content = str(args.get("content", ""))
        if not self._confirm("write file", f"path: {p}\nbytes: {len(content.encode('utf-8'))}"):
            return ToolResult(False, "", "user denied")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
        return ToolResult(True, f"wrote {p}")

    def list_directory(self, args: dict) -> ToolResult:
        p = self._resolve(str(args.get("path") or "."))
        if not p.is_dir():
            return ToolResult(False, "", f"not a directory: {p}")
        rows = []
        for child in sorted(p.iterdir(), key=lambda x: (not x.is_dir(), x.name.lower()))[:500]:
            icon = f"{C.info}{G.dir}{C.R}" if child.is_dir() else f"{C.muted}{G.file}{C.R}"
            rows.append(f"{icon} {child.name}")
        return ToolResult(True, "\n".join(rows))

    def processes(self, args: dict) -> ToolResult:
        proc = subprocess.run(
            ["ps", "-eo", "pid,ppid,%cpu,%mem,stat,comm,args", "--sort=-%mem"],
            capture_output=True, text=True, timeout=20,
        )
        return ToolResult(proc.returncode == 0, proc.stdout[:20_000], proc.stderr.strip())

    def systemctl(self, args: dict) -> ToolResult:
        raw = args.get("args", [])
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            return ToolResult(False, "", "args must be an array of strings")
        command = "systemctl " + " ".join(shlex.quote(x) for x in raw)
        cls = self.policy.classify_bash(command)
        if cls == "DENY":
            return ToolResult(False, "", "denied by policy")
        if self.mode == "manual-all" or cls == "ASK":
            if not self._confirm("systemctl request", command):
                return ToolResult(False, "", "user denied")
        proc = subprocess.run(["systemctl", *raw], capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return ToolResult(proc.returncode == 0, out,
                          f"exit={proc.returncode}" if proc.returncode else "")

    def git(self, args: dict) -> ToolResult:
        raw = args.get("args", [])
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            return ToolResult(False, "", "args must be an array of strings")
        command = "git " + " ".join(shlex.quote(x) for x in raw)
        cls = self.policy.classify_bash(command)
        if cls == "DENY":
            return ToolResult(False, "", "denied by policy")
        if self.mode == "manual-all" or cls == "ASK":
            if not self._confirm("git request", command):
                return ToolResult(False, "", "user denied")
        proc = subprocess.run(["git", *raw], cwd=str(self.cwd),
                              capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return ToolResult(proc.returncode == 0, out,
                          f"exit={proc.returncode}" if proc.returncode else "")

    def python(self, args: dict) -> ToolResult:
        code = str(args.get("code", ""))
        if not code.strip():
            return ToolResult(False, "", "empty code")
        if not self._confirm("python execution", code):
            return ToolResult(False, "", "user denied")
        proc = subprocess.run([sys.executable, "-c", code], cwd=str(self.cwd),
                              capture_output=True, text=True, timeout=DEFAULT_TIMEOUT)
        out = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        return ToolResult(proc.returncode == 0, out,
                          f"exit={proc.returncode}" if proc.returncode else "")

    _CURL_SAFE = ("--max-time", "15", "--max-filesize", "1M", "--fail", "--silent", "--show-error")
    _CURL_DENY = ("--data", "--data-raw", "--data-binary", "--upload-file", "-F", "--form")

    def curl(self, args: dict) -> ToolResult:
        raw = args.get("args", [])
        if not isinstance(raw, list) or not all(isinstance(x, str) for x in raw):
            return ToolResult(False, "", "args must be an array of strings")
        for bad in self._CURL_DENY:
            if any(bad in a for a in raw):
                return ToolResult(False, "", f"curl option {bad} is not allowed")
        command = "curl " + " ".join(shlex.quote(x) for x in (self._CURL_SAFE + tuple(raw)))
        cls = self.policy.classify_bash(command)
        if cls == "DENY":
            return ToolResult(False, "", "denied by policy")
        if self.mode == "manual-all" or cls == "ASK":
            if not self._confirm("curl request", command):
                return ToolResult(False, "", "user denied")
        proc = subprocess.run(["curl", *self._CURL_SAFE, *raw],
                              capture_output=True, text=True, timeout=20)
        return ToolResult(proc.returncode == 0, (proc.stdout or "")[:20_000], proc.stderr.strip())

    def ip_addr(self, args: dict) -> ToolResult:
        if shutil.which("ip"):
            return self._run_argv("ip", ["addr", "show"])
        if shutil.which("ifconfig"):
            return self._run_argv("ifconfig", ["-a"])
        return ToolResult(False, "", "neither 'ip' nor 'ifconfig' available")

    def ip_route(self, args: dict) -> ToolResult:
        if shutil.which("ip"):
            return self._run_argv("ip", ["route", "show"])
        if shutil.which("route"):
            return self._run_argv("route", ["-n"])
        return ToolResult(False, "", "no 'ip' or 'route' binary")

    def ip_neigh(self, args: dict) -> ToolResult:
        if shutil.which("ip"):
            return self._run_argv("ip", ["neigh", "show"])
        if shutil.which("arp"):
            return self._run_argv("arp", ["-an"])
        return ToolResult(False, "", "no 'ip neigh' or 'arp'")

    def ss(self, args: dict) -> ToolResult:
        opts = args.get("options", ["-tulnp"])
        if not isinstance(opts, list) or not all(isinstance(x, str) for x in opts):
            opts = ["-tulnp"]
        if shutil.which("ss"):
            return self._run_argv("ss", opts)
        if shutil.which("netstat"):
            return self._run_argv("netstat", opts)
        return ToolResult(False, "", "no 'ss' or 'netstat'")

    def ping(self, args: dict) -> ToolResult:
        target = str(args.get("target", "")).strip()
        if not target:
            return ToolResult(False, "", "target required")
        count = int(args.get("count", 4))
        if shutil.which("ping"):
            return self._run_argv("ping", ["-c", str(count), target])
        return ToolResult(False, "", "ping not installed")

    def traceroute(self, args: dict) -> ToolResult:
        target = str(args.get("target", "")).strip()
        if not target:
            return ToolResult(False, "", "target required")
        hops = int(args.get("max_hops", 30))
        binary = _first_which(["traceroute", "tracepath"])
        if not binary:
            return ToolResult(False, "", "traceroute / tracepath not installed")
        tool = Path(binary).name
        return self._run_argv(tool, ["-m", str(hops), target])

    def dig(self, args: dict) -> ToolResult:
        target = str(args.get("target", "")).strip()
        if not target:
            return ToolResult(False, "", "target required")
        record = args.get("record")
        extra  = args.get("args", [])
        if not isinstance(extra, list):
            extra = []
        argv: List[str] = []
        if record:
            argv.append(str(record))
        argv.append(target)
        argv += [str(x) for x in extra]
        if shutil.which("dig"):
            return self._run_argv("dig", argv)
        if shutil.which("nslookup"):
            return self._run_argv("nslookup", [target])
        if shutil.which("host"):
            return self._run_argv("host", argv)
        return ToolResult(False, "", "no dig/nslookup/host installed")

    def whois(self, args: dict) -> ToolResult:
        target = str(args.get("target", "")).strip()
        if not target:
            return ToolResult(False, "", "target required")
        return self._run_argv("whois", [target])

    def nmap(self, args: dict) -> ToolResult:
        target = str(args.get("target", "")).strip()
        if not target:
            return ToolResult(False, "", "target required (IP / host / CIDR / range)")
        profile = str(args.get("profile", "quick")).strip().lower()
        base = NMAP_PROFILES.get(profile)
        if base is None:
            return ToolResult(False, "",
                              f"unknown profile '{profile}'. "
                              f"Valid: {', '.join(NMAP_PROFILES)}")
        options = args.get("options", [])
        if not isinstance(options, list) or not all(isinstance(x, str) for x in options):
            options = []
        script = args.get("script")

        argv: List[str] = list(base)
        if script and "--script" not in " ".join(base):
            argv += ["--script", str(script)]
        argv += options
        argv.append(target)

        cmd_display = "nmap " + " ".join(shlex.quote(x) for x in argv)
        intrusive = profile not in NMAP_SAFE_PROFILES
        if not self._net_confirm("nmap", cmd_display, intrusive):
            return ToolResult(False, "", "denied by mode/policy")
        return self._run_argv("nmap", argv)

    def web_fetch(self, args: dict) -> ToolResult:
        url = str(args.get("url", "")).strip()
        if not url:
            return ToolResult(False, "", "url required")
        if not _RE_URL.match(url):
            url = "http://" + url
        max_bytes = int(args.get("max_bytes", 200_000))
        timeout   = float(args.get("timeout", 20))
        if not self._net_confirm("web_fetch", f"GET {url}", intrusive=False):
            return ToolResult(False, "", "denied by mode/policy")
        req = urllib.request.Request(
            url, headers={"User-Agent": "Mozilla/5.0 (LocalGGUFAgent)"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status  = resp.status
                headers = list(resp.headers.items())
                body    = resp.read(max_bytes)
        except urllib.error.HTTPError as e:
            body_bytes = e.read(max_bytes) if hasattr(e, "read") else b""
            return ToolResult(False, "",
                              f"HTTP {e.code} {e.reason}\n"
                              + body_bytes.decode("utf-8", errors="replace")[:4000])
        except Exception as exc:
            return ToolResult(False, "", f"{type(exc).__name__}: {exc}")

        header_str = "\n".join(f"{k}: {v}" for k, v in headers)
        text = body.decode("utf-8", errors="replace")
        payload = (
            f"HTTP {status}\nURL: {url}\n"
            f"--- HEADERS ---\n{header_str}\n"
            f"--- BODY (first {max_bytes} bytes) ---\n{text}"
        )
        return ToolResult(True, payload)

    def web_headers(self, args: dict) -> ToolResult:
        url = str(args.get("url", "")).strip()
        if not url:
            return ToolResult(False, "", "url required")
        if not _RE_URL.match(url):
            url = "http://" + url
        if not self._net_confirm("web_headers", f"HEAD {url}", intrusive=False):
            return ToolResult(False, "", "denied by mode/policy")
        req = urllib.request.Request(
            url, method="HEAD",
            headers={"User-Agent": "Mozilla/5.0 (LocalGGUFAgent)"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                headers = list(resp.headers.items())
                status  = resp.status
        except urllib.error.HTTPError as e:
            headers = list(e.headers.items()) if e.headers else []
            status  = e.code
        except Exception as exc:
            return ToolResult(False, "", f"{type(exc).__name__}: {exc}")
        header_str = "\n".join(f"{k}: {v}" for k, v in headers)
        return ToolResult(True, f"HTTP {status}\n{header_str}")

    def nmap_cheatsheet(self, args: dict) -> ToolResult:
        return ToolResult(True, NMAP_CHEATSHEET)

    def list_tools(self, args: dict) -> ToolResult:
        category = str(args.get("category") or "").strip().lower()
        lines = []
        for name, spec in self.specs().items():
            haystack = (name + " " + spec.get("description", "")).lower()
            if category and category not in haystack:
                continue
            arg_names = list((spec.get("arguments") or {}).keys())
            arg_str = ", ".join(arg_names) if arg_names else ""
            lines.append(f"- {name}({arg_str}) — {spec.get('description','')}")
        if not lines:
            return ToolResult(False, "", f"no tools match category '{category}'")
        header = f"TOOL CATALOG ({len(lines)} entries"
        header += f", filter='{category}')" if category else ")"
        return ToolResult(True, header + "\n" + "\n".join(lines))

# ══════════════════════════════════════════════════════════════════════
#  COMPACT SPEC FORMATTERS
# ══════════════════════════════════════════════════════════════════════

def format_specs_full(specs: dict) -> str:
    lines = []
    for name, spec in specs.items():
        arg_names = list((spec.get("arguments") or {}).keys())
        arg_str = ", ".join(arg_names) if arg_names else ""
        lines.append(f"- {name}({arg_str}) — {spec.get('description','')}")
    return "\n".join(lines)

def format_specs_core(specs: dict, core_names: List[str]) -> str:
    lines = []
    for name in core_names:
        spec = specs.get(name)
        if not spec:
            continue
        arg_names = list((spec.get("arguments") or {}).keys())
        arg_str = ", ".join(arg_names) if arg_names else ""
        lines.append(f"- {name}({arg_str}) — {spec.get('description','')}")
    others = [n for n in specs if n not in core_names]
    if others:
        lines.append("")
        lines.append(
            "Other tools exist but are not listed here. Use "
            "list_tools() to see the full catalog, then call by name."
        )
        lines.append("Hidden tools: " + ", ".join(others))
    return "\n".join(lines)

# ══════════════════════════════════════════════════════════════════════
#  LOCAL LLM ENGINE
# ══════════════════════════════════════════════════════════════════════

_THINK_OPEN_TAGS  = ("<think>", "<thinking>")
_THINK_CLOSE_TAGS = ("</think>", "</thinking>")

class LocalLLM:
    def __init__(self, model_path: str, n_threads: int, n_ctx: int, debug: bool = False):
        self.model_path = model_path
        self.n_threads = n_threads
        self.n_ctx = n_ctx
        self.debug = debug
        self.llm: Optional[Llama] = None
        self._load()

    def _load(self) -> None:
        info(f"loading model {C.muted}{self.model_path}{C.R}")
        info(f"threads {C.B}{self.n_threads}{C.R} · ctx {C.B}{self.n_ctx}{C.R}")
        t0 = time.perf_counter()
        try:
            self.llm = Llama(
                model_path=self.model_path,
                n_ctx=self.n_ctx,
                n_threads=self.n_threads,
                n_batch=512,
                use_mmap=True,
                use_mlock=False,
                verbose=self.debug,
            )
        except Exception as exc:
            err(f"model load failed: {exc}")
            raise
        ok(f"model ready in {C.B}{time.perf_counter() - t0:.2f}s{C.R}")

    @staticmethod
    def _collect_delta(delta: dict) -> Tuple[str, str, list]:
        content   = delta.get("content") or ""
        reasoning = delta.get("reasoning_content") or delta.get("thinking") or ""
        tcs       = delta.get("tool_calls") or []
        return content, reasoning, tcs

    def _normalize_tool_calls(self, tcs: list) -> str:
        out = []
        for tc in tcs:
            fn = tc.get("function") or tc
            name = sanitize_tool_name(fn.get("name") or "?")
            args = fn.get("arguments") or "{}"
            if isinstance(args, str):
                try:
                    args = json.loads(args)
                except Exception:
                    args = {"_raw": args}
            payload = json.dumps({"tool": name, "arguments": args}, ensure_ascii=False)
            out.append(f"\n{TOOL_BEGIN}\n{payload}\n{TOOL_END}\n")
        return "".join(out)

    def generate(self, messages: List[dict], max_tokens: int,
                 temperature: float = DEFAULT_TEMPERATURE,
                 live: bool = True) -> str:
        if not self.llm:
            raise RuntimeError("model not loaded")

        content_parts:   List[str] = []
        reasoning_parts: List[str] = []
        toolcall_parts:  List[dict] = []
        got_any = False
        t_start = time.monotonic()

        stop_event = threading.Event()
        ticker_thread: Optional[threading.Thread] = None
        ticker_running = False
        ticker_stopped = False

        def _start_ticker() -> None:
            nonlocal ticker_thread, ticker_running
            if not live or not sys.stderr.isatty():
                return
            ticker_running = True
            ticker_thread = threading.Thread(
                target=_waiting_ticker, args=(stop_event, t_start), daemon=True
            )
            ticker_thread.start()

        def _kill_ticker() -> None:
            nonlocal ticker_stopped
            if ticker_stopped:
                return
            ticker_stopped = True
            stop_event.set()
            if ticker_thread is not None:
                ticker_thread.join(timeout=0.4)
            if ticker_running:
                _clear_ticker()

        streamed_accum = ""

        def _emit_content_piece(piece: str) -> None:
            nonlocal streamed_accum
            streamed_accum += piece
            opens  = sum(streamed_accum.count(t) for t in _THINK_OPEN_TAGS)
            closes = sum(streamed_accum.count(t) for t in _THINK_CLOSE_TAGS)
            in_think = opens > closes
            clean = piece
            for tag in _THINK_OPEN_TAGS + _THINK_CLOSE_TAGS:
                clean = clean.replace(tag, "")
            if not clean:
                return
            if in_think:
                sys.stdout.write(f"{C.reason}{clean}{C.R}")
            else:
                sys.stdout.write(clean)
            sys.stdout.flush()

        _start_ticker()

        try:
            stream = self.llm.create_chat_completion(
                messages=messages,
                max_tokens=max_tokens,
                temperature=temperature,
                stream=True,
            )
            for chunk in stream:
                choices = chunk.get("choices")
                if not choices:
                    continue
                delta = choices[0].get("delta") or {}
                content, reasoning, tcs = self._collect_delta(delta)

                if (content or reasoning or tcs) and not ticker_stopped:
                    _kill_ticker()
                    sys.stdout.write("\n")
                    sys.stdout.flush()

                if content:
                    got_any = True
                    content_parts.append(content)
                    _emit_content_piece(content)

                if reasoning:
                    got_any = True
                    reasoning_parts.append(reasoning)
                    sys.stdout.write(f"{C.reason}{reasoning}{C.R}")
                    sys.stdout.flush()

                for tc in tcs:
                    got_any = True
                    toolcall_parts.append(tc)
        except Exception as exc:
            dbg(f"stream error: {exc}", self.debug)
        finally:
            _kill_ticker()

        if not got_any:
            dbg("streaming produced 0 tokens — retrying non-streaming", self.debug)
            try:
                resp = self.llm.create_chat_completion(
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    stream=False,
                )
                msg = (resp.get("choices") or [{}])[0].get("message") or {}
                c = msg.get("content") or ""
                r = msg.get("reasoning_content") or msg.get("thinking") or ""
                tcs = msg.get("tool_calls") or []
                if c:
                    sys.stdout.write("\n")
                    _emit_content_piece(c)
                    sys.stdout.write("\n")
                    sys.stdout.flush()
                    content_parts.append(c)
                if r:
                    reasoning_parts.append(r)
                for tc in tcs:
                    toolcall_parts.append(tc)
                got_any = bool(c or r or tcs)
            except Exception as exc:
                dbg(f"non-stream error: {exc}", self.debug)

        result = ""
        if reasoning_parts:
            result += "<think>" + "".join(reasoning_parts) + "</think>\n"
        result += "".join(content_parts)
        if toolcall_parts:
            result += self._normalize_tool_calls(toolcall_parts)

        elapsed = time.monotonic() - t_start
        if self.debug:
            dbg(f"generated {len(result)} chars in {elapsed:.2f}s "
                f"(content={sum(len(x) for x in content_parts)} "
                f"reasoning={sum(len(x) for x in reasoning_parts)} "
                f"tool_calls={len(toolcall_parts)})", True)

        return result

# ══════════════════════════════════════════════════════════════════════
#  AGENT
# ══════════════════════════════════════════════════════════════════════

class Agent:
    def __init__(self, llm: LocalLLM, tools: LocalTools,
                 max_tokens: int = DEFAULT_MAX_TOKENS,
                 temperature: float = DEFAULT_TEMPERATURE,
                 tool_set: str = "core",
                 debug: bool = False):
        self.llm = llm
        self.tools = tools
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.tool_set = tool_set
        self.debug = debug
        self.history: List[dict] = []
        self._rebuild_system()

    def _rebuild_system(self) -> None:
        specs = self.tools.specs()
        cwd_line = f"Working directory for relative paths: {self.tools.cwd}"
        if self.tool_set == "all":
            tools_block = "AVAILABLE TOOLS (all registered; call by name):\n" \
                          + format_specs_full(specs)
        else:
            tools_block = "AVAILABLE TOOLS — CORE:\n" \
                          + format_specs_core(specs, CORE_TOOLS)

        content = (
            PROTOCOL_PROMPT
            + "\n" + cwd_line + "\n\n"
            + tools_block
        )
        self._system_msg = {"role": "system", "content": content}
        if self.debug:
            dbg(f"system prompt: {len(content)} chars "
                f"(~{len(content)//4} est. tokens), tool_set={self.tool_set}", True)

    def clear_history(self) -> None:
        self.history.clear()
        ok("history cleared")

    @staticmethod
    def _extract_reasoning(text: str) -> Tuple[str, str]:
        parts: List[str] = []

        def grab(m: re.Match) -> str:
            parts.append(m.group(1).strip())
            return ""

        clean = _RE_THINK_XML.sub(grab, text)
        clean = _RE_REASON_MD.sub(grab, clean)
        clean = _RE_THINK_TAG.sub("", clean)
        return clean.strip(), "\n\n".join(p for p in parts if p).strip()

    @staticmethod
    def _iter_json_objects(s: str) -> Iterator[str]:
        i, n = 0, len(s)
        while i < n:
            if s[i] != "{":
                i += 1
                continue
            start, depth = i, 0
            in_str, esc = False, False
            j = i
            closed = False
            while j < n:
                ch = s[j]
                if in_str:
                    if esc:
                        esc = False
                    elif ch == "\\":
                        esc = True
                    elif ch == '"':
                        in_str = False
                else:
                    if ch == '"':
                        in_str = True
                    elif ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            yield s[start:j + 1]
                            i = j + 1
                            closed = True
                            break
                j += 1
            if not closed:
                return

    @staticmethod
    def _coerce_call(body: str) -> Optional[dict]:
        body = body.strip()
        body = _RE_FENCE_OPEN.sub("", body)
        body = _RE_FENCE_CLOSE.sub("", body).strip()
        for candidate in Agent._iter_json_objects(body):
            try:
                data = json.loads(candidate)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue
            if not isinstance(data.get("tool"), str):
                continue
            tool_name = sanitize_tool_name(data["tool"])
            if not tool_name:
                continue
            args = data.get("arguments")
            if args is None:
                args = {}
            if not isinstance(args, dict):
                return {"__invalid__": "arguments must be a JSON object", "raw": candidate}
            return {"tool": tool_name, "arguments": args}
        return None

    def _find_tool_call(self, raw: str) -> Optional[dict]:
        if TOOL_BEGIN in raw:
            body = raw.split(TOOL_BEGIN, 1)[1]
            if TOOL_END in body:
                body = body.split(TOOL_END, 1)[0]
            tc = self._coerce_call(body)
            if tc and "__invalid__" not in tc:
                return tc

        m = _RE_TOOLCALL.search(raw)
        if m:
            tc = self._coerce_call(m.group(1))
            if tc and "__invalid__" not in tc:
                return tc

        for m in _RE_FENCE_JSON.finditer(raw):
            tc = self._coerce_call(m.group(1))
            if tc and "__invalid__" not in tc:
                return tc

        last: Optional[dict] = None
        for obj in self._iter_json_objects(raw):
            if '"tool"' not in obj:
                continue
            tc = self._coerce_call(obj)
            if tc and "__invalid__" not in tc:
                last = tc
        return last

    def _tool_result_message(self, name: str, result: ToolResult) -> str:
        payload = {"tool": name, "result": result.as_dict()}
        return (
            "TOOL RESULT FROM LOCAL CONTROLLER:\n"
            + safe_json(payload)
            + "\nContinue the task. Do not repeat the same tool call unless it failed."
        )

    def _build_messages(self, user_msg: str) -> List[dict]:
        return [self._system_msg, *self.history, {"role": "user", "content": user_msg}]

    def ask(self, user_input: str, max_tool_calls: int = 20,
            live_stream: bool = True) -> Tuple[str, str]:
        current = user_input
        reasoning_parts: List[str] = []
        final = ""

        for hop in range(max_tool_calls + 1):
            messages = self._build_messages(user_input if hop == 0 else current)

            ai_label()
            raw = self.llm.generate(
                messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                live=live_stream,
            )
            print()

            if not raw.strip():
                warn("model returned no tokens (empty generation)")
                warn("hint: try a larger model, or run with --tool-set core / --debug")
                final = "(model produced no output — see warnings above)"
                self.history.append({"role": "assistant", "content": final})
                break

            clean, reasoning = self._extract_reasoning(raw)
            if reasoning:
                reasoning_parts.append(reasoning)

            tool_call = self._find_tool_call(raw)

            if tool_call is None:
                final = clean or raw.strip()
                if not final:
                    final = "(model returned no visible content)"
                self.history.append({"role": "assistant", "content": final})
                break

            if "__invalid__" in tool_call:
                err(f"invalid tool call: {tool_call['__invalid__']}")
                self.history.append({"role": "assistant", "content": raw})
                current = (
                    "Your previous response contained an invalid tool call "
                    f"({tool_call['__invalid__']}). "
                    f"Re-emit it correctly using the {TOOL_BEGIN} / {TOOL_END} markers, "
                    "with a single JSON object and an `arguments` object."
                )
                continue

            name = tool_call["tool"]
            args = tool_call["arguments"]
            step(f"{G.tool} {C.B}{name}{C.R} {C.muted}{safe_json(args)}{C.R}")

            result = self.tools.execute(name, args)
            icon = G.check if result.ok else G.cross
            col  = C.success if result.ok else C.error
            body = result.output or result.error or "(empty)"
            box(f"tool → {name}", body, col, icon)

            self.history.append({"role": "assistant", "content": raw})
            current = self._tool_result_message(name, result)
        else:
            final = "Agent stopped: max tool-call count reached."

        return final, "\n\n".join(reasoning_parts)

# ══════════════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════════════

def _default_cwd() -> Path:
    env = os.environ.get("LOCAL_AGENT_CWD")
    if env:
        p = Path(env).expanduser()
        if p.is_dir():
            return p
    home = Path.home()
    return home if home.is_dir() else Path.cwd()

def parse_args() -> argparse.Namespace:
    ap = argparse.ArgumentParser(prog="AI", description=f"{APP_NAME} v{VERSION}")
    ap.add_argument("--message", default=None)
    ap.add_argument("--model", default=None)
    ap.add_argument("--cwd", default=None)
    ap.add_argument("--threads", type=int, default=DEFAULT_THREADS)
    ap.add_argument("--ctx-size", type=int, default=DEFAULT_CONTEXT_SIZE)
    ap.add_argument("--max-tokens", type=int, default=DEFAULT_MAX_TOKENS)
    ap.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE)
    ap.add_argument("--max-confirm", type=int, default=DEFAULT_CONFIRM_LIMIT)
    ap.add_argument("--mode", choices=["auto-safe", "confirm-dangerous", "manual-all"],
                    default="confirm-dangerous")
    ap.add_argument("--max-tool-calls", type=int, default=20)
    ap.add_argument("--tool-set", choices=["auto", "core", "all"], default="auto")
    ap.add_argument("--debug", action="store_true")
    ap.add_argument("--no-reasoning", action="store_false", dest="show_reasoning",
                    default=True)
    ap.add_argument("--no-stream", action="store_false", dest="stream",
                    default=True,
                    help="disable live token streaming (ticker + boxes only)")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--skip-tool-check", action="store_true")
    ap.add_argument("--repl", action="store_true", default=True)
    ap.add_argument("--once", action="store_false", dest="repl")
    return ap.parse_args()

def _print_status(model_path: str, args, tools: LocalTools, agent: Agent) -> None:
    print(safe_json({
        "model": model_path,
        "cwd": str(tools.cwd),
        "threads": args.threads,
        "ctx_size": args.ctx_size,
        "max_tokens": args.max_tokens,
        "temperature": args.temperature,
        "history_len": len(agent.history),
        "confirm_count": tools.confirm_count,
        "max_confirm": tools.max_confirm,
        "mode": tools.mode,
        "tools_count": len(tools.specs()),
        "tool_set": agent.tool_set,
    }))

def _print_tools(tools: LocalTools) -> None:
    for name, spec in tools.specs().items():
        print(f"{C.tool}{G.tool}{C.R} {C.B}{name}{C.R} {C.dim}— {spec['description']}{C.R}")

def _self_test(llm: LocalLLM, agent: Agent) -> bool:
    info("self-test 1/2: trivial prompt (no system prompt)")
    try:
        out1 = llm.generate(
            [{"role": "user", "content": "Reply with the single word: OK"}],
            max_tokens=16, temperature=0.0, live=False,
        )
    except Exception as exc:
        err(f"crashed: {exc}")
        return False
    snippet1 = (out1 or "").strip().replace("\n", " ")[:60]
    if not snippet1:
        warn("no tokens returned from trivial prompt")
        return False
    ok(f"trivial prompt OK ({len(out1)} chars): {snippet1!r}")

    info("self-test 2/2: full chat prompt (system + tools)")
    try:
        out2 = llm.generate(
            agent._build_messages("Reply with the single word: OK"),
            max_tokens=24, temperature=0.0, live=False,
        )
    except Exception as exc:
        err(f"crashed: {exc}")
        return False
    snippet2 = (out2 or "").strip().replace("\n", " ")[:60]
    if not snippet2:
        warn("no tokens with full system prompt — this is why REPL was silent")
        warn(f"hint: use --tool-set core or try a bigger model than "
             f"{Path(llm.model_path).name}")
        return False
    ok(f"full chat prompt OK ({len(out2)} chars): {snippet2!r}")
    return True

def main() -> int:
    args = parse_args()
    banner()

    audit = audit_network_tools()
    if not args.skip_tool_check:
        if not report_tool_audit(audit):
            info("exiting per user request")
            return 1
    else:
        if audit.missing:
            warn(f"{len(audit.missing)} network tool(s) missing "
                 f"(skipping prompt): {', '.join(audit.missing)}")

    ok(f"python {sys.version.split()[0]}")
    if check_internet():
        ok("network reachable")
    else:
        warn("no network — some tools may fail")

    model_path = args.model
    if not model_path:
        found = find_gguf_model()
        if found:
            model_path = str(found)
            ok(f"auto-detected model {C.muted}{model_path}{C.R}")
        else:
            err("no .gguf file found next to the script — pass --model")
            return 1
    elif not Path(model_path).exists():
        err(f"model not found: {model_path}")
        return 1

    tool_set = args.tool_set
    size_b = detect_model_size_b(model_path)
    if tool_set == "auto":
        if size_b is not None and size_b >= 1.5:
            tool_set = "all"
        else:
            tool_set = "core"
        size_repr = f"{size_b}B" if size_b is not None else "unknown"
        info(f"model size {C.B}{size_repr}{C.R} → tool-set = {C.B}{tool_set}{C.R}")

    try:
        llm = LocalLLM(model_path, n_threads=args.threads,
                       n_ctx=args.ctx_size, debug=args.debug)
    except Exception:
        return 1

    cwd = Path(args.cwd).expanduser().resolve() if args.cwd else _default_cwd()
    if not cwd.is_dir():
        err(f"cwd does not exist: {cwd}")
        return 1
    ok(f"working directory {C.muted}{cwd}{C.R}")

    policy = ToolPolicy()
    tools = LocalTools(policy, cwd=cwd, mode=args.mode, max_confirm=args.max_confirm)
    agent = Agent(llm, tools,
                  max_tokens=args.max_tokens,
                  temperature=args.temperature,
                  tool_set=tool_set,
                  debug=args.debug)

    spec_names = list(tools.specs().keys())
    ok(f"agent registered {C.B}{len(spec_names)}{C.R} tools "
       f"(advertising {C.B}{len(CORE_TOOLS) if tool_set=='core' else len(spec_names)}{C.R})")

    if args.self_test:
        _self_test(llm, agent)

    show_reasoning = args.show_reasoning or args.debug
    live_stream = args.stream

    def render_result(answer: str, reasoning: str) -> None:
        if reasoning and show_reasoning and not live_stream:
            box("reasoning", reasoning, C.reason, G.brain)
        if answer:
            box("answer", answer, C.ai, G.spark)
        else:
            warn("no answer captured")

    if args.message:
        user_echo(args.message)
        answer, reasoning = agent.ask(args.message,
                                      max_tool_calls=args.max_tool_calls,
                                      live_stream=live_stream)
        render_result(answer, reasoning)
        if not args.repl:
            agent.clear_history()
            return 0

    if args.repl:
        print(f"\n{C.muted}{G.eye}  /help  /status  /tools  /clear  /cwd PATH  /exit{C.R}")
        while True:
            try:
                line = read_line(f"\n{C.user}{C.B}{G.arrow}{C.R} ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                continue
            if line in ("/exit", "/quit"):
                break
            if line == "/help":
                print(f"{C.muted}/status          session state\n"
                      f"/tools           list all tools\n"
                      f"/clear           drop chat history\n"
                      f"/cwd PATH        change working directory\n"
                      f"/exit            quit{C.R}")
                continue
            if line == "/status":
                _print_status(model_path, args, tools, agent)
                continue
            if line == "/tools":
                _print_tools(tools)
                continue
            if line == "/clear":
                agent.clear_history()
                continue
            if line.startswith("/cwd"):
                parts = line.split(maxsplit=1)
                if len(parts) == 2:
                    newp = Path(parts[1]).expanduser().resolve()
                    if newp.is_dir():
                        tools.cwd = newp
                        agent._rebuild_system()
                        ok(f"cwd → {newp}")
                    else:
                        err(f"not a directory: {newp}")
                else:
                    print(f"{C.muted}usage: /cwd PATH{C.R}")
                continue

            user_echo(line)
            answer, reasoning = agent.ask(line,
                                          max_tool_calls=args.max_tool_calls,
                                          live_stream=live_stream)
            render_result(answer, reasoning)

    agent.clear_history()
    info("session ended")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.muted}interrupted{C.R}")
        sys.exit(130)
