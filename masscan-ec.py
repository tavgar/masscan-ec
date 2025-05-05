#!/usr/bin/env python3
"""
masscan-ec
~~~~~~~~~~
A wrapper that adds Naabu‑style “--exclude‑cdn / -ec” behaviour to masscan.

Core ideas
----------
• `-ec / --exclude-cdn`   – limit CDN IPs to a small port list (default 80,443)
• Trailing / internal blank lines, comments, and hostnames in -iL files are
  handled safely.
• Flags (e.g. -p, --ports, --rate) and their parameters are *never* mistaken
  for targets, so masscan always receives a valid port list.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time
from typing import Iterable, Set, Union

# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #
CDN_JSON_URL = (
    "https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/"
    "sources_data.json"
)
CACHE_PATH = pathlib.Path.home() / ".cache" / "masscan_cdn_ranges.json"
CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
CACHE_MAX_AGE_DAYS = 7

# Flags after which masscan expects *one* positional parameter
FLAGS_WITH_PARAM = {
    "-p",
    "--ports",
    "-iX",
    "--pexclude",
    "--excludefile",
    "-oX",
    "-oJ",
    "-oL",
    "-oG",
    "-oB",
    "-iL",
    "--includefile",
    "--rate",
    "--router-mac",
    "--router-ip",
    "--source-ip",
    "--source-port",
    "--source-mac",
    "-e",
    "--interface",
}

# --------------------------------------------------------------------------- #
# CDN helpers                                                                 #
# --------------------------------------------------------------------------- #
def _cache_is_fresh(path: pathlib.Path, max_days: int = CACHE_MAX_AGE_DAYS) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < max_days * 86_400


def _download_sources_json() -> dict:
    from urllib.request import urlopen

    with urlopen(CDN_JSON_URL, timeout=30) as resp:
        return json.loads(resp.read().decode())


def _flatten_cidrs(node: Union[dict, list, str], acc: Set[ipaddress.IPv4Network]):
    """Collect every valid CIDR string in *node* (recursing through dicts/lists)."""
    if isinstance(node, str):
        try:
            acc.add(ipaddress.ip_network(node))
        except ValueError:
            pass
    elif isinstance(node, dict):
        for v in node.values():
            _flatten_cidrs(v, acc)
    elif isinstance(node, list):
        for v in node:
            _flatten_cidrs(v, acc)


def _load_cdn_ranges() -> list[ipaddress.IPv4Network]:
    """Return sorted list of IPv4 CDN networks (cached)."""
    if not _cache_is_fresh(CACHE_PATH):
        try:
            data = _download_sources_json()
            CACHE_PATH.write_text(json.dumps(data))
        except Exception as e:
            if not CACHE_PATH.exists():
                sys.exit(f"[!] Unable to download CDN ranges: {e}")
    else:
        data = json.loads(CACHE_PATH.read_text())

    cidrs: set[ipaddress.IPv4Network] = set()
    _flatten_cidrs(data.get("cdn", {}), cidrs)
    return sorted(cidrs, key=lambda n: (n.network_address, n.prefixlen))


# --------------------------------------------------------------------------- #
# Target expansion & cleaning                                                 #
# --------------------------------------------------------------------------- #
def _clean_line(line: str) -> str:
    """Strip comments & surrounding whitespace; return '' if resulting line is empty."""
    return line.split("#", 1)[0].strip()


def _expand_target_tokens(tokens: list[str]) -> list[str]:
    """
    Return a list of **potential target tokens only**:
      • Reads include files (‑iL/‑‑includefile) and yields their lines.
      • Skips everything that starts with '-'  (flags like -p, --rate etc.).
      • Skips parameters that belong to a flag expecting one (‑p 80, --rate 5000).
    """
    expanded: list[str] = []
    i = 0
    n = len(tokens)

    while i < n:
        tok = tokens[i]

        # Handle include file flag
        if tok in ("-iL", "--includefile"):
            if i + 1 >= n:
                sys.exit("[!] -iL flag provided without a file name.")
            fname = tokens[i + 1]
            for line in pathlib.Path(fname).read_text().splitlines():
                line = _clean_line(line)
                if line:
                    expanded.append(line)
            i += 2
            continue

        # Skip flags and their separate parameters
        if tok.startswith("-"):
            if tok in FLAGS_WITH_PARAM and "=" not in tok:
                i += 2  # flag + param
            else:
                i += 1  # flag alone (e.g. -p1-65535 or --ports=80,443)
            continue

        # Positional token → potential target
        tok = _clean_line(tok)
        if tok:
            expanded.append(tok)
        i += 1

    return expanded


def _resolve_hostname(host: str) -> list[str]:
    """Return *unique* IPv4 strings for *host*.  Empty list if none."""
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except socket.gaierror:
        print(f"[!] Warning: could not resolve {host!r}; skipping.", file=sys.stderr)
        return []


def _split_targets(
    ms_args: list[str], cdn_ranges
) -> tuple[list[str], list[str], set[str]]:
    """
    Parse *ms_args*, returning
      • non_cdn_ips
      • cdn_only_ips
      • seen_targets  – tokens (from CLI) that were used as explicit targets
    """
    non_cdn, cdn_only = [], []
    seen: set[str] = set()

    for item in _expand_target_tokens(ms_args):
        seen.add(item)  # regardless of success; we’ll strip it later

        # Support IP[:port] and CIDR forms
        strip_port = item.split(":", 1)[0]
        try:
            net = ipaddress.ip_network(strip_port, strict=False)
            lst = cdn_only if any(net.overlaps(c) for c in cdn_ranges) else non_cdn
            lst.append(str(net))
            continue
        except ValueError:
            pass  # not an IP/CIDR

        # Try hostname resolution
        ips = _resolve_hostname(strip_port)
        for ip in ips:
            net = ipaddress.ip_network(ip)
            lst = cdn_only if any(net.overlaps(c) for c in cdn_ranges) else non_cdn
            lst.append(ip)

    # Deduplicate while preserving order
    non_cdn = list(dict.fromkeys(non_cdn))
    cdn_only = list(dict.fromkeys(cdn_only))
    return non_cdn, cdn_only, seen


# --------------------------------------------------------------------------- #
# Strip original target arguments so there are no duplicates/invalids         #
# --------------------------------------------------------------------------- #
def _strip_target_args(ms_args: list[str], seen_targets: set[str]) -> list[str]:
    """
    Remove every explicit CLI target (in *seen_targets*) and every -iL/--includefile pair.
    Everything else (flags, port lists, tuning options, etc.) is returned intact.
    """
    stripped: list[str] = []
    i = 0
    n = len(ms_args)

    while i < n:
        arg = ms_args[i]

        # Drop include file flag + filename
        if arg in ("-iL", "--includefile"):
            i += 2
            continue

        # Drop positional target tokens we already extracted
        if arg in seen_targets:
            i += 1
            continue

        # Keep flags (and their param if separate)
        stripped.append(arg)
        if arg in FLAGS_WITH_PARAM and "=" not in arg:
            if i + 1 < n:
                stripped.append(ms_args[i + 1])
            i += 2
        else:
            i += 1

    return stripped


def _write_tempfile(targets: list[str]) -> str:
    """Write *targets* (no blanks) to a temp file, returning its path."""
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("\n".join(targets))
        return tf.name


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #
def main() -> None:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-ec", "--exclude-cdn", action="store_true", dest="ec")
    parser.add_argument(
        "--cdn-ports",
        default="80,443",
        metavar="PORTS",
        help="Port list used for CDN IPs when -ec is active (default: 80,443)",
    )
    args, ms_args = parser.parse_known_args()

    # Fast path – no CDN logic requested.
    if not args.ec:
        os.execvp("masscan", ["masscan", *ms_args])

    cdn_ranges = _load_cdn_ranges()
    non_cdn, cdn_only, seen_targets = _split_targets(ms_args, cdn_ranges)
    ms_args_clean = _strip_target_args(ms_args, seen_targets)

    # Restricted scan for CDN addresses
    if cdn_only:
        print(f"[+] {len(cdn_only)} CDN targets → ports {args.cdn_ports}")
        tf = _write_tempfile(cdn_only)
        subprocess.run(
            ["masscan", "-p", args.cdn_ports, "-iL", tf, *ms_args_clean],
            check=False,
        )
        os.unlink(tf)

    # Full scan for everything else
    if non_cdn:
        print(f"[+] {len(non_cdn)} non‑CDN targets → full scan")
        tf = _write_tempfile(non_cdn)
        subprocess.run(["masscan", "-iL", tf, *ms_args_clean], check=False)
        os.unlink(tf)


if __name__ == "__main__":
    main()
