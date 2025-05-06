"""
masscan-ec
~~~~~~~~~~
A wrapper that adds Naabu‑style “--exclude‑cdn / -ec” behaviour to **masscan**.

Key points
----------
• `-ec / --exclude-cdn`   → **skip** every IP that belongs to a CDN network, never probed at all.  
• CDN ranges pulled from seven public feeds and cached locally:
  – ProjectDiscovery *cdncheck* mega‑list  
  – Cloudflare official list  
  – AWS **CloudFront** only  
  – Google **CDN / APIs** (goog − cloud)  
  – Fastly public list  
  – Akamai (MISP warninglist)  
• `--cdn-extra-file FILE` lets you inject your own CIDRs; `--refresh-cdn-cache` forces a refresh.
• Blank lines, comments, hostnames, and include‑files are handled safely.
• Command‑line flags (‑p, --rate, …) are never mistaken for targets.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import tempfile
import time
from typing import Set

# --------------------------------------------------------------------------- #
# Config                                                                      #
# --------------------------------------------------------------------------- #
CDN_SOURCE_URLS = [
    # Community‑maintained mega‑list aggregating dozens of providers
    "https://raw.githubusercontent.com/projectdiscovery/cdncheck/main/sources_data.json",
    # Cloudflare official list
    "https://www.cloudflare.com/ips-v4",
    # AWS global list – we’ll keep only CLOUDFRONT ranges
    "https://ip-ranges.amazonaws.com/ip-ranges.json",
    # Google: full public ranges & customer ranges (we’ll keep goog − cloud)
    "https://www.gstatic.com/ipranges/goog.json",
    "https://www.gstatic.com/ipranges/cloud.json",
    # Fastly
    "https://api.fastly.com/public-ip-list",
    # Akamai (BGP‑derived list maintained by MISP project)
    "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/akamai/list.json",
]

CACHE_PATH = pathlib.Path.home() / ".cache" / "masscan_cdn_ranges.json"
CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
CACHE_MAX_AGE_DAYS = 3

# Flags after which masscan expects *one* positional parameter
FLAGS_WITH_PARAM = {
    "-p", "--ports", "-iX", "--pexclude", "--excludefile", "-oX", "-oJ", "-oL",
    "-oG", "-oB", "-iL", "--includefile", "--rate", "--router-mac", "--router-ip",
    "--source-ip", "--source-port", "--source-mac", "-e", "--interface",
}

# --------------------------------------------------------------------------- #
# CDN helpers                                                                 #
# --------------------------------------------------------------------------- #
CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b")


def _cache_is_fresh(path: pathlib.Path, max_days: int = CACHE_MAX_AGE_DAYS) -> bool:
    return path.exists() and (time.time() - path.stat().st_mtime) < max_days * 86_400


def _download_text(url: str) -> str:
    """Download *url* and return its decoded text.
    Adds a browser‑like User‑Agent header to sail past providers (e.g. Cloudflare)
    that block the default *Python‑urllib* UA and would otherwise return 403.
    """
    from urllib.request import Request, urlopen, HTTPError, URLError

    headers = {"User-Agent": "Mozilla/5.0 (compatible; masscan-ec/1.0; +https://github.com/yourname/masscan-ec)"}
    req = Request(url, headers=headers)
    try:
        with urlopen(req, timeout=45) as resp:
            return resp.read().decode()
    except HTTPError as e:
        # Some feeds (rare) may block non‑GET methods or need Accept headers.
        # Raise for everything except 403/429, which we treat as hard‑fail so we
        # can continue with the other feeds gracefully.
        raise e


def _download_and_extract_cidrs() -> Set[str]:
    """Download all feeds and return a *deduplicated* set of IPv4 CIDR strings."""
    generic: Set[str] = set()
    goog_all: Set[str] = set()
    goog_cloud: Set[str] = set()

    for url in CDN_SOURCE_URLS:
        try:
            txt = _download_text(url)
        except Exception as e:
            print(f"[!] Warning: could not fetch {url}: {e}", file=sys.stderr)
            continue

        # ------------------------------------------------------------------ #
        # AWS – keep only CloudFront
        # ------------------------------------------------------------------ #
        if url.endswith("ip-ranges.json"):
            try:
                data = json.loads(txt)
                for pre in data.get("prefixes", []):
                    if pre.get("service") == "CLOUDFRONT":
                        generic.add(pre["ip_prefix"])
                continue
            except Exception:
                pass  # fall through to generic extractor if JSON parse fails

        # ------------------------------------------------------------------ #
        # Google feeds – we want: goog.json minus cloud.json
        # ------------------------------------------------------------------ #
        if url.endswith("goog.json") or url.endswith("cloud.json"):
            try:
                data = json.loads(txt)
                for pre in data.get("prefixes", []):
                    cidr = pre.get("ipv4Prefix")
                    if cidr:
                        if url.endswith("goog.json"):
                            goog_all.add(cidr)
                        else:  # cloud.json
                            goog_cloud.add(cidr)
                continue
            except Exception:
                pass  # fall through to generic extractor if JSON parse fails

        # ------------------------------------------------------------------ #
        # Akamai & every other feed – just grab any CIDR looking string
        # ------------------------------------------------------------------ #
        generic.update(CIDR_RE.findall(txt))

    # Add “Google CDN / APIs” ranges = goog.json minus cloud.json
    generic.update(goog_all - goog_cloud)
    return generic


def _load_cdn_ranges(extra_files: list[str] | None = None):
    """Return sorted list of IPv4 CDN networks (cached + optional user files)."""
    if not _cache_is_fresh(CACHE_PATH):
        cidr_texts = _download_and_extract_cidrs()
        CACHE_PATH.write_text(json.dumps(sorted(cidr_texts)))
    else:
        cidr_texts = set(json.loads(CACHE_PATH.read_text()))

    # Merge user‑supplied ranges
    if extra_files:
        for fname in extra_files:
            try:
                for line in pathlib.Path(fname).read_text().splitlines():
                    line = line.split("#", 1)[0].strip()
                    if line:
                        cidr_texts.add(line)
            except Exception as e:
                print(f"[!] Warning: could not read {fname}: {e}", file=sys.stderr)

    nets: Set[ipaddress.IPv4Network] = set()
    for txt in cidr_texts:
        try:
            nets.add(ipaddress.ip_network(txt))
        except ValueError:
            pass

    return sorted(nets, key=lambda n: (n.network_address, n.prefixlen))


# --------------------------------------------------------------------------- #
# Target expansion & cleaning (unchanged from previous version)               #
# --------------------------------------------------------------------------- #


def _clean_line(line: str) -> str:
    return line.split("#", 1)[0].strip()


def _expand_target_tokens(tokens: list[str]):
    expanded: list[str] = []
    i = 0
    n = len(tokens)
    while i < n:
        tok = tokens[i]
        if tok in ("-iL", "--includefile"):
            if i + 1 >= n:
                sys.exit("[!] -iL flag provided without a file name.")
            for line in pathlib.Path(tokens[i + 1]).read_text().splitlines():
                line = _clean_line(line)
                if line:
                    expanded.append(line)
            i += 2
            continue
        if tok.startswith("-"):
            if tok in FLAGS_WITH_PARAM and "=" not in tok:
                i += 2
            else:
                i += 1
            continue
        tok = _clean_line(tok)
        if tok:
            expanded.append(tok)
        i += 1
    return expanded


def _resolve_hostname(host: str):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None, socket.AF_INET)})
    except socket.gaierror:
        print(f"[!] Warning: could not resolve {host!r}; skipping.", file=sys.stderr)
        return []


def _split_targets(ms_args, cdn_ranges):
    non_cdn, cdn_only = [], []
    seen: Set[str] = set()
    for item in _expand_target_tokens(ms_args):
        seen.add(item)
        strip_port = item.split(":", 1)[0]
        try:
            net = ipaddress.ip_network(strip_port, strict=False)
            (cdn_only if any(net.overlaps(c) for c in cdn_ranges) else non_cdn).append(str(net))
            continue
        except ValueError:
            pass
        for ip in _resolve_hostname(strip_port):
            net = ipaddress.ip_network(ip)
            (cdn_only if any(net.overlaps(c) for c in cdn_ranges) else non_cdn).append(ip)
    non_cdn = list(dict.fromkeys(non_cdn))
    cdn_only = list(dict.fromkeys(cdn_only))
    return non_cdn, cdn_only, seen


# --------------------------------------------------------------------------- #
# Strip original targets from the CLI vector                                  #
# --------------------------------------------------------------------------- #


def _strip_target_args(ms_args, seen_targets):
    stripped: list[str] = []
    i = 0
    n = len(ms_args)
    while i < n:
        arg = ms_args[i]
        if arg in ("-iL", "--includefile"):
            i += 2
            continue
        if arg in seen_targets:
            i += 1
            continue
        stripped.append(arg)
        if arg in FLAGS_WITH_PARAM and "=" not in arg:
            if i + 1 < n:
                stripped.append(ms_args[i + 1])
            i += 2
        else:
            i += 1
    return stripped


def _write_tempfile(targets):
    with tempfile.NamedTemporaryFile("w+", delete=False) as tf:
        tf.write("\n".join(targets))
        return tf.name


# --------------------------------------------------------------------------- #
# Main                                                                        #
# --------------------------------------------------------------------------- #


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-ec", "--exclude-cdn", action="store_true", dest="ec",
                        help="Skip any IPs that belong to known CDN ranges.")
    parser.add_argument("--cdn-extra-file", action="append", metavar="FILE",
                        help="Append extra CIDR ranges to the CDN list (one per line; can be used multiple times).")
    parser.add_argument("--refresh-cdn-cache", action="store_true",
                        help="Force redownload of CDN range lists, bypassing the cache.")
    args, ms_args = parser.parse_known_args()

    if args.refresh_cdn_cache and CACHE_PATH.exists():
        CACHE_PATH.unlink()

    # Fast path
    if not args.ec:
        os.execvp("masscan", ["masscan", *ms_args])

    cdn_ranges = _load_cdn_ranges(args.cdn_extra_file)
    non_cdn, cdn_only, seen_targets = _split_targets(ms_args, cdn_ranges)
    ms_args_clean = _strip_target_args(ms_args, seen_targets)

    if cdn_only:
        print(f"[+] {len(cdn_only)} CDN targets skipped due to -ec")
    if not non_cdn:
        print("[!] All targets belong to CDN ranges — nothing to scan.")
        sys.exit(0)

    tf = _write_tempfile(non_cdn)
    print(f"[+] {len(non_cdn)} non‑CDN targets → full scan")
    try:
        subprocess.run(["masscan", "-iL", tf, *ms_args_clean], check=False)
    finally:
        os.unlink(tf)


if __name__ == "__main__":
    main()
