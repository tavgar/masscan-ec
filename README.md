# masscan-ec

`masscan-ec` is a drop-in wrapper for [Masscan](https://github.com/robertdavidgraham/masscan) that adds Naabu‑style CDN exclusion behavior. When scanning large IP ranges, `masscan-ec` ensures known CDN IP blocks are only scanned on a limited port set (default: 80 and 443), while non-CDN targets receive the full port scan.

---

## Features

* **CDN exclusion (`-ec` / `--exclude-cdn`)**: Limit Masscan’s scan of CDN IP ranges to a small set of ports (default: 80,443).
* **Automatic CDN list updates**: Fetches the latest CDN IP CIDRs from ProjectDiscovery’s cdncheck dataset and caches them for up to 7 days.
* **Blank / comment stripping**: Ignores blank lines and `#` comments in include (`-iL`) files.
* **Hostname support**: Resolves hostnames in target lists to IPv4 addresses; skips unresolved names with a warning.
* **Flag-safe parsing**: Recognizes and preserves all Masscan flags (like `-p`, `--rate`, etc.) so port parameters are never mistaken for targets.

---

## Requirements

* **Python 3.8+**
* **Masscan** installed and available in your `$PATH`.

All other dependencies use the Python standard library.

---


## Usage

```bash
python3 masscan-ec.py [options] [targets]
```

### Key Flags

| Flag                        | Description                                                        |
| --------------------------- | ------------------------------------------------------------------ |
| `-ec`, `--exclude-cdn`      | Enable CDN exclusion behavior.                                     |
| `--cdn-ports PORTS`         | Comma-separated ports for CDN IPs (default: `80,443`).             |
| `-p PORTS`, `--ports PORTS` | Masscan port specification (e.g. `80`, `1-65535`, `22,80,443`).    |
| `-iL FILE`, `--includefile` | Read targets from FILE (blank lines & comments supported).         |
| `--rate RATE`               | Masscan packet rate.                                               |
| *All other Masscan options* | Supported (e.g. `--router-mac`, `-e <iface>`, `-oX <file>`, etc.). |

### Examples

1. **Full 65k-port scan**, skipping CDN blocks (those on ports 80 & 443 only):

   ```bash
   masscan-ec -ec -p1-65535 -iL ips-inscope.txt --rate 5000
   ```

2. **Scan port 22 and 3389**, limiting CDN IPs to port 443:

   ```bash
   masscan-ec -ec -p22,3389 --cdn-ports 443 example.com
   ```

3. **Standard Masscan usage** (no CDN logic):

   ```bash
   masscan-ec -p80,443 203.0.113.0/24 --rate 1000
   ```

---

## Caching Behavior

* CDN IP lists are stored at `~/.cache/masscan_cdn_ranges.json`.
* Cached data is considered fresh for **7 days**; after that, the script re-downloads.
* If network download fails and no cache exists, the script exits with an error.