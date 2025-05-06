# masscan-ec

A lightweight wrapper for [masscan](https://github.com/robertdavidgraham/masscan) that adds Naabu‑style `--exclude‑cdn` (or `-ec`) behavior, and way better than Naabu -ec. This tool lets you skip scanning targets within known CDN IP ranges, reducing noise and focusing on non‑CDN endpoints.

## Key Features

* **Exclude CDN networks**: `-ec / --exclude-cdn` skips any IP that belongs to a CDN, never probed.
* **Up-to-date CDN feeds**: Aggregates ranges from seven public sources and caches them locally:

  * ProjectDiscovery *cdncheck* mega‑list
  * Cloudflare official IP list
  * AWS **CloudFront** ranges
  * Google **CDN / APIs** (google minus cloud.json)
  * Fastly public IP list
  * Akamai (MISP warninglist)
* **Custom CIDRs**: `--cdn-extra-file FILE` to inject your own CIDR blocks.
* **Cache management**: `--refresh-cdn-cache` to force a fresh download of all feeds.
* **Safe input handling**: Blank lines, comments, hostnames, and nested include-files are processed correctly.
* **Transparent masscan flags**: Flags like `-p`, `--rate`, etc. are never misinterpreted as targets.

## Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/yourname/masscan-ec.git
   cd masscan-ec
   ```
2. **Ensure dependencies**

   * Python 3.7+
   * `masscan` must be installed and on your `$PATH`
3. **(Optional) Create a virtual environment**

   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
4. **Install Python requirements** (if any)

   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic scan excluding CDNs

```bash
./masscan-ec -ec -p80,443 10.0.0.0/24
```

* Scans port 80 and 443 on 10.0.0.0/24, skipping any IPs in known CDN ranges.

### Common options

| Option                  | Description                                              |
| ----------------------- | -------------------------------------------------------- |
| `-ec`, `--exclude-cdn`  | Enable CDN exclusion mode.                               |
| `--cdn-extra-file FILE` | Append extra CIDR ranges (one per line) to exclude.      |
| `--refresh-cdn-cache`   | Bypass and redownload CDN feeds, refreshing local cache. |

*All other `masscan` flags* are passed through unchanged, e.g., `-p`, `--rate`, `-e`, etc.

### Examples

* **Exclude CDNs and set scan rate**:

  ```bash
  masscan-ec -ec --rate=1000 -p80 192.168.0.0/16
  ```
* **Add custom CDN ranges**:

  ```bash
  echo "203.0.113.0/24" > extra-cdns.txt
  masscan-ec -ec --cdn-extra-file extra-cdns.txt -p443 198.51.100.0/24
  ```
* **Force cache refresh**:

  ```bash
  masscan-ec -ec --refresh-cdn-cache -p53 example.com
  ```

## How It Works

1. **Download & cache**: Fetches IP ranges from multiple public feeds; cached under `~/.cache/masscan_cdn_ranges.json` for up to 3 days.
2. **Parsing**: Extracts CIDRs via JSON parsing or regex, deduplicates, and filters Google ranges (`goog.json` minus `cloud.json`).
3. **Target expansion**: Resolves hostnames and includes nested files safely.
4. **Filtering**: Splits targets into `non-cdn` and `cdn-only` lists.
5. **Masscan execution**: Creates a temporary target file for `non-cdn` IPs and runs `masscan` with original flags.

## CDN Sources

* ProjectDiscovery `cdncheck`: GitHub JSON feed
* Cloudflare: `https://www.cloudflare.com/ips-v4`
* AWS CloudFront: `https://ip-ranges.amazonaws.com/ip-ranges.json`
* Google APIs: `https://www.gstatic.com/ipranges/goog.json` & `cloud.json`
* Fastly: `https://api.fastly.com/public-ip-list`
* Akamai (MISP): `https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/akamai/list.json`

## Troubleshooting

* **Permission denied**: Ensure `masscan` is executable and in your `$PATH`.
* **Stale cache**: Use `--refresh-cdn-cache` if you suspect outdated ranges.
* **Timeouts or 403s**: The script uses a browser-like User-Agent; check network/firewall settings.

## License

This project is licensed under the [MIT License](LICENSE).

---

*Stay focused on real targets by keeping CDNs out of your scans!*
