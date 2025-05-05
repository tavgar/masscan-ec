# masscan-ec
masscan-ec is a drop-in wrapper for Masscan that adds Naabu‑style CDN exclusion behavior. When scanning large IP ranges, masscan-ec ensures known CDN IP blocks are only scanned on a limited port set (default: 80 and 443), while non-CDN targets receive the full port scan.
