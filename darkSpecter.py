#!/usr/bin/env python3
# Dark Spectre - Tor Keyword Hunter (Recursive + Regex + JSON)
import argparse, requests, sys, time, random, pathlib, re, json
from urllib.parse import urljoin, urlparse
from collections import deque

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("Missing dependency: beautifulsoup4\nInstall with: pip install beautifulsoup4", file=sys.stderr)
    sys.exit(1)

# ANSI Colors
RED="\033[91m"; PURPLE="\033[95m"; DIM="\033[2m"; RESET="\033[0m"

ASCII_BANNER = rf"""
{RED}  ____             _        {PURPLE}____                  _            
{RED} |  _ \  __ _ _ __| | __   {PURPLE}/ ___| _ __   ___  ___| |_ ___ _ __ 
{RED} | | | |/ _` | '__| |/ /   {PURPLE}\___ \| '_ \ / _ \/ __| __/ _ \ '__|
{RED} | |_| | (_| | |  |   <     {PURPLE}___) | |_) |  __/ (__| ||  __/ |   
{RED} |____/ \__,_|_|  |_|\_\   {PURPLE}|____/| .__/ \___|\___|\__\___|_|   
{PURPLE}                                 |_|                           
{RESET}                ==== {RED}Dark {PURPLE}Spectre{RESET} - Tor Keyword Hunter ====
"""

DESCRIPTION = f"""{RED}Dark Spectre{RESET} is a Tor-powered keyword hunter for darknet & clearnet URLs.
It recursively follows links ONLY along branches where the keyword/phrase keeps re-appearing.
Now supports regex searches and a JSON report with depth and parent chains.

Example:
  python3 dark_spectre.py urls.txt "ransom(ware|note)" --regex --max-depth 3 --json -o hits.txt --json-out hits.json
"""

class BannerHelp(argparse.RawTextHelpFormatter):
    def add_usage(self, usage, actions, groups, prefix=None):
        prefix = (f"{ASCII_BANNER}\n{DESCRIPTION}\n\n" if prefix is None else prefix)
        return super().add_usage(usage, actions, groups, prefix=prefix)

def load_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

def make_session(socks_host="127.0.0.1", socks_port=9050, ua=None):
    s = requests.Session()
    s.proxies = {"http": f"socks5h://{socks_host}:{socks_port}",
                 "https": f"socks5h://{socks_host}:{socks_port}"}
    s.headers.update({"User-Agent": ua or "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.2"})
    return s

def is_http_like(url):
    scheme = urlparse(url).scheme.lower()
    return scheme in ("http", "https", "")

def same_domain(u1, u2):
    h1 = (urlparse(u1).hostname or "").lower()
    h2 = (urlparse(u2).hostname or "").lower()
    return h1 == h2

def fetch_text(session, url, timeout):
    try:
        r = session.get(url, timeout=timeout, allow_redirects=True)
        ct = r.headers.get("Content-Type", "")
        if r.status_code == 200 and ("text" in ct or ct == "" or url.endswith(".onion")):
            return r.text[:2_000_000]  # cap large pages
    except requests.RequestException:
        return None
    return None

def extract_links(base_url, html, allow_offdomain=False):
    links = set()
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = a.get("href").strip()
        if href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        abs_url = urljoin(base_url, href)
        if not is_http_like(abs_url):
            continue
        if not allow_offdomain and not same_domain(base_url, abs_url):
            continue
        links.add(abs_url)
    return list(links)

def build_matcher(phrase, use_regex):
    if use_regex:
        try:
            rx = re.compile(phrase, re.IGNORECASE)
        except re.error as e:
            print(f"Invalid regex: {e}", file=sys.stderr); sys.exit(2)
    else:
        # literal, case-insensitive
        rx = re.compile(re.escape(phrase), re.IGNORECASE)
    return lambda text: (rx.search(text) is not None)

def chain_for(url, parent_map):
    chain = []
    cur = url
    seen = set()
    while cur and cur not in seen:
        chain.append(cur)
        seen.add(cur)
        cur = parent_map.get(cur)
    chain.reverse()
    return chain

def crawl_recursive(session, root_url, matcher, timeout, delay, allow_offdomain,
                    max_depth, max_pages, visited, matched, parent_map, json_records):
    stack = deque([(root_url, 0, None)])  # (url, depth, parent)
    total_fetched = 0

    while stack:
        url, depth, parent = stack.pop()
        if url in visited:
            continue
        if total_fetched >= max_pages:
            print(f"{DIM}[limit] max-pages reached{RESET}")
            break

        visited.add(url)
        if parent and url not in parent_map:
            parent_map[url] = parent

        txt = fetch_text(session, url, timeout)
        total_fetched += 1

        if not txt:
            print(f"{DIM}[fail]{RESET} {url}")
            continue

        if matcher(txt):
            matched.add(url)
            ch = chain_for(url, parent_map)
            print(f"{RED}{'  '*depth}[MATCH]{RESET} {url}")
            json_records.append({
                "url": url,
                "depth": depth,
                "parent": parent,
                "chain": ch
            })

            if depth < max_depth:
                for link in extract_links(url, txt, allow_offdomain=allow_offdomain):
                    if link not in visited:
                        stack.append((link, depth+1, url))
        else:
            print(f"{'  '*depth}[.... ] {url}")
            # do not expand children; branch ends

        time.sleep(delay + random.uniform(0, 0.8))

def main():
    parser = argparse.ArgumentParser(description="", formatter_class=BannerHelp)
    parser.add_argument("url_list", help="Path to file with URLs (.onion or clearnet), one per line")
    parser.add_argument("phrase", help="Word or phrase to search for (literal by default)")
    parser.add_argument("-o", "--out", default="matches.txt", help="Output file for matching URLs (default: matches.txt)")
    parser.add_argument("--json", action="store_true", help="Also write a JSON report with depth and parent chain")
    parser.add_argument("--json-out", default="matches.json", help="Path for JSON report (default: matches.json)")
    parser.add_argument("--regex", action="store_true", help="Treat PHRASE as a case-insensitive regex")
    parser.add_argument("--socks-host", default="127.0.0.1", help="Tor SOCKS host (default: 127.0.0.1)")
    parser.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS port (default: 9050)")
    parser.add_argument("--timeout", type=int, default=25, help="Per-request timeout seconds (default: 25)")
    parser.add_argument("--delay", type=float, default=1.2, help="Base delay between requests (default: 1.2s)")
    parser.add_argument("--max-depth", type=int, default=3, help="Maximum recursion depth along matching branches")
    parser.add_argument("--max-pages", type=int, default=200, help="Safety cap on total fetched pages")
    parser.add_argument("--offdomain", action="store_true",
                        help="Allow following links to other domains/hidden services (default: same host only)")

    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        parser.print_help(); sys.exit(0)

    args = parser.parse_args()
    print(ASCII_BANNER)

    urls = load_urls(args.url_list)
    if not urls:
        print("No URLs loaded.", file=sys.stderr); sys.exit(1)

    session = make_session(args.socks_host, args.socks_port)
    matcher = build_matcher(args.phrase, args.regex)

    out_path = pathlib.Path(args.out)
    visited, matched = set(), set()
    parent_map = {}          # child -> parent
    json_records = []        # appended per match

    for seed in urls:
        print(f"{PURPLE}[*]{RESET} seed: {seed}")
        crawl_recursive(session=session,
                        root_url=seed,
                        matcher=matcher,
                        timeout=args.timeout,
                        delay=args.delay,
                        allow_offdomain=args.offdomain,
                        max_depth=args.max_depth,
                        max_pages=args.max_pages,
                        visited=visited,
                        matched=matched,
                        parent_map=parent_map,
                        json_records=json_records)

    out_path.write_text("\n".join(sorted(matched)) + ("\n" if matched else ""), encoding="utf-8")
    if args.json:
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump({
                "phrase": args.phrase,
                "regex": bool(args.regex),
                "total_matches": len(matched),
                "matches": json_records
            }, jf, indent=2, ensure_ascii=False)

    print(f"\nDone. {len(matched)} matches → {out_path}"
          + (f"  |  JSON → {args.json_out}" if args.json else ""))

if __name__ == "__main__":
    main()
