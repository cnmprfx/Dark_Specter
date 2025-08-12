#!/usr/bin/env python3
# Dark Spectre - Tor Keyword Hunter (Recursive + Regex + JSON + Auth + Render + Screenshots)
# Requires: requests[socks], beautifulsoup4
# Optional (for --render / --shots): playwright + `playwright install firefox`

import argparse, sys, time, random, pathlib, re, json, os
import requests
from urllib.parse import urljoin, urlparse
from collections import deque

# ===== ANSI Colors =====
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

DESCRIPTION = f"""{RED}Dark Spectre{RESET} hunts for keywords/regex on darknet & clearnet URLs via Tor.
It recurses ONLY along links where the match keeps reappearing. Supports:
- Regex matching, JSON reports (with depth & chains)
- Auth (basic / form with CSRF / bearer)
- Verbose & debug HTML dumps
- Optional headless rendering + screenshots
"""

# ===== Helpers =====
def load_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

def make_session(socks_host="127.0.0.1", socks_port=9050, ua=None):
    s = requests.Session()
    s.proxies = {
        "http":  f"socks5h://{socks_host}:{socks_port}",
        "https": f"socks5h://{socks_host}:{socks_port}",
    }
    s.headers.update({
        "User-Agent": ua or "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.4"
    })
    return s

def is_http_like(url):
    scheme = (urlparse(url).scheme or "").lower()
    return scheme in ("http", "https", "")

def same_domain(u1, u2):
    h1 = (urlparse(u1).hostname or "").lower()
    h2 = (urlparse(u2).hostname or "").lower()
    return h1 == h2

def fetch_text(session, url, timeout, verify_tls=True, verbose=False, save_debug=False):
    try:
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
            headers={
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
            },
        )
        ct = r.headers.get("Content-Type", "")
        if verbose:
            print(f"[http] {r.status_code} {ct} {url}")

        html = None
        if 200 <= r.status_code < 400 and ("text" in ct or ct == "" or url.endswith(".onion")):
            html = r.text[:2_000_000]
        elif "text" in ct:
            html = r.text[:2_000_000]

        if save_debug and html:
            os.makedirs("debug_pages", exist_ok=True)
            safe = url.replace("://", "_").replace("/", "_")[:120]
            with open(os.path.join("debug_pages", f"{safe}.html"), "w", encoding="utf-8") as f:
                f.write(html)

        return html
    except requests.RequestException as e:
        if verbose:
            print(f"[http] EXC {type(e).__name__}: {e} {url}")
        return None

def extract_links(base_url, html, allow_offdomain=False):
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("Missing dependency: beautifulsoup4\nInstall with: pip install beautifulsoup4", file=sys.stderr)
        sys.exit(1)

    links = set()
    soup = BeautifulSoup(html, "html.parser")
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
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
        rx = re.compile(re.escape(phrase), re.IGNORECASE)
    return lambda text: (text is not None) and (rx.search(text) is not None)

def chain_for(url, parent_map):
    chain, cur, seen = [], url, set()
    while cur and cur not in seen:
        chain.append(cur); seen.add(cur); cur = parent_map.get(cur)
    chain.reverse()
    return chain

# ===== Auth helpers =====
def parse_kv_pairs(pairs):
    out = {}
    for p in pairs or []:
        if "=" not in p:
            print(f"{DIM}[auth] ignoring field (not k=v):{RESET} {p}")
            continue
        k,v = p.split("=",1)
        out[k]=v
    return out

def get_csrf_value(html, selector, attr):
    if not selector:
        return None
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("Missing dependency: beautifulsoup4\nInstall with: pip install beautifulsoup4", file=sys.stderr)
        sys.exit(1)
    soup = BeautifulSoup(html, "html.parser")
    el = soup.select_one(selector)
    if not el:
        return None
    if (attr or "").lower() == "text":
        return el.get_text(strip=True)
    return el.get(attr or "value", None)

def do_basic_auth(session, username, password):
    session.auth = (username, password)
    print(f"{PURPLE}[*]{RESET} Basic auth enabled")

def do_bearer_auth(session, token, token_file):
    if not token and token_file:
        token = pathlib.Path(token_file).read_text(encoding="utf-8").strip()
    if not token:
        print(f"{DIM}[auth]{RESET} No bearer token provided"); return
    session.headers["Authorization"] = f"Bearer {token}"
    print(f"{PURPLE}[*]{RESET} Bearer token set")

def do_form_auth(session, auth_url, method, username, password,
                 user_field, pass_field, extra_fields, csrf_selector, csrf_attr,
                 timeout, success_regex):
    if not auth_url:
        print(f"{DIM}[auth]{RESET} No auth URL provided for form mode"); return False
    try:
        r = session.get(auth_url, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        print(f"{DIM}[auth]{RESET} Failed to GET login page"); return False

    payload = dict(extra_fields or {})
    if username is not None and user_field:
        payload[user_field] = username
    if password is not None and pass_field:
        payload[pass_field] = password

    if csrf_selector:
        token = get_csrf_value(r.text, csrf_selector, csrf_attr or "value")
        if token is not None:
            # Try infer field name if input[name=...]
            try:
                from bs4 import BeautifulSoup
                soup = BeautifulSoup(r.text, "html.parser")
                el = soup.select_one(csrf_selector)
                name = el.get("name") if el else None
            except Exception:
                name = None
            payload[name or "_csrf"] = token

    method = (method or "POST").upper()
    try:
        if method == "POST":
            resp = session.post(auth_url, data=payload, timeout=timeout, allow_redirects=True)
        else:
            resp = session.get(auth_url, params=payload, timeout=timeout, allow_redirects=True)
    except requests.RequestException:
        print(f"{DIM}[auth]{RESET} Login request failed"); return False

    ok = (resp.status_code < 400)
    if success_regex:
        try:
            ok = ok and (re.search(success_regex, resp.text, re.IGNORECASE) is not None)
        except re.error as e:
            print(f"{DIM}[auth]{RESET} invalid success regex: {e}")
    print(f"{PURPLE}[*]{RESET} Form auth {'OK' if ok else 'FAILED'} (HTTP {resp.status_code})")
    return ok

# ===== Optional headless renderer (Playwright) =====
class Renderer:
    def __init__(self, proxy_server, user_agent=None, headless=True,
                 wait_until="networkidle", timeout_ms=30000):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install firefox")
        self._sync_playwright = __import__("playwright").sync_api.sync_playwright().start()
        self._browser = self._sync_playwright.firefox.launch(
            headless=headless,
            proxy={"server": proxy_server}
        )
        self._context = self._browser.new_context(
            user_agent=user_agent or "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.4"
        )
        self.wait_until = wait_until
        self.timeout_ms = timeout_ms

    def render(self, url, screenshot_path=None, full_page=True):
        page = self._context.new_page()
        page.goto(url, wait_until=self.wait_until, timeout=self.timeout_ms)
        if screenshot_path:
            page.screenshot(path=screenshot_path, full_page=full_page)
        html = page.content()
        page.close()
        return html

    def close(self):
        try:
            self._context.close()
            self._browser.close()
            self._sync_playwright.stop()
        except Exception:
            pass

# ===== Filename helper for screenshots =====
import re as _re, time as _time
def _safe_name(url, depth):
    base = url.replace("://","_").replace("/", "_")
    base = _re.sub(r"[^A-Za-z0-9_.-]", "_", base)
    ts = _time.strftime("%Y%m%d-%H%M%S")
    return f"d{depth}_{ts}_{base[:120]}.png"

# ===== Crawl =====
def crawl_recursive(session, root_url, matcher, timeout, delay, allow_offdomain,
                    max_depth, max_pages, visited, matched, parent_map, json_records,
                    *, verify_tls=True, verbose=False, save_debug=False,
                    renderer=None, shots=False, shots_dir="screenshots",
                    shot_mode="matches", render_for_match=False):
    stack = deque([(root_url, 0, None)])
    total_fetched = 0

    while stack:
        url, depth, parent = stack.pop()
        if url in visited:
            continue
        if total_fetched >= max_pages:
            print(f"{DIM}[limit]{RESET} max-pages reached"); break

        visited.add(url)
        if parent and url not in parent_map:
            parent_map[url] = parent

        txt = fetch_text(session, url, timeout,
                         verify_tls=verify_tls,
                         verbose=verbose,
                         save_debug=save_debug)
        total_fetched += 1

        # If using renderer for match (JS-heavy), grab rendered HTML; optionally screenshot ALL pages
        if renderer and render_for_match:
            try:
                ss_path = None
                if shots and shot_mode == "all":
                    os.makedirs(shots_dir, exist_ok=True)
                    ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                txt = renderer.render(url, screenshot_path=ss_path)
                if verbose:
                    print(f"[render] {url} -> {'shot' if ss_path else 'no-shot'}")
            except Exception as e:
                if verbose:
                    print(f"[render] EXC {type(e).__name__}: {e} {url}")

        if not txt:
            print(f"{DIM}[fail]{RESET} {url}")
            continue

        if matcher(txt):
            matched.add(url)
            print(f"{RED}{'  '*depth}[MATCH]{RESET} {url}")
            json_records.append({
                "url": url, "depth": depth, "parent": parent,
                "chain": chain_for(url, parent_map)
            })

            # Screenshot on match (if not already shot in ALL mode)
            if shots and shot_mode == "matches":
                if renderer:
                    try:
                        os.makedirs(shots_dir, exist_ok=True)
                        ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                        renderer.render(url, screenshot_path=ss_path)  # render for shot
                        if verbose:
                            print(f"[shot] saved {ss_path}")
                    except Exception as e:
                        if verbose:
                            print(f"[shot] EXC {type(e).__name__}: {e} {url}")
                else:
                    if verbose:
                        print("[shot] --shots requested but --render not enabled; enable --render to capture screenshots.")

            if depth < max_depth:
                for link in extract_links(url, txt, allow_offdomain=allow_offdomain):
                    if link not in visited:
                        stack.append((link, depth+1, url))
        else:
            print(f"{'  '*depth}[STOP ] {url}")
        time.sleep(delay + random.uniform(0, 0.8))

# ===== Main =====
def main():
    class BannerHelp(argparse.RawTextHelpFormatter):
        def add_usage(self, usage, actions, groups, prefix=None):
            prefix = (f"{ASCII_BANNER}\n{DESCRIPTION}\n\n" if prefix is None else prefix)
            return super().add_usage(usage, actions, groups, prefix=prefix)

    p = argparse.ArgumentParser(description="", formatter_class=BannerHelp)

    # Core
    p.add_argument("url_list", help="Path to file with URLs (.onion or clearnet), one per line")
    p.add_argument("phrase", help="Word or regex pattern to search for (case-insensitive)")
    p.add_argument("-o","--out", default="matches.txt", help="Output file for matching URLs (default: matches.txt)")
    p.add_argument("--json", action="store_true", help="Also write a JSON report")
    p.add_argument("--json-out", default="matches.json", help="Path for JSON report (default: matches.json)")
    p.add_argument("--regex", action="store_true", help="Treat PHRASE as a regex (otherwise literal)")

    # Crawl limits
    p.add_argument("--max-depth", type=int, default=3, help="Max recursion depth along matching branches")
    p.add_argument("--max-pages", type=int, default=200, help="Safety cap on total fetched pages")
    p.add_argument("--delay", type=float, default=1.2, help="Base delay between requests")
    p.add_argument("--offdomain", action="store_true", help="Allow following links to other domains/hidden services")

    # Tor & HTTP
    p.add_argument("--socks-host", default="127.0.0.1", help="Tor SOCKS host")
    p.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS port")
    p.add_argument("--timeout", type=int, default=45, help="Per-request timeout seconds")

    # Verbose / TLS / Debug
    p.add_argument("--verbose", action="store_true", help="Print HTTP status and content-type for each fetch")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS verification (debug only)")
    p.add_argument("--save-debug", action="store_true", help="Save fetched HTML to debug_pages/ for inspection")

    # Auth
    p.add_argument("--auth-mode", choices=["none","basic","form","bearer"], default="none",
                   help="Authentication mode (default: none)")
    p.add_argument("--auth-url", help="Login URL (required for form auth)")
    p.add_argument("--auth-method", choices=["GET","POST"], default="POST", help="Form auth HTTP method")
    p.add_argument("--username", help="Username for basic/form auth")
    p.add_argument("--password", help="Password for basic/form auth")
    p.add_argument("--user-field", default="username", help="Form field name for username")
    p.add_argument("--pass-field", default="password", help="Form field name for password")
    p.add_argument("--field", action="append", help="Extra form field k=v (repeatable)")
    p.add_argument("--csrf-selector", help="CSS selector to capture CSRF token from login page")
    p.add_argument("--csrf-attr", default="value", help="Attribute name for CSRF token (e.g., value|content|text)")
    p.add_argument("--success-regex", help="Regex that must appear in the response after login")
    p.add_argument("--bearer-token", help="Bearer token string")
    p.add_argument("--bearer-token-file", help="Path to file containing bearer token")

    # Screenshots & Rendering
    p.add_argument("--shots", action="store_true",
                   help="Take screenshots (saved to --shots-dir). Default mode captures only matched pages.")
    p.add_argument("--shots-dir", default="screenshots",
                   help="Directory to store screenshots (default: screenshots)")
    p.add_argument("--shot-mode", choices=["matches","all"], default="matches",
                   help="Screenshot only matched pages or all visited pages (default: matches)")
    p.add_argument("--render", action="store_true",
                   help="Use a headless browser for JS rendering (Playwright via Tor proxy)")
    p.add_argument("--render-timeout", type=int, default=30000,
                   help="Render timeout in ms for page navigation (default: 30000)")
    p.add_argument("--render-wait", choices=["load","domcontentloaded","networkidle"], default="networkidle",
                   help="Playwright wait_until condition (default: networkidle)")

    # Help banner handling
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        p.print_help(); sys.exit(0)

    args = p.parse_args()
    print(ASCII_BANNER)

    urls = load_urls(args.url_list)
    if not urls:
        print("No URLs loaded.", file=sys.stderr); sys.exit(1)

    session = make_session(args.socks_host, args.socks_port)

    # Auth (global)
    if args.auth_mode != "none":
        if args.auth_mode == "basic":
            if not (args.username and args.password):
                print(f"{DIM}[auth]{RESET} basic requires --username & --password"); sys.exit(2)
            do_basic_auth(session, args.username, args.password)

        elif args.auth_mode == "bearer":
            do_bearer_auth(session, args.bearer_token, args.bearer_token_file)

        elif args.auth_mode == "form":
            extras = parse_kv_pairs(args.field)
            ok = do_form_auth(session=session,
                              auth_url=args.auth_url,
                              method=args.auth_method,
                              username=args.username,
                              password=args.password,
                              user_field=args.user_field,
                              pass_field=args.pass_field,
                              extra_fields=extras,
                              csrf_selector=args.csrf_selector,
                              csrf_attr=args.csrf_attr,
                              timeout=args.timeout,
                              success_regex=args.success_regex)
            if not ok:
                print(f"{DIM}[auth]{RESET} form auth failed (continuing without guaranteed session)")

    # Build matcher
    matcher = build_matcher(args.phrase, args.regex)

    # Optional renderer
    renderer = None
    try:
        if args.render or args.shots:
            proxy = f"socks5://{args.socks_host}:{args.socks_port}"
            renderer = Renderer(
                proxy_server=proxy,
                user_agent="Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.4",
                headless=True,
                wait_until=args.render_wait,
                timeout_ms=args.render_timeout
            )
    except RuntimeError as e:
        print(f"[render] {e}")
        if args.render or args.shots:
            print("[render] Rendering disabled (continuing without renderer).")

    render_for_match = args.render  # use rendered HTML for matching only when --render is given

    out_path = pathlib.Path(args.out)
    visited, matched = set(), set()
    parent_map, json_records = {}, []

    for seed in urls:
        print(f"{PURPLE}[*]{RESET} seed: {seed}")
        crawl_recursive(
            session=session,
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
            json_records=json_records,
            verify_tls=not args.no_verify,
            verbose=args.verbose,
            save_debug=args.save_debug,
            renderer=renderer,
            shots=args.shots,
            shots_dir=args.shots_dir,
            shot_mode=args.shot_mode,
            render_for_match=render_for_match
        )

    out_path.write_text("\n".join(sorted(matched)) + ("\n" if matched else ""), encoding="utf-8")
    if args.json:
        with open(args.json_out, "w", encoding="utf-8") as jf:
            json.dump({
                "phrase": args.phrase,
                "regex": bool(args.regex),
                "total_matches": len(matched),
                "matches": json_records
            }, jf, indent=2, ensure_ascii=False)

    if renderer:
        renderer.close()

    print(f"\nDone. {len(matched)} matches → {out_path}"
          + (f"  |  JSON → {args.json_out}" if args.json else ""))

if __name__ == "__main__":
    main()
