#!/usr/bin/env python3
# Dark Spectre - Tor Keyword Hunter
# Now spiders entire apps (default) + per-URL/host session profiles (--session-map)
# Features: Regex/Literal + JSON + Auth (basic/form/bearer global or per-profile)
#           Verbose/Debug + Optional Headless Rendering (Playwright) + Screenshots (de-duped per URL)
# Deps:    pip install requests[socks] beautifulsoup4
# Optional (for --render/--shots):
#          pip install playwright && playwright install firefox

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
It now spiders entire apps by default (keeps crawling even when a page doesn't match).
Supports: regex matching, JSON reports, global or per-URL auth, verbose/debug, rendering & screenshots.
"""

# ===== Helpers =====
def load_urls(path):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]

def make_base_session(socks_host="127.0.0.1", socks_port=9050, ua=None):
    s = requests.Session()
    s.proxies = {"http": f"socks5h://{socks_host}:{socks_port}",
                 "https": f"socks5h://{socks_host}:{socks_port}"}
    s.headers.update({"User-Agent": ua or "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.6"})
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

# ===== Auth & Session helpers =====
def parse_kv_pairs(pairs):
    out = {}
    for p in pairs or []:
        if "=" not in p:
            print(f"{DIM}[auth] ignoring field (not k=v):{RESET} {p}")
            continue
        k, v = p.split("=", 1)
        out[k] = v
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

# ---- Per-URL/host session map ----
def load_session_map(path):
    """
    JSON format: list of profiles like:
    [
      {
        "match": "example.onion",         # value to match
        "kind": "host",                   # host | prefix | regex  (default host)
        "auth": {                         # optional auth block
          "mode": "basic|bearer|form",
          "auth_url": "http://.../login", # for form
          "method": "POST",
          "username": "u", "password": "p",
          "user_field": "username", "pass_field": "password",
          "csrf_selector": "input[name=csrf_token]", "csrf_attr": "value",
          "success_regex": "dashboard|logout",
          "bearer_token": "xyz", "bearer_token_file": "token.txt"
        },
        "headers": { "X-API-Key": "abc" },# optional extra headers
        "cookies": { "sid": "..." }       # optional cookies
      }
    ]
    """
    if not path:
        return []
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        raise ValueError("session-map must be a JSON list of profiles")
    return data

def profile_matches(url, prof):
    kind = (prof.get("kind") or "host").lower()
    target = prof.get("match") or ""
    if not target:
        return False
    if kind == "host":
        return (urlparse(url).hostname or "").lower() == target.lower()
    if kind == "prefix":
        return url.lower().startswith(target.lower())
    if kind == "regex":
        try:
            return re.search(target, url, re.IGNORECASE) is not None
        except re.error:
            return False
    return False

def make_session_from_profile(base_session, prof, socks_host, socks_port, timeout):
    s = requests.Session()
    # copy Tor proxies
    s.proxies = {"http": f"socks5h://{socks_host}:{socks_port}",
                 "https": f"socks5h://{socks_host}:{socks_port}"}
    # start with base headers
    s.headers.update(base_session.headers.copy())
    # add extra headers/cookies
    if prof.get("headers"):
        s.headers.update(dict(prof["headers"]))
    if prof.get("cookies"):
        for k, v in prof["cookies"].items():
            s.cookies.set(k, v)

    # auth block
    auth = prof.get("auth") or {}
    mode = (auth.get("mode") or "none").lower()
    if mode == "basic":
        do_basic_auth(s, auth.get("username"), auth.get("password"))
    elif mode == "bearer":
        do_bearer_auth(s, auth.get("bearer_token"), auth.get("bearer_token_file"))
    elif mode == "form":
        do_form_auth(
            session=s,
            auth_url=auth.get("auth_url"),
            method=auth.get("method") or "POST",
            username=auth.get("username"),
            password=auth.get("password"),
            user_field=auth.get("user_field") or "username",
            pass_field=auth.get("pass_field") or "password",
            extra_fields=None,  # if needed, could add auth["fields"]
            csrf_selector=auth.get("csrf_selector"),
            csrf_attr=auth.get("csrf_attr") or "value",
            timeout=timeout,
            success_regex=auth.get("success_regex"),
        )
    return s

class SessionRouter:
    """Chooses a requests.Session based on URL, using session-map profiles."""
    def __init__(self, base_session, profiles, socks_host, socks_port, timeout, verbose=False):
        self.base = base_session
        self.profiles = profiles or []
        self.cache = {}  # prof_idx -> Session
        self.socks_host = socks_host; self.socks_port = socks_port
        self.timeout = timeout; self.verbose = verbose

    def session_for(self, url):
        for idx, prof in enumerate(self.profiles):
            if profile_matches(url, prof):
                if idx not in self.cache:
                    if self.verbose:
                        print(f"[sess] create profile session {idx} for {prof.get('match')}")
                    self.cache[idx] = make_session_from_profile(
                        self.base, prof, self.socks_host, self.socks_port, self.timeout
                    )
                return self.cache[idx]
        return self.base

# ===== Optional headless renderer (Playwright) =====
class Renderer:
    def __init__(self, proxy_server, user_agent=None, headless=True,
                 wait_until="networkidle", timeout_ms=30000):
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            raise RuntimeError("Playwright not installed. Run: pip install playwright && playwright install firefox")
        self._pw = sync_playwright().start()
        self._browser = self._pw.firefox.launch(headless=headless, proxy={"server": proxy_server})
        self._context = self._browser.new_context(
            user_agent=user_agent or "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.6"
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
            self._pw.stop()
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
def crawl_recursive(session_router, root_url, matcher, timeout, delay, allow_offdomain,
                    max_depth, max_pages, visited, matched, parent_map, json_records,
                    *, verify_tls=True, verbose=False, save_debug=False,
                    renderer=None, shots=False, shots_dir="screenshots",
                    shot_mode="matches", render_for_match=False,
                    shot_taken=None, follow_only_if_match=False,
                    crawl_log=False):
    if shot_taken is None:
        shot_taken = set()

    stack = deque([(root_url, 0, None)])
    total_fetched = 0

    while stack:
        url, depth, parent = stack.pop()

        if crawl_log:
            print(f"{'  '*depth}[fetch] depth={depth} url={url}")

        if url in visited:
            continue
        if total_fetched >= max_pages:
            print(f"{DIM}[limit]{RESET} max-pages reached"); break

        visited.add(url)
        if parent and url not in parent_map:
            parent_map[url] = parent

        # pick session based on URL/profile
        session = session_router.session_for(url)

        # 1) Fetch raw HTML via requests
        txt = fetch_text(session, url, timeout,
                         verify_tls=verify_tls,
                         verbose=verbose,
                         save_debug=save_debug)
        total_fetched += 1

        # 2) Optional rendering for matching; optionally screenshot ALL pages
        if renderer and render_for_match:
            try:
                ss_path = None
                if shots and shot_mode == "all" and (url not in shot_taken):
                    os.makedirs(shots_dir, exist_ok=True)
                    ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                txt = renderer.render(url, screenshot_path=ss_path)
                if ss_path:
                    shot_taken.add(url)
                    if verbose:
                        print(f"[shot] saved {ss_path}")
                elif verbose:
                    print(f"[render] {url} -> no-shot")
            except Exception as e:
                if verbose:
                    print(f"[render] EXC {type(e).__name__}: {e} {url}")

        elif renderer and shots and shot_mode == "all" and (url not in shot_taken):
            # Screenshot ALL pages even if not rendering for match (don’t replace txt)
            try:
                os.makedirs(shots_dir, exist_ok=True)
                ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                renderer.render(url, screenshot_path=ss_path)
                shot_taken.add(url)
                if verbose:
                    print(f"[shot] saved {ss_path}")
            except Exception as e:
                if verbose:
                    print(f"[shot] EXC {type(e).__name__}: {e} {url}")

        if not txt:
            print(f"{DIM}[fail]{RESET} {url}")
            continue

        # Match / record
        is_match = matcher(txt)
        if is_match:
            matched.add(url)
            print(f"{RED}{'  '*depth}[MATCH]{RESET} {url}")
            json_records.append({
                "url": url, "depth": depth, "parent": parent,
                "chain": chain_for(url, parent_map)
            })
            # Screenshot on match (if not already shot in ALL mode)
            if shots and (shot_mode == "matches") and renderer and (url not in shot_taken):
                try:
                    os.makedirs(shots_dir, exist_ok=True)
                    ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                    renderer.render(url, screenshot_path=ss_path)
                    shot_taken.add(url)
                    if verbose:
                        print(f"[shot] saved {ss_path}")
                except Exception as e:
                    if verbose:
                        print(f"[shot] EXC {type(e).__name__}: {e} {url}")
            elif shots and (shot_mode == "matches") and not renderer and verbose:
                print("[shot] --shots requested but --render not enabled; enable --render to capture screenshots.")
        else:
            # Non-matching page (still spider unless --follow-only-if-match)
            print(f"{'  '*depth}[.... ] {url}")

        # === Branching rule ===
        # Spider entire app by default; only restrict when --follow-only-if-match is set
        should_expand = (depth < max_depth) and (not follow_only_if_match or is_match)
        if should_expand:
            children = extract_links(url, txt, allow_offdomain=allow_offdomain)
            enq = 0
            for link in children:
                if link not in visited:
                    stack.append((link, depth+1, url))
                    enq += 1
                    if crawl_log:
                        print(f"{'  '*(depth+1)}[enqueue] {link}")
            if crawl_log:
                print(f"{'  '*depth}[links] extracted={len(children)} enqueued={enq} depth={depth+1}")

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

    # Crawl limits / behavior
    p.add_argument("--max-depth", type=int, default=3, help="Max recursion depth (default: 3)")
    p.add_argument("--max-pages", type=int, default=400, help="Safety cap on total fetched pages (default: 400)")
    p.add_argument("--delay", type=float, default=1.2, help="Base delay between requests (default: 1.2)")
    p.add_argument("--offdomain", action="store_true", help="Allow following links to other domains/hidden services")
    p.add_argument("--follow-only-if-match", action="store_true",
                   help="Use legacy behavior: only follow links when the current page matches")

    # Tor & HTTP
    p.add_argument("--socks-host", default="127.0.0.1", help="Tor SOCKS host")
    p.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS port")
    p.add_argument("--timeout", type=int, default=60, help="Per-request timeout seconds (default: 60)")

    # Verbose / TLS / Debug
    p.add_argument("--verbose", action="store_true", help="Print HTTP status and content-type for each fetch")
    p.add_argument("--no-verify", action="store_true", help="Disable TLS verification (debug only)")
    p.add_argument("--save-debug", action="store_true", help="Save fetched HTML to debug_pages/ for inspection")

    # Global Auth (fallback)
    p.add_argument("--auth-mode", choices=["none","basic","form","bearer"], default="none",
                   help="Global authentication mode (default: none)")
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

    # Per-URL/host Session Map
    p.add_argument("--session-map", help="Path to JSON file with per-URL/host session profiles")

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
    p.add_argument("--crawl-log", action="store_true",
               help="Show each page fetch and enqueue in real-time")

    # Help banner handling
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        p.print_help(); sys.exit(0)

    args = p.parse_args()
    print(ASCII_BANNER)

    urls = load_urls(args.url_list)
    if not urls:
        print("No URLs loaded.", file=sys.stderr); sys.exit(1)

    # Base session (Tor)
    base_session = make_base_session(args.socks_host, args.socks_port)

    # Global auth (fallback) applies to base session if provided
    if args.auth_mode != "none":
        if args.auth_mode == "basic":
            if not (args.username and args.password):
                print(f"{DIM}[auth]{RESET} basic requires --username & --password"); sys.exit(2)
            do_basic_auth(base_session, args.username, args.password)
        elif args.auth_mode == "bearer":
            do_bearer_auth(base_session, args.bearer_token, args.bearer_token_file)
        elif args.auth_mode == "form":
            extras = parse_kv_pairs(args.field)
            ok = do_form_auth(session=base_session,
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

    # Load per-URL/host session profiles and router
    profiles = load_session_map(args.session_map) if args.session_map else []
    session_router = SessionRouter(base_session, profiles, args.socks_host, args.socks_port, args.timeout, verbose=args.verbose)

    # Build matcher & renderer
    matcher = build_matcher(args.phrase, args.regex)

    renderer = None
    try:
        if args.render or args.shots:
            proxy = f"socks5://{args.socks_host}:{args.socks_port}"
            renderer = Renderer(
                proxy_server=proxy,
                user_agent="Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.6",
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
    shot_taken = set()  # global de-dupe across entire run

    for seed in urls:
        print(f"{PURPLE}[*]{RESET} seed: {seed}")
        crawl_recursive(
            session_router=session_router,
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
            render_for_match=render_for_match,
            shot_taken=shot_taken,
            follow_only_if_match=args.follow_only_if_match,
            crawl_log=args.crawl_log,
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
