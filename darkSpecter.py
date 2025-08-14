#!/usr/bin/env python3
# Dark Spectre - Tor Keyword Hunter
# Spiders entire apps (default) + per-URL/host session profiles (--session-map)
# Features: Regex/Literal + JSON + Auth (basic/form/bearer global or per-profile)
#           Verbose/Debug + Live Stats + Optional Headless Rendering (Playwright)
#           Screenshots via a dedicated render thread (de-duped per URL)
# Deps:    pip install requests[socks] beautifulsoup4
# Optional (for --shots):
#          pip install playwright && playwright install firefox

import argparse, sys, time, random, pathlib, json, os, re, threading, traceback, socket
import requests
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from queue import Queue, Empty

# ===== Global locks for shared state =====
INFLIGHT = 0
INFLIGHT_LOCK = threading.Lock()
VISITED_LOCK = threading.Lock()
MATCHED_LOCK = threading.Lock()
PARENT_LOCK = threading.Lock()
ROTATE_LOCK = threading.Lock()
ROTATE_COUNT = 0

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
It spiders entire apps by default (keeps crawling even when a page doesn't match).
Supports: regex, JSON reports, global/per-URL auth, verbose/debug, live stats, rendering & screenshots.
"""

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/117.0",
]


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

def rotate_tor_circuit(control_host="127.0.0.1", control_port=9051, password=None):
    try:
        with socket.create_connection((control_host, control_port), timeout=5) as s:
            if password:
                s.sendall(f'AUTHENTICATE "{password}"\r\n'.encode())
            else:
                s.sendall(b"AUTHENTICATE\r\n")
            if not s.recv(1024).startswith(b"250"):
                return False
            s.sendall(b"SIGNAL NEWNYM\r\n")
            return s.recv(1024).startswith(b"250")
    except Exception as e:
        print(f"[tor] circuit rotation failed: {e}")
        return False

def is_http_like(url):
    scheme = (urlparse(url).scheme or "").lower()
    return scheme in ("http", "https", "")

def compile_exclude_patterns(patterns):
    compiled = []
    for pat in patterns or []:
        pat = pat.strip()
        if not pat:
            continue
        try:
            compiled.append(re.compile(pat, re.IGNORECASE))
        except re.error as e:
            print(f"[warn] Invalid regex in exclude-domains: {pat} ({e})", file=sys.stderr)
    return compiled

def is_excluded(url, compiled_patterns):
    host = (urlparse(url).hostname or "").lower()
    if not host:
        return False
    return any(p.search(host) for p in compiled_patterns)

# --- Host helpers ---
def _host(h: str) -> str:
    return (h or "").lower().strip()

def _strip_www(h: str) -> str:
    h = _host(h)
    return h[4:] if h.startswith("www.") else h

def same_domain(u1, u2):
    """Strict host equality (foo.example.com == foo.example.com)."""
    return _host(urlparse(u1).hostname) == _host(urlparse(u2).hostname)

def same_site(u1, u2):
    """Consider subdomains the same 'site'."""
    h1 = _strip_www(urlparse(u1).hostname)
    h2 = _strip_www(urlparse(u2).hostname)
    if not h1 or not h2:
        return False
    return h1 == h2 or h1.endswith("." + h2) or h2.endswith("." + h1)

def fetch_text(session, url, timeout, verify_tls=True, verbose=False, save_debug=False, ua_pool=None):
    try:
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate",
        }
        if ua_pool:
            headers["User-Agent"] = random.choice(ua_pool)
        r = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=verify_tls,
            headers=headers,
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

PLAIN_URL_RE = re.compile(r'\bhttps?://[^\s"\'<>]+', re.IGNORECASE)
def extract_links(base_url, html, allow_offdomain=False, allow_subdomains=False, exclude_patterns=None):
    exclude_patterns = exclude_patterns or []
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        print("Missing dependency: beautifulsoup4\nInstall with: pip install beautifulsoup4", file=sys.stderr)
        sys.exit(1)

    links = set()
    soup = BeautifulSoup(html or "", "html.parser")

    # <a>
    for a in soup.find_all("a", href=True):
        href = (a.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        links.add(urljoin(base_url, href))

    # <area>
    for ar in soup.find_all("area", href=True):
        href = (ar.get("href") or "").strip()
        if not href or href.startswith("#") or href.lower().startswith("javascript:"):
            continue
        links.add(urljoin(base_url, href))

    # plain text URLs
    for m in PLAIN_URL_RE.finditer(html or ""):
        links.add(m.group(0))

    # Scope filtering
    filtered = set()
    for abs_url in links:
        if not is_http_like(abs_url):
            continue
        if is_excluded(abs_url, exclude_patterns):
            continue
        if allow_offdomain:
            filtered.add(abs_url)
        else:
            if same_domain(base_url, abs_url) or (allow_subdomains and same_site(base_url, abs_url)):
                filtered.add(abs_url)
    return list(filtered)

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

# ===== Live stats =====
class CrawlStats:
    def __init__(self):
        self.lock = threading.Lock()
        self.start = time.time()
        self.visited = 0
        self.matched = 0
        self.max_depth = 0
        self.fetched = 0

    def on_visit(self, depth):
        with self.lock:
            self.visited += 1
            if depth > self.max_depth:
                self.max_depth = depth

    def on_fetch(self):
        with self.lock:
            self.fetched += 1

    def on_match(self):
        with self.lock:
            self.matched += 1

    def snapshot(self):
        with self.lock:
            return {
                "visited": self.visited,
                "matched": self.matched,
                "max_depth": self.max_depth,
                "fetched": self.fetched,
                "elapsed": max(0.001, time.time() - self.start),
            }

def _stats_printer(queue, stats: CrawlStats, stop_evt: threading.Event, interval: float, use_cr: bool,
                   matched_set=None, visited_set=None):
    # Print a single line periodically with carriage-return (unless crawl_log is on)
    while not stop_evt.is_set():
        snap = stats.snapshot()
        
     # Use unfinished_tasks for accurate pending count (includes in-flight)
        try:
            pending = queue.unfinished_tasks
        except Exception:
            pending = 0

        if pending == 0:
            with INFLIGHT_LOCK:
                if INFLIGHT == 0:
                    stop_evt.set()
                    break
            
        # Use the ground truth for matched (and optionally visited)
        matched_count = len(matched_set or [])
        visited_count = snap["visited"] if visited_set is None else len(visited_set)

        rate = snap["fetched"] / snap["elapsed"]
        line = (f"[stats] visited={visited_count} queued={pending} matched={matched_count} "
                f"depth={snap['max_depth']} rate={rate:.2f}/s elapsed={int(snap['elapsed'])}s")
        if use_cr:
            print("\r" + line + " " * 10, end="", flush=True)
        else:
            print(line, flush=True)
        stop_evt.wait(interval)
    if use_cr:
        print("")


# ===== Page limiter (max-pages) =====
class PageLimiter:
    """Thread-safe fetch reservation to enforce --max-pages."""
    def __init__(self, max_pages:int):
        self.max_pages = int(max_pages)
        self._count = 0
        self._lock = threading.Lock()

    def allow_fetch(self) -> bool:
        with self._lock:
            if self.max_pages <= 0:
                return True  # unlimited
            if self._count >= self.max_pages:
                return False
            self._count += 1
            return True

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
    s.proxies = {"http": f"socks5h://{socks_host}:{socks_port}",
                 "https": f"socks5h://{socks_host}:{socks_port}"}
    s.headers.update(base_session.headers.copy())
    if prof.get("headers"):
        s.headers.update(dict(prof["headers"]))
    if prof.get("cookies"):
        for k, v in prof["cookies"].items():
            s.cookies.set(k, v)

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
            extra_fields=None,
            csrf_selector=auth.get("csrf_selector"),
            csrf_attr=auth.get("csrf_attr") or "value",
            timeout=auth.get("timeout"),
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

# ===== Worker & Crawl =====
def crawl_worker(queue, session_router, matcher, matched, visited, parent_map, json_records,
                 max_depth, allow_offdomain, allow_subdomains, exclude_patterns,
                 follow_only_if_match, crawl_log, delay, timeout, verify_tls, verbose, save_debug,
                 stats: CrawlStats, limiter, stop_evt: threading.Event,
                 render_queue=None, shots=False, shot_mode="matches", ua_pool=None,
                 rotate_every=0, control_host="127.0.0.1", control_port=9051, control_pass=None):

    while not stop_evt.is_set():
        try:
            url, depth, parent = queue.get(timeout=0.5)
        except Empty:
            continue
        except Exception:
            break

        with INFLIGHT_LOCK:
            global INFLIGHT
            INFLIGHT += 1

        try:
            # de-dupe / enforce max-pages / mark visited
            with VISITED_LOCK:
                if url in visited:
                    continue
                allowed = limiter.allow_fetch()
                if allowed:
                    visited.add(url)
                else:
                    if crawl_log:
                        print(f"{DIM}[limit]{RESET} max-pages reached, stopping crawl")
                    stop_evt.set()
            if not allowed:
                while True:
                    try:
                        queue.get_nowait()
                        queue.task_done()
                    except Empty:
                        break
                break
            stats.on_visit(depth)

            if parent:
                with PARENT_LOCK:
                    if url not in parent_map:
                        parent_map[url] = parent

            if crawl_log:
                print(f"{'  '*depth}[fetch] depth={depth} url={url}")

                        # Pick session based on URL/profile
            session = session_router.session_for(url)

            # Fetch
            txt = fetch_text(session, url, timeout,
                             verify_tls=verify_tls,
                             verbose=verbose,
                             save_debug=save_debug,
                             ua_pool=ua_pool)
            stats.on_fetch()
            if rotate_every > 0:
                with ROTATE_LOCK:
                    global ROTATE_COUNT
                    ROTATE_COUNT += 1
                    if ROTATE_COUNT % rotate_every == 0:
                        rotate_tor_circuit(control_host, control_port, control_pass)
            
            if not txt:
                if crawl_log:
                    print(f"{DIM}[fail]{RESET} {url}")
                continue

            # Match check
            is_match = matcher(txt)
            if is_match:
                with MATCHED_LOCK:
                    matched.add(url)
                print(f"{RED}{'  '*depth}[MATCH]{RESET} {url}")
                json_records.append({
                    "url": url, "depth": depth, "parent": parent,
                    "chain": chain_for(url, parent_map)
                })
                # Schedule screenshot on match (matches mode)
                if shots and shot_mode == "matches" and render_queue is not None and not stop_evt.is_set():
                    render_queue.put((url, depth))

            elif crawl_log:
                print(f"{'  '*depth}[....] {url}")
            
            # Screenshot ALL pages (enqueue to render thread)
            if shots and shot_mode == "all" and render_queue is not None and not stop_evt.is_set():
                render_queue.put((url, depth))

            # Spider children unless we've been told to stop
            should_expand = (depth < max_depth) and (not follow_only_if_match or is_match)
            if should_expand and not stop_evt.is_set():
                children = extract_links(
                    url, txt,
                    allow_offdomain=allow_offdomain,
                    allow_subdomains=allow_subdomains,
                    exclude_patterns=exclude_patterns
                )
                enq = 0
                for link in children:
                    with VISITED_LOCK:
                        already_visited = (link in visited)
                        total_known = len(visited) + queue.unfinished_tasks
                    if limiter.max_pages > 0 and total_known >= limiter.max_pages:
                        break
                    with PARENT_LOCK:
                        already_enqueued = (link in parent_map)
                        if not already_enqueued and not already_visited:
                            parent_map[link] = url
                            do_enqueue = True
                        else:
                            do_enqueue = False
                    if do_enqueue:
                        queue.put((link, depth+1, url))
                        enq += 1
                        if crawl_log:
                            print(f"{'  '*(depth+1)}[enqueue] {link}")
                if crawl_log:
                    print(f"{'  '*depth}[links] extracted={len(children)} enqueued={enq} depth={depth+1}")

            if delay > 0:
                time.sleep(delay + random.uniform(0, 0.8))

        except Exception as e:
            print(f"[worker ERROR] {type(e).__name__}: {e}")
            traceback.print_exc()
        finally:
            try:
                # Mark queue item done exactly once for all code paths
                queue.task_done()
            except Exception:
                pass
            with INFLIGHT_LOCK:
                INFLIGHT -= 1

def crawl_recursive(session_router, root_url, matcher, matched, visited, parent_map, json_records,
                    max_depth, allow_offdomain, allow_subdomains, exclude_patterns,
                    follow_only_if_match=False, shots=False, shot_mode="matches",
                    shots_dir=None, crawl_log=False, delay=0, timeout=30, verify_tls=True,
                    verbose=False, save_debug=False, max_workers=5, stats_interval=2.0,
                    max_pages=0, render_settings=None, rotate_every=0, control_host="127.0.0.1",
                    control_port=9051, control_pass=None, ua_pool=None):

    q = Queue()
    q.put((root_url, 0, None))

    stats = CrawlStats()
    stop_evt = threading.Event()
    limiter = PageLimiter(max_pages)

    # Live stats thread (single line when crawl_log is off)
    stats_thread = None
    if stats_interval and stats_interval > 0:
        stats_thread = threading.Thread(
            target=_stats_printer,
            args=(q, stats, stop_evt, float(stats_interval), not crawl_log, matched, visited),
            daemon=True,
        )
        stats_thread.start()

    # Optional render queue/worker (create & use Playwright **inside** this thread)
    render_queue = None
    render_thread = None
    SENTINEL = object()
    if shots:
        shots_dir = shots_dir or "screenshots"
        os.makedirs(shots_dir, exist_ok=True)
        render_queue = Queue()

        def render_worker():
            renderer_local = None
            try:
                # Build a fresh Renderer in THIS thread only
                renderer_local = Renderer(
                    proxy_server=render_settings["proxy_server"],
                    user_agent=render_settings["user_agent"],
                    headless=True,
                    wait_until=render_settings["wait_until"],
                    timeout_ms=render_settings["timeout_ms"],
                )
            except RuntimeError as e:
                print(f"[render] {e}")
                print("[render] Rendering disabled (continuing without renderer).")
                # Drain items so workers don't block forever
                while True:
                    try:
                        item = render_queue.get_nowait()
                        render_queue.task_done()
                        if item is SENTINEL:
                            break
                    except Empty:
                        break
                return

            while True:
                # If we've been asked to stop and nothing remains, exit
                if stop_evt.is_set() and render_queue.empty():
                    break
                try:
                    item = render_queue.get(timeout=0.5)
                except Empty:
                    continue
                if item is SENTINEL:
                    render_queue.task_done()
                    break
                url, depth = item
                try:
                    ss_path = os.path.join(shots_dir, _safe_name(url, depth))
                    renderer_local.render(url, screenshot_path=ss_path)
                    if verbose:
                        print(f"[shot] saved {ss_path}")
                except Exception as e:
                    print(f"[shot] EXC {type(e).__name__}: {e} {url}")
                finally:
                    render_queue.task_done()

            if renderer_local:
                renderer_local.close()

        render_thread = threading.Thread(target=render_worker, daemon=True)
        render_thread.start()

    # Crawl workers
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for _ in range(max_workers):
            executor.submit(
                crawl_worker, q, session_router, matcher, matched, visited, parent_map, json_records,
                max_depth, allow_offdomain, allow_subdomains, exclude_patterns,
                follow_only_if_match, crawl_log, delay, timeout, verify_tls, verbose, save_debug,
                stats, limiter, stop_evt, render_queue, shots, shot_mode, ua_pool,
                rotate_every, control_host, control_port, control_pass
            )
        q.join()

    # Queue drained: signal workers/stats thread to exit
        stop_evt.set()
   
   # Signal shutdown for stats + render threads
    if render_queue:
        render_queue.put(SENTINEL)
        render_queue.join()
        if render_thread:
            render_thread.join(timeout=1.0)
    if stats_interval and stats_interval > 0 and stats_thread:
        stats_thread.join(timeout=1.0)

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
    p.add_argument("--allow-subdomains", action="store_true",
                   help="Treat subdomains (incl. www) as same site when --offdomain is not set")
    p.add_argument("--exclude-domains", nargs="+", default=[],
                   help="Space-separated domain patterns to skip (regex OK, e.g., '.*bitcoin.*' badsite.onion)")
    p.add_argument("--follow-only-if-match", action="store_true",
                   help="Legacy behavior: only follow links when the current page matches")

    # Tor & HTTP
    p.add_argument("--socks-host", default="127.0.0.1", help="Tor SOCKS host")
    p.add_argument("--socks-port", type=int, default=9050, help="Tor SOCKS port")
    p.add_argument("--timeout", type=int, default=60, help="Per-request timeout seconds (default: 60)")
    p.add_argument("--control-port", type=int, default=9051, help="Tor control port")
    p.add_argument("--control-pass", help="Tor control password")
    p.add_argument("--rotate-every", type=int, default=0, help="Rotate Tor circuit after N pages (0 disables)")
    p.add_argument("--random-ua", action="store_true", help="Randomize User-Agent header on each request")
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

    # Screenshots (Playwright used only inside the render thread)
    p.add_argument("--shots", action="store_true",
                   help="Take screenshots via a dedicated render thread. Default captures only matched pages.")
    p.add_argument("--shots-dir", default="screenshots",
                   help="Directory to store screenshots (default: screenshots)")
    p.add_argument("--shot-mode", choices=["matches","all"], default="matches",
                   help="Screenshot only matched pages or all visited pages (default: matches)")
    p.add_argument("--render-timeout", type=int, default=30000,
                   help="Render timeout in ms for page navigation (default: 30000)")
    p.add_argument("--render-wait", choices=["load","domcontentloaded","networkidle"], default="networkidle",
                   help="Playwright wait_until condition (default: networkidle)")

    
    # Concurrency / telemetry
    p.add_argument("--max-workers", type=int, default=5,
                   help="Max concurrent fetch workers")
    p.add_argument("--low-concurrency", action="store_true",
                   help="Use a single worker (overrides --max-workers)")
    p.add_argument("--stats-interval", type=float, default=2.0,
                   help="Seconds between live stats updates (0 to disable)")
    p.add_argument("--crawl-log", action="store_true",
                   help="Show each page fetch and enqueue in real-time")

    # Help banner handling
    if len(sys.argv) == 1 or "-h" in sys.argv or "--help" in sys.argv:
        p.print_help(); sys.exit(0)

    args = p.parse_args()
    print(ASCII_BANNER)
    
    if args.low_concurrency:
        args.max_workers = 1

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

    # Build matcher
    matcher = build_matcher(args.phrase, args.regex)

    out_path = pathlib.Path(args.out)
    visited, matched = set(), set()
    parent_map, json_records = {}, []
    compiled_excludes = compile_exclude_patterns(args.exclude_domains)

    # Render settings (only used inside render thread if --shots)
    render_settings = {
        "proxy_server": f"socks5://{args.socks_host}:{args.socks_port}",
        "user_agent": "Mozilla/5.0 (X11; Linux x86_64) DarkSpectre/1.6",
        "wait_until": args.render_wait,
        "timeout_ms": args.render_timeout,
    }

    for seed in urls:
        print(f"{PURPLE}[*]{RESET} seed: {seed}")
        crawl_recursive(
            session_router=session_router,
            root_url=seed,
            matcher=matcher,
            matched=matched,
            visited=visited,
            parent_map=parent_map,
            json_records=json_records,
            max_depth=args.max_depth,
            allow_offdomain=args.offdomain,
            allow_subdomains=args.allow_subdomains,
            exclude_patterns=compiled_excludes,
            follow_only_if_match=args.follow_only_if_match,
            shots=args.shots,
            shot_mode=args.shot_mode,
            shots_dir=args.shots_dir,
            crawl_log=args.crawl_log,
            delay=args.delay,
            timeout=args.timeout,
            verify_tls=not args.no_verify,
            verbose=args.verbose,
            save_debug=args.save_debug,
            max_workers=args.max_workers,
            stats_interval=args.stats_interval,
            max_pages=args.max_pages,
            render_settings=render_settings,
            rotate_every=args.rotate_every,
            control_host=args.socks_host,
            control_port=args.control_port,
            control_pass=args.control_pass,
            ua_pool=USER_AGENTS if args.random_ua else None,
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

    print(f"\nDone. {len(matched)} matches → {out_path}"
          + (f"  |  JSON → {args.json_out}" if args.json else ""))

if __name__ == "__main__":
    main()
