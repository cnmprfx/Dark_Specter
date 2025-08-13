 
                                 |_|                           
                ==== Dark Spectre - Tor Keyword Hunter ====




<img width="468" height="626" alt="image" src="https://github.com/user-attachments/assets/7c278df5-efb4-40ba-83ff-3e06e2e64979" />






# 🕵️‍♂️ Dark Spectre - Tor Keyword Hunter

**Dark Spectre** is a high-performance, multithreaded crawler for the Tor/Darknet and regular web, designed to search for specific words or phrases, capture screenshots, and optionally authenticate to sites that require login. It is optimized for OPSEC, large-scale scraping, and investigative workflows.

---

## 🚀 Features

- **Recursive Spidering** – Crawl entire onion or clearnet sites up to a specified depth
- **Regex or Simple Match** – Match exact phrases or full regex patterns
- **Auth Support** – Supply session cookies or credentials per URL
- **Live Stats** – Real-time `visited / queued / matched / depth / rate / elapsed` output
- **Domain Exclusion** – Skip specific domains or patterns (supports regex)
- **Multithreaded Crawling** – Adjustable `--max-workers` for speed
- **Screenshot & Rendering** – Capture matches or all visited pages
- **Safe Screenshot Threading** – Dedicated main-thread render worker to avoid Playwright thread errors
- **Onion & Clearnet** – Works via Tor (SOCKS5 proxy) or standard HTTP/S
- **Debug Logging** – Save HTML source of visited pages
- **Depth & Scope Control** – Restrict or expand spidering
- **OPSEC-Friendly** – Adjustable delays, timeouts, and randomized sleep

---

## ⚙️ Installation

```bash
# Clone repo
git clone https://github.com/yourusername/dark-spectre.git
cd dark-spectre

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (for screenshots)
playwright install


If crawling `.onion` sites:
```
bash
sudo apt install tor
systemctl start tor
```

Run with:

```bash
torsocks python3 darkSpecter.py ...
```


or configure your HTTP/SOCKS proxy in the script/session router.



## Usage

```bash
python3 darkSpecter.py URLS_FILE "KEYWORD" [OPTIONS]
```

**Example:**

```bash
python3 darkSpecter.py urls.txt "Interlock" \
    --max-depth 5 --max-workers 10 \
    --shots --shot-mode matches --shots-dir shots \
    --exclude-domains ".*bitcoin.*" badsite.onion \
    --stats-interval 2 --max-pages 200
```

---

## Options

| Option                                   | Description                                                              |                                      |
| ---------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------ |
| `URLS_FILE`                              | Text file containing seed URLs (one per line)                            |                                      |
| `"KEYWORD"`                              | Keyword or regex to search for                                           |                                      |
| `--max-depth N`                          | Max recursion depth (default: 3)                                         |                                      |
| `--max-pages N`                          | Hard cap on total pages fetched (0 = unlimited)                          |                                      |
| `--max-workers N`                        | Number of concurrent threads (default: 5)                                |                                      |
| `--offdomain`                            | Allow leaving the starting domain                                        |                                      |
| `--allow-subdomains`                     | Follow links to subdomains                                               |                                      |
| `--exclude-domains PATTERN [PATTERN...]` | Regex or plain text domains to skip                                      |                                      |
| `--follow-only-if-match`                 | Only follow links from matched pages                                     |                                      |
| `--shots`                                | Capture screenshots                                                      |                                      |
| `--shot-mode matches`                    | all                                                                      | Screenshot only matches or all pages |
| `--shots-dir DIR`                        | Directory to save screenshots                                            |                                      |
| `--render`                               | Use headless browser rendering (needed for JS-heavy sites & screenshots) |                                      |
| `--auth-file FILE`                       | JSON with per-URL auth/session cookies                                   |                                      |
| `--crawl-log`                            | Log every fetch & enqueue event                                          |                                      |
| `--stats-interval SECS`                  | Seconds between live stats updates (0 disables)                          |                                      |
| `--timeout N`                            | Request timeout in seconds                                               |                                      |
| `--delay N`                              | Delay between requests                                                   |                                      |
| `--no-verify`                            | Disable TLS verification                                                 |                                      |
| `--verbose`                              | Verbose output                                                           |                                      |
| `--save-debug`                           | Save raw HTML of fetched pages                                           |                                      |

---

## Live Stats Output

When `--stats-interval` > 0, Dark Spectre will print:

```
[stats] visited=38 queued=21 matched=5 depth=4 rate=0.78/s elapsed=49s
```

* **visited** – Pages fetched
* **queued** – Pages waiting in queue
* **matched** – Pages matching keyword/regex
* **depth** – Max depth reached so far
* **rate** – Fetch rate in pages/sec
* **elapsed** – Crawl time in seconds

With `--crawl-log`, stats appear as separate lines (no overwrite).

---

## Authentication

You can pass a JSON auth file via `--auth-file FILE` containing session data per domain:

```json
{
  "example.com": {
    "cookies": {
      "sessionid": "abc123",
      "auth": "tokenvalue"
    },
    "headers": {
      "Authorization": "Bearer sometoken"
    }
  }
}
```

---

## Screenshots

Requires `--render` and `playwright` installed.
Example:

```bash
python3 darkSpecter.py urls.txt "keyword" \
    --shots --shot-mode matches --shots-dir ./shots --render
```

* **matches** – Only screenshot pages containing the keyword/regex
* **all** – Screenshot every fetched page

---

## Domain Exclusion

Skip matching domains with:

```bash
--exclude-domains ".*bitcoin.*" badsite.onion
```

Supports regex patterns and exact matches.



## Parallel Crawler + Max Pages

Dark Specter uses a **thread-safe limiter** to stop all workers once `--max-pages` is reached.
Workers stop enqueuing new links after the limit.



## Legal Disclaimer

This tool is for **educational and authorized security research** purposes only.
Do not use it on systems or networks you do not own or have explicit permission to test.


## License

MIT License – see [LICENSE](LICENSE) for details.


