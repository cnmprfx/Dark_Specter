# Dark Spectre Cheat Sheet
### Run the crawler with a URL list and search phrase, adding any desired options:
```python darkSpecter.py URL_LIST PHRASE [options]```
## Core
| Option            | Purpose                                                                | Example                  |
| ----------------- | ---------------------------------------------------------------------- | ------------------------ |
| `url_list`        | File containing one URL per line to crawl                              | `urls.txt`               |
| `phrase`          | Word or regex pattern to search for (case-insensitive)                 | `"treasure"`             |
| `-o, --out PATH`  | File to record matching URLs (default `matches.txt`)                   | `--out hits.txt`         |
| `--json`          | Emit a JSON report in addition to text output                          | `--json`                 |
| `--json-out PATH` | Where to write the JSON report (default `matches.json`)                | `--json-out report.json` |
| `--regex`         | Interpret `PHRASE` as a regular expression instead of a literal string | `--regex`                |


## Output & Matching
| Option             | Description                  | Example                                                             |
| ------------------ | ---------------------------- | ------------------------------------------------------------------- |
| `-o`, `--out FILE` | Save matching URLs to `FILE` | `python3 darkSpecter.py urls.txt "key" --out results.txt`           |
| `--json`           | Also create JSON report      | `python3 darkSpecter.py urls.txt "key" --json`                      |
| `--json-out FILE`  | Path for JSON report         | `python3 darkSpecter.py urls.txt "key" --json --json-out data.json` |
| `--regex`          | Treat `PHRASE` as regex      | `python3 darkSpecter.py urls.txt "user\\d+" --regex`                |

## Crawl Behavior
| Option                       | Purpose                                                                 | Example                                         |
| ---------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------- |
| `--max-depth N`              | Maximum recursion depth (default 3)                                     | `--max-depth 5`                                 |
| `--max-pages N`              | Cap on total pages fetched (default 400)                                | `--max-pages 1000`                              |
| `--delay SEC`                | Base delay between requests in seconds (default 1.2)                    | `--delay 0.5`                                   |
| `--offdomain`                | Allow following links to different domains/hidden services              | `--offdomain`                                   |
| `--allow-subdomains`         | Treat subdomains (incl. `www`) as same site when `--offdomain` is unset | `--allow-subdomains`                            |
| `--exclude-domains PATTERN…` | Skip domains matching any regex pattern provided                        | `--exclude-domains '.*bitcoin.*' badsite.onion` |
| `--follow-only-if-match`     | Only follow links when the current page matches the search phrase       | `--follow-only-if-match`                        |


## Tor & HTTP
| Option                | Purpose                                       | Example                 |
| --------------------- | --------------------------------------------- | ----------------------- |
| `--socks-host HOST`   | Tor SOCKS proxy host (default `127.0.0.1`)    | `--socks-host 10.0.0.2` |
| `--socks-port PORT`   | Tor SOCKS proxy port (default `9050`)         | `--socks-port 9150`     |
| `--timeout SEC`       | Per-request timeout in seconds (default 60)   | `--timeout 30`          |
| `--control-port PORT` | Tor control port (default `9051`)             | `--control-port 9151`   |
| `--control-pass PASS` | Tor control password                          | `--control-pass mypass` |
| `--rotate-every N`    | Rotate Tor circuit after N pages (0 disables) | `--rotate-every 50`     |
| `--random-ua`         | Randomize User-Agent header on each request   | `--random-ua`           |

>*Note:* `--rotate-every` needs Tor control-port access (and `--control-pass` if set) to request a new circuit. `--random-ua` simply randomizes the User-Agent each request.
## Verbosity, TLS & Debug
| Option         | Purpose                                              | Example        |
| -------------- | ---------------------------------------------------- | -------------- |
| `--verbose`    | Print HTTP status and content-type for each fetch    | `--verbose`    |
| `--no-verify`  | Disable TLS certificate verification (debug)         | `--no-verify`  |
| `--save-debug` | Save fetched HTML into `debug_pages/` for inspection | `--save-debug` |


## Authentication
### Global Modes
| Option               | Description      | Example                                                                                                                 |
| -------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `--auth-mode none`   | Default: no auth | *(Implicit)*                                                                                                            |
| `--auth-mode basic`  | HTTP basic auth  | `python3 darkSpecter.py urls.txt "key" --auth-mode basic --username bob --password secret`                              |
| `--auth-mode bearer` | Bearer token     | `python3 darkSpecter.py urls.txt "key" --auth-mode bearer --bearer-token token123`                                      |
| `--auth-mode form`   | HTML form login  | `python3 darkSpecter.py urls.txt "key" --auth-mode form --auth-url https://site/login --username bob --password secret` |

### Additional Auth Options
| Option                     | Example                                                                   |
| -------------------------- | ------------------------------------------------------------------------- |
| `--auth-url URL`           | `--auth-mode form --auth-url https://site/login`                          |
| `--auth-method METHOD`     | `--auth-mode form --auth-url ... --auth-method GET`                       |
| `--username USER`          | `--auth-mode basic --username alice`                                      |
| `--password PASS`          | `--auth-mode basic --password hunter2`                                    |
| `--user-field NAME`        | `--auth-mode form --auth-url ... --user-field email`                      |
| `--pass-field NAME`        | `--auth-mode form --auth-url ... --pass-field passwd`                     |
| `--field k=v` (repeatable) | `--auth-mode form --auth-url ... --field otp=123456 --field remember=1`   |
| `--csrf-selector CSS`      | `--auth-mode form --auth-url ... --csrf-selector input[name=csrf]`        |
| `--csrf-attr ATTR`         | `--auth-mode form --auth-url ... --csrf-selector ... --csrf-attr content` |
| `--success-regex REGEX`    | `--auth-mode form --auth-url ... --success-regex "Welcome"`               |
| `--bearer-token TOKEN`     | `--auth-mode bearer --bearer-token "$(cat token.txt)"`                    |
| `--bearer-token-file FILE` | `--auth-mode bearer --bearer-token-file token.txt`                        |

## Session Profiles
| Option               | Example                                                             |
| -------------------- | ------------------------------------------------------------------- |
| `--session-map FILE` | `python3 darkSpecter.py urls.txt "key" --session-map sessions.json` |

## Screenshots & Rendering
| Option                                              | Purpose                                                     | Example                  |
| --------------------------------------------------- | ----------------------------------------------------------- | ------------------------ |
| `--shots`                                           | Capture screenshots via a dedicated render thread           | `--shots`                |
| `--shots-dir DIR`                                   | Directory to store screenshots (default `screenshots`)      | `--shots-dir grabs`      |
| `--shot-mode matches\|all`                          | Capture only matched pages or all pages (default `matches`) | `--shot-mode all`        |
| `--render-timeout MS`                               | Page navigation timeout in milliseconds (default 30000)     | `--render-timeout 60000` |
| `--render-wait load\|domcontentloaded\|networkidle` | Playwright `wait_until` condition (default `networkidle`)   | `--render-wait load`     |
>*Note:* if adding screenshots to the crawl set `--render-timout` to a low number to avoid hanging on exit.

## Concurrency & Telemetry
| Option                  | Description                                      | Example                                                   |
| ----------------------- | ------------------------------------------------ | --------------------------------------------------------- |
| `--max-workers N`       | Max concurrent fetch workers                     | `python3 darkSpecter.py urls.txt "key" --max-workers 10`  |
| `--low-concurrency`     | Use a single worker (overrides `--max-workers`)  | `python3 darkSpecter.py urls.txt "key" --low-concurrency` |
| `--stats-interval SECS` | Seconds between live stats updates (0 to disable) | `python3 darkSpecter.py urls.txt "key" --stats-interval 5` |
| `--crawl-log`           | Show each page fetch and enqueue in real-time    | `python3 darkSpecter.py urls.txt "key" --crawl-log`       |

## Putting It All Together
### Example command combining several options:
```
python3 darkSpecter.py urls.txt "ransomware" \
    -o matches.txt --json --json-out matches.json --regex \
    --max-depth 4 --max-pages 500 --delay 1.5 \
    --offdomain --allow-subdomains \
    --exclude-domains ".*bitcoin.*" bad.onion \
    --follow-only-if-match \
    --socks-host 127.0.0.1 --socks-port 9050 --timeout 80 \
    --verbose --no-verify --save-debug \
    --auth-mode form --auth-url https://example.onion/login \
    --username alice --password secret \
    --user-field user --pass-field pass \
    --field otp=123456 --csrf-selector "input[name=csrf]" \
    --csrf-attr value --success-regex "Welcome" \
    --session-map sessions.json \
    --shots --shots-dir shots --shot-mode all \
    --render-timeout 60000 --render-wait networkidle \
    --max-workers 8 --stats-interval 3 --crawl-log
```
Use this cheat sheet as a quick reference for all Dark Specter arguments and their practical command-line examples.

