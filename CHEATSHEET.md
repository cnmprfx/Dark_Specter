# Dark Specter Cheat Sheet
> python3 darkSpecter.py URLS_FILE "KEYWORD_OR_REGEX" [options]

## Positional Arguments
| Argument    | Example                                        |
| ----------- | ---------------------------------------------- |
| `URLS_FILE` | `python3 darkSpecter.py urls.txt "keyword"`    |
| `PHRASE`    | `python3 darkSpecter.py urls.txt "ransomware group"` |

## Output & Matching
| Option             | Description                  | Example                                                             |
| ------------------ | ---------------------------- | ------------------------------------------------------------------- |
| `-o`, `--out FILE` | Save matching URLs to `FILE` | `python3 darkSpecter.py urls.txt "key" --out results.txt`           |
| `--json`           | Also create JSON report      | `python3 darkSpecter.py urls.txt "key" --json`                      |
| `--json-out FILE`  | Path for JSON report         | `python3 darkSpecter.py urls.txt "key" --json --json-out data.json` |
| `--regex`          | Treat `PHRASE` as regex      | `python3 darkSpecter.py urls.txt "user\\d+" --regex`                |

## Crawl Behavior
| Option                       | Example                                                                               |
| ---------------------------- | ------------------------------------------------------------------------------------- |
| `--max-depth N`              | `python3 darkSpecter.py urls.txt "key" --max-depth 5`                                 |
| `--max-pages N`              | `python3 darkSpecter.py urls.txt "key" --max-pages 200`                               |
| `--delay SECS`               | `python3 darkSpecter.py urls.txt "key" --delay 2.5`                                   |
| `--offdomain`                | `python3 darkSpecter.py urls.txt "key" --offdomain`                                   |
| `--allow-subdomains`         | `python3 darkSpecter.py urls.txt "key" --allow-subdomains`                            |
| `--exclude-domains PATTERN…` | `python3 darkSpecter.py urls.txt "key" --exclude-domains ".*bitcoin.*" badsite.onion` |
| `--follow-only-if-match`     | `python3 darkSpecter.py urls.txt "key" --follow-only-if-match`                        |

## Network & Timing
| Option              | Example                                                        |
| ------------------- | -------------------------------------------------------------- |
| `--socks-host HOST` | `python3 darkSpecter.py urls.txt "key" --socks-host 192.0.2.5` |
| `--socks-port PORT` | `python3 darkSpecter.py urls.txt "key" --socks-port 9150`      |
| `--timeout SECS`    | `python3 darkSpecter.py urls.txt "key" --timeout 90`           |
| `--control-port PORT` | `python3 darkSpecter.py urls.txt "key" --control-port 9051` |
| `--control-pass PASS` | `python3 darkSpecter.py urls.txt "key" --control-pass torpw` |
| `--rotate-every N` | `python3 darkSpecter.py urls.txt "key" --rotate-every 10` |
| `--random-ua` | `python3 darkSpecter.py urls.txt "key" --random-ua` |
*Note:* `--rotate-every` needs Tor control-port access (and `--control-pass` if set) to request a new circuit. `--random-ua` simply randomizes the User-Agent each request.
## Verbosity, TLS & Debug
| Option         | Example                                              |
| -------------- | ---------------------------------------------------- |
| `--verbose`    | `python3 darkSpecter.py urls.txt "key" --verbose`    |
| `--no-verify`  | `python3 darkSpecter.py urls.txt "key" --no-verify`  |
| `--save-debug` | `python3 darkSpecter.py urls.txt "key" --save-debug` |

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
| Option                                                            | Example                                                                        |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `--shots`                                                         | `python3 darkSpecter.py urls.txt "key" --shots`                                |
| `--shots-dir DIR`                                                 | `python3 darkSpecter.py urls.txt "key" --shots --shots-dir shots`              |
| `--shot-mode MODE` (`matches`/`all`)                              | `python3 darkSpecter.py urls.txt "key" --shots --shot-mode all`                |
| `--render-timeout MS`                                             | `python3 darkSpecter.py urls.txt "key" --shots --render-timeout 45000`         |
| `--render-wait STATE` (`load`, `domcontentloaded`, `networkidle`) | `python3 darkSpecter.py urls.txt "key" --shots --render-wait domcontentloaded` |

## Concurrency, Stats & Logging
| Option                  | Description                                      | Example                                                   |
| ----------------------- | ------------------------------------------------ | --------------------------------------------------------- |
| `--max-workers N`       | Max concurrent fetch workers                     | `python3 darkSpecter.py urls.txt "key" --max-workers 10`  |
| `--low-concurrency`     | Use a single worker (overrides `--max-workers`)  | `python3 darkSpecter.py urls.txt "key" --low-concurrency` |
| `--stats-interval SECS` | Seconds between live stats updates (0 to disable) | `python3 darkSpecter.py urls.txt "key" --stats-interval 5` |
| `--crawl-log`           | Show each page fetch and enqueue in real-time    | `python3 darkSpecter.py urls.txt "key" --crawl-log`       |

## Putting It All Together
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

