# 🕷️ XSShunter

**XSS scanner that actually works.**

Not another python script that spams `<script>alert(1)</script>` and calls it a day.

I built this because most open source XSS tools are garbage. They either:
- flood your terminal with false positives
- break after 2 minutes
- can't handle modern shit like Angular, Vue, or React

So here's mine.

## What it does

- Crawls like a real browser (respects robots.txt, depth limits, same‑domain)
- Injects payloads where they actually matter
- Finds reflected, DOM‑based, and blind XSS
- Uses headless Chrome to verify (no more "maybe" alerts)
- Detects WAFs (Cloudflare, ModSecurity, etc) and tries to bypass
- Multi‑threaded so you don't wait all day

## Install

```bash
git clone https://github.com/i3rrb/XSShunter
cd XSShunter
pip install -r requirements.txt
```

You also need Chrome + chromedriver if you want `--headless`.  
Or just skip that flag if you don't care.

## Quick usage

Scan one URL:

```bash
python xssHunter.py -u "http://testphp.vulnweb.com/listproducts.php?cat=1"
```

Crawl the whole site:

```bash
python xssHunter.py -u "http://testphp.vulnweb.com" --crawl --depth 2
```

Full power (DOM + headless + WAF bypass):

```bash
python xssHunter.py -u "http://target.com" --crawl --dom --headless --waf -o report.html
```

## All options (the boring part)

| Flag | What it does |
|||
| `-u` | single URL |
| `-f` | file with list of URLs |
| `--crawl` | enable crawler |
| `--depth` | max crawl depth (default 3) |
| `-t` | threads (default 20) |
| `--cookie` | set cookie |
| `--header` | custom header (can be used multiple times) |
| `--data` | POST data (JSON or key=value) |
| `--blind` | blind XSS mode |
| `--dom` | deep DOM analysis (Angular, Vue, React, AST) |
| `--headless` | verify with real browser |
| `--waf` | detect and try to bypass WAF |
| `-p` | custom payloads file |
| `--timeout` | request timeout in sec (default 15) |
| `--delay` | delay between requests (default 0.1) |
| `-o` | output file (.json, .html, .txt) |
| `-v` | verbose |
| `--quiet` | only show findings |
| `--no-color` | disable colors |
| `--proxy` | e.g. `http://127.0.0.1:8080` |
| `--user-agent` | custom UA |
| `--version` | show version |

## Examples you'll actually use

**Test a parameter quickly:**
```bash
python xssHunter.py -u "https://xss.haozi.me/#/0?query=test" --dom
```

**Authenticated scan (with cookie):**
```bash
python xssHunter.py -u "https://admin.target.com/dashboard" --cookie "PHPSESSID=abc123" --header "X-Custom: 1"
```

**Save results as HTML (looks clean):**
```bash
python xssHunter.py -u "http://testhtml5.vulnweb.com" --crawl -o report.html
```

**Blind XSS (for stored / feedback forms):**
```bash
python xssHunter.py -u "https://feedback.site.com" --blind
```

**Quiet + file output (for automation):**
```bash
python xssHunter.py -f targets.txt --quiet -o results.json
```

## What makes it not terrible

- **No blind payload spam** - it checks reflection context first.
- **Understands frontend frameworks** - looks for `ng-bind-html`, `v-html`, `dangerouslySetInnerHTML`, jQuery sinks.
- **AST parsing** - detects `eval`, `setTimeout`, dynamic sinks in JS code.
- **Headless verification** - actually opens Chrome to confirm XSS execution.
- **WAF detection** - knows if Cloudflare or ModSecurity is blocking you.

## Known issues (because nothing is perfect)

- `--headless` sometimes fails on sites with anti‑bot detection. Use without if that happens.
- Crawler might miss some JS‑generated links (working on it).
- WAF bypass is basic - don't expect miracles against enterprise Fortinet.

## Contributing

Found a bug? Have a better payload? Open an issue or PR.

I'm not actively maintaining 24/7, but I'll check every few days.

## License

GPL‑3.0 - free, but if you make something better, share it back.

## Author

**@i3rrb**  
[3rabdev.online](https://3rabdev.online)  
Just a guy who got tired of shitty XSS tools.
*"If it reflects, we catch it."*

