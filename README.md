# XSShunter

XSShunter is a Python-based XSS scanning utility focused on practical reflected XSS testing, lightweight DOM inspection, basic crawling, and optional headless verification.

The current codebase is centered around:
- Query-parameter scanning with custom payloads
- POST body testing with `--data`
- Simple same-domain crawling
- Basic DOM sink/source discovery
- Optional Selenium-based verification
- JSON, HTML, and TXT reporting

## Current Version

`v1.5`

## Features

- Scan a single URL with query parameters using `-u`
- Scan multiple targets from a file using `-f`
- Crawl a target and scan discovered URLs with `--crawl`
- Test POST parameters using `--data`
- Add cookies, headers, proxy, timeout, delay, and custom user-agent
- Load custom payloads from a file
- Run lightweight DOM analysis with `--dom`
- Attempt headless verification with `--headless`
- Save results as `json`, `html`, or `txt`
- Reduce console noise with `--quiet`

## What The Tool Actually Detects Right Now

- Reflected XSS when a payload is returned unescaped in the response body
- POST-based reflected behavior when payloads are injected through `--data`
- DOM-related findings such as:
  - inline event handlers
  - common DOM source-to-sink patterns
  - common framework sinks like `dangerouslySetInnerHTML`, `v-html`, `ng-bind-html`, and jQuery `.html(...)`
  - form input surfaces

## Current Limitations

- `--blind` is currently only a mode flag and does not include a callback collector/backend
- `--waf` performs basic detection only; it does not implement a real bypass engine
- The crawler is intentionally lightweight and does not execute client-side JavaScript for discovery
- `--headless` depends on a working local Chrome/Selenium setup
- DOM analysis is heuristic-based and should be treated as triage, not proof of exploitation

## Installation

```bash
git clone https://github.com/3rabDev/XSShunter
cd XSShunter
pip install -r requirements.txt
```

If you want `--headless`, make sure Chrome and a compatible Selenium browser setup are available on the machine.

## Usage

Show help:

```bash
python xssHunter.py -h
```

Show version:

```bash
python xssHunter.py --version
```

Scan a single URL:

```bash
python xssHunter.py -u "https://example.com/search?q=test"
```

Scan using a custom payload file:

```bash
python xssHunter.py -u "https://example.com/search?q=test" -p payloads.txt
```

Scan multiple targets from a file:

```bash
python xssHunter.py -f targets.txt
```

Crawl and scan discovered URLs:

```bash
python xssHunter.py -u "https://example.com" --crawl --depth 2
```

Test POST data:

```bash
python xssHunter.py -u "https://example.com/contact" --data "name=test&message=hello"
```

Run DOM inspection:

```bash
python xssHunter.py -u "https://example.com/search?q=test" --dom
```

Run headless verification:

```bash
python xssHunter.py -u "https://example.com/search?q=test" --headless
```

Authenticated/custom-header scan:

```bash
python xssHunter.py -u "https://example.com/dashboard?q=test" --cookie "session=abc123" --header "X-Test: 1"
```

Use a proxy:

```bash
python xssHunter.py -u "https://example.com/search?q=test" --proxy "http://127.0.0.1:8080"
```

Save a report:

```bash
python xssHunter.py -u "https://example.com/search?q=test" -o report.json
python xssHunter.py -u "https://example.com/search?q=test" -o report.html
python xssHunter.py -u "https://example.com/search?q=test" -o report.txt
```

Quiet mode:

```bash
python xssHunter.py -f targets.txt --quiet -o results.json
```

## Command-Line Options

| Flag | Description |
| --- | --- |
| `-u`, `--url` | Single target URL |
| `-f`, `--file` | File containing target URLs |
| `--crawl` | Enable crawler mode |
| `--depth` | Crawl depth, clamped between `1` and `5` |
| `--same-domain` | Keep crawling on the same domain |
| `-t`, `--threads` | Number of worker threads |
| `--cookie` | Cookie string such as `name=value; name2=value2` |
| `--header` | Custom header, can be used more than once |
| `--data` | POST data as JSON or `key=value&...` |
| `--blind` | Enable blind XSS mode flag |
| `--dom` | Run DOM analysis |
| `--headless` | Verify findings using Selenium |
| `--waf` | Run basic WAF detection |
| `-p`, `--payloads` | Custom payload file |
| `--timeout` | Request timeout in seconds |
| `-o`, `--output` | Output report path |
| `-v`, `--verbose` | Enable verbose logging |
| `--no-color` | Disable colored output |
| `--quiet` | Suppress non-finding output |
| `--proxy` | Proxy URL |
| `--delay` | Delay between requests |
| `--user-agent` | Custom User-Agent |
| `--version` | Print version and exit |

## Output Formats

The tool supports:
- `json`
- `html`
- `txt`

If the output extension is unknown, it falls back to JSON.

## Project Structure

```text
XSShunter/
├── xssHunter.py
├── core/
│   └── payloads.txt
├── modules/
│   ├── crawler.py
│   ├── dom_analyzer.py
│   ├── headless.py
│   ├── scanner.py
│   └── utils.py
└── requirements.txt
```

## Notes

- Targets without query parameters and without `--data` will be skipped by the scanner
- The crawler only follows HTTP/HTTPS pages and ignores common static asset extensions
- Report generation works even when no findings are discovered
- Verbose mode is mainly useful for debugging scanner/runtime issues

## License

GPL-3.0
