# XSShunter

XSShunter is a production-ready Python-based XSS discovery framework built for comprehensive XSS vulnerability testing. It features reflected XSS detection, DOM analysis with confidence scoring, POST-based probing, WAF-aware payload variants, JavaScript rendering for crawling, blind XSS callback collection, Selenium-based verification, and advanced reporting.

## Current Version

`v1.6` - Full Feature Release with Blind XSS Collector, WAF Bypass Engine, and JavaScript Crawling

## 🚀 Core Capabilities

### Scanning & Discovery
- Scan single or multiple URLs (`-u`, `-f`)
- Intelligent crawling with depth control (`--crawl`, `--depth`)
- **JavaScript-rendered crawling** (`--crawl-js`) - Discover URLs created by client-side JavaScript
- POST data testing (`--data`)
- Custom payload support (`-p`)
- Concurrent scanning with configurable threads (`-t`)

### Advanced Detection
- **Reflected XSS** - Payload echo detection in response bodies
- **POST-based XSS** - Injected POST parameter detection
- **DOM Analysis** - Framework-specific sink detection (Angular, Vue, React, jQuery)
- **Blind XSS** - Callback-based blind XSS with built-in collector
- **WAF Detection** - Identify WAF presence and generate bypass variants
- **Headless Verification** - Selenium-based XSS confirmation with JavaScript alert detection

### Enhanced Features (v1.6)
- **Blind XSS Callback Collector** - Built-in HTTP server for receiving blind XSS callbacks
- **Advanced WAF Bypass Engine** - Multiple encoding techniques, polyglot payloads, fragmentation
- **JavaScript Crawling** - Render pages with Selenium to discover dynamic URLs
- **Chrome Setup Detection** - Automatic Chrome detection with helpful setup guidance
- **Confidence-Based DOM Analysis** - Ranked vulnerability findings with confidence scores
- **URL Validation** - Strict URL format validation to prevent invalid targets
- **Payload File Validation** - Explicit error messages for missing custom payload files

### Reporting & Output
- Multiple export formats (JSON, HTML, TXT)
- Metadata tracking (timestamp, config, elapsed time)
- Deduplication of findings
- Verified vs unverified counting

## 🔍 What It Detects

### Reflected Vulnerabilities
- Query parameter XSS
- POST body XSS
- Header injection XSS
- Multi-parameter XSS

### DOM Vulnerabilities
- Unsafe DOM sink usage (innerHTML, eval, dangerouslySetInnerHTML, etc.)
- Framework-specific sinks (Angular `ng-bind-html`, Vue `v-html`, React dangerous HTML)
- jQuery `.html()` and similar methods
- JavaScript URL schemes
- Form input surfaces with dynamic sinks

### Blind XSS
- Out-of-band callback detection
- Cookie exfiltration
- Referrer tracking
- User-Agent logging
- Source URL identification

### WAF Detection
- Firewall signatures
- WAF-specific payload mutations for bypass
- Alternative encoding schemes
- Polyglot payloads

## ✨ What's New in v1.6

### New Features
1. **Blind XSS Callback Collector** (`--start-collector`, `--collector-port`)
   - Standalone HTTP server for receiving blind XSS callbacks
   - REST API for querying results (`/api/status`, `/api/callbacks`, `/api/export`)
   - Automatic callback registration and triggering
   - JSON export of findings

2. **Advanced WAF Bypass Engine** (`--waf`)
   - Triple URL encoding
   - Mixed-case mutations
   - HTML entity encoding
   - Null byte injection
   - Comment insertion
   - Unicode variations
   - Polyglot JavaScript payloads
   - Event handler mutations
   - Fragmentation-based bypasses
   - Protocol manipulation variants

3. **JavaScript Crawling Mode** (`--crawl-js`)
   - Uses Selenium to render JavaScript-heavy pages
   - Discovers dynamically-generated URLs
   - Extracts links created by client-side code
   - Integrates seamlessly with traditional crawling

4. **Chrome Setup Detection** (`--check-setup`)
   - Verifies Chrome/Chromium availability
   - Provides installation guidance for Windows/Linux/macOS
   - Checks Selenium availability
   - Displays troubleshooting steps

5. **Enhanced DOM Analysis**
   - Confidence scoring (Low/Medium/High)
   - Improved framework detection
   - Pattern weighting system
   - More accurate vulnerability ranking

6. **Robust Validation**
   - URL format validation (scheme, netloc, domain checks)
   - Custom payload file validation with clear error messages
   - UTF-8 encoding support on Windows
   - Safe file operations with proper error handling

### Bug Fixes
- Fixed Unicode banner rendering on Windows PowerShell
- Fixed silent fallback for missing custom payload files
- Added explicit URL validation to prevent processing invalid targets
- Improved error handling across all modules

## ✅ What's Resolved (v1.6)

All previous limitations have been addressed:

1. ✅ **Blind XSS Collector** - Built-in callback server with REST API
2. ✅ **WAF Bypass Engine** - Advanced payload variants and encoding techniques
3. ✅ **JavaScript Crawling** - Full Selenium integration for dynamic discovery
4. ✅ **Chrome Detection** - Automatic setup verification with guidance
5. ✅ **DOM Confidence Scoring** - Ranked findings with confidence levels

## 📦 Installation

```bash
git clone https://github.com/3rabDev/XSShunter
cd XSShunter
pip install -r requirements.txt
```

### Optional Dependencies

For headless verification and JavaScript crawling:
```bash
pip install selenium webdriver-manager
# Also ensure Chrome/Chromium is installed on your system
```

Verify your setup:
```bash
python xssHunter.py --check-setup
```

## 📖 Usage Examples

### Basic Scanning

Single URL scan:
```bash
python xssHunter.py -u "https://example.com/search?q=test"
```

Multiple targets from file:
```bash
python xssHunter.py -f targets.txt
```

### Crawling & Discovery

Standard crawling:
```bash
python xssHunter.py -u "https://example.com" --crawl --depth 2
```

JavaScript-rendered crawling (finds dynamic URLs):
```bash
python xssHunter.py -u "https://example.com" --crawl --crawl-js --depth 2
```

### Advanced Testing

WAF-aware scanning with bypass payloads:
```bash
python xssHunter.py -u "https://example.com/search?q=test" --waf -t 15
```

Blind XSS with built-in callback collector:
```bash
python xssHunter.py -u "https://example.com/feedback" --blind --start-collector --collector-port 8000
```

DOM analysis with confidence scoring:
```bash
python xssHunter.py -u "https://example.com" --dom --verbose
```

Headless verification with Chrome:
```bash
python xssHunter.py -u "https://example.com/search?q=test" --headless
```

### POST Data Testing

JSON payload:
```bash
python xssHunter.py -u "https://example.com/api/submit" --data '{"name":"test","msg":"hello"}'
```

Form-encoded payload:
```bash
python xssHunter.py -u "https://example.com/contact" --data "name=test&message=hello"
```

### Authentication & Custom Headers

Cookie-based authentication:
```bash
python xssHunter.py -u "https://example.com/dashboard?q=test" --cookie "session=abc123; role=admin"
```

Custom headers:
```bash
python xssHunter.py -u "https://example.com/api/test?q=1" --header "Authorization: Bearer token" --header "X-Custom: value"
```

### Proxy & Custom Agent

Through proxy:
```bash
python xssHunter.py -u "https://example.com/search?q=test" --proxy "http://127.0.0.1:8080"
```

Custom User-Agent:
```bash
python xssHunter.py -u "https://example.com" --user-agent "Mozilla/5.0 Custom Bot"
```

### Reporting

JSON report:
```bash
python xssHunter.py -f targets.txt -o findings.json
```

HTML report:
```bash
python xssHunter.py -f targets.txt -o findings.html
```

Text report:
```bash
python xssHunter.py -f targets.txt -o findings.txt
```

### Performance Tuning

Increase threads for faster scanning:
```bash
python xssHunter.py -f targets.txt -t 20 --delay 0.05
```

Adjust timeout for slow servers:
```bash
python xssHunter.py -u "https://slow-server.com" --timeout 30
```

### Quiet & Verbose Modes

Minimal output:
```bash
python xssHunter.py -f targets.txt --quiet -o results.json
```

Detailed logging:
```bash
python xssHunter.py -u "https://example.com" -v --verbose
```

## Command-Line Options Reference

### Target Options
| Flag | Description |
| --- | --- |
| `-u`, `--url` | Single target URL |
| `-f`, `--file` | File with target URLs (one per line) |
| `--crawl` | Enable site crawling before scanning |
| `--crawl-js` | Use JavaScript rendering for crawling (requires Selenium) |
| `--depth` | Crawler depth limit (1-5, default: 2) |
| `--same-domain` | Restrict crawling to starting domain |

### Scan Options
| Flag | Description |
| --- | --- |
| `-t`, `--threads` | Worker thread count (default: 10) |
| `--cookie` | Cookie string (e.g., `name=value; name2=value2`) |
| `--header` | Custom HTTP header (can be used multiple times) |
| `--data` | POST data (JSON or form-encoded) |
| `--blind` | Enable blind XSS mode |
| `--blind-url` | Blind XSS callback URL |
| `--start-collector` | Start built-in blind XSS callback server |
| `--collector-port` | Callback collector port (default: 8000) |
| `--collector-wait` | Keep collector alive after scan (seconds, -1 = forever) |
| `--dom` | Enable DOM analysis |
| `--headless` | Verify XSS with Selenium headless browser |
| `--waf` | Enable WAF detection and bypass variants |
| `-p`, `--payloads` | Custom payload file path |
| `--timeout` | HTTP request timeout (default: 15s) |

### Output Options
| Flag | Description |
| --- | --- |
| `-o`, `--output` | Save report (supports .json, .html, .txt) |
| `-v`, `--verbose` | Detailed logging output |
| `--no-color` | Disable colored terminal output |
| `--quiet` | Suppress non-essential output |

### Connection Options
| Flag | Description |
| --- | --- |
| `--proxy` | HTTP/HTTPS proxy URL |
| `--delay` | Delay between requests in seconds (default: 0.1) |
| `--user-agent` | Custom User-Agent header |

### Other
| Flag | Description |
| --- | --- |
| `--version` | Show version information |
| `--check-setup` | Verify Chrome/Selenium availability |
| `-h`, `--help` | Show help message |

## Output Formats

Supported export formats:

- **JSON** - Complete structured output with metadata
- **HTML** - Interactive report with filtering and statistics
- **TXT** - Simple text format for quick review

All formats include timestamps, configuration details, and elapsed time.


## 🔧 Advanced Configuration

### Custom Payloads

Create a custom payload file (one per line, # for comments):

```
# Custom XSS Payloads
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
';alert(1)//
```

Use it:
```bash
python xssHunter.py -u "https://example.com" -p custom_payloads.txt
```

### Blind XSS Collector API

Start collector separately:
```bash
python -m modules.blind_collector
```

Or integrated with scan:
```bash
python xssHunter.py -u "https://target.com" --blind --start-collector --collector-port 9000
```

API endpoints:
- `GET /api/status` - Server status and callback counts
- `GET /api/callbacks?marker=<marker>` - Get callbacks for a marker
- `GET /api/export` - Export all findings as JSON
- `POST /api/register` - Register a marker for tracking

### Environment Variables

```bash
# Blind URL from environment
export XSSHUNTER_BLIND_URL="http://myserver.com:8000"
python xssHunter.py -u "https://target.com" --blind
```

## 📊 Performance Notes

- **Threads**: More threads = faster scanning (default: 10, max: 100)
- **Delay**: Reduce between-request delay for speed, increase for stealth (default: 0.1s)
- **Timeout**: Longer timeout for slow servers, shorter for quick failure (default: 15s)
- **Crawl Depth**: Higher depth finds more URLs but takes longer (max: 5)
- **JavaScript Crawling**: Slower than static crawling but discovers dynamic URLs

## 🐛 Troubleshooting

### Chrome/Chromium Not Found
```bash
python xssHunter.py --check-setup
```

This will detect Chrome and provide installation guidance.

### Selenium Connection Errors
- Ensure Chrome/Chromium is installed
- Update webdriver-manager: `pip install --upgrade webdriver-manager`
- Check browser compatibility with Selenium version

### Blind Callback Not Receiving
- Verify callback URL is accessible from target network
- Check firewall/port forwarding settings
- Enable verbose mode to see callback payload details

### SSL Certificate Errors
The tool disables SSL verification by default. For strict verification:
- Update network configuration or provide proper certificates

## 📝 Notes & Best Practices

- **No Query Parameters?** XSShunter skips targets without testable parameters (use `--data` for POST)
- **Static Assets**: Crawler automatically ignores `.jpg`, `.png`, `.pdf`, etc.
- **Large Payloads**: With 170 optimized payloads, average scan = ~170 requests per URL
- **Rate Limiting**: Many targets rate-limit scanners; adjust `--delay` and `--threads` accordingly
- **Legal**: Only scan targets you own or have explicit permission to test

## 🤝 Contributing

Found bugs or have feature requests? Open an issue or submit a pull request on GitHub.

## 📜 License

GNU General Public License v3.0 - See LICENSE file for details

## 👤 Author

**@3rabDev** - https://3rabdev.online

---

**XSShunter v1.6** - Advanced XSS Discovery Framework
