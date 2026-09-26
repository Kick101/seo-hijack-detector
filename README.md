# SEO Hijack Detector

**A lightweight scanner that detects compromised websites redirecting visitors to gambling and phishing scam pages.**

Built for investigating domains that have been hijacked via **SEO poisoning** — the "fake 404 + hidden JS redirect" pattern that serves gambling content to mobile visitors while showing a harmless 404 to everyone else.

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Dependencies](https://img.shields.io/badge/dependencies-requests-blue)

---

## Why

Scammers compromise legitimate high-authority domains and inject obfuscated scripts that redirect mobile users to gambling sites. The compromised page usually:

- Returns a **fake 404** to fool the site owner
- **Hex-encodes** the redirect URL so it's not obvious in the source
- Uses **`noindex, nofollow`** so search engines drop the page
- Only fires the redirect for **Android user agents**

This tool automates the detection of all of the above.

---

## What it detects

| Indicator | Description |
|---|---|
| **Hex-encoded payloads** | Obfuscated URLs embedded as hex strings in JavaScript |
| **Fake 404 pages** | A `<title>404</title>` page containing a hidden redirect script |
| **JavaScript redirects** | `location.replace()`, `window.location`, `go()`, etc. |
| **Cloaking** | `noindex, nofollow` meta tags combined with redirect logic |
| **Known malicious domains** | Built-in blocklist of confirmed scam hosts |
| **Suspicious TLDs** | `.top`, `.xyz`, `.win`, `.bid`, `.loan`, `.pw`, and others |
| **Trackers** | Chinese analytics SDKs (`sdk.51.la`, `cnzz`, `umeng`), plus GA/GTM |

---

## Screenshot

<img width="1352" height="968" alt="image" src="https://github.com/user-attachments/assets/dca4bfbc-3e71-4922-90ed-fb7b9fc73e3a" />

```
┌─ SUSPICIOUS ────────────────────────────────────────────────┐
│ https://example.com/apps-official-game
│
│ status             200
│ redirect           https://ppe71.inonline.games
│ size               1600 bytes
│
│ indicators
│   • Hex-encoded payload
│   • Fake 404 redirect
│   • JS redirect
│   • Cloaking (noindex+redir)
│   • 1 hex-encoded string(s)
│
│ hex payload
│   68747470733a2f2f70706537316...
│     -> https://ppe71.inonline.games
└──────────────────────────────────────────────────────────────┘

┌─ CLEAN ─────────────────────────────────────────────────────┐
│ https://example.com
│
│ status             200
│ size               1256 bytes
└──────────────────────────────────────────────────────────────┘

┌─ SUMMARY ───────────────────────────────────────────────────┐
│ Total scanned      4
│ Clean              1
│ Suspicious         2
│ Errors             1
└──────────────────────────────────────────────────────────────┘
```

---

## Install

```bash
git clone https://github.com/Kick101/seo-hijack-detector.git
cd seo-hijack-detector
pip install -r requirements.txt
```

---

## Usage

Add URLs to `gambling-urls.txt` in the project root, one URL per line:

```
https://example.in/some-page
https://another-site.edu/suspicious-path

# Lines starting with # are ignored
# https://commented-out-url.example
```

Run the scanner:

```bash
python seo-hijack-detector.py
```

Output prints to your terminal and is saved to `scan_results.json`.

---

## How it works

For each URL the scanner:

1. **Fetches the page** using a mobile Android user-agent — scam pages frequently serve different content to mobile visitors
2. **Checks HTTP status** for `3xx` redirects
3. **Runs ~10 regex signatures** over the HTML for known scam patterns
4. **Decodes hex strings** and checks if they resolve to URLs
5. **Extracts inline JS redirects** and suspicious `<a href>` targets
6. **Flags trackers** and **known-malicious domains**
7. **Prints a color-coded box** and writes a JSON report

No headless browser required — it's a pure HTTP + regex scanner, fast enough to run over thousands of URLs.

---

## Background: what is SEO hijacking?

SEO hijacking is a class of attack where an adversary:

1. Gains write access to a legitimate, high-authority website — via a vulnerable CMS plugin, stolen credentials, or an exposed admin panel
2. Injects pages or scripts that only activate for **search engine crawlers and mobile users**
3. Redirects those visitors to a gambling, adult, or phishing site
4. Serves a **fake 404** to the actual site owner so they don't notice

Victims are usually government portals, universities, and small-business sites with outdated CMS installs. The compromised domain's authority is abused to rank the scam pages in Google, while the site owner has no idea anything is wrong.

The obvious redirect makes it detectable — that's what this tool looks for.

---

## Customization

**Add malicious domains** — edit `MALICIOUS_DOMAINS` in `ScamDetector`:

```python
MALICIOUS_DOMAINS = {
    "jeahxuwy.com", "inonline.games", "pipecast.org",
    # add new ones here
}
```

**Add a new indicator** — edit `INDICATORS`:

```python
INDICATORS = {
    # ...
    "My new pattern": r"some-regex-here",
}
```

**Change the user-agent** — edit `ANDROID_UA` at the top of the file.

---

## Limitations

- **Regex-based, not a browser.** Heavily obfuscated pages or sites that require JS execution to redirect may slip through. Pair with a headless browser (Playwright, Selenium) for those.
- **Static blocklist.** `MALICIOUS_DOMAINS` is manually curated. Update it as you find new scam hosts.
- **No threat-intel integration yet.** The `check_domain_reputation` method is a natural hook for VirusTotal, URLScan, or Google Safe Browsing APIs.
- **Only inspects the first page.** Doesn't follow redirects or crawl linked pages.

---

## Roadmap

- [ ] VirusTotal / URLScan.io integration
- [ ] Optional Playwright mode for JS-rendered redirects
- [ ] CSV output alongside JSON
- [ ] Config file (`config.yaml`) instead of editing constants
- [ ] Concurrency with `asyncio` or `ThreadPoolExecutor`
- [ ] UI

---

## Contributing

Pull requests welcome. If you find a new scam pattern or a false positive, open an issue with:

- The URL (or a sanitized version)
- The HTML snippet that matched
- What the correct verdict should be

Please do not open issues containing live scam URLs without sanitizing them first.

---

## Disclaimer

This tool is intended for **defensive security research and incident response**. Only scan domains you own or have explicit permission to investigate. Do not use it to attack, overload, or enumerate systems you don't control.

The author takes no responsibility for misuse.

---

## License

[MIT](LICENSE)




