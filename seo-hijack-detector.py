#!/usr/bin/env python3
"""
Website Scanner for Gambling Scam/Phishing Indicators
Detects compromised websites redirecting to gambling scams.
"""

import os
import re
import sys
import json
import logging
import requests
from urllib.parse import urlparse
from dataclasses import dataclass, asdict, field
from datetime import datetime
from typing import List, Optional

# ---------------------------------------------------------------------------
# ANSI colors 
# ---------------------------------------------------------------------------
if os.name == "nt":
    os.system("")
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
ORANGE = "\033[38;5;208m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

COLOR = sys.stdout.isatty()

def paint(text, *colors):
    """Wrap text in ANSI color codes (no-op if colors disabled)."""
    return "".join(colors) + str(text) + RESET if COLOR else str(text)


logger = logging.getLogger(__name__)

ANDROID_UA = ("Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/92.0.4515.159 Mobile Safari/537.36")

# Box width (excluding the leading │ char)
WIDTH = 66


# ---------------------------------------------------------------------------
# Result container
# ---------------------------------------------------------------------------
@dataclass
class ScanResult:
    url: str
    timestamp: str
    status_code: int
    is_suspicious: bool
    indicators: List[str] = field(default_factory=list)
    redirect_target: Optional[str] = None
    trackers: List[str] = field(default_factory=list)
    hex_strings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    content_length: int = 0


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class ScamDetector:
    INDICATORS = {
        "Hex-encoded payload":      r"[0-9a-fA-F]{20,}",
        "Hex decoding function":    r"function\s+[Dd]\s*\([^)]*\)\s*\{[^}]*match\s*\(\s*/\../g",
        "Chinese tracker":          r"(sdk\.51\.la|51\.la|cnzz|umeng)",
        "Known malicious domain":   r"(jeahxuwy\.com|inonline\.games|pipecast\.org)",
        "Fake 404 redirect":        r"<title>404</title>.*?<script>.*?(?:location\.replace|window\.location)",
        "JS redirect":              r"(location\.replace|window\.location|location\.href\s*=|go\()",
        "Storage-based tracking":   r"(localStorage|sessionStorage)\.(setItem|getItem)",
        "Beacon tracking":          r"navigator\.sendBeacon|fetch\s*\([^)]*keepalive",
        "Cloaking (noindex+redir)": r"<meta.*?robots.*?noindex.*?nofollow.*?>.*?<script>.*?location",
    }

    MALICIOUS_DOMAINS = {
        "jeahxuwy.com", "inonline.games", "pipecast.org",
        "seo-gen.pipecast.org", "77.jeahxuwy.com", "b.inonline.games",
    }

    SUSPICIOUS_TLDS = (".top", ".xyz", ".club", ".online", ".site", ".win",
                       ".bid", ".loan", ".date", ".men", ".pw", ".space")

    TRACKERS = (r"sdk\.51\.la", r"cnzz\.com", r"umeng\.com",
                r"google-analytics\.com", r"gtag\.com", r"googletagmanager\.com")

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": ANDROID_UA,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Referer": "https://www.google.com/search?q=gambling+sites+india",
        })

    @staticmethod
    def _decode_hex(text: str):
        """Find hex strings that decode into URLs."""
        out = []
        for h in re.findall(r"[0-9a-fA-F]{20,}", text):
            if len(h) % 2 == 0:
                try:
                    d = bytes.fromhex(h).decode("utf-8", "ignore")
                    if d.startswith(("http", "/", "www")):
                        out.append((h, d))
                except Exception:
                    pass
        return out

    @staticmethod
    def _find_redirects(html: str):
        """Pull redirect URLs out of inline JS / anchors."""
        patterns = [
            r"location\.href\s*=\s*['\"]([^'\"]+)['\"]",
            r"location\.replace\s*\(\s*['\"]([^'\"]+)['\"]",
            r"window\.location\s*=\s*['\"]([^'\"]+)['\"]",
            r"<a\s+[^>]*href\s*=\s*['\"]([^'\"]+)['\"]",
        ]
        urls = []
        for p in patterns:
            urls.extend(re.findall(p, html))
        skip = ("/favicon", ".css", ".js", "data:")
        return [u for u in urls
                if u.startswith(("http", "/")) and not any(s in u for s in skip)]

    def _domain_issues(self, url: str):
        """Blocklist / suspicious-TLD check."""
        domain = urlparse(url).netloc.lower()
        issues = []
        if domain in self.MALICIOUS_DOMAINS:
            issues.append(f"Domain in blocklist: {domain}")
        for tld in self.SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                issues.append(f"Suspicious TLD: {tld}")
                break
        return issues

    def scan(self, url: str) -> ScanResult:
        """Fetch a URL and check it against all indicators."""
        r = ScanResult(url, datetime.now().isoformat(), 0, False)

        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
            r.status_code = resp.status_code
            html = resp.text
            r.content_length = len(html)

            if resp.status_code in (301, 302, 307, 308):
                loc = resp.headers.get("Location", "")
                if loc:
                    r.redirect_target = loc
                    r.indicators.append(f"HTTP redirect to {loc}")

            for label, pattern in self.INDICATORS.items():
                if re.search(pattern, html, re.I | re.S):
                    r.indicators.append(label)

            hexes = self._decode_hex(html)
            if hexes:
                r.hex_strings = [f"{h} -> {d}" for h, d in hexes[:3]]
                r.indicators.append(f"{len(hexes)} hex-encoded string(s)")

            redirects = self._find_redirects(html)
            if redirects:
                r.redirect_target = r.redirect_target or redirects[0]
                r.indicators.append(f"JS redirect -> {redirects[0]}")

            r.trackers = [p for p in self.TRACKERS if re.search(p, html, re.I)]
            r.indicators.extend(self._domain_issues(url))
            r.is_suspicious = bool(r.indicators)

        except requests.exceptions.Timeout:
            r.error = "timeout"
        except requests.exceptions.ConnectionError:
            r.error = "connection error"
        except Exception as e:
            r.error = str(e)

        return r


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------
def _verdict(r: ScanResult):
    """Return (label, color) based on the result state."""
    if r.error:
        return f"ERROR — {r.error}", YELLOW
    if r.is_suspicious:
        return "SUSPICIOUS", RED
    return "CLEAN", GREEN


def _truncate(text: str, width: int) -> str:
    """Cut text to width, adding ellipsis if it was longer."""
    return text if len(text) <= width else text[: width - 3] + "..."


def print_result(r: ScanResult):
    """Print one result as a self-contained box."""
    label, color = _verdict(r)
    url_color = ORANGE if r.error else color

    # Top border: ┌─ VERDICT ─────...
    title = f" {label} "
    fill = max(0, WIDTH - len(title) - 2)
    print()
    print(paint("┌─", color) + paint(title, color, BOLD) + paint("─" * fill + "┐", color))

    # URL line
    url_line = _truncate(r.url, WIDTH - 2)
    print(paint("│ ", color) + paint(url_line, url_color, BOLD))

    # Body
    body = []
    if r.status_code:
        s_color = RED if r.status_code >= 400 else (YELLOW if r.status_code >= 300 else GREEN)
        body.append(("status", paint(r.status_code, s_color)))
    if r.redirect_target:
        body.append(("redirect", paint(_truncate(r.redirect_target, WIDTH - 14), YELLOW)))
    if r.content_length:
        body.append(("size", f"{r.content_length} bytes"))

    if body:
        print(paint("│", color))
        for key, value in body:
            print(paint("│ ", color) + f"{paint(key, DIM):<18} {value}")

    # Indicators
    if r.indicators:
        print(paint("│", color))
        print(paint("│ ", color) + paint("indicators", BOLD))
        for ind in r.indicators:
            print(paint("│ ", color) + f"  • {_truncate(ind, WIDTH - 6)}")

    # Trackers
    if r.trackers:
        print(paint("│", color))
        print(paint("│ ", color) + paint("trackers", BOLD))
        for t in r.trackers:
            print(paint("│ ", color) + f"  • {t}")

    # Hex (decoded URL on its own line to avoid wrapping)
    if r.hex_strings:
        print(paint("│", color))
        print(paint("│ ", color) + paint("hex payload", BOLD))
        for entry in r.hex_strings:
            hex_part, _, url_part = entry.partition(" -> ")
            print(paint("│ ", color) + f"  {_truncate(hex_part, WIDTH - 6)}")
            print(paint("│ ", color) + f"    -> {paint(_truncate(url_part, WIDTH - 10), YELLOW)}")

    # Bottom border
    print(paint("└" + "─" * (WIDTH - 1) + "┘", color))


def print_summary(results: List[ScanResult]):
    """Total / clean / suspicious / errored counts."""
    clean   = [r for r in results if not r.is_suspicious and not r.error]
    bad     = [r for r in results if r.is_suspicious]
    errored = [r for r in results if r.error]

    print()
    print(paint("┌─ SUMMARY " + "─" * (WIDTH - 11) + "┐", BOLD))
    print(paint("│ ", BOLD) + f"{'Total scanned':<18} {len(results)}")
    print(paint("│ ", BOLD) + f"{'Clean':<18} {paint(len(clean), GREEN)}")
    print(paint("│ ", BOLD) + f"{'Suspicious':<18} {paint(len(bad), RED)}")
    print(paint("│ ", BOLD) + f"{'Errors':<18} {paint(len(errored), YELLOW)}")
    print(paint("└" + "─" * (WIDTH - 1) + "┘", BOLD))

    if bad:
        print()
        print(paint("Suspicious URLs", RED, BOLD))
        for r in bad:
            print(f"  {paint('•', RED)} {r.url}")
            if r.redirect_target:
                print(f"      {paint('->', DIM)} {r.redirect_target}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    with open("gambling-urls.txt") as f:
        urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]

    detector = ScamDetector(timeout=10)
    results = [detector.scan(u) for u in urls]

    for r in results:
        print_result(r)
    print_summary(results)

    report = {
        "scan_timestamp": datetime.now().isoformat(),
        "total_scanned": len(results),
        "suspicious_count": sum(r.is_suspicious for r in results),
        "results": [asdict(r) for r in results],
    }
    with open("scan_results.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print()
    print("Report saved to scan_results.json")


if __name__ == "__main__":
    main()
