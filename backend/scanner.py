#!/usr/bin/env python3
"""
WeakPoint Web Security Scanner
--------------------------------

Provides the scanning core that powers the CLI as well as the API layer.
The scanner focuses on non-intrusive checks grouped into:

* Critical checks   – HTTPS/TLS, security headers, cookies, etc.
* Important checks  – app misconfigurations such as verbose errors or exposed backups.
* Nice-to-have      – performance, accessibility, SEO, privacy signals.

All requests are performed with regular GET/HEAD calls and respect timeouts
to avoid unnecessary load on the target.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import socket
import ssl
import gzip
from collections import deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from bs4 import BeautifulSoup

DEFAULT_TIMEOUT = 12
USER_AGENT = "WeakPoint-Scanner/2.0 (+https://weakpoint.example)"

STATUS_PASS = "pass"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
STATUS_INFO = "info"

SEVERITY_CRITICAL = "critical"
SEVERITY_IMPORTANT = "important"
SEVERITY_NICE = "nice-to-have"

DEFAULT_MAX_PAGES = 80
DEFAULT_MAX_DEPTH = 4
MAX_SEED_URLS = 120
MAX_SITEMAP_URLS = 60
MAX_ROBOTS_ALLOW_PATHS = 20
MAX_REFLECTION_TESTS = 8
REFLECTION_PARAM = "__weakpoint_probe"
HEADLESS_TRIGGER_CODES = {401, 403, 406, 429, 451}
HEADLESS_ENV_FLAG = os.getenv("WEAKPOINT_HEADLESS", "0") == "1"

SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql_fetch",
    "sqlstate",
    "odbc",
    "ora-",
    "pg::",
    "fatal error",
]

PENTEST_FORM_LIMIT = 8
PENTEST_PAYLOAD_TEMPLATE = "\"'><weakpoint-{token}>"

try:
    from playwright.sync_api import sync_playwright
except Exception:  # pragma: no cover - optional dependency
    sync_playwright = None

HEADLESS_AVAILABLE = bool(sync_playwright and HEADLESS_ENV_FLAG)
SITEMAP_GUESSES = [
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/sitemap1.xml",
    "/sitemap-news.xml",
]
COMMON_CONTENT_PATHS = [
    "/",
    "/home",
    "/index",
    "/nieuws",
    "/actueel",
    "/over-ons",
    "/overons",
    "/contact",
    "/diensten",
    "/service",
    "/blog",
    "/cases",
    "/projecten",
    "/support",
    "/privacy",
    "/voorwaarden",
]

SECURITY_HEADERS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
]

LEGACY_TLS_PROTOCOLS: List[Tuple[str, Optional[int]]] = [
    ("TLSv1.0", getattr(ssl, "PROTOCOL_TLSv1", None)),
    ("TLSv1.1", getattr(ssl, "PROTOCOL_TLSv1_1", None)),
]

BACKUP_PROBES = [
    "/.git/HEAD",
    "/backup.zip",
    "/backup.tar.gz",
    "/wp-config.php",
    "/config.php.bak",
    "/.env",
]

PRIVACY_KEYWORDS = ("privacy", "avg", "gdpr", "gegevensbescherming", "cookie")

COMMON_LOGIN_PATHS = [
    "/login",
    "/admin",
    "/beheer",
    "/wp-login.php",
    "/wp-admin",
    "/user/login",
    "/auth/login",
    "/account/login",
    "/signin",
    "/dashboard",
    "/beheer/login",
    "/cms",
]

DIRECTORY_LISTING_MARKERS = [
    "index of /",
    "directory listing",
    "parent directory",
]

JS_LIBRARY_BASELINES: Dict[str, Tuple[int, ...]] = {
    "jquery": (3, 6, 0),
    "bootstrap": (4, 6, 0),
    "angular": (1, 8, 3),
    "react": (17, 0, 2),
    "vue": (2, 6, 14),
}

GRAPHQL_COMMON_PATHS = ["/graphql", "/api/graphql", "/graphiql"]

GRAPHQL_INTROSPECTION_QUERY = {
    "query": (
        "query WeakPointIntrospection { __schema { queryType { name } mutationType { name } } }"
    )
}

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})


@dataclass
class PageSnapshot:
    url: str
    status_code: int
    html: str
    soup: BeautifulSoup
    headers: Dict[str, str]


@dataclass
class CheckResult:
    id: str
    title: str
    severity: str
    status: str
    summary: str
    remediation: str
    impact: Optional[str] = None
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        return {k: v for k, v in payload.items() if v is not None}


@dataclass
class ScanContext:
    target_url: str
    response: requests.Response
    html: str
    soup: BeautifulSoup
    robots_txt: Optional[str]
    sitemap_found: bool
    pages: List[PageSnapshot] = field(default_factory=list)

    @property
    def parsed_url(self):
        return urlparse(self.response.url)


def _safe_request(
    url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT, **kwargs
) -> Optional[requests.Response]:
    resp: Optional[requests.Response]
    try:
        resp = SESSION.request(method, url, timeout=timeout, **kwargs)
    except Exception:
        resp = None

    should_try_headless = (
        HEADLESS_AVAILABLE
        and method.upper() == "GET"
        and (resp is None or resp.status_code in HEADLESS_TRIGGER_CODES)
    )
    if should_try_headless:
        fallback = _headless_request(url, timeout=timeout)
        if fallback:
            return fallback
    return resp


def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    if path != "/":
        path = path.rstrip("/") or "/"
    normalized = urlunparse((scheme, netloc, path, "", parsed.query, ""))
    return normalized


def _append_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    query.append((key, value))
    new_query = urlencode(query)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path or "/",
            parsed.params,
            new_query,
            parsed.fragment,
        )
    )


def _normalize_hostname(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    normalized = host.lower().rstrip(".")
    if normalized.startswith("www."):
        normalized = normalized[4:]
    return normalized


def _extract_version_tuple(candidate: str) -> Tuple[int, ...]:
    match = re.search(r"(\d+(?:\.\d+){0,2})", candidate)
    if not match:
        return ()
    parts = match.group(1).split(".")
    try:
        return tuple(int(part) for part in parts)
    except ValueError:
        return ()


def _version_is_older(found: Tuple[int, ...], baseline: Tuple[int, ...]) -> bool:
    if not found:
        return False
    max_len = max(len(found), len(baseline))
    padded_found = found + (0,) * (max_len - len(found))
    padded_baseline = baseline + (0,) * (max_len - len(baseline))
    return padded_found < padded_baseline


def _hosts_match(base_host: Optional[str], candidate_host: Optional[str]) -> bool:
    base = _normalize_hostname(base_host)
    candidate = _normalize_hostname(candidate_host)
    if not base or not candidate:
        return True
    if candidate == base:
        return True
    return candidate.endswith(f".{base}")


class HeadlessResponse:
    def __init__(self, url: str, status_code: int, headers: Dict[str, str], html: str):
        self.url = url
        self.status_code = status_code
        self.headers = headers
        self._text = html
        self.content = html.encode("utf-8", errors="ignore")
        self.encoding = "utf-8"
        self.history: List[Any] = []

    @property
    def text(self) -> str:
        return self._text


def _headless_request(url: str, timeout: int = DEFAULT_TIMEOUT) -> Optional[HeadlessResponse]:
    if not HEADLESS_AVAILABLE:
        return None
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=USER_AGENT,
                viewport={"width": 1280, "height": 720},
            )
            page = context.new_page()
            try:
                response = page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                if response is None:
                    return None
                html = page.content()
                headers = dict(response.headers())
                final_url = page.url
                status_code = response.status or 0
                return HeadlessResponse(final_url, status_code, headers, html)
            finally:
                context.close()
                browser.close()
    except Exception:
        return None


def _notify_progress(
    callback: Optional[Callable[[Dict[str, Any]], None]],
    payload: Dict[str, Any],
) -> None:
    if not callback:
        return
    try:
        callback(payload)
    except Exception:
        # Progress callbacks are best-effort only.
        pass


def _estimate_progress(count: int, budget: int, *, floor: float = 5.0, ceiling: float = 92.0) -> float:
    if budget <= 0:
        return floor
    ratio = min(max(count / budget, 0.0), 1.0)
    span = max(ceiling - floor, 1.0)
    return round(floor + ratio * span, 2)


def _read_limit_from_env(var_name: str, default: int, minimum: int) -> int:
    value = os.getenv(var_name)
    if value is None:
        return default
    try:
        parsed = int(value)
    except ValueError:
        return default
    return max(minimum, parsed)


def _get_scan_limits() -> Tuple[int, int]:
    max_pages = _read_limit_from_env("WEAKPOINT_MAX_PAGES", DEFAULT_MAX_PAGES, 8)
    max_depth = _read_limit_from_env("WEAKPOINT_MAX_DEPTH", DEFAULT_MAX_DEPTH, 2)
    return max_pages, max_depth


def _is_html_response(resp: requests.Response) -> bool:
    content_type = resp.headers.get("Content-Type", "").lower()
    return "html" in content_type or "xml" in content_type or not content_type


def _extract_links(
    soup: BeautifulSoup, base_url: str, base_host: Optional[str]
) -> Iterable[str]:
    links: Set[str] = set()
    for tag in soup.find_all("a", href=True):
        href = tag.get("href") or ""
        href = href.strip()
        if not href or href.startswith("#"):
            continue
        if any(href.lower().startswith(prefix) for prefix in ("mailto:", "javascript:", "tel:", "data:")):
            continue
        absolute = urljoin(base_url, href)
        parsed = urlparse(absolute)
        if parsed.scheme not in {"http", "https"}:
            continue
        if base_host and parsed.hostname and not _hosts_match(base_host, parsed.hostname):
            continue
        links.add(_normalize_url(absolute))
    return links


def _extract_sitemaps_from_robots(robots_txt: str, base_root: str) -> List[str]:
    urls: List[str] = []
    for line in robots_txt.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        if lower.startswith("sitemap:"):
            parts = stripped.split(":", 1)
            if len(parts) < 2:
                continue
            candidate = parts[1].strip()
            if not candidate:
                continue
            if candidate.startswith(("http://", "https://")):
                urls.append(candidate)
            elif candidate.startswith("/"):
                urls.append(urljoin(base_root, candidate))
    return urls


def _extract_allowed_paths_from_robots(robots_txt: str, base_root: str) -> List[str]:
    paths: List[str] = []
    for line in robots_txt.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        lower = stripped.lower()
        if lower.startswith("allow:"):
            parts = stripped.split(":", 1)
            if len(parts) < 2:
                continue
            path = parts[1].strip()
            if not path or not path.startswith("/"):
                continue
            paths.append(urljoin(base_root, path))
            if len(paths) >= MAX_ROBOTS_ALLOW_PATHS:
                break
    return paths


def _fetch_sitemap_document(url: str) -> Optional[str]:
    resp = _safe_request(url, timeout=10)
    if not resp or resp.status_code >= 400:
        return None
    content = resp.content
    content_type = resp.headers.get("Content-Type", "").lower()
    is_gzip = url.lower().endswith(".gz") or "gzip" in content_type
    if is_gzip:
        try:
            content = gzip.decompress(content)
        except OSError:
            return None
    encoding = resp.encoding or "utf-8"
    try:
        return content.decode(encoding, errors="ignore")
    except Exception:
        return content.decode("utf-8", errors="ignore")


def _parse_sitemap_document(
    xml_text: str, base_host: Optional[str]
) -> Tuple[List[str], List[str]]:
    try:
        soup = BeautifulSoup(xml_text, "xml")
    except Exception:
        return [], []

    page_urls: List[str] = []
    nested_sitemaps: List[str] = []

    for url_tag in soup.find_all("url"):
        loc = url_tag.find("loc")
        if not loc or not loc.text:
            continue
        candidate = loc.text.strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            continue
        if not _hosts_match(base_host, parsed.hostname):
            continue
        page_urls.append(_normalize_url(candidate))
        if len(page_urls) >= MAX_SITEMAP_URLS:
            break

    for sitemap_tag in soup.find_all("sitemap"):
        loc = sitemap_tag.find("loc")
        if not loc or not loc.text:
            continue
        candidate = loc.text.strip()
        parsed = urlparse(candidate)
        if parsed.scheme not in {"http", "https"}:
            continue
        if not _hosts_match(base_host, parsed.hostname):
            continue
        nested_sitemaps.append(_normalize_url(candidate))

    if not page_urls and not nested_sitemaps:
        for loc in soup.find_all("loc"):
            candidate = (loc.text or "").strip()
            if not candidate:
                continue
            parsed = urlparse(candidate)
            if parsed.scheme not in {"http", "https"}:
                continue
            if not _hosts_match(base_host, parsed.hostname):
                continue
            page_urls.append(_normalize_url(candidate))
            if len(page_urls) >= MAX_SITEMAP_URLS:
                break

    return page_urls, nested_sitemaps


def _collect_sitemap_pages(
    base_root: str,
    base_host: Optional[str],
    robots_txt: Optional[str],
    *,
    max_sitemaps: int = 12,
) -> List[str]:
    targets: deque[str] = deque()
    seen_targets: Set[str] = set()
    collected_pages: List[str] = []

    initial_targets = {urljoin(base_root, guess) for guess in SITEMAP_GUESSES}
    if robots_txt:
        initial_targets.update(_extract_sitemaps_from_robots(robots_txt, base_root))
    for target in initial_targets:
        targets.append(_normalize_url(target))

    while targets and len(seen_targets) < max_sitemaps:
        target = targets.popleft()
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        xml_doc = _fetch_sitemap_document(target)
        if not xml_doc:
            continue
        pages, nested = _parse_sitemap_document(xml_doc, base_host)
        for page in pages:
            if page not in collected_pages:
                collected_pages.append(page)
                if len(collected_pages) >= MAX_SITEMAP_URLS:
                    return collected_pages
        for nested_url in nested:
            if nested_url not in seen_targets:
                targets.append(nested_url)
        if len(seen_targets) >= max_sitemaps:
            break
    return collected_pages


def _build_seed_urls(
    base_root: str,
    base_host: Optional[str],
    robots_txt: Optional[str],
    sitemap_pages: List[str],
) -> List[str]:
    seeds: List[str] = [urljoin(base_root, path) for path in COMMON_CONTENT_PATHS]
    seeds.extend(urljoin(base_root, path) for path in COMMON_LOGIN_PATHS)
    if robots_txt:
        seeds.extend(_extract_allowed_paths_from_robots(robots_txt, base_root))
    seeds.extend(sitemap_pages)

    unique: List[str] = []
    seen: Set[str] = set()
    for seed in seeds:
        normalized = _normalize_url(seed)
        if normalized in seen:
            continue
        seen.add(normalized)
        unique.append(normalized)
        if len(unique) >= MAX_SEED_URLS:
            break
    return unique


def _snapshot_from_response(resp: requests.Response) -> PageSnapshot:
    html = resp.text or ""
    soup = BeautifulSoup(html, "html.parser")
    headers = {k: v for k, v in resp.headers.items()}
    return PageSnapshot(
        url=resp.url,
        status_code=resp.status_code,
        html=html,
        soup=soup,
        headers=headers,
    )


def _crawl_site(
    initial: PageSnapshot,
    *,
    max_pages: int = 12,
    max_depth: int = 2,
    seed_urls: Optional[Iterable[str]] = None,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
) -> List[PageSnapshot]:
    base_parsed = urlparse(initial.url)
    base_host = base_parsed.hostname
    base_root = f"{base_parsed.scheme}://{base_parsed.netloc}"

    snapshots: List[PageSnapshot] = [initial]
    visited: Set[str] = {_normalize_url(initial.url)}
    queued: Set[str] = set()
    queue: deque[Tuple[str, int]] = deque()

    def enqueue(candidate: str, depth: int) -> None:
        normalized = _normalize_url(candidate)
        if normalized in visited or normalized in queued:
            return
        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"}:
            return
        if parsed.hostname and base_host and not _hosts_match(base_host, parsed.hostname):
            return
        queued.add(normalized)
        queue.append((normalized, depth))

    _notify_progress(
        progress_callback,
        {
            "type": "page",
            "url": initial.url,
            "status_code": initial.status_code,
            "depth": 0,
            "count": len(snapshots),
            "budget": max_pages,
            "progress": _estimate_progress(len(snapshots), max_pages),
        },
    )

    for link in _extract_links(initial.soup, initial.url, base_host):
        enqueue(link, 1)

    for path in COMMON_LOGIN_PATHS:
        enqueue(urljoin(base_root, path), 1)

    if seed_urls:
        for seed in seed_urls:
            enqueue(seed, 1)

    while queue and len(snapshots) < max_pages:
        candidate, depth = queue.popleft()
        queued.discard(candidate)
        if candidate in visited:
            continue
        resp = _safe_request(candidate, allow_redirects=True)
        visited.add(candidate)
        if resp is None:
            continue
        normalized_final = _normalize_url(resp.url)
        if normalized_final in visited:
            continue
        if resp.status_code >= 500:
            visited.add(normalized_final)
            continue
        if not _is_html_response(resp):
            visited.add(normalized_final)
            continue
        snapshot = _snapshot_from_response(resp)
        snapshots.append(snapshot)
        visited.add(normalized_final)
        _notify_progress(
            progress_callback,
            {
                "type": "page",
                "url": snapshot.url,
                "status_code": snapshot.status_code,
                "depth": depth,
                "count": len(snapshots),
                "budget": max_pages,
                "progress": _estimate_progress(len(snapshots), max_pages),
            },
        )
        if depth < max_depth:
            for link in _extract_links(snapshot.soup, snapshot.url, base_host):
                enqueue(link, depth + 1)
        if len(snapshots) >= max_pages:
            break

    unique_snapshots: Dict[str, PageSnapshot] = {}
    for snap in snapshots:
        key = _normalize_url(snap.url)
        if key not in unique_snapshots:
            unique_snapshots[key] = snap

    return list(unique_snapshots.values())


def _iter_pages(context: ScanContext) -> List[PageSnapshot]:
    if context.pages:
        return context.pages
    fallback = PageSnapshot(
        url=context.response.url,
        status_code=context.response.status_code,
        html=context.html,
        soup=context.soup,
        headers={k: v for k, v in context.response.headers.items()},
    )
    return [fallback]


def _extract_cookies(resp: requests.Response) -> List[Dict[str, Any]]:
    cookies = []
    header = resp.headers.get("Set-Cookie")
    if not header:
        return cookies
    raw_cookies = [c.strip() for c in header.split(", ")]
    for raw in raw_cookies:
        parts = raw.split(";")
        attrs: Dict[str, Any] = {"name": parts[0].strip()}
        for attr in parts[1:]:
            attr = attr.strip()
            if "=" in attr:
                key, value = attr.split("=", 1)
                attrs[key.lower()] = value
            else:
                attrs[attr.lower()] = True
        cookies.append(attrs)
    return cookies


def _build_result(
    *,
    id: str,
    title: str,
    severity: str,
    status: str,
    summary: str,
    remediation: str,
    impact: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
) -> CheckResult:
    return CheckResult(
        id=id,
        title=title,
        severity=severity,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_tls(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    if parsed.scheme != "https":
        return _build_result(
            id="tls",
            title="HTTPS / TLS",
            severity=SEVERITY_CRITICAL,
            status=STATUS_WARN,
            summary="Site gebruikt geen HTTPS; verkeer kan onderschept worden.",
            remediation="Forceer HTTPS en installeer een geldig certificaat (bijv. Let's Encrypt).",
            impact="Aanvallers kunnen verkeer meelezen of manipuleren via een man-in-the-middle aanval waardoor inloggegevens of sessies uitlekken.",
        )

    host = parsed.hostname
    port = parsed.port or 443
    details: Dict[str, Any] = {"host": host, "port": port}

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                details["subject"] = cert.get("subject")
                details["issuer"] = cert.get("issuer")
                details["tls_version"] = ssock.version()
                cipher = ssock.cipher()
                if cipher:
                    details["cipher_suite"] = cipher[0]
                not_after = cert.get("notAfter")
                if not_after:
                    try:
                        expires = datetime.strptime(
                            not_after, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        details["expires_at"] = expires.isoformat()
                        details["days_remaining"] = int(
                            (expires - datetime.now(timezone.utc)).days
                        )
                    except Exception:
                        details["expires_raw"] = not_after
    except ssl.SSLCertVerificationError as exc:
        details["error"] = str(exc)
        return _build_result(
            id="tls",
            title="HTTPS / TLS",
            severity=SEVERITY_CRITICAL,
            status=STATUS_FAIL,
            summary="Certificaat is ongeldig of niet te valideren.",
            remediation="Controleer intermediate ketens en voer een heruitgifte uit.",
            impact="Browsers vertrouwen de verbinding niet waardoor bezoekers eenvoudig kunnen worden omgeleid naar malafide servers.",
            details=details,
        )
    except Exception as exc:
        details["error"] = str(exc)
        return _build_result(
            id="tls",
            title="HTTPS / TLS",
            severity=SEVERITY_CRITICAL,
            status=STATUS_FAIL,
            summary="TLS-handshake mislukt; controleer serverconfiguratie.",
            remediation="Controleer firewall, certificaatketen en sluit oude protocollen uit.",
            impact="Wanneer TLS faalt kunnen bezoekers geen veilige verbinding opzetten en is spoofing of downtime mogelijk.",
            details=details,
        )

    legacy = []
    for label, protocol in LEGACY_TLS_PROTOCOLS:
        if protocol is None or not host:
            continue
        try:
            ctx = ssl.SSLContext(protocol)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=DEFAULT_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    legacy.append(label)
        except Exception:
            continue
    if legacy:
        details["legacy_protocols"] = legacy

    status = STATUS_PASS
    summary = "Geldig certificaat en moderne TLS-configuratie aangetroffen."
    remediation = "Blijf certificaten automatisch vernieuwen en schakel zwakke ciphers uit."
    impact: Optional[str] = (
        "Verkeer is beschermd tegen afluisteren; misbruik via netwerk-sniffing wordt voorkomen."
    )

    days_remaining = details.get("days_remaining")
    if isinstance(days_remaining, int) and days_remaining < 0:
        status = STATUS_FAIL
        summary = "Certificaat is verlopen."
        remediation = "Vernieuw het certificaat en controleer automatische vernieuwing."
        impact = "Browsers blokkeren verlopen certificaten waardoor bezoekers eerder malafide varianten accepteren."
    elif isinstance(days_remaining, int) and days_remaining < 30:
        status = STATUS_WARN
        summary = "Certificaat verloopt binnen 30 dagen."
        remediation = "Plan vernieuwing via ACME (Let's Encrypt) of eigen CA."
        impact = "Zodra het certificaat verloopt zien bezoekers waarschuwingen en kunnen aanvallers MITM-aanvallen forceren."
    if legacy:
        status = STATUS_WARN
        summary = (
            "Server accepteert legacy TLS-versies (" + ", ".join(legacy) + "); schakel ze uit."
        )
        remediation = "Sta alleen TLS1.2+ toe met ECDHE/ECDSA-ciphers."
        impact = "Legacy TLS-protocollen bevatten bekende zwaktes waardoor downgrade-aanvallen mogelijk zijn."

    return _build_result(
        id="tls",
        title="HTTPS / TLS",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_security_headers(context: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    missing = [header for header in SECURITY_HEADERS if header not in headers]
    details = {"present": {k: headers[k] for k in headers if k in SECURITY_HEADERS}}
    if missing:
        details["missing"] = missing
        return _build_result(
            id="security_headers",
            title="Security headers",
            severity=SEVERITY_CRITICAL,
            status=STATUS_WARN,
            summary="Ontbrekende headers: " + ", ".join(missing),
            remediation="Configureer CSP, HSTS, XFO, Referrer-Policy, Permissions-Policy en X-Content-Type-Options.",
            impact="Zonder deze headers kunnen aanvallers eenvoudiger clickjacking, XSS of content-sniffing aanvallen uitvoeren.",
            details=details,
        )
    return _build_result(
        id="security_headers",
        title="Security headers",
        severity=SEVERITY_CRITICAL,
        status=STATUS_PASS,
        summary="Essentiële beveiligingsheaders zijn aanwezig.",
        remediation="Controleer periodiek of policies up-to-date zijn.",
        impact="Browsers blokkeren veelvoorkomende aanvalsvectoren dankzij de ingestelde headers.",
        details=details,
    )


def _check_cache_control(context: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    cache_control = headers.get("cache-control")
    pragma = headers.get("pragma")
    issues = []
    if not cache_control:
        issues.append("Cache-Control header ontbreekt op de hoofdpagina.")
    else:
        lowered = cache_control.lower()
        if "no-cache" not in lowered and "no-store" not in lowered:
            issues.append("Cache-Control ontbreekt no-cache/no-store voor dynamische content.")
    if pragma and "no-cache" not in pragma.lower():
        issues.append("Pragma header staat caching toe; verwijder of zet op no-cache.")

    status = STATUS_PASS if not issues else STATUS_WARN
    summary = (
        "Cache headers voorkomen opslag van gevoelige inhoud."
        if not issues
        else "; ".join(issues)
    )
    remediation = (
        "Stel Cache-Control: no-store, no-cache, must-revalidate in voor gevoelige pagina's."
    )
    impact = (
        "Browsers en proxies bewaren geen gevoelige data waardoor sessies moeilijker te kapen zijn."
        if status == STATUS_PASS
        else "Zonder strikte cache-directives kunnen derden op gedeelde apparaten sessies of persoonsgegevens terughalen."
    )
    return _build_result(
        id="cache_control",
        title="Cache-Control & privacy",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"cache_control": cache_control, "pragma": pragma},
    )


def _check_csp_strength(context: ScanContext) -> CheckResult:
    csp_header = context.response.headers.get("Content-Security-Policy")
    if not csp_header:
        return _build_result(
            id="csp_quality",
            title="Content Security Policy kwaliteit",
            severity=SEVERITY_CRITICAL,
            status=STATUS_WARN,
            summary="Geen CSP header gevonden; inline scripts kunnen XSS mogelijk maken.",
            remediation="Implementeer een CSP met default-src 'self' en beperk externe bronnen.",
            impact="Zonder CSP kunnen ingesloten scripts van aanvallers wachtwoorden en sessies buitmaken.",
        )

    policy = csp_header.lower()
    findings = []
    if "unsafe-inline" in policy:
        findings.append("'unsafe-inline' staat toe dat inline scripts draaien.")
    if "unsafe-eval" in policy:
        findings.append("'unsafe-eval' maakt eval()/new Function mogelijk.")
    if "http:" in policy:
        findings.append("CSP staat onversleutelde http-resources toe.")
    if not re.search(r"default-src\s+[^;]+", policy):
        findings.append("default-src ontbreekt; browsers vallen terug op alles toestaan.")

    status = STATUS_PASS if not findings else STATUS_WARN
    summary = (
        "CSP lijkt streng geconfigureerd."
        if not findings
        else "; ".join(findings)
    )
    remediation = "Verwijder onveilige directives en beperk bronnen tot 'self' of specifieke hosts."
    impact = (
        "De CSP is streng en beperkt scriptinjecties tot vertrouwde bronnen."
        if not findings
        else "Een zwakke CSP laat kwaadaardige scripts toe die bezoekers kunnen omleiden of data stelen."
    )
    return _build_result(
        id="csp_quality",
        title="Content Security Policy kwaliteit",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"csp": csp_header, "issues": findings} if findings else {"csp": csp_header},
    )


def _check_mixed_content(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    if parsed.scheme != "https":
        return _build_result(
            id="mixed_content",
            title="Mixed content",
            severity=SEVERITY_CRITICAL,
            status=STATUS_INFO,
            summary="Pagina draait op HTTP; mixed content niet van toepassing.",
            remediation="Stap over op HTTPS om mixed content te voorkomen.",
            impact="Omdat alles over HTTP gaat kunnen aanvallers eenvoudig scripts of malware injecteren.",
        )

    mixed = []
    for tag in context.soup.find_all(["script", "img", "link", "iframe", "audio", "video", "source"]):
        candidate = tag.get("src") or tag.get("href")
        if not candidate:
            continue
        absolute = urljoin(context.response.url, candidate)
        if absolute.startswith("http://"):
            mixed.append({"tag": tag.name, "url": absolute})
    if mixed:
        return _build_result(
            id="mixed_content",
            title="Mixed content",
            severity=SEVERITY_CRITICAL,
            status=STATUS_WARN,
            summary=f"{len(mixed)} HTTP-resources op een HTTPS pagina.",
            remediation="Serve alle assets via HTTPS of gebruik protocol-relatieve URL's.",
            impact="HTTP-assets laten man-in-the-middle aanvallen toe waarbij hackers content aanpassen of sessies stelen.",
            details={"items": mixed[:25]},
        )
    return _build_result(
        id="mixed_content",
        title="Mixed content",
        severity=SEVERITY_CRITICAL,
        status=STATUS_PASS,
        summary="Geen mixed-content risico's gevonden.",
        remediation="Blijf CI/CD checks inzetten om HTTP-assets te blokkeren.",
        impact="Alle assets laden via HTTPS waardoor injectie door netwerk-aanvallers wordt voorkomen.",
    )


def _check_redirects_and_canonical(context: ScanContext) -> CheckResult:
    history = context.response.history or []
    chain = [resp.status_code for resp in history] + [context.response.status_code]
    issues = []
    if len(history) > 3:
        issues.append("Redirectketen langer dan 3 stappen.")
    unique_urls = {resp.url for resp in history}
    unique_urls.add(context.response.url)
    if len(unique_urls) != len(chain):
        issues.append("Mogelijke redirect-loop of dubbele URL's.")

    canonical = context.soup.find("link", attrs={"rel": lambda val: val and "canonical" in val.lower()})
    if not canonical or not canonical.get("href"):
        issues.append("Ontbrekende canonical tag.")
    else:
        canonical_host = urlparse(urljoin(context.response.url, canonical["href"])).hostname
        if canonical_host and canonical_host != context.parsed_url.hostname:
            issues.append("Canonical verwijst naar andere host; check www/non-www.")

    status = STATUS_PASS if not issues else STATUS_WARN
    summary = "Redirect en canonical configuratie ziet er goed uit." if not issues else "; ".join(issues)
    remediation = "Gebruik korte 301-ketens en stel een eenduidige canonical in."
    impact = (
        "Stabiele redirectketens voorkomen dat bezoekers op malafide varianten terechtkomen."
        if status == STATUS_PASS
        else "Inconsistente redirects maken phishing en SEO-poisoning makkelijker voor aanvallers."
    )
    return _build_result(
        id="redirects",
        title="Redirects & canonical",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"redirect_chain": chain, "final_url": context.response.url},
    )


def _check_cors(context: ScanContext) -> CheckResult:
    headers = context.response.headers
    acao = headers.get("Access-Control-Allow-Origin")
    acac = headers.get("Access-Control-Allow-Credentials")
    if acao == "*":
        return _build_result(
            id="cors",
            title="CORS configuratie",
            severity=SEVERITY_CRITICAL,
            status=STATUS_FAIL if (acac and acac.lower() == "true") else STATUS_WARN,
            summary="Alle origins mogen API benaderen; risico op data-exfiltratie.",
            remediation="Gebruik specifieke origins of verwijder CORS-header waar niet nodig.",
            impact="Kwaadaardige websites kunnen requests namens ingelogde gebruikers uitvoeren en gevoelige API-data uitlezen.",
            details={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac},
        )
    if not acao:
        return _build_result(
            id="cors",
            title="CORS configuratie",
            severity=SEVERITY_CRITICAL,
            status=STATUS_PASS,
            summary="Geen CORS-header aangetroffen (default deny).",
            remediation="Sta alleen origins toe die het nodig hebben; gebruik allowlists.",
            impact="Requests vanaf onbekende origins worden standaard geweigerd waardoor sessies niet te kapen zijn.",
        )
    return _build_result(
        id="cors",
        title="CORS configuratie",
        severity=SEVERITY_CRITICAL,
        status=STATUS_INFO,
        summary=f"CORS staat {acao} toe; controleer of dit gewenst is.",
        remediation="Synchroniseer Access-Control-Allow-Origin met toegestane clients.",
        impact="Controleer of de toegestane origin geen malafide site is die sessies kan misbruiken.",
        details={"Access-Control-Allow-Origin": acao, "Access-Control-Allow-Credentials": acac},
    )


def _check_cookies(context: ScanContext) -> CheckResult:
    cookies = _extract_cookies(context.response)
    issues = []
    for cookie in cookies:
        flags = {k.lower(): v for k, v in cookie.items()}
        name = flags.get("name")
        cookie_issues = []
        if "secure" not in flags:
            cookie_issues.append("Secure-flag mist")
        if "httponly" not in flags:
            cookie_issues.append("HttpOnly-flag mist")
        if "samesite" not in flags:
            cookie_issues.append("SameSite-attribute ontbreekt")
        if cookie_issues:
            issues.append({"cookie": name, "issues": cookie_issues})
    status = STATUS_PASS if not issues else STATUS_WARN
    summary = (
        "Cookies bevatten Secure/HttpOnly/SameSite."
        if not issues
        else "Onveilige cookie-instellingen aangetroffen."
    )
    remediation = "Markeer sessiecookies als Secure, HttpOnly en SameSite=Lax/Strict."
    impact = (
        "Beschermde cookie-flags voorkomen dat sessies via XSS of netwerk sniffing worden gestolen."
        if status == STATUS_PASS
        else "Ontbrekende cookie-flags maken het voor aanvallers makkelijker om sessies te kapen of mee te lezen."
    )
    return _build_result(
        id="cookies",
        title="Cookies & sessies",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"cookies_tested": len(cookies), "issues": issues},
    )


def _check_http_methods(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    base = f"{parsed.scheme}://{parsed.netloc}"
    allow_details: Dict[str, Any] = {}
    methods_with_risk = []

    options_resp = _safe_request(base, method="OPTIONS", timeout=6, allow_redirects=False)
    if options_resp is not None:
        allow = options_resp.headers.get("Allow") or options_resp.headers.get("allow")
        if allow:
            verbs = {verb.strip().upper() for verb in allow.split(",")}
            allow_details["allow_header"] = sorted(verbs)
            for risky in {"TRACE", "PUT", "DELETE"}:
                if risky in verbs:
                    methods_with_risk.append(risky)

    trace_resp = _safe_request(base, method="TRACE", timeout=6, allow_redirects=False)
    if trace_resp is not None and trace_resp.status_code < 400:
        methods_with_risk.append("TRACE (direct toegestaan)")
        allow_details["trace_status"] = trace_resp.status_code

    status = STATUS_PASS if not methods_with_risk else STATUS_WARN
    summary = (
        "Onveilige HTTP methodes lijken geblokkeerd."
        if not methods_with_risk
        else "Risicovolle methodes toegestaan: " + ", ".join(sorted(set(methods_with_risk)))
    )
    remediation = "Blokkeer TRACE/PUT/DELETE voor publieke origin en beperk OPTIONS responses."
    impact = (
        "Aanvallers kunnen geen misbruik maken van verborgen HTTP-methodes om data te stelen of te wijzigen."
        if status == STATUS_PASS
        else "Toegestane methodes zoals TRACE/PUT/DELETE kunnen worden misbruikt voor XST-aanvallen of defacement."
    )
    return _build_result(
        id="http_methods",
        title="HTTP methodes & hardening",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=allow_details or None,
    )


def _check_forms(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    insecure: List[Dict[str, Any]] = []
    total_forms = 0
    pages_with_forms: Set[str] = set()

    for page in pages:
        forms = page.soup.find_all("form")
        if not forms:
            continue
        pages_with_forms.add(page.url)
        for idx, form in enumerate(forms, start=1):
            total_forms += 1
            method = (form.get("method") or "get").lower()
            inputs = form.find_all(["input", "textarea"])
            text_inputs = [
                field
                for field in inputs
                if field.get("type", "text").lower()
                in ("text", "email", "password", "tel", "number")
            ]
            for field in text_inputs:
                if not field.has_attr("required") and not field.get("pattern"):
                    insecure.append(
                        {
                            "page": page.url,
                            "form": idx,
                            "input": field.get("name") or field.get("id"),
                            "reason": "Geen verplichting/patroon; validering ontbreekt mogelijk server-side.",
                        }
                    )
            if method != "post" and any(
                inp.get("type", "text").lower() == "password" for inp in text_inputs
            ):
                insecure.append(
                    {
                        "page": page.url,
                        "form": idx,
                        "reason": "Wachtwoordformulier gebruikt GET i.p.v. POST.",
                    }
                )

    status = STATUS_PASS if not insecure else STATUS_WARN
    if not pages_with_forms:
        summary = "Geen formulieren aangetroffen tijdens crawling."
        status = STATUS_INFO
    elif not insecure:
        summary = f"{total_forms} formulieren gevonden; basisvalidatie lijkt aanwezig."
    else:
        summary = (
            f"{len(insecure)} formulierproblemen gevonden op {len(pages_with_forms)} pagina's."
        )
    remediation = "Valideer server-side, markeer verplichte velden en gebruik POST voor gevoelige data."
    if status == STATUS_WARN:
        impact = "Zwakke validatie laat aanvallers SQL/XSS payloads indienen of wachtwoorden onderscheppen via GET."
    elif status == STATUS_PASS:
        impact = "Formulieren beperken misbruik doordat kritieke velden gevalideerd en veilig verzonden worden."
    else:
        impact = "Geen formulieren gevonden tijdens deze crawl; het aanvalsoppervlak via invoer is beperkt."
    return _build_result(
        id="forms",
        title="Forms & input validatie",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={
            "total_forms": total_forms,
            "pages_with_forms": sorted(pages_with_forms)[:10],
            "issues": insecure[:15],
        },
    )


def _check_xss(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    suspicious_pages: List[Dict[str, Any]] = []

    for page in pages:
        inline_handlers = re.findall(r"on\w+=", page.html, flags=re.IGNORECASE)
        reflections = []
        parsed = urlparse(page.url)
        for key, value in parse_qsl(parsed.query):
            if value and value in page.html:
                reflections.append({"param": key, "value": value})
        inline_scripts = [
            script
            for script in page.soup.find_all("script")
            if not script.get("src") and script.string and "innerHTML" in script.string
        ]
        if inline_handlers or reflections or inline_scripts:
            suspicious_pages.append(
                {
                    "page": page.url,
                    "inline_event_handlers": len(inline_handlers),
                    "reflections": reflections[:5],
                    "inline_scripts": len(inline_scripts),
                }
            )

    suspicious = bool(suspicious_pages)
    status = STATUS_WARN if suspicious else STATUS_INFO
    if suspicious:
        summary = f"Inline handlers of reflecties op {len(suspicious_pages)} pagina's."
        impact = "Deze patronen kunnen leiden tot XSS waardoor aanvallers accounts of sessies kapen."
    else:
        summary = "Geen directe aanwijzingen voor reflectieve XSS."
        impact = "Er zijn geen duidelijke XSS-triggers aangetroffen, waardoor misbruik minder waarschijnlijk is."
    remediation = "Escape user input, gebruik CSP en vermijd inline event handlers."
    return _build_result(
        id="xss",
        title="XSS detectie (oppervlakkig)",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"pages": suspicious_pages[:10]},
    )


def _check_reflection_probes(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    if not pages:
        return _build_result(
            id="xss_reflection_probe",
            title="XSS reflectie test",
            severity=SEVERITY_IMPORTANT,
            status=STATUS_INFO,
            summary="Geen pagina's beschikbaar voor reflectietest.",
            remediation="Zorg dat de scan toegang heeft tot pagina's om te testen.",
        )

    sample_size = min(len(pages), MAX_REFLECTION_TESTS)
    sampled_pages = random.sample(pages, sample_size)
    findings: List[Dict[str, Any]] = []

    for page in sampled_pages:
        token = f"wp_reflect_{random.randint(10_000, 99_999)}"
        probe_url = _append_query_param(page.url, REFLECTION_PARAM, token)
        resp = _safe_request(probe_url, allow_redirects=True)
        if not resp or resp.status_code >= 500:
            continue
        html = resp.text or ""
        if token in html:
            findings.append(
                {
                    "page": resp.url,
                    "token": token,
                    "status_code": resp.status_code,
                }
            )
            if len(findings) >= MAX_REFLECTION_TESTS:
                break

    status = STATUS_FAIL if findings else STATUS_INFO
    if findings:
        summary = f"Ongefilterde reflectie gedetecteerd op {len(findings)} pagina's."
        impact = "Een aanvaller kan invoer laten uitvoeren in de browser, wat tot accountovername kan leiden."
    else:
        summary = "Geen reflecties aangetroffen met testpayloads."
        impact = "Invoer wordt vermoedelijk ontsmet of niet teruggestuurd, waardoor XSS minder waarschijnlijk is."

    remediation = "Escape user input, gebruik templating zonder inline HTML en zet een strikte CSP in."
    details = {
        "tested_pages": sample_size,
        "reflections": findings[:MAX_REFLECTION_TESTS],
        "parameter": REFLECTION_PARAM,
    }

    return _build_result(
        id="xss_reflection_probe",
        title="XSS reflectie test",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_sql_errors(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    hits: List[Dict[str, Any]] = []
    for page in pages:
        html = page.html.lower()
        found = sorted({pattern for pattern in SQL_ERROR_PATTERNS if pattern in html})
        if found:
            hits.append({"page": page.url, "patterns": found})

    status = STATUS_FAIL if hits else STATUS_INFO
    if hits:
        summary = f"Database foutmeldingen zichtbaar op {len(hits)} pagina's."
        impact = "Gedetailleerde fouten verraden tabelnamen of queries die aanvallers kunnen gebruiken voor SQL-injectie."
    else:
        summary = "Geen DB foutmeldingen gevonden in responses."
        impact = "De applicatie lekt geen databasefouten waardoor misbruik lastiger is."
    remediation = "Zet debug-modes uit en toon generieke fouten; gebruik parameterized queries."
    return _build_result(
        id="sql_injection",
        title="SQL/command injection (passief)",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"pages": hits[:10]},
    )


def _check_active_form_attacks(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    token = f"{random.randint(100000, 999999)}"
    payload = PENTEST_PAYLOAD_TEMPLATE.format(token=token)
    reflections: List[Dict[str, Any]] = []
    sanitized: List[Dict[str, Any]] = []
    sql_errors: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []
    tested = 0

    for page in pages:
        if tested >= PENTEST_FORM_LIMIT:
            break
        forms = page.soup.find_all("form")
        if not forms:
            continue
        for idx, form in enumerate(forms, start=1):
            if tested >= PENTEST_FORM_LIMIT:
                break
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page.url
            target = urljoin(page.url, action)

            field_names: List[str] = []
            for input_tag in form.find_all("input"):
                name = input_tag.get("name")
                if not name:
                    continue
                input_type = (input_tag.get("type") or "text").lower()
                if input_type in {"submit", "button", "image", "reset", "file"}:
                    continue
                field_names.append(name)
            for textarea in form.find_all("textarea"):
                name = textarea.get("name")
                if name:
                    field_names.append(name)

            if not field_names:
                continue

            tested += 1
            data = {name: payload for name in field_names}
            if method == "post":
                resp = _safe_request(target, method="POST", data=data, timeout=DEFAULT_TIMEOUT)
            else:
                resp = _safe_request(target, method="GET", params=data, timeout=DEFAULT_TIMEOUT)

            if resp is None:
                blocked.append(
                    {
                        "page": page.url,
                        "target": target,
                        "form_index": idx,
                        "reason": "no-response",
                    }
                )
                continue

            text = resp.text or ""
            lowered = text.lower()
            marker = f"weakpoint-{token}".lower()
            if f"<weakpoint-{token}>" in text:
                reflections.append(
                    {
                        "page": page.url,
                        "target": target,
                        "form_index": idx,
                        "status_code": resp.status_code,
                    }
                )
            elif marker in lowered:
                if f"&lt;weakpoint-{token}&gt;" in lowered:
                    sanitized.append(
                        {
                            "page": page.url,
                            "target": target,
                            "form_index": idx,
                            "status_code": resp.status_code,
                        }
                    )

            hits = sorted({pattern for pattern in SQL_ERROR_PATTERNS if pattern in lowered})
            if hits:
                sql_errors.append(
                    {
                        "page": page.url,
                        "target": target,
                        "form_index": idx,
                        "status_code": resp.status_code,
                        "patterns": hits,
                    }
                )

            if resp.status_code >= 400:
                blocked.append(
                    {
                        "page": page.url,
                        "target": target,
                        "form_index": idx,
                        "status_code": resp.status_code,
                    }
                )

    status = STATUS_PASS
    summary = "Formulieren filteren actieve payloads of reageren veilig."
    remediation = "Blijf input valideren en ontsmetten; monitor WAF-logs op afwijkingen."
    impact = "Aanvallers krijgen geen directe feedback om XSS/SQL-injectie via formulieren te misbruiken."

    if reflections or sql_errors:
        status = STATUS_FAIL
        parts = []
        if reflections:
            parts.append(
                f"Payload reflecteert ongesanitized op {len(reflections)} formulier(en)."
            )
        if sql_errors:
            parts.append(
                f"Databasefouten na injectie op {len(sql_errors)} doel(en)."
            )
        summary = " ".join(parts)
        remediation = (
            "Valideer en ontsmet invoer server-side, encodeer output en gebruik parameterized queries."
        )
        impact = (
            "Aanvallers kunnen de reflectie gebruiken voor XSS of de foutmeldingen om SQL-injecties te ontwikkelen."
        )
    elif blocked:
        status = STATUS_WARN
        summary = (
            f"Actieve payloads werden geblokkeerd of geweigerd ({len(blocked)} keer)."
        )
        remediation = (
            "Controleer of blokkades legitiem zijn en documenteer WAF/rate limit regels."
        )
        impact = (
            "Blokkade wijst op tegenmaatregelen, maar handmatige review blijft nodig om ev. bypasses uit te sluiten."
        )

    details: Dict[str, Any] = {
        "tested_forms": tested,
        "payload": payload,
        "reflections": reflections[:10],
        "sanitized": sanitized[:10],
        "sql_errors": sql_errors[:10],
        "blocked": blocked[:10],
    }

    return _build_result(
        id="active_forms",
        title="Actieve formulier pentest",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_auth_session(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    issues: List[str] = []
    login_forms_total = 0
    login_pages: Set[str] = set()
    detailed_issues: List[Dict[str, Any]] = []
    rate_headers_found: Set[str] = set()
    mfa_mentioned = False

    for page in pages:
        page_headers = {k.lower(): v for k, v in page.headers.items()}
        for key in page_headers:
            if "ratelimit" in key or key == "retry-after":
                rate_headers_found.add(key)

        forms = [
            form
            for form in page.soup.find_all("form")
            if form.find("input", {"type": "password"})
        ]
        if forms:
            login_pages.add(page.url)
        for idx, form in enumerate(forms, start=1):
            login_forms_total += 1
            method = (form.get("method") or "get").lower()
            if method != "post":
                msg = f"Loginformulier gebruikt {method.upper()} i.p.v. POST."
                detailed_issues.append({"page": page.url, "form": idx, "issue": msg})
            token = form.find("input", {"type": "hidden", "name": re.compile("csrf", re.I)})
            if not token:
                detailed_issues.append(
                    {
                        "page": page.url,
                        "form": idx,
                        "issue": "Geen CSRF-token aangetroffen in formulier.",
                    }
                )

        text = page.soup.get_text(" ", strip=True).lower()
        if any(term in text for term in ("mfa", "twee-factor", "2fa")):
            mfa_mentioned = True

    if not rate_headers_found:
        issues.append("Geen rate-limit headers aangetroffen; beperk aanmeldpogingen.")
    if login_forms_total and not mfa_mentioned:
        issues.append("Geen verwijzing naar MFA/twee-factor authenticatie gevonden.")
    if detailed_issues:
        issues.extend(sorted({item["issue"] for item in detailed_issues}))

    if login_forms_total == 0:
        status = STATUS_INFO
        summary = "Geen loginformulieren gevonden tijdens crawling."
        impact = "Er is geen loginoppervlak ontdekt in de gecrawlde pages, dus brute-force risico is laag."
    elif not issues:
        status = STATUS_PASS
        summary = "Loginflows gebruiken POST, hebben CSRF en benoemen MFA/rate limiting."
        impact = "Beschermde loginflows beperken brute force en sessiekaping door aanvallers."
    else:
        status = STATUS_WARN
        summary = f"{len(issues)} aandachtspunten rond login/sessie beveiliging."
        impact = "Ontbrekende CSRF/MFA of rate limiting laat aanvallers wachtwoorden uitproberen of sessies overnemen."

    return _build_result(
        id="auth",
        title="Authenticatie & sessiebeheer",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation="Forceer POST, voeg CSRF-tokens toe, implementeer rate limiting en bied MFA aan.",
        impact=impact,
        details={
            "login_forms": login_forms_total,
            "login_pages": sorted(login_pages)[:10],
            "issues": detailed_issues[:15],
            "rate_limit_headers": sorted(rate_headers_found),
        },
    )


def _check_server_versions(context: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    banner = headers.get("server") or headers.get("x-powered-by")
    outdated = []
    if banner:
        lower = banner.lower()
        if "php/" in lower:
            version = banner.split("/", 1)[-1]
            if version and version < "8":
                outdated.append(f"PHP {version}")
        if "apache" in lower and "2.4" not in lower:
            outdated.append(banner.strip())
        if "nginx" in lower and "1.2" in lower:
            outdated.append(banner.strip())
    status = STATUS_WARN if outdated else STATUS_INFO
    summary = (
        "Server header onthult verouderde versies: " + ", ".join(outdated)
        if outdated
        else "Geen evidente legacy serverversies gedetecteerd."
    )
    remediation = "Werk webserver/frameworks bij en verberg versienummers."
    impact = (
        "Bekende kwetsbaarheden in deze versies kunnen direct worden misbruikt voor RCE of informatielekken."
        if status == STATUS_WARN
        else "Er worden geen gevoelige versies blootgegeven waardoor fingerprinting minder oplevert."
    )
    return _build_result(
        id="server_banner",
        title="Outdated software / server info",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"server_header": banner},
    )


def _check_backup_files(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    base = f"{parsed.scheme}://{parsed.netloc}"
    exposed = []
    for path in BACKUP_PROBES:
        url = urljoin(base, path)
        resp = _safe_request(url, timeout=6, allow_redirects=False)
        if not resp:
            continue
        if resp.status_code == 200 and len(resp.content) > 0:
            exposed.append({"path": path, "status": resp.status_code})
    status = STATUS_FAIL if exposed else STATUS_PASS
    summary = (
        "Publieke backup/config bestanden gevonden."
        if exposed
        else "Geen bekende backup/config bestanden publiek benaderbaar."
    )
    remediation = "Verplaats gevoelige bestanden buiten webroot of beperk via ACL."
    impact = (
        "Deze bestanden bevatten vaak wachtwoorden of database dumps die directe toegang geven aan aanvallers."
        if status == STATUS_FAIL
        else "Back-upbestanden zijn afgeschermd waardoor gevoelige configuraties niet uitlekken."
    )
    return _build_result(
        id="backup_files",
        title="Backup/sensitive files",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"exposed": exposed},
    )


def _check_directory_listing(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    listings: List[Dict[str, Any]] = []

    for page in pages:
        title = (page.soup.title.string or "") if page.soup.title else ""
        lower_title = title.strip().lower()
        lower_html = page.html.lower()
        has_marker = any(marker in lower_html for marker in DIRECTORY_LISTING_MARKERS)
        has_title = any(marker in lower_title for marker in DIRECTORY_LISTING_MARKERS)
        pre = page.soup.find("pre")
        links = page.soup.find_all("a")
        looks_like_listing = False
        if pre and "parent directory" in pre.get_text(" ", strip=True).lower():
            looks_like_listing = True
        if len(links) >= 5 and any(
            (link.get_text(" ", strip=True) or "").lower().startswith("parent directory")
            for link in links
        ):
            looks_like_listing = True
        if has_marker or has_title or looks_like_listing:
            listings.append({
                "url": page.url,
                "status_code": page.status_code,
                "title": title.strip(),
            })

    status = STATUS_FAIL if listings else STATUS_PASS
    summary = (
        "Directory listing actief op publiek toegankelijke paden."
        if listings
        else "Geen tekenen van directory listing gevonden."
    )
    remediation = "Schakel autoindexering uit en plaats een indexbestand of gebruik toegangsrestricties."
    impact = (
        "Met directory listing kunnen aanvallers eenvoudig gevoelige bestanden en broncode downloaden."
        if listings
        else "Zonder directory listing blijft interne mappenstructuur verborgen voor bezoekers."
    )

    return _build_result(
        id="directory_listing",
        title="Directory listing",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"pages": listings[:10]} if listings else None,
    )


def _check_outdated_js_libraries(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    outdated: List[Dict[str, Any]] = []
    checked_scripts: Set[str] = set()

    for page in pages:
        for tag in page.soup.find_all("script"):
            src = tag.get("src")
            if not src:
                continue
            absolute = urljoin(page.url, src)
            normalized = absolute.split("#")[0]
            if normalized in checked_scripts:
                continue
            checked_scripts.add(normalized)
            lower_src = normalized.lower()
            for library, baseline in JS_LIBRARY_BASELINES.items():
                if library not in lower_src:
                    continue
                version_tuple = _extract_version_tuple(lower_src)
                if not version_tuple:
                    continue
                if _version_is_older(version_tuple, baseline):
                    outdated.append(
                        {
                            "library": library,
                            "detected_version": ".".join(str(part) for part in version_tuple),
                            "minimum_recommended": ".".join(str(part) for part in baseline),
                            "script": normalized,
                        }
                    )

    status = STATUS_WARN if outdated else STATUS_INFO
    summary = (
        "Verouderde JavaScript bibliotheken aangetroffen."
        if outdated
        else "Geen duidelijke verouderde JavaScript bibliotheken gevonden."
    )
    remediation = "Update CDN/self-hosted bibliotheken naar ondersteunde versies en verwijder ongebruikte libraries."
    impact = (
        "Bekende kwetsbaarheden in oude bibliotheken kunnen leiden tot XSS of RCE via derde-partij scripts."
        if outdated
        else "Actuele bibliotheken verkleinen de kans op misbruik van bekende kwetsbaarheden."
    )

    return _build_result(
        id="js_libraries",
        title="Verouderde JavaScript componenten",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"outdated": outdated[:10]} if outdated else None,
    )


def _check_rate_limiting(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    aggregated: Dict[str, str] = {}
    for page in pages:
        for key, value in page.headers.items():
            lower = key.lower()
            if "ratelimit" in lower or lower == "retry-after":
                aggregated[lower] = value

    status = STATUS_INFO if aggregated else STATUS_WARN
    summary = (
        "Rate-limit headers aangetroffen op responses."
        if aggregated
        else "Geen rate-limit headers; implementeer throttling voor API/login."
    )
    remediation = "Expose X-RateLimit headers en voer server-side throttling in."
    impact = (
        "Zonder rate limiting kunnen brute-force en DoS aanvallen ongestoord doorgaan."
        if status == STATUS_WARN
        else "Aanwezige rate-limit signalen helpen misbruik snel af te remmen."
    )
    return _build_result(
        id="rate_limiting",
        title="Rate limiting / DoS",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"headers": aggregated},
    )


def _check_security_txt(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    base = f"{parsed.scheme}://{parsed.netloc}"
    candidates = ["/.well-known/security.txt", "/security.txt"]
    found: Optional[str] = None
    status_code: Optional[int] = None

    for candidate in candidates:
        url = urljoin(base, candidate)
        resp = _safe_request(url, timeout=6, allow_redirects=True)
        if resp is not None and resp.status_code < 400 and resp.text:
            found = candidate
            status_code = resp.status_code
            break

    status = STATUS_PASS if found else STATUS_WARN
    summary = (
        "security.txt aanwezig voor responsible disclosure."
        if found
        else "Geen security.txt gevonden; documenteer meldproces."
    )
    remediation = "Publiceer een security.txt onder /.well-known/ met contactinformatie."
    impact = (
        "Onderzoekers weten direct waar ze kwetsbaarheden veilig kunnen melden, waardoor zero-days minder snel op straat belanden."
        if status == STATUS_PASS
        else "Zonder disclosure-proces melden onderzoekers kwetsbaarheden mogelijk niet of publiceren ze ze publiek."
    )
    return _build_result(
        id="security_txt",
        title="security.txt responsible disclosure",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"path": found, "status_code": status_code} if found else None,
    )


def _check_error_handling(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    probe_path = f"/__weakpoint_probe_{random.randint(1000, 9999)}"
    probe_url = urljoin(f"{parsed.scheme}://{parsed.netloc}", probe_path)
    resp = _safe_request(probe_url, timeout=6)
    verbose = False
    snippet = None
    if resp is not None and resp.text:
        lower = resp.text.lower()
        for token in ("traceback", "exception", "warning:", "stack trace"):
            if token in lower:
                verbose = True
                snippet = resp.text[:400]
                break
    status = STATUS_WARN if verbose else STATUS_PASS
    summary = (
        "Gedetailleerde foutmeldingen zichtbaar."
        if verbose
        else "Geen verbose errors aangetroffen."
    )
    remediation = "Toon generieke 4xx/5xx pagina's en log details server-side."
    impact = (
        "Uitgebreide foutmeldingen geven aanvallers stack traces en paden prijs voor verdere exploitatie."
        if status == STATUS_WARN
        else "Doordat er geen technische details uitlekken, hebben aanvallers minder aanknopingspunten."
    )
    return _build_result(
        id="error_handling",
        title="Error handling",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"sample": snippet},
    )


def _check_graphql_introspection(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    candidates: Set[str] = set()
    hint_detected = False

    for page in pages:
        html_lower = page.html.lower()
        if "graphql" in html_lower:
            hint_detected = True
        parsed = urlparse(page.url)
        if "graphql" in (parsed.path or "").lower():
            candidates.add(page.url.split("#")[0])
        for tag in page.soup.find_all(["form", "a", "script"]):
            attr = tag.get("action") if tag.name == "form" else tag.get("href") or tag.get("src")
            if not attr:
                continue
            if "graphql" in attr.lower():
                candidates.add(urljoin(page.url, attr))

    if hint_detected:
        parsed = context.parsed_url
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in GRAPHQL_COMMON_PATHS:
            candidates.add(urljoin(base, path))

    tested: List[Dict[str, Any]] = []
    exposed: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []

    for endpoint in list(sorted(candidates))[:5]:
        resp = _safe_request(
            endpoint,
            method="POST",
            json=GRAPHQL_INTROSPECTION_QUERY,
            timeout=8,
            headers={"Content-Type": "application/json"},
        )
        entry = {"endpoint": endpoint}
        if resp is None:
            entry["status"] = "no_response"
            blocked.append(entry)
            continue
        entry["http_status"] = resp.status_code
        tested.append(entry)
        try:
            payload = resp.json()
        except ValueError:
            blocked.append(entry)
            continue
        schema = payload.get("data", {}).get("__schema")
        if schema:
            exposed.append(entry)
        else:
            blocked.append(entry)

    if not candidates:
        status = STATUS_INFO
        summary = "Geen aanwijzingen voor GraphQL endpoints gevonden tijdens de crawl."
        impact = "Zonder GraphQL oppervlakte is het risico op introspection misbruik laag."
    elif exposed:
        status = STATUS_WARN
        summary = f"GraphQL introspection open op {len(exposed)} endpoint(s)."
        impact = "Open introspection lekt schema's en types waardoor aanvallers API-misbruik eenvoudiger plannen."
    else:
        status = STATUS_PASS
        summary = "GraphQL endpoints blokkeren introspection verzoeken."
        impact = "Geblokkeerde introspection beperkt informatielekken over interne API-structuren."

    return _build_result(
        id="graphql",
        title="GraphQL introspection",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation="Schakel introspection uit in productie of bescherm endpoints met authenticatie.",
        impact=impact,
        details={
            "tested": tested[:10],
            "exposed": exposed[:10],
            "blocked": blocked[:10],
        }
        if candidates
        else None,
    )


def _check_performance(context: ScanContext) -> CheckResult:
    body_size = len(context.response.content or b"")
    ttfb = context.response.elapsed.total_seconds()
    script_count = len(context.soup.find_all("script"))
    status = STATUS_PASS
    issues = []
    if ttfb > 2:
        status = STATUS_WARN
        issues.append(f"TTFB {ttfb:.2f}s")
    if body_size > 2_000_000:
        status = STATUS_WARN
        issues.append(f"Documentgrootte {body_size / 1024:.0f} KiB")
    summary = "Prima laadtijd en paginagrootte." if not issues else ", ".join(issues)
    remediation = "Optimaliseer caching, comprimeer assets en laad scripts async/defer."
    impact = (
        "Goede performance houdt de site responsief en verkleint het DoS-aanvalsoppervlak."
        if status == STATUS_PASS
        else "Trage pagina's vergroten de kans op timeouts en maken het makkelijker om DoS-aanvallen te laten slagen."
    )
    return _build_result(
        id="performance",
        title="Performance / Core Web Vitals (indicatief)",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"ttfb": ttfb, "body_bytes": body_size, "script_count": script_count},
    )


def _check_accessibility(context: ScanContext) -> CheckResult:
    imgs = context.soup.find_all("img")
    missing_alt = [img.get("src") for img in imgs if not img.get("alt")]
    forms = context.soup.find_all("form")
    unlabeled = []
    for form in forms:
        inputs = form.find_all(["input", "textarea"])
        for inp in inputs:
            if inp.get("type") in ("hidden", "submit", "button"):
                continue
            label = form.find("label", {"for": inp.get("id")})
            if not label:
                unlabeled.append(inp.get("name") or inp.get("id"))
    issues = []
    if missing_alt:
        issues.append(f"{len(missing_alt)} afbeeldingen zonder alt.")
    if unlabeled:
        issues.append(f"{len(unlabeled)} invoervelden zonder label.")
    status = STATUS_PASS if not issues else STATUS_WARN
    summary = "Basis a11y-checks lijken in orde." if not issues else "; ".join(issues)
    remediation = "Voorzie media van alt-teksten en koppel labels aan inputs."
    impact = (
        "Een toegankelijke site is bruikbaar voor iedereen en voorkomt klachten of juridische risico's."
        if status == STATUS_PASS
        else "Gebrek aan toegankelijkheid kan leiden tot klachten en uitsluiting van gebruikers."
    )
    return _build_result(
        id="accessibility",
        title="Toegankelijkheid (basis)",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"images_without_alt": missing_alt[:10], "unlabeled_fields": unlabeled[:10]},
    )


def _check_seo(context: ScanContext) -> CheckResult:
    title = context.soup.find("title")
    meta_desc = context.soup.find("meta", attrs={"name": "description"})
    robots_tag = context.soup.find("meta", attrs={"name": "robots"})
    summary_parts = []
    if not title or not title.get_text(strip=True):
        summary_parts.append("Ontbrekende <title> tag.")
    if not meta_desc or not meta_desc.get("content"):
        summary_parts.append("Meta description ontbreekt.")
    if robots_tag and "noindex" in (robots_tag.get("content") or "").lower():
        summary_parts.append("Robots meta staat op noindex.")
    sitemap_url = urljoin(
        f"{context.parsed_url.scheme}://{context.parsed_url.netloc}", "/sitemap.xml"
    )
    sitemap_resp = _safe_request(sitemap_url, method="HEAD", timeout=6, allow_redirects=True)
    sitemap_exists = sitemap_resp is not None and sitemap_resp.status_code < 400
    details = {
        "title": title.get_text(strip=True) if title else None,
        "meta_description": meta_desc.get("content") if meta_desc else None,
        "sitemap": sitemap_exists,
        "robots_meta": robots_tag.get("content") if robots_tag else None,
    }
    if summary_parts:
        status = STATUS_WARN
        summary = "; ".join(summary_parts)
        impact = "Ontbrekende SEO-elementen maken het moeilijker om gevonden te worden en kunnen omzet kosten."
    else:
        status = STATUS_PASS
        summary = "Basis SEO metadata aanwezig."
        impact = "Basis SEO is op orde waardoor bezoekers de site beter terugvinden."
    remediation = "Zorg voor unieke titles/descriptions en publiceer sitemap/robots."
    return _build_result(
        id="seo",
        title="SEO basics",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_mobile(context: ScanContext) -> CheckResult:
    viewport = context.soup.find("meta", attrs={"name": re.compile("viewport", re.I)})
    status = STATUS_PASS if viewport else STATUS_WARN
    summary = "Responsive viewport meta aanwezig." if viewport else "Geen meta viewport -> slechte mobile ervaring."
    remediation = "Gebruik <meta name='viewport' content='width=device-width, initial-scale=1'>."
    impact = (
        "Mobiele gebruikers krijgen een optimale ervaring, wat conversieproblemen voorkomt."
        if status == STATUS_PASS
        else "Zonder viewport schalen pagina's slecht waardoor gebruikers afhaken."
    )
    return _build_result(
        id="mobile",
        title="Mobile responsiveness",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
    )


def _check_third_party(context: ScanContext) -> CheckResult:
    base_host = context.parsed_url.hostname
    external_scripts = []
    for tag in context.soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        host = urlparse(urljoin(context.response.url, src)).hostname
        if host and host != base_host:
            external_scripts.append(host)
    unique_hosts = sorted(set(external_scripts))
    status = STATUS_INFO if unique_hosts else STATUS_PASS
    summary = (
        f"{len(unique_hosts)} externe scriptdomeinen gebruikt."
        if unique_hosts
        else "Geen externe scripts aangetroffen."
    )
    remediation = "Houd derde partijen beperkt en laad ze async met consent."
    impact = (
        "Elke externe scriptbron vormt een supply-chain risico en kan bezoekers volgen."
        if status == STATUS_INFO
        else "Door scripts zelf te hosten is het risico op supply-chain injecties minimaal."
    )
    return _build_result(
        id="third_party",
        title="Third-party scripts / privacy",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"third_party_hosts": unique_hosts},
    )


def _check_privacy(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    keyword_map: Dict[str, List[str]] = {}
    for page in pages:
        text = page.html.lower()
        found = sorted({word for word in PRIVACY_KEYWORDS if word in text})
        if found:
            keyword_map[page.url] = found

    status = STATUS_PASS if keyword_map else STATUS_WARN
    if keyword_map:
        summary = f"Privacy/cookie informatie aangetroffen op {len(keyword_map)} pagina's."
        impact = "Bezoekers vinden het privacybeleid en kunnen toestemming geven volgens AVG."
    else:
        summary = "Geen verwijzing naar privacy/cookiebeleid gevonden."
        impact = "Zonder zichtbaar beleid voldoet de site mogelijk niet aan AVG en ontbreekt transparantie."
    remediation = "Link duidelijk naar privacy- en cookiebeleid en implementeer consentbanner."
    return _build_result(
        id="privacy",
        title="Privacy & compliance",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"keywords": keyword_map},
    )


def _check_sri(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    hostname = parsed.hostname or ""
    external_scripts = []
    for tag in context.soup.find_all("script"):
        src = tag.get("src")
        if not src:
            continue
        absolute = urljoin(context.response.url, src)
        parsed_src = urlparse(absolute)
        if parsed_src.hostname and parsed_src.hostname != hostname:
            has_integrity = bool(tag.get("integrity"))
            if not has_integrity:
                external_scripts.append(absolute)

    status = STATUS_PASS if not external_scripts else STATUS_WARN
    summary = (
        "Externe scripts gebruiken Subresource Integrity."
        if not external_scripts
        else f"{len(external_scripts)} externe scripts zonder SRI."
    )
    remediation = "Voeg integriteits-hashes toe aan externe scripts of host assets zelf."
    impact = (
        "Integriteitshashes voorkomen dat gemanipuleerde CDN-bestanden bezoekers infecteren."
        if status == STATUS_PASS
        else "Zonder SRI kunnen aanvallers externe scripts vervangen en eigen code uitvoeren."
    )
    return _build_result(
        id="sri",
        title="Subresource Integrity voor externe scripts",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"scripts": external_scripts[:10]} if external_scripts else None,
    )


def _aggregate_status_counts(items: List[CheckResult]) -> Dict[str, int]:
    counts = {
        STATUS_PASS: 0,
        STATUS_WARN: 0,
        STATUS_FAIL: 0,
        STATUS_INFO: 0,
    }
    for item in items:
        if item.status in counts:
            counts[item.status] += 1
    counts["total"] = len(items)
    return counts


def _grade_from_percentage(percentage: float) -> Tuple[str, str]:
    if percentage >= 90:
        return "A", "Uitstekend"
    if percentage >= 80:
        return "B", "Zeer goed"
    if percentage >= 70:
        return "C", "Goed"
    if percentage >= 60:
        return "D", "Matig"
    if percentage >= 40:
        return "E", "Zorgelijk"
    return "F", "Kritiek"


def _calculate_score(groups: Dict[str, List[CheckResult]]) -> Dict[str, Any]:
    severity_weights = {
        SEVERITY_CRITICAL: 5,
        SEVERITY_IMPORTANT: 3,
        SEVERITY_NICE: 1,
    }
    status_multiplier = {
        STATUS_PASS: 1.0,
        STATUS_INFO: 0.85,
        STATUS_WARN: 0.45,
        STATUS_FAIL: 0.0,
    }

    section_payload: Dict[str, Any] = {}
    total_max = 0.0
    total_score = 0.0
    all_items: List[CheckResult] = []

    for key, items in groups.items():
        all_items.extend(items)
        max_points = sum(severity_weights.get(item.severity, 1) for item in items)
        achieved = sum(
            severity_weights.get(item.severity, 1)
            * status_multiplier.get(item.status, 0.5)
            for item in items
        )
        percentage = 100.0 if max_points == 0 else (achieved / max_points) * 100.0
        section_payload[key] = {
            "score": round(achieved, 2),
            "max_score": round(max_points, 2),
            "percentage": round(percentage, 1),
            "status_counts": _aggregate_status_counts(items),
        }
        total_max += max_points
        total_score += achieved

    overall_percentage = 100.0 if total_max == 0 else (total_score / total_max) * 100.0
    grade, label = _grade_from_percentage(overall_percentage)

    payload = {
        "overall": int(round(overall_percentage)),
        "grade": grade,
        "label": label,
        "sections": section_payload,
        "status_counts": _aggregate_status_counts(all_items),
    }
    return payload


CRITICAL_CHECKS = [
    _check_tls,
    _check_security_headers,
    _check_csp_strength,
    _check_cache_control,
    _check_mixed_content,
    _check_redirects_and_canonical,
    _check_cors,
    _check_cookies,
    _check_forms,
]

IMPORTANT_CHECKS = [
    _check_xss,
    _check_reflection_probes,
    _check_sql_errors,
    _check_auth_session,
    _check_server_versions,
    _check_backup_files,
    _check_directory_listing,
    _check_outdated_js_libraries,
    _check_rate_limiting,
    _check_error_handling,
    _check_graphql_introspection,
    _check_http_methods,
    _check_security_txt,
    _check_sri,
]

PENTEST_CHECKS = [
    _check_active_form_attacks,
]

NICE_CHECKS = [
    _check_performance,
    _check_accessibility,
    _check_seo,
    _check_mobile,
    _check_third_party,
    _check_privacy,
]


def run_scan(
    target_url: str, progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None
) -> Dict[str, Any]:
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "warmup", "progress": 5},
    )
    resp = _safe_request(target_url, allow_redirects=True)
    if resp is None:
        raise RuntimeError(f"Kan {target_url} niet bereiken.")

    html = resp.text or ""
    soup = BeautifulSoup(html, "html.parser")
    parsed_response = urlparse(resp.url)
    base = f"{parsed_response.scheme}://{parsed_response.netloc}"

    robots_resp = _safe_request(urljoin(base, "/robots.txt"), timeout=6)
    robots_txt = robots_resp.text if robots_resp and robots_resp.status_code == 200 else None

    sitemap_pages = _collect_sitemap_pages(base, parsed_response.hostname, robots_txt)
    sitemap_found = bool(sitemap_pages)

    initial_page = PageSnapshot(
        url=resp.url,
        status_code=resp.status_code,
        html=html,
        soup=soup,
        headers={k: v for k, v in resp.headers.items()},
    )
    seed_urls = _build_seed_urls(base, parsed_response.hostname, robots_txt, sitemap_pages)
    max_pages, max_depth = _get_scan_limits()
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "crawl", "progress": 18},
    )
    crawled_pages = _crawl_site(
        initial_page,
        max_pages=max_pages,
        max_depth=max_depth,
        seed_urls=seed_urls,
        progress_callback=progress_callback,
    )
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "forms", "progress": 55},
    )

    context = ScanContext(
        target_url=target_url,
        response=resp,
        html=html,
        soup=soup,
        robots_txt=robots_txt,
        sitemap_found=sitemap_found,
        pages=crawled_pages,
    )

    critical_results = [check(context) for check in CRITICAL_CHECKS]
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "security", "progress": 72},
    )
    important_results = [check(context) for check in IMPORTANT_CHECKS]
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "pentest", "progress": 80},
    )
    pentest_results = [check(context) for check in PENTEST_CHECKS]
    nice_results = [check(context) for check in NICE_CHECKS]

    score = _calculate_score(
        {
            "critical": critical_results,
            "important": important_results,
            "pentest": pentest_results,
            "nice_to_have": nice_results,
        }
    )
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "report", "progress": 88},
    )

    login_like_pages = [
        page.url
        for page in crawled_pages
        if any(marker in urlparse(page.url).path.lower() for marker in ("login", "admin", "signin", "cms"))
    ]

    return {
        "meta": {
            "target": target_url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "history": [r.status_code for r in resp.history],
            "sitemap_found": sitemap_found,
            "robots_present": bool(robots_txt),
            "pages_scanned": len(crawled_pages),
            "sample_pages": [page.url for page in crawled_pages[:10]],
            "login_like_pages": login_like_pages[:10],
            "max_pages_budget": max_pages,
            "max_depth_budget": max_depth,
            "seed_urls": seed_urls[:10],
        },
        "critical": [result.to_dict() for result in critical_results],
        "important": [result.to_dict() for result in important_results],
        "pentest": [result.to_dict() for result in pentest_results],
        "nice_to_have": [result.to_dict() for result in nice_results],
        "score": score,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="WeakPoint web security scanner")
    parser.add_argument("--url", "-u", required=True, help="Doel URL (inclusief schema).")
    parser.add_argument(
        "--output",
        "-o",
        default="report.json",
        help="Bestand waar het JSON rapport wordt opgeslagen.",
    )
    args = parser.parse_args()
    report = run_scan(args.url)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    print(f"Rapport opgeslagen in {args.output}")


if __name__ == "__main__":
    main()
