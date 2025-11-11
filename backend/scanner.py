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
import importlib
import json
import logging
import os
import random
import re
import socket
import ssl
import threading
import gzip
from collections import deque
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from http.cookies import SimpleCookie
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests
from requests.cookies import RequestsCookieJar, merge_cookies
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

DEFAULT_MAX_PAGES = 500
DEFAULT_PAGE_BUDGET = 50
DEFAULT_MAX_DEPTH = 4
DEFAULT_CRAWLER_WORKERS = 4
DEFAULT_MAX_SEED_URLS = 120
DEFAULT_MAX_SITEMAP_URLS = 60
HARD_MAX_SEED_URLS = 900
HARD_MAX_SITEMAP_URLS = 1500
MAX_ROBOTS_ALLOW_PATHS = 20
MAX_REFLECTION_TESTS = 8
HTTP_METHOD_ENDPOINT_LIMIT = 6
SQLI_ACTIVE_PARAM_LIMIT = 6
SQLI_ACTIVE_PAYLOADS = ["'", "' OR '1'='1"]
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
PENTEST_PAYLOADS = [
    {
        "id": "xss",
        "label": "XSS reflectie",
        "template": "\"'><weakpoint-{token}>",
    },
    {
        "id": "sql",
        "label": "SQL injectie",
        "template": "' OR '1'='1'--weakpoint-{token}",
    },
    {
        "id": "ssti",
        "label": "Template injectie",
        "template": "{{7*7}}weakpoint-{token}",
    },
]

DEFAULT_PENTEST_ACCOUNTS = ("admin", "user", "guest")
SENSITIVE_CONTENT_KEYWORDS = ("password", "wachtwoord", "passphrase")
SENSITIVE_URL_KEYWORDS = ("password", "secret", "token", "credential")
ADMIN_TITLE_KEYWORDS = ("admin", "beheer", "dashboard")
SOURCE_LEAK_MARKERS = ("<?php", "begin rsa private key", "aws_secret_access_key", "api_key")
STACK_TRACE_MARKERS = (
    "traceback",
    "stack trace",
    "exception in thread",
    "fatal error",
    "undefined index",
)
SSRF_PARAM_HINTS = ("url", "target", "dest", "redirect", "callback", "feed", "next", "data", "resource")
OUTDATED_COMPONENT_BASELINES: Dict[str, Tuple[int, ...]] = {
    "php": (8, 1, 0),
    "wordpress": (6, 0, 0),
    "drupal": (10, 0, 0),
    "joomla": (5, 0, 0),
}
VERSION_PATTERN = re.compile(r"(\d+(?:\.\d+)+)")

CSRF_FIELD_HINTS = ("csrf", "xsrf", "token", "authenticity", "verification")

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

OWASP_HEADER_BASELINE = SECURITY_HEADERS + [
    "x-content-security-policy",
    "feature-policy",
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

SUPPLY_CHAIN_PATHS = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/pnpm-lock.yaml",
    "/composer.json",
    "/composer.lock",
    "/Gemfile.lock",
    "/requirements.txt",
    "/poetry.lock",
    "/Pipfile",
    "/Pipfile.lock",
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

SSRF_PARAMETER_NAMES = {
    "url",
    "target",
    "redirect",
    "dest",
    "destination",
    "next",
    "callback",
    "continue",
    "return",
    "returnurl",
}

INSECURE_DESIGN_HINTS = (
    "debug mode",
    "debug",
    "staging",
    "testomgeving",
    "test mode",
    "niet voor productie",
    "not for production",
    "internal only",
    "demo data",
    "placeholder",
)

SUBDOMAIN_GUESSES = [
    "www",
    "admin",
    "beheer",
    "portal",
    "intranet",
    "api",
    "app",
    "beta",
    "dev",
    "test",
    "staging",
    "stage",
    "dashboard",
    "secure",
    "vpn",
    "mail",
]

SUBDOMAIN_DISCOVERY_LIMIT = 12

PORT_PROBES = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

LEGACY_PORTS = {21, 23, 25, 110, 143, 445, 3389}

IDOR_TEST_LIMIT = 6

API_CANDIDATE_LIMIT = 12

FILE_UPLOAD_FLAG_FIELDS = ("accept", "capture", "data-max-size", "data-allowed")

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


logger = logging.getLogger("weakpoint.scanner")
logger.addHandler(logging.NullHandler())

_THREAD_LOCAL_SESSION: threading.local = threading.local()


def _load_auth_configuration() -> Dict[str, Any]:
    config: Dict[str, Any] = {}
    bearer = os.getenv("WEAKPOINT_AUTH_BEARER")
    if bearer:
        SESSION.headers["Authorization"] = f"Bearer {bearer.strip()}"
        config["authorization"] = "bearer"

    custom_header = os.getenv("WEAKPOINT_AUTH_HEADER")
    if custom_header:
        if ":" in custom_header:
            name, value = custom_header.split(":", 1)
            header_name = name.strip()
            if header_name:
                SESSION.headers[header_name] = value.strip()
                config.setdefault("extra_headers", []).append(header_name)
        else:
            config["invalid_header_format"] = True

    cookie_blob = os.getenv("WEAKPOINT_AUTH_COOKIES")
    if cookie_blob:
        try:
            parsed_cookies = json.loads(cookie_blob)
        except json.JSONDecodeError:
            parsed_cookies = None
        if isinstance(parsed_cookies, dict):
            for key, value in parsed_cookies.items():
                SESSION.cookies.set(key, value)
            config["cookies"] = sorted(parsed_cookies.keys())
        else:
            SESSION.headers["Cookie"] = cookie_blob
            config["cookies_raw"] = True

    return config


AUTH_CONTEXT = _load_auth_configuration()


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
    auth: Dict[str, Any] = field(default_factory=dict)

    @property
    def parsed_url(self):
        return urlparse(self.response.url)


def _clone_cookies(source: RequestsCookieJar) -> RequestsCookieJar:
    jar = RequestsCookieJar()
    for cookie in source:
        jar.set(
            cookie.name,
            cookie.value,
            domain=cookie.domain,
            path=cookie.path,
            secure=cookie.secure,
            rest=getattr(cookie, "_rest", {}),
        )
    return jar


def _get_thread_session() -> requests.Session:
    session = getattr(_THREAD_LOCAL_SESSION, "session", None)
    if session is None:
        session = requests.Session()
        session.headers.update(SESSION.headers)
        session.cookies.update(SESSION.cookies)
        setattr(_THREAD_LOCAL_SESSION, "session", session)
    return session


def _safe_request(
    url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT, **kwargs
) -> Optional[requests.Response]:
    request_kwargs = dict(kwargs)
    extra_headers = request_kwargs.pop("headers", None)
    extra_cookies = request_kwargs.pop("cookies", None)

    session = _get_thread_session()
    headers = dict(session.headers)
    if extra_headers:
        headers.update(extra_headers)

    resp: Optional[requests.Response]
    try:
        if extra_cookies is not None:
            try:
                merged_cookies = merge_cookies(
                    _clone_cookies(session.cookies), extra_cookies
                )
            except Exception:
                merged_cookies = merge_cookies(RequestsCookieJar(), extra_cookies)
            request_kwargs["cookies"] = merged_cookies

        resp = session.request(
            method,
            url,
            timeout=timeout,
            headers=headers,
            **request_kwargs,
        )
    except requests.RequestException as exc:
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Request %s %s failed", method.upper(), url)
        else:
            logger.warning("Request %s %s failed: %s", method.upper(), url, exc)
        resp = None
    except Exception as exc:  # pragma: no cover - defensive
        if logger.isEnabledFor(logging.DEBUG):
            logger.exception("Unexpected error during request %s %s", method.upper(), url)
        else:
            logger.error("Unexpected error during request %s %s: %s", method.upper(), url, exc)
        resp = None

    should_try_headless = (
        HEADLESS_AVAILABLE
        and method.upper() == "GET"
        and (resp is None or resp.status_code in HEADLESS_TRIGGER_CODES)
    )
    if should_try_headless:
        fallback = _headless_request(url, timeout=timeout)
        if fallback:
            logger.info(
                "Headless fallback succeeded for %s %s after initial failure", method.upper(), url
            )
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


def _replace_query_param(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    new_pairs = []
    for existing_key, existing_value in query:
        if not replaced and existing_key == key:
            new_pairs.append((existing_key, value))
            replaced = True
        else:
            new_pairs.append((existing_key, existing_value))
    if not replaced:
        new_pairs.append((key, value))
    new_query = urlencode(new_pairs)
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


def _resolve_host_ips(host: str) -> List[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []
    except Exception:
        return []
    ips = {info[4][0] for info in infos if info and info[4]}
    return sorted(ips)


def _port_is_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


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


def _get_scan_limits(user_max_pages: Optional[int] = None) -> Tuple[int, int]:
    configured_cap = _read_limit_from_env("WEAKPOINT_MAX_PAGES", DEFAULT_MAX_PAGES, 8)
    max_depth = _read_limit_from_env("WEAKPOINT_MAX_DEPTH", DEFAULT_MAX_DEPTH, 2)
    if user_max_pages is None:
        max_pages = min(configured_cap, DEFAULT_PAGE_BUDGET)
    else:
        max_pages = max(8, min(user_max_pages, configured_cap))
    return max_pages, max_depth


def _resolve_seed_limit(page_budget: int) -> int:
    hard_cap = _read_limit_from_env(
        "WEAKPOINT_MAX_SEED_URLS",
        HARD_MAX_SEED_URLS,
        DEFAULT_MAX_SEED_URLS,
    )
    target = max(DEFAULT_MAX_SEED_URLS, int(page_budget * 1.2))
    return min(hard_cap, target)


def _resolve_sitemap_limit(page_budget: int) -> int:
    hard_cap = _read_limit_from_env(
        "WEAKPOINT_MAX_SITEMAP_URLS",
        HARD_MAX_SITEMAP_URLS,
        DEFAULT_MAX_SITEMAP_URLS,
    )
    target = max(DEFAULT_MAX_SITEMAP_URLS, int(page_budget * 1.5))
    return min(hard_cap, target)


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
    xml_text: str, base_host: Optional[str], limit: int
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
        if len(page_urls) >= limit:
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
            if len(page_urls) >= limit:
                break

    return page_urls, nested_sitemaps


def _collect_sitemap_pages(
    base_root: str,
    base_host: Optional[str],
    robots_txt: Optional[str],
    *,
    max_sitemaps: int = 12,
    url_limit: int = DEFAULT_MAX_SITEMAP_URLS,
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
        remaining = url_limit - len(collected_pages)
        if remaining <= 0:
            return collected_pages
        pages, nested = _parse_sitemap_document(xml_doc, base_host, remaining)
        for page in pages:
            if page not in collected_pages:
                collected_pages.append(page)
                if len(collected_pages) >= url_limit:
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
    *,
    seed_limit: int = DEFAULT_MAX_SEED_URLS,
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
        if len(unique) >= seed_limit:
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
    in_flight: Dict[Any, Tuple[str, int]] = {}
    max_workers = _read_limit_from_env(
        "WEAKPOINT_CRAWLER_WORKERS", DEFAULT_CRAWLER_WORKERS, 1
    )

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

    budget_exhausted = False

    def _schedule_from_queue(executor: ThreadPoolExecutor) -> None:
        while (
            not budget_exhausted
            and queue
            and len(in_flight) < max_workers
        ):
            candidate, depth = queue.popleft()
            queued.discard(candidate)
            if candidate in visited:
                continue
            future = executor.submit(_safe_request, candidate, allow_redirects=True)
            in_flight[future] = (candidate, depth)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        _schedule_from_queue(executor)

        while in_flight or queue:
            if not in_flight:
                _schedule_from_queue(executor)
                if not in_flight:
                    break

            done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED)
            for future in done:
                candidate, depth = in_flight.pop(future)
                try:
                    resp = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.error("Crawler worker failed for %s: %s", candidate, exc)
                    resp = None

                if resp is None or budget_exhausted:
                    visited.add(candidate)
                    continue

                normalized_final = _normalize_url(resp.url)
                if normalized_final in visited:
                    visited.add(candidate)
                    continue
                if resp.status_code >= 500 or not _is_html_response(resp):
                    visited.add(candidate)
                    visited.add(normalized_final)
                    continue

                snapshot = _snapshot_from_response(resp)
                snapshots.append(snapshot)
                visited.add(candidate)
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
                    budget_exhausted = True
                    break

            if budget_exhausted:
                # Drain remaining futures without processing new pages.
                for future in list(in_flight.keys()):
                    in_flight.pop(future, None)
                break

            _schedule_from_queue(executor)

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
    parsed: List[Dict[str, Any]] = []

    header_values: List[str] = []
    raw_headers = getattr(resp, "raw", None)
    if raw_headers and hasattr(raw_headers, "headers"):
        header_source = raw_headers.headers
        getter = getattr(header_source, "getlist", None) or getattr(
            header_source, "get_all", None
        )
        if getter:
            try:
                header_values.extend(getter("Set-Cookie") or [])
            except Exception:
                pass

    if not header_values:
        header = resp.headers.get("Set-Cookie")
        if header:
            header_values.append(header)

    for header in header_values:
        cookie = SimpleCookie()
        try:
            cookie.load(header)
        except Exception:
            logger.debug("Kon Set-Cookie header niet parsen: %s", header)
            continue
        for morsel in cookie.values():
            payload: Dict[str, Any] = {
                "name": morsel.key,
                "value": morsel.value,
            }
            for key in morsel.keys():
                value = morsel[key]
                if isinstance(value, str) and not value:
                    value = None
                if key == "secure" or key == "httponly":
                    payload[key] = bool(value)
                elif key in {"max-age"}:
                    payload[key.replace("-", "_")] = value
                else:
                    payload[key] = value
            parsed.append(payload)
    return parsed


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


def _looks_like_csrf_field(tag: Any) -> bool:
    if not hasattr(tag, "get"):
        return False
    candidates = [
        (tag.get("name") or "").lower(),
        (tag.get("id") or "").lower(),
    ]
    classes = tag.get("class")
    if isinstance(classes, (list, tuple)):
        candidates.extend(cls.lower() for cls in classes if isinstance(cls, str))
    elif isinstance(classes, str):
        candidates.extend(part.lower() for part in classes.split())
    for candidate in candidates:
        if any(hint in candidate for hint in CSRF_FIELD_HINTS):
            return True
    return False


def _form_has_csrf_token(form: Any) -> bool:
    if not hasattr(form, "find_all"):
        return False
    for field in form.find_all("input"):
        input_type = (field.get("type") or "").lower()
        if input_type in {"submit", "button", "image", "reset"}:
            continue
        if _looks_like_csrf_field(field):
            return True
    return False


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


def _check_dns_surface(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    hostname = parsed.hostname
    normalized = _normalize_hostname(hostname)
    if not hostname or not normalized:
        return _build_result(
            id="dns_surface",
            title="DNS & netwerkoppervlakte",
            severity=SEVERITY_CRITICAL,
            status=STATUS_INFO,
            summary="Doelhost kon niet worden geïnterpreteerd voor DNS-analyse.",
            remediation="Controleer of de opgegeven URL een geldig hostname bevat.",
            impact="Zonder hostname kan geen netwerkoppervlak worden bepaald.",
        )

    discovered: List[Dict[str, Any]] = []
    seen_hosts: Set[str] = set()
    for guess in SUBDOMAIN_GUESSES:
        if len(discovered) >= SUBDOMAIN_DISCOVERY_LIMIT:
            break
        candidate = f"{guess}.{normalized}"
        if candidate in seen_hosts or _normalize_hostname(candidate) == normalized:
            continue
        ips = _resolve_host_ips(candidate)
        if not ips:
            continue
        seen_hosts.add(candidate)
        statuses: Dict[str, int] = {}
        for scheme in ("https", "http"):
            url = f"{scheme}://{candidate}"
            resp = _safe_request(url, method="HEAD", timeout=4, allow_redirects=True)
            if resp is None or resp.status_code >= 400:
                resp = _safe_request(url, timeout=4, allow_redirects=True)
            if resp is not None:
                statuses[scheme] = resp.status_code
        discovered.append({"host": candidate, "ips": ips, "statuses": statuses})

    open_ports: List[Dict[str, Any]] = []
    base_ips = _resolve_host_ips(hostname)
    for port, service in PORT_PROBES.items():
        if _port_is_open(hostname, port):
            open_ports.append(
                {
                    "port": port,
                    "service": service,
                    "legacy": port in LEGACY_PORTS,
                }
            )

    legacy_exposure = any(entry["legacy"] for entry in open_ports)
    has_extra_subdomains = bool(discovered)
    has_ports = bool(open_ports)

    if legacy_exposure:
        status = STATUS_FAIL
        summary = "Legacy-services of gevoelige poorten publiek bereikbaar."
    elif has_extra_subdomains or has_ports:
        status = STATUS_WARN
        summary = "Aanvullende subdomeinen of open poorten ontdekt."
    else:
        status = STATUS_PASS
        summary = "Geen extra subdomeinen of onverwachte poorten gevonden."

    remediation = "Inventariseer DNS records, sluit overbodige poorten en scherm beheerinterfaces af."
    impact = (
        "Extra attack surface (subdomeinen/poorten) kan worden misbruikt om verouderde services aan te vallen."
        if status in {STATUS_WARN, STATUS_FAIL}
        else "Beperkt netwerkoppervlak verkleint de kans dat aanvallers zwakke plekken vinden."
    )
    details = {
        "subdomains": discovered,
        "open_ports": open_ports,
        "base_ips": base_ips,
    }
    return _build_result(
        id="dns_surface",
        title="DNS & netwerkoppervlakte",
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
    pages = _iter_pages(context)

    candidates: List[str] = [base]
    seen: Set[str] = {base}

    def register(url: str) -> None:
        normalized = _normalize_url(url)
        if normalized not in seen and len(candidates) < HTTP_METHOD_ENDPOINT_LIMIT:
            seen.add(normalized)
            candidates.append(normalized)

    for page in pages:
        register(page.url)
        for form in page.soup.find_all("form"):
            action = form.get("action")
            if not action:
                continue
            target = urljoin(page.url, action)
            parsed_target = urlparse(target)
            if parsed_target.scheme in {"http", "https"} and _hosts_match(parsed.hostname, parsed_target.hostname):
                register(target)

    findings: List[str] = []
    tested_endpoints: List[Dict[str, Any]] = []

    for candidate in candidates:
        endpoint_result: Dict[str, Any] = {"url": candidate}
        options_resp = _safe_request(candidate, method="OPTIONS", timeout=6, allow_redirects=False)
        if options_resp is not None:
            allow = options_resp.headers.get("Allow") or options_resp.headers.get("allow")
            if allow:
                verbs = {verb.strip().upper() for verb in allow.split(",") if verb.strip()}
                endpoint_result["allow_header"] = sorted(verbs)
                risky = sorted(verb for verb in verbs if verb in {"TRACE", "PUT", "DELETE"})
                if risky:
                    findings.append(f"{candidate} -> {', '.join(risky)}")

        trace_resp = _safe_request(candidate, method="TRACE", timeout=6, allow_redirects=False)
        if trace_resp is not None:
            endpoint_result["trace_status"] = trace_resp.status_code
            if trace_resp.status_code < 400:
                findings.append(f"{candidate} -> TRACE toegestaan")

        tested_endpoints.append(endpoint_result)

    status = STATUS_PASS if not findings else STATUS_WARN
    summary = (
        "Onveilige HTTP methodes lijken geblokkeerd."
        if not findings
        else "Risicovolle methodes toegestaan: " + "; ".join(sorted(set(findings)))
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
        details={"tested_endpoints": tested_endpoints} if tested_endpoints else None,
    )


def _check_api_surface(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    base_host = context.parsed_url.hostname
    candidates: List[Dict[str, Any]] = []
    seen: Set[str] = set()

    def register(url: str, source: str) -> None:
        if len(candidates) >= API_CANDIDATE_LIMIT:
            return
        parsed_url = urlparse(url)
        if parsed_url.scheme not in {"http", "https"}:
            return
        if not _hosts_match(base_host, parsed_url.hostname):
            return
        normalized = _normalize_url(url)
        if normalized in seen:
            return
        path_lower = parsed_url.path.lower()
        if not any(
            indicator in path_lower
            for indicator in ("/api", "graphql", ".json", "/rest", "/v1", "/v2")
        ):
            return
        seen.add(normalized)
        candidates.append({"url": url, "source": source})

    for page in pages:
        for tag in page.soup.find_all(True):
            for attr in ("href", "src", "data-url", "data-endpoint", "action"):
                value = tag.get(attr)
                if not value:
                    continue
                register(urljoin(page.url, value), f"{page.url}::{tag.name}[{attr}]")
        for match in re.findall(r"https?://[^'\"\s>]+", page.html):
            register(match, f"{page.url}::inline")
        for match in re.findall(r"['\"](/[^'\"\s>]+)['\"]", page.html):
            register(urljoin(page.url, match), f"{page.url}::inline")

    tested: List[Dict[str, Any]] = []
    exposures: List[Dict[str, Any]] = []

    for candidate in candidates:
        url = candidate["url"]
        resp = _safe_request(
            url,
            timeout=6,
            allow_redirects=False,
            headers={"Accept": "application/json, */*;q=0.1"},
        )
        entry: Dict[str, Any] = {
            "url": url,
            "source": candidate["source"],
            "status": resp.status_code if resp else None,
        }
        issue_reasons: List[str] = []
        if resp is not None:
            content_type = resp.headers.get("Content-Type")
            if content_type:
                entry["content_type"] = content_type
            aco = resp.headers.get("Access-Control-Allow-Origin")
            if aco:
                entry["cors"] = aco
                if aco.strip() == "*":
                    issue_reasons.append("CORS staat alle origins toe")
            if resp.status_code < 400 and resp.status_code not in {401, 403}:
                issue_reasons.append(f"Publiek bereikbaar (status {resp.status_code})")
            body_sample = (resp.text or "")[:200] if resp and resp.text else None
            if body_sample and any(keyword in body_sample.lower() for keyword in ("error", "exception", "trace")):
                entry["body_sample"] = body_sample
            allow = resp.headers.get("Allow")
            if allow:
                entry["allow"] = allow
                if any(method in allow.upper() for method in ("PUT", "PATCH", "DELETE")):
                    issue_reasons.append("API ondersteunt muterende methodes zonder auth-signaal")
        if issue_reasons:
            exposures.append({**entry, "issues": issue_reasons})
        tested.append(entry)

    status = STATUS_WARN if exposures else (STATUS_INFO if candidates else STATUS_PASS)
    if exposures:
        summary = f"Open API endpoints gevonden ({len(exposures)})."
    elif candidates:
        summary = "API-indicatoren gevonden maar geen directe blootstelling vastgesteld."
    else:
        summary = "Geen API-eindpunten aangetroffen tijdens heuristische scan."

    remediation = (
        "Bescherm API's met authenticatie, schema-validatie en rate limiting; beperk CORS tot vertrouwde origins."
    )
    impact = (
        "Publieke API's zonder auth kunnen gevoelige gegevens of beheeracties prijsgeven."
        if exposures
        else "Wanneer API's afgeschermd zijn neemt het risico op data-exfiltratie sterk af."
    )
    details = {"candidates": candidates, "tested": tested, "issues": exposures}
    return _build_result(
        id="api_surface",
        title="API oppervlakte",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
    )


def _check_forms(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    insecure: List[Dict[str, Any]] = []
    total_forms = 0
    pages_with_forms: Set[str] = set()
    form_details: List[Dict[str, Any]] = []

    for page in pages:
        forms = page.soup.find_all("form")
        if not forms:
            continue
        pages_with_forms.add(page.url)
        for idx, form in enumerate(forms, start=1):
            total_forms += 1
            method = (form.get("method") or "get").lower()
            action = form.get("action") or page.url
            target = urljoin(page.url, action)
            inputs = form.find_all(["input", "textarea"])
            text_inputs = [
                field
                for field in inputs
                if field.get("type", "text").lower()
                in ("text", "email", "password", "tel", "number")
            ]
            field_metadata: List[Dict[str, Any]] = []
            for field in text_inputs:
                input_type = field.get("type", "text").lower()
                name = field.get("name") or field.get("id")
                field_metadata.append(
                    {
                        "name": name,
                        "type": input_type,
                        "required": field.has_attr("required"),
                        "pattern": bool(field.get("pattern")),
                        "inputmode": field.get("inputmode"),
                        "autocomplete": field.get("autocomplete"),
                    }
                )
                if not field.has_attr("required") and not field.get("pattern"):
                    insecure.append(
                        {
                            "page": page.url,
                            "form": idx,
                            "action": target,
                            "input": name,
                            "reason": "Geen verplichting/patroon; validering ontbreekt mogelijk server-side.",
                        }
                    )
                if input_type in {"password", "email", "tel"} and not field.get("autocomplete"):
                    insecure.append(
                        {
                            "page": page.url,
                            "form": idx,
                            "action": target,
                            "input": name,
                            "reason": "Geen autocomplete-profiel voor gevoelig veld; gebruikers vullen mogelijk willekeurig in.",
                        }
                    )
                if input_type in {"number", "tel"} and not field.get("inputmode"):
                    insecure.append(
                        {
                            "page": page.url,
                            "form": idx,
                            "action": target,
                            "input": name,
                            "reason": "Geen inputmode voor numerieke invoer; verhoog server-side validatie.",
                        }
                    )
            if method != "post" and any(
                inp.get("type", "text").lower() == "password" for inp in text_inputs
            ):
                insecure.append(
                    {
                        "page": page.url,
                        "form": idx,
                        "action": target,
                        "reason": "Wachtwoordformulier gebruikt GET i.p.v. POST.",
                    }
                )

            form_details.append(
                {
                    "page": page.url,
                    "form": idx,
                    "action": target,
                    "method": method.upper(),
                    "text_field_count": len(text_inputs),
                    "client_side_validations": {
                        "required": sum(1 for meta in field_metadata if meta["required"]),
                        "pattern": sum(1 for meta in field_metadata if meta["pattern"]),
                        "inputmode": sum(1 for meta in field_metadata if meta["inputmode"]),
                        "autocomplete": sum(1 for meta in field_metadata if meta["autocomplete"]),
                    },
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
            "form_inventory": form_details[:15],
        },
    )


def _check_file_uploads(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    upload_forms: List[Dict[str, Any]] = []
    issues: List[str] = []

    for page in pages:
        for idx, form in enumerate(page.soup.find_all("form"), start=1):
            file_inputs = [
                field
                for field in form.find_all("input")
                if (field.get("type") or "").lower() == "file"
            ]
            if not file_inputs:
                continue
            method = (form.get("method") or "get").lower()
            enctype = (form.get("enctype") or "").lower()
            action = urljoin(page.url, form.get("action") or page.url)
            has_csrf = any(
                hidden.get("name")
                and re.search(r"csrf|token", hidden.get("name"), re.I)
                for hidden in form.find_all("input", {"type": "hidden"})
            )
            field_meta: List[Dict[str, Any]] = []
            for field in file_inputs:
                attrs = {
                    attr: field.get(attr)
                    for attr in FILE_UPLOAD_FLAG_FIELDS
                    if field.get(attr)
                }
                field_meta.append(
                    {
                        "name": field.get("name") or field.get("id"),
                        "accept": field.get("accept"),
                        "multiple": field.has_attr("multiple"),
                        "flags": attrs,
                    }
                )
                if not field.get("accept"):
                    issues.append(
                        f"{page.url} formulier #{idx}: file input '{field.get('name')}' zonder accept whitelist."
                    )
            if method != "post":
                issues.append(
                    f"{page.url} formulier #{idx}: file upload gebruikt {method.upper()} i.p.v. POST."
                )
            if "multipart/form-data" not in enctype:
                issues.append(
                    f"{page.url} formulier #{idx}: ontbrekende enctype multipart/form-data."
                )
            if not has_csrf:
                issues.append(
                    f"{page.url} formulier #{idx}: geen CSRF-token zichtbaar bij upload."
                )

            upload_forms.append(
                {
                    "page": page.url,
                    "form": idx,
                    "action": action,
                    "method": method.upper(),
                    "enctype": enctype or None,
                    "has_csrf": has_csrf,
                    "file_fields": field_meta,
                }
            )

    if not upload_forms:
        return _build_result(
            id="file_uploads",
            title="File uploads",
            severity=SEVERITY_IMPORTANT,
            status=STATUS_PASS,
            summary="Geen file-upload formulieren gevonden.",
            remediation="Voeg upload-validatie toe als de applicatie bestanden accepteert.",
            impact="Zonder uploadoppervlak is het risico op malafide bestanden beperkt.",
            details=None,
        )

    status = STATUS_WARN if issues else STATUS_PASS
    summary = (
        "Aandachtspunten bij file upload formulieren."
        if issues
        else "File uploads tonen basismaatregelen zoals accept-whitelists."
    )
    remediation = (
        "Beperk toegestane bestandstypen, valideer server-side, scan op malware en sla buiten de webroot op."
    )
    impact = (
        "Inadequate uploadbeveiliging kan leiden tot RCE of data-exfiltratie via kwaadaardige bestanden."
        if issues
        else "Goede uploadbeveiliging verkleint het risico op webshells en ransomware."
    )
    details = {"forms": upload_forms, "issues": issues}
    return _build_result(
        id="file_uploads",
        title="File uploads",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
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
        base_token = f"wp_reflect_{random.randint(10_000, 99_999)}"
        vectors = [
            (
                "query",
                _append_query_param(page.url, REFLECTION_PARAM, f"{base_token}_q"),
                {"method": "GET"},
            ),
            (
                "form",
                page.url,
                {
                    "method": "POST",
                    "data": {REFLECTION_PARAM: f"{base_token}_f"},
                },
            ),
            (
                "json",
                page.url,
                {
                    "method": "POST",
                    "json": {REFLECTION_PARAM: f"{base_token}_j"},
                    "headers": {"Content-Type": "application/json"},
                },
            ),
        ]

        for vector, url, options in vectors:
            method = options.get("method", "GET")
            data = options.get("data")
            json_payload = options.get("json")
            extra_headers = options.get("headers")
            resp = _safe_request(
                url,
                method=method,
                allow_redirects=True,
                data=data,
                json=json_payload,
                headers=extra_headers,
            )
            if not resp or resp.status_code >= 500:
                continue
            html = resp.text or ""
            marker = (data or json_payload or {}).get(REFLECTION_PARAM)
            if marker is None and "_q" in url:
                marker = f"{base_token}_q"
            if marker and marker in html:
                findings.append(
                    {
                        "page": resp.url,
                        "token": marker,
                        "vector": vector,
                        "status_code": resp.status_code,
                    }
                )
                if len(findings) >= MAX_REFLECTION_TESTS:
                    break
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
    active_hits: List[Dict[str, Any]] = []
    tested_params = 0
    for page in pages:
        html = page.html.lower()
        found = sorted({pattern for pattern in SQL_ERROR_PATTERNS if pattern in html})
        if found:
            hits.append({"page": page.url, "patterns": found})

        if tested_params >= SQLI_ACTIVE_PARAM_LIMIT:
            continue
        parsed_page = urlparse(page.url)
        params = parse_qsl(parsed_page.query, keep_blank_values=True)
        if not params:
            continue
        for key, _ in params:
            if tested_params >= SQLI_ACTIVE_PARAM_LIMIT:
                break
            for payload in SQLI_ACTIVE_PAYLOADS:
                if tested_params >= SQLI_ACTIVE_PARAM_LIMIT:
                    break
                crafted_url = _replace_query_param(page.url, key, payload)
                resp = _safe_request(crafted_url, allow_redirects=True)
                tested_params += 1
                if resp is None:
                    continue
                lowered = (resp.text or "").lower()
                evidence = sorted(
                    {pattern for pattern in SQL_ERROR_PATTERNS if pattern in lowered}
                )
                if evidence or resp.status_code >= 500:
                    active_hits.append(
                        {
                            "page": page.url,
                            "tested_url": crafted_url,
                            "param": key,
                            "payload": payload,
                            "status_code": resp.status_code,
                            "patterns": evidence,
                        }
                    )
                    break

    status = STATUS_FAIL if (hits or active_hits) else STATUS_INFO
    if hits or active_hits:
        passive_count = len(hits)
        active_count = len(active_hits)
        summary_parts = []
        if passive_count:
            summary_parts.append(
                f"Database foutmeldingen zichtbaar op {passive_count} pagina's"
            )
        if active_count:
            summary_parts.append(
                f"Injectieprobes veroorzaakten errors bij {active_count} parameter(s)"
            )
        summary = "; ".join(summary_parts)
        impact = "Gedetailleerde fouten of responses na injectie helpen aanvallers payloads te verfijnen en data te lezen."
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
        details={
            "pages": hits[:10],
            "active_vectors": active_hits[:10],
            "tested_params": tested_params,
        },
    )


def _check_active_form_attacks(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    seed_token = f"{random.randint(100000, 999999)}"
    payload_results: Dict[str, Dict[str, Any]] = {}
    for payload in PENTEST_PAYLOADS:
        payload_results[payload["id"]] = {
            "label": payload["label"],
            "template": payload["template"],
            "reflections": [],
            "sanitized": [],
            "sql_errors": [],
            "executed": [],
            "dom_reflections": [],
            "blocked": [],
        }
    tested = 0
    forms_missing_csrf: List[Dict[str, Any]] = []

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
            has_csrf = _form_has_csrf_token(form)
            if method == "post" and not has_csrf:
                forms_missing_csrf.append(
                    {
                        "page": page.url,
                        "target": target,
                        "form_index": idx,
                        "reason": "missing_csrf",
                    }
                )
            for payload in PENTEST_PAYLOADS:
                payload_id = payload["id"]
                marker = f"{seed_token}-{payload_id}-{tested}"
                value = payload["template"].format(token=marker)
                data = {name: value for name in field_names}
                if method == "post":
                    resp = _safe_request(
                        target, method="POST", data=data, timeout=DEFAULT_TIMEOUT
                    )
                else:
                    resp = _safe_request(
                        target, method="GET", params=data, timeout=DEFAULT_TIMEOUT
                    )

                result_bucket = payload_results[payload_id]

                if resp is None:
                    result_bucket["blocked"].append(
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
                marker_lower = marker.lower()
                headless_text = ""
                headless_lower = ""
                if HEADLESS_AVAILABLE and method == "get":
                    headless_resp = _headless_request(resp.url, timeout=DEFAULT_TIMEOUT)
                    if headless_resp:
                        headless_text = headless_resp.text or ""
                        headless_lower = headless_text.lower()

                if payload_id == "xss":
                    raw_marker = f"<weakpoint-{marker}>"
                    if raw_marker in text:
                        result_bucket["reflections"].append(
                            {
                                "page": page.url,
                                "target": target,
                                "form_index": idx,
                                "status_code": resp.status_code,
                            }
                        )
                    elif f"weakpoint-{marker_lower}" in lowered:
                        if f"&lt;weakpoint-{marker_lower}&gt;" in lowered:
                            result_bucket["sanitized"].append(
                                {
                                    "page": page.url,
                                    "target": target,
                                    "form_index": idx,
                                    "status_code": resp.status_code,
                                }
                            )
                    elif headless_text:
                        if raw_marker in headless_text:
                            result_bucket["dom_reflections"].append(
                                {
                                    "page": page.url,
                                    "target": resp.url,
                                    "form_index": idx,
                                    "status_code": resp.status_code,
                                }
                            )
                        elif f"weakpoint-{marker_lower}" in headless_lower:
                            result_bucket["dom_reflections"].append(
                                {
                                    "page": page.url,
                                    "target": resp.url,
                                    "form_index": idx,
                                    "status_code": resp.status_code,
                                    "context": "encoded",
                                }
                            )
                elif payload_id == "sql":
                    hits = sorted(
                        {pattern for pattern in SQL_ERROR_PATTERNS if pattern in lowered}
                    )
                    if hits:
                        result_bucket["sql_errors"].append(
                            {
                                "page": page.url,
                                "target": target,
                                "form_index": idx,
                                "status_code": resp.status_code,
                                "patterns": hits,
                            }
                        )
                elif payload_id == "ssti":
                    if f"49weakpoint-{marker_lower}" in lowered or f"weakpoint-{marker_lower}" in lowered:
                        result_bucket["executed"].append(
                            {
                                "page": page.url,
                                "target": target,
                                "form_index": idx,
                                "status_code": resp.status_code,
                            }
                        )

                if resp.status_code >= 400:
                    result_bucket["blocked"].append(
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

    fail_messages: List[str] = []
    total_blocked = 0
    for payload_id, result in payload_results.items():
        total_hits = (
            len(result["reflections"])
            + len(result["sql_errors"])
            + len(result["executed"])
            + len(result["dom_reflections"])
        )
        if total_hits:
            fail_messages.append(
                f"{result['label']}: {total_hits} treffers"
            )
        total_blocked += len(result["blocked"])

    if fail_messages:
        status = STATUS_FAIL
        summary = "; ".join(fail_messages)
        remediation = (
            "Valideer en ontsmet invoer server-side, encodeer output en gebruik parameterized queries."
        )
        impact = (
            "Aanvallers kunnen de reflectie of foutmeldingen gebruiken om XSS/SSTI/SQL-aanvallen te bouwen."
        )
    elif total_blocked:
        status = STATUS_WARN
        summary = f"Actieve payloads werden geblokkeerd of geweigerd ({total_blocked} keer)."
        remediation = (
            "Controleer of blokkades legitiem zijn en documenteer WAF/rate limit regels."
        )
        impact = (
            "Blokkade wijst op tegenmaatregelen, maar handmatige review blijft nodig om ev. bypasses uit te sluiten."
        )
    elif forms_missing_csrf:
        status = STATUS_WARN
        summary = f"{len(forms_missing_csrf)} formulier(en) zonder CSRF-token gevonden."
        remediation = "Voeg unieke CSRF-tokens toe aan POST formulieren en valideer ze server-side."
        impact = "Zonder CSRF-tokens kunnen aanvallers authenticatie misbruiken voor cross-site request forgery."

    details_payloads = {
        payload_id: {
            "label": result["label"],
            "payload": result["template"],
            "reflections": result["reflections"][:10],
            "sanitized": result["sanitized"][:10],
            "sql_errors": result["sql_errors"][:10],
            "executed": result["executed"][:10],
            "dom_reflections": result["dom_reflections"][:10],
            "blocked": result["blocked"][:10],
        }
        for payload_id, result in payload_results.items()
    }

    details: Dict[str, Any] = {
        "tested_forms": tested,
        "payloads": details_payloads,
        "forms_missing_csrf": forms_missing_csrf[:10],
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


def _parse_version_tuple(text: str) -> Optional[Tuple[int, ...]]:
    if not text:
        return None
    match = VERSION_PATTERN.search(text)
    if not match:
        return None
    try:
        return tuple(int(part) for part in match.group(1).split("."))
    except ValueError:
        return None


def _is_version_less(found: Tuple[int, ...], baseline: Tuple[int, ...]) -> bool:
    max_len = max(len(found), len(baseline))
    padded_found = tuple(list(found) + [0] * (max_len - len(found)))
    padded_baseline = tuple(list(baseline) + [0] * (max_len - len(baseline)))
    return padded_found < padded_baseline


def _check_owasp_top10_quickscan(context: ScanContext) -> CheckResult:
    parsed_root = context.parsed_url
    origin = f"{parsed_root.scheme}://{parsed_root.netloc}" if parsed_root.netloc else context.target_url
    extra_requests = 0
    normalized_headers = {k.lower(): v for k, v in context.response.headers.items()}
    server_header = normalized_headers.get("server", "")
    powered_header = normalized_headers.get("x-powered-by", "")

    def tracked_request(url: str, **kwargs):
        nonlocal extra_requests
        extra_requests += 1
        return _safe_request(url, **kwargs)

    categories: List[Dict[str, Any]] = []

    def add_category(
        category_id: str,
        title: str,
        status: str,
        summary: str,
        evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        categories.append(
            {
                "id": category_id,
                "title": title,
                "status": status,
                "summary": summary,
                "evidence": evidence or {},
            }
        )

    component_findings: List[Dict[str, Any]] = []

    def record_component(keyword: str, source: str, text: str) -> None:
        if not text:
            return
        lowered = text.lower()
        key = keyword.lower()
        if key not in lowered:
            return
        pattern = re.compile(rf"{re.escape(keyword)}[\\s/:_-]*([0-9]+(?:\\.[0-9]+)*)", re.I)
        match = pattern.search(text)
        version_text = match.group(1) if match else None
        version_tuple = _parse_version_tuple(version_text or "")
        baseline = OUTDATED_COMPONENT_BASELINES.get(key)
        outdated = bool(
            version_tuple and baseline and _is_version_less(version_tuple, baseline)
        )
        component_findings.append(
            {
                "component": key,
                "source": source,
                "evidence": match.group(0) if match else keyword,
                "version": version_text,
                "baseline": ".".join(str(part) for part in baseline) if baseline else None,
                "outdated": outdated,
            }
        )

    for keyword in ("php", "apache", "nginx"):
        record_component(keyword, "server", server_header)
    if powered_header:
        for keyword in ("php", "asp.net", "express"):
            record_component(keyword, "x-powered-by", powered_header)

    generator_entries: List[str] = []
    if context.soup:
        for meta in context.soup.find_all("meta"):
            if (meta.get("name") or "").lower() != "generator":
                continue
            content = meta.get("content") or ""
            if not content:
                continue
            generator_entries.append(content)
            for keyword in ("wordpress", "drupal", "joomla"):
                record_component(keyword, "meta:generator", content)

    # A01: Broken Access Control
    default_account_hits: List[Dict[str, Any]] = []
    login_probe_url = urljoin(origin, "/login")
    if parsed_root.scheme in {"http", "https"} and parsed_root.netloc:
        for username in DEFAULT_PENTEST_ACCOUNTS:
            resp = tracked_request(
                login_probe_url,
                params={"username": username, "password": "password"},
                timeout=DEFAULT_TIMEOUT,
            )
            if resp is None:
                continue
            lowered = (resp.text or "").lower() if resp.text else ""
            if resp.status_code == 200 and not any(
                hint in lowered for hint in ("invalid", "error", "failed")
            ):
                default_account_hits.append(
                    {
                        "username": username,
                        "status_code": resp.status_code,
                        "url": resp.url,
                    }
                )
    sensitive_data_links: List[Dict[str, Any]] = []
    admin_links: List[str] = []
    title_flags: List[str] = []
    seen_links: Set[str] = set()
    if context.soup:
        page_title = context.soup.title.get_text(strip=True) if context.soup.title else ""
        lowered_title = page_title.lower()
        for keyword in ADMIN_TITLE_KEYWORDS:
            if keyword in lowered_title:
                title_flags.append(keyword)
        for anchor in context.soup.find_all("a", href=True):
            if len(seen_links) >= 10 or len(sensitive_data_links) >= 5:
                break
            href = anchor["href"].strip()
            if not href or href.startswith("#") or href.lower().startswith(("mailto:", "javascript:")):
                continue
            full_url = urljoin(context.response.url, href)
            parsed = urlparse(full_url)
            if parsed.netloc and parsed_root.netloc and parsed.netloc != parsed_root.netloc:
                continue
            normalized = _normalize_url(full_url)
            href_lower = normalized.lower()
            if "admin" in href_lower:
                if normalized not in admin_links:
                    admin_links.append(normalized)
            if normalized in seen_links:
                continue
            seen_links.add(normalized)
            resp = tracked_request(full_url, timeout=DEFAULT_TIMEOUT)
            if not resp or resp.status_code >= 400:
                continue
            text_lower = (resp.text or "").lower()
            if any(keyword in text_lower for keyword in SENSITIVE_CONTENT_KEYWORDS):
                sensitive_data_links.append(
                    {"url": full_url, "status_code": resp.status_code}
                )
    if default_account_hits or admin_links:
        a01_status = STATUS_FAIL
        fail_parts = []
        if default_account_hits:
            fail_parts.append(f"default account probes ({len(default_account_hits)})")
        if admin_links:
            fail_parts.append(f"publieke admin-links ({len(admin_links)})")
        a01_summary = " en ".join(fail_parts)
    elif sensitive_data_links or title_flags:
        a01_status = STATUS_WARN
        warn_parts = []
        if sensitive_data_links:
            warn_parts.append(f"{len(sensitive_data_links)} link(s) met wachtwoordwoorden")
        if title_flags:
            warn_parts.append("titel bevat admin-termen")
        a01_summary = "; ".join(warn_parts)
    else:
        a01_status = STATUS_PASS
        a01_summary = "Geen aanwijzingen voor standaardaccounts of gelekte wachtwoorden op hoofdlinks."
    add_category(
        "A01",
        "Broken Access Control",
        a01_status,
        a01_summary,
        {
            "default_account_responses": default_account_hits[:5],
            "sensitive_links": sensitive_data_links[:5],
            "probe_url": login_probe_url,
            "admin_links": admin_links[:5],
            "title_flags": title_flags,
        },
    )

    # A02: Cryptographic Failures
    tls_messages: List[str] = []
    hsts_missing = False
    if parsed_root.scheme != "https":
        tls_messages.append("Doel gebruikt geen HTTPS (HTTP).")
    else:
        hostname = parsed_root.hostname
        port = parsed_root.port or 443
        if hostname:
            try:
                context_ssl = ssl.create_default_context()
                with context_ssl.wrap_socket(
                    socket.socket(socket.AF_INET),
                    server_hostname=hostname,
                ) as tls_socket:
                    tls_socket.settimeout(5)
                    tls_socket.connect((hostname, port))
            except (ssl.SSLError, OSError) as exc:
                tls_messages.append(f"TLS-handshake mislukt: {exc}")
        else:
            tls_messages.append("Kon hostnaam niet bepalen voor TLS-check.")
        if "strict-transport-security" not in normalized_headers:
            hsts_missing = True
    if tls_messages:
        a02_status = STATUS_FAIL
        a02_summary = "; ".join(tls_messages)
    elif hsts_missing:
        a02_status = STATUS_WARN
        a02_summary = "HTTPS actief maar HSTS-header ontbreekt op root."
    else:
        a02_status = STATUS_PASS
        a02_summary = "HTTPS-verbinding accepteert standaard TLS-handshake."
    add_category(
        "A02",
        "Cryptographic Failures",
        a02_status,
        a02_summary,
        {
            "issues": tls_messages,
            "hsts_missing": hsts_missing,
            "server_header": server_header,
        },
    )

    # A03: Injection
    sql_payload = "' OR 1=1 --"
    xss_payload = "<script>alert('XSS')</script>"
    sql_issue: Optional[Dict[str, Any]] = None
    xss_issue: Optional[Dict[str, Any]] = None
    search_url = urljoin(origin, "/search")

    sql_resp = tracked_request(search_url, params={"q": sql_payload}, timeout=DEFAULT_TIMEOUT)
    if sql_resp:
        lowered = (sql_resp.text or "").lower()
        if sql_resp.status_code >= 500 or "results" in lowered:
            sql_issue = {
                "status_code": sql_resp.status_code,
                "url": sql_resp.url,
            }

    xss_resp = tracked_request(search_url, params={"q": xss_payload}, timeout=DEFAULT_TIMEOUT)
    if xss_resp:
        lowered = (xss_resp.text or "").lower()
        if "alert" in lowered or "<script>alert('xss')</script>" in lowered:
            xss_issue = {
                "status_code": xss_resp.status_code,
                "url": xss_resp.url,
            }

    if sql_issue:
        a03_status = STATUS_FAIL
        a03_summary = "SQL-payload veroorzaakt zichtbare fout of succes."
    elif xss_issue:
        a03_status = STATUS_WARN
        a03_summary = "XSS-payload reflecteerde in zoekresultaten."
    else:
        a03_status = STATUS_PASS
        a03_summary = "Zoek-endpoint reageerde niet gevoelig op standaard payloads."
    add_category(
        "A03",
        "Injection",
        a03_status,
        a03_summary,
        {
            "sql_probe": sql_issue,
            "xss_probe": xss_issue,
            "tested_endpoint": search_url,
        },
    )

    # A04: Insecure Design
    insecure_links: List[str] = []
    design_flags: List[str] = []
    if server_header and "php" in server_header.lower():
        design_flags.append("Server-header onthult PHP-stack.")
    if context.soup:
        for anchor in context.soup.find_all("a", href=True):
            if len(insecure_links) >= 5:
                break
            href = anchor["href"].strip()
            if not href:
                continue
            full_url = urljoin(context.response.url, href)
            if any(keyword in full_url.lower() for keyword in SENSITIVE_URL_KEYWORDS):
                insecure_links.append(full_url)
    if insecure_links or design_flags:
        a04_status = STATUS_WARN
        summary_bits = []
        if insecure_links:
            summary_bits.append(f"URLs met gevoelige sleutelwoorden ({len(insecure_links)}x)")
        if design_flags:
            summary_bits.extend(design_flags)
        a04_summary = "; ".join(summary_bits)
    else:
        a04_status = STATUS_PASS
        a04_summary = "Geen gevoelige sleutelwoorden aangetroffen in URL-paden."
    add_category(
        "A04",
        "Insecure Design",
        a04_status,
        a04_summary,
        {"urls": insecure_links, "design_flags": design_flags},
    )

    # A05: Security Misconfiguration
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    missing_headers = [header for header in OWASP_HEADER_BASELINE if header not in headers]
    if missing_headers:
        if len(missing_headers) >= 4:
            a05_status = STATUS_FAIL
        else:
            a05_status = STATUS_WARN
        a05_summary = f"Ontbrekende security-headers: {', '.join(missing_headers)}."
    else:
        a05_status = STATUS_PASS
        a05_summary = "Belangrijkste security-headers aanwezig op hoofdpagina."
    add_category(
        "A05",
        "Security Misconfiguration",
        a05_status,
        a05_summary,
        {"missing_headers": missing_headers},
    )

    # A06: Vulnerable & Outdated Components
    outdated_components = [entry for entry in component_findings if entry["outdated"]]
    if outdated_components:
        a06_status = STATUS_FAIL
        a06_summary = f"Verouderde componenten: {', '.join(sorted({entry['component'] for entry in outdated_components}))}."
    elif component_findings:
        a06_status = STATUS_WARN
        a06_summary = "Server onthult componentversies; controleer patchniveau."
    else:
        a06_status = STATUS_PASS
        a06_summary = "Geen componentversies blootgelegd op basis van headers/meta."
    add_category(
        "A06",
        "Vulnerable & Outdated Components",
        a06_status,
        a06_summary,
        {"components": component_findings, "generator_meta": generator_entries[:3]},
    )

    # A07: Identification & Authentication Failures
    weak_login_forms: List[Dict[str, Any]] = []
    login_text_present = False
    mfa_mentioned = False
    if context.soup:
        text_blob = context.soup.get_text(" ", strip=True).lower()
        login_text_present = any(term in text_blob for term in ("login", "signin", "aanmelden"))
        mfa_mentioned = any(term in text_blob for term in ("mfa", "2fa", "twee-factor"))
        for form in context.soup.find_all("form"):
            password_inputs = [
                field
                for field in form.find_all("input")
                if (field.get("type") or "").lower() == "password"
            ]
            if not password_inputs:
                continue
            form_issues: List[str] = []
            method = (form.get("method") or "get").lower()
            if method != "post":
                form_issues.append("method_is_get")
            if not _form_has_csrf_token(form):
                form_issues.append("missing_csrf")
            if any(
                (field.get("autocomplete") or "").lower() not in {"current-password", "new-password"}
                for field in password_inputs
            ):
                form_issues.append("password_autocomplete")
            if form_issues:
                weak_login_forms.append(
                    {
                        "action": urljoin(context.response.url, form.get("action") or context.response.url),
                        "method": method,
                        "issues": form_issues,
                    }
                )
    if any("method_is_get" in form["issues"] for form in weak_login_forms):
        a07_status = STATUS_FAIL
        a07_summary = "Loginformulier gebruikt GET of mist basale auth-verdediging."
    elif weak_login_forms:
        a07_status = STATUS_WARN
        a07_summary = f"{len(weak_login_forms)} loginformulier(en) missen CSRF of veilige autocomplete."
    elif login_text_present and not mfa_mentioned:
        a07_status = STATUS_WARN
        a07_summary = "Login vermeld zonder zichtbare verwijzing naar MFA."
    else:
        a07_status = STATUS_PASS
        a07_summary = "Geen aanwijzingen voor zwakke authenticatie op de hoofdpagina."
    add_category(
        "A07",
        "Identification & Authentication Failures",
        a07_status,
        a07_summary,
        {
            "weak_forms": weak_login_forms[:5],
            "login_text_present": login_text_present,
            "mfa_mentioned": mfa_mentioned,
        },
    )

    # A08: Software & Data Integrity Failures
    html_lower = (context.html or "").lower()
    source_code_hits = [marker for marker in SOURCE_LEAK_MARKERS if marker in html_lower]
    high_risk_markers = {"begin rsa private key", "aws_secret_access_key"}
    if any(marker in high_risk_markers for marker in source_code_hits):
        a08_status = STATUS_FAIL
        a08_summary = "Broncode of sleutels in HTML-body aangetroffen."
    elif source_code_hits:
        a08_status = STATUS_WARN
        a08_summary = "Inline codefragmenten gedetecteerd; controleer deployment-integriteit."
    else:
        a08_status = STATUS_PASS
        a08_summary = "Geen codefragmenten of secrets aangetroffen in HTML."
    add_category(
        "A08",
        "Software & Data Integrity Failures",
        a08_status,
        a08_summary,
        {"markers": source_code_hits},
    )

    # A09: Security Logging & Monitoring Failures
    stack_trace_hits = [marker for marker in STACK_TRACE_MARKERS if marker in html_lower]
    if stack_trace_hits:
        a09_status = STATUS_WARN
        a09_summary = "Response bevat stacktrace/debug-informatie."
    else:
        a09_status = STATUS_PASS
        a09_summary = "Geen debug stacktraces aangetroffen."
    add_category(
        "A09",
        "Security Logging & Monitoring Failures",
        a09_status,
        a09_summary,
        {"markers": stack_trace_hits},
    )

    # A10: SSRF & overige server-side issues
    ssrf_vectors: List[Dict[str, Any]] = []
    if context.soup:
        for anchor in context.soup.find_all("a", href=True):
            if len(ssrf_vectors) >= 5:
                break
            full_url = urljoin(context.response.url, anchor["href"])
            parsed = urlparse(full_url)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True):
                if key.lower() in SSRF_PARAM_HINTS:
                    ssrf_vectors.append(
                        {
                            "url": full_url,
                            "param": key,
                            "value_hint": value[:60],
                        }
                    )
                    break
        for form in context.soup.find_all("form"):
            if len(ssrf_vectors) >= 5:
                break
            for input_tag in form.find_all("input"):
                name = (input_tag.get("name") or "").lower()
                if name in SSRF_PARAM_HINTS:
                    ssrf_vectors.append(
                        {
                            "form_action": urljoin(context.response.url, form.get("action") or context.response.url),
                            "param": name,
                            "type": "form",
                        }
                    )
                    break
    if ssrf_vectors:
        a10_status = STATUS_WARN
        a10_summary = "Parameters aangetroffen die externe URL's accepteren; controleer SSRF-hardening."
    else:
        a10_status = STATUS_PASS
        a10_summary = "Geen directe SSRF-indicatoren op hoofdpagina."
    add_category(
        "A10",
        "SSRF & Server-side Issues",
        a10_status,
        a10_summary,
        {"vectors": ssrf_vectors},
    )

    status_rank = {
        STATUS_FAIL: 3,
        STATUS_WARN: 2,
        STATUS_INFO: 1,
        STATUS_PASS: 0,
    }
    overall_status = STATUS_PASS
    for cat in categories:
        if status_rank[cat["status"]] > status_rank[overall_status]:
            overall_status = cat["status"]
    fail_ids = [cat["id"] for cat in categories if cat["status"] == STATUS_FAIL]
    warn_ids = [cat["id"] for cat in categories if cat["status"] == STATUS_WARN]
    if fail_ids:
        summary = f"Problemen in {', '.join(fail_ids)} tijdens OWASP quickscan."
    elif warn_ids:
        summary = f"Waarschuwingen in {', '.join(warn_ids)} tijdens OWASP quickscan."
    else:
        summary = "OWASP quickscan vond geen kritieke afwijkingen."

    remediation = "Los de genoemde OWASP-categorieën op: versterk toegangscontrole, beveilig TLS en valideer invoer."
    impact = "Gebreken in deze top 10 verhogen de kans op privilege-escalatie, datalekken en misbruik van serverresources."

    details = {
        "owasp_top10": categories,
        "extra_requests": extra_requests,
        "login_probe_url": login_probe_url,
    }

    return _build_result(
        id="owasp_top10_quickscan",
        title="OWASP Top 10 quickscan",
        severity=SEVERITY_CRITICAL,
        status=overall_status,
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
    token_inputs: List[Dict[str, Any]] = []
    spa_indicators: List[str] = []
    spa_seen: Set[str] = set()

    for page in pages:
        html_lower = page.html.lower()
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
            else:
                token_inputs.append(
                    {
                        "page": page.url,
                        "form": idx,
                        "name": token.get("name"),
                    }
                )

            password_fields = form.find_all("input", {"type": "password"})
            for field in password_fields:
                autocomplete = (field.get("autocomplete") or "").lower()
                if autocomplete not in {"current-password", "new-password"}:
                    detailed_issues.append(
                        {
                            "page": page.url,
                            "form": idx,
                            "issue": "Password veld mist autocomplete=current-password/new-password.",
                        }
                    )

        text = page.soup.get_text(" ", strip=True).lower()
        if any(term in text for term in ("mfa", "twee-factor", "2fa")):
            mfa_mentioned = True

        if any(hint in html_lower for hint in ("authorization", "access_token", "id_token")):
            if page.url not in spa_seen:
                spa_seen.add(page.url)
                spa_indicators.append(page.url)
        elif re.search(r"/oauth|authorize|login\?.*client_id", page.html, re.I):
            if page.url not in spa_seen:
                spa_seen.add(page.url)
                spa_indicators.append(page.url)

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
            "token_inputs": token_inputs[:10],
            "spa_indicators": spa_indicators[:10],
            "auth_configuration": context.auth,
        },
    )


def _check_access_control(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    base_host = context.parsed_url.hostname
    tested: List[Dict[str, Any]] = []
    findings: List[str] = []
    tested_count = 0

    for page in pages:
        if tested_count >= IDOR_TEST_LIMIT:
            break
        parsed_page = urlparse(page.url)
        if not _hosts_match(base_host, parsed_page.hostname):
            continue
        baseline_status = page.status_code
        baseline_length = len(page.html or "")

        params = parse_qsl(parsed_page.query, keep_blank_values=False)
        for key, value in params:
            if tested_count >= IDOR_TEST_LIMIT:
                break
            if not value or len(value) < 2:
                continue
            if value.isdigit():
                mutated_value = str(int(value) + 1)
            else:
                match = re.search(r"\d+", value)
                if not match:
                    continue
                mutated_value = (
                    value[: match.start()]
                    + str(int(match.group()) + 1)
                    + value[match.end() :]
                )
            mutated_url = _replace_query_param(page.url, key, mutated_value)
            resp = _safe_request(mutated_url, timeout=6, allow_redirects=False)
            tested_count += 1
            entry: Dict[str, Any] = {
                "url": mutated_url,
                "parameter": key,
                "original": value,
                "modified": mutated_value,
                "status": resp.status_code if resp else None,
            }
            if resp is not None:
                body = resp.text or ""
                entry["length"] = len(body)
                if resp.status_code < 400 and (
                    resp.status_code != baseline_status
                    or abs(len(body) - baseline_length) > 200
                ):
                    entry["suspicious"] = True
                    findings.append(
                        f"{page.url} -> parameter '{key}' reageert afwijkend zonder foutmelding"
                    )
                if resp.status_code in {401, 403}:
                    entry["blocked"] = True
            tested.append(entry)

        segments = parsed_page.path.split("/")
        for idx, segment in enumerate(segments):
            if tested_count >= IDOR_TEST_LIMIT:
                break
            if not segment or not segment.isdigit() or len(segment) < 2:
                continue
            mutated_segments = list(segments)
            mutated_segments[idx] = str(int(segment) + 1)
            mutated_path = "/".join(mutated_segments)
            mutated_parsed = parsed_page._replace(path=mutated_path)
            mutated_url = urlunparse(mutated_parsed)
            resp = _safe_request(mutated_url, timeout=6, allow_redirects=False)
            tested_count += 1
            entry = {
                "url": mutated_url,
                "original_segment": segment,
                "modified_segment": mutated_segments[idx],
                "status": resp.status_code if resp else None,
            }
            if resp is not None:
                body = resp.text or ""
                entry["length"] = len(body)
                if resp.status_code < 400 and (
                    resp.status_code != baseline_status
                    or abs(len(body) - baseline_length) > 200
                ):
                    entry["suspicious"] = True
                    findings.append(
                        f"{page.url} -> padsegment '{segment}' lijkt manipuleerbaar"
                    )
                if resp.status_code in {401, 403}:
                    entry["blocked"] = True
            tested.append(entry)

    status = STATUS_WARN if findings else STATUS_PASS
    summary = (
        "Mogelijke IDOR/BAC zwaktes gevonden."
        if findings
        else "Geen duidelijke IDOR-patronen ontdekt in beperkte heuristiek."
    )
    remediation = (
        "Implementeer server-side autorisatiecontroles per object en gebruik onvoorspelbare referenties."
    )
    impact = (
        "Gebruikers zouden via IDOR andermans data kunnen lezen of wijzigen."
        if findings
        else "Autorisatiecontroles lijken parametrische manipulatie te blokkeren."
    )
    details = {"tested": tested, "findings": findings}
    return _build_result(
        id="access_control",
        title="Toegangscontrole & IDOR",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
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


def _check_supply_chain(context: ScanContext) -> CheckResult:
    parsed = context.parsed_url
    base = f"{parsed.scheme}://{parsed.netloc}"
    exposed: List[Dict[str, Any]] = []

    for path in SUPPLY_CHAIN_PATHS:
        url = urljoin(base, path)
        resp = _safe_request(url, timeout=6, allow_redirects=False)
        if resp is None or resp.status_code >= 400 or not resp.text:
            continue
        snippet = resp.text[:200]
        exposed.append(
            {
                "path": path,
                "status": resp.status_code,
                "snippet": snippet,
            }
        )
        if len(exposed) >= 10:
            break

    status = STATUS_FAIL if exposed else STATUS_PASS
    summary = (
        "Software supply chain artefacten publiek toegankelijk."
        if exposed
        else "Geen dependency manifests publiek gevonden."
    )
    remediation = "Voorkom dat package manifests/lockfiles via de webserver uitlekken en publiceer SBOMs gecontroleerd."
    impact = (
        "Lekkende lockfiles geven inzicht in kwetsbare bibliotheken en interne structuur, nuttig voor aanvallers."
        if exposed
        else "Afgeschermde dependency-informatie beperkt reconnaissance voor supply-chain aanvallen."
    )
    details = {"exposed": exposed} if exposed else {"checked_paths": SUPPLY_CHAIN_PATHS[:10]}
    return _build_result(
        id="supply_chain",
        title="Supply chain blootstelling",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
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


def _check_ssrf_parameters(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    findings: List[Dict[str, Any]] = []
    seen: Set[Tuple[str, str, str, str]] = set()

    def register(source: str, parameter: str, value: str, kind: str) -> None:
        sample = value[:120] if value else ""
        fingerprint = (source, parameter.lower(), sample, kind)
        if fingerprint in seen:
            return
        seen.add(fingerprint)
        entry: Dict[str, Any] = {
            "source": source,
            "parameter": parameter,
            "value_sample": sample,
            "kind": kind,
        }
        if value and (value.startswith(("http://", "https://")) or "://" in value):
            entry["external_candidate"] = True
        findings.append(entry)

    for page in pages:
        parsed_page = urlparse(page.url)
        for key, value in parse_qsl(parsed_page.query, keep_blank_values=False):
            lowered = key.lower()
            if lowered in SSRF_PARAMETER_NAMES:
                register(page.url, key, value, "page_url")

        for form in page.soup.find_all("form"):
            action = urljoin(page.url, form.get("action") or page.url)
            parsed_action = urlparse(action)
            for key, value in parse_qsl(parsed_action.query, keep_blank_values=False):
                lowered = key.lower()
                if lowered in SSRF_PARAMETER_NAMES:
                    register(action, key, value, "form_action")
            for field in form.find_all(["input", "select"]):
                name = (field.get("name") or "").strip()
                if not name:
                    continue
                lowered = name.lower()
                if lowered not in SSRF_PARAMETER_NAMES:
                    continue
                value = (field.get("value") or "").strip()
                if value:
                    register(page.url, name, value, "form_field")

    status = STATUS_PASS if not findings else STATUS_INFO
    summary = (
        "Geen duidelijke SSRF/open redirect parameters aangetroffen."
        if not findings
        else f"{len(findings)} potentiële SSRF/open redirect parameters gevonden."
    )
    remediation = (
        "Valideer en whitelist externe URL-parameters en splits redirect logica van server-side fetches."
    )
    impact = (
        "Ongecontroleerde URL-parameters kunnen leiden tot SSRF of open redirects naar malafide domeinen."
        if findings
        else "Beperkte URL-parameters verkleinen de kans op SSRF of open redirect misbruik."
    )

    return _build_result(
        id="ssrf_redirect_params",
        title="SSRF & open redirect parameters",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"findings": findings[:12]} if findings else None,
    )


def _check_insecure_design_hints(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    matches: List[Dict[str, Any]] = []

    for page in pages:
        text = page.html.lower()
        hits = sorted({hint for hint in INSECURE_DESIGN_HINTS if hint in text})
        if hits:
            matches.append({"page": page.url, "hints": hits})

    status = STATUS_PASS if not matches else STATUS_INFO
    summary = (
        "Geen debug/test aanwijzingen gevonden."
        if not matches
        else f"Debug/test aanwijzingen op {len(matches)} pagina('s)."
    )
    remediation = "Verwijder debug/test content uit productie en beperk toegang tot interne tooling."
    impact = (
        "Debug teksten kunnen gevoelige info prijsgeven of duiden op onvoldoende hardening."
        if matches
        else "Het ontbreken van debug hints verkleint de kans op informatielekken."
    )

    return _build_result(
        id="insecure_design_hints",
        title="Debug/test artefacten",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details={"matches": matches[:12]} if matches else None,
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


def _check_business_logic(context: ScanContext) -> CheckResult:
    pages = _iter_pages(context)
    keywords = {
        "korting",
        "discount",
        "coupon",
        "voucher",
        "promo",
        "tegoed",
        "credit",
        "loyalty",
        "punten",
        "cadeau",
        "gift",
        "refund",
        "betaal",
    }
    flow_indicators: List[Dict[str, Any]] = []
    risky_inputs: List[Dict[str, Any]] = []

    for page in pages:
        text = page.soup.get_text(" ", strip=True).lower()
        hits = sorted({word for word in keywords if word in text})
        if hits:
            flow_indicators.append({"page": page.url, "keywords": hits})

        for form in page.soup.find_all("form"):
            action = urljoin(page.url, form.get("action") or page.url)
            for field in form.find_all(["input", "select", "button"]):
                identifier = (field.get("name") or field.get("id") or "").lower()
                label = field.get("value") or field.get_text(" ", strip=True)
                label_lower = (label or "").lower()
                if not identifier and not label_lower:
                    continue
                haystack = f"{identifier} {label_lower}".strip()
                if any(term in haystack for term in ("coupon", "korting", "discount", "voucher", "gift", "admin", "role", "price", "amount")):
                    risky_inputs.append(
                        {
                            "page": page.url,
                            "action": action,
                            "field": identifier or label_lower[:40],
                        }
                    )

    status = STATUS_WARN if risky_inputs else (STATUS_INFO if flow_indicators else STATUS_PASS)
    if risky_inputs:
        summary = f"Business-logic inputs gevonden die misbruikbaar kunnen zijn ({len(risky_inputs)})."
    elif flow_indicators:
        summary = "Business-flow triggers gevonden; handmatige review aanbevolen."
    else:
        summary = "Geen duidelijke business-logic oppervlakken gevonden."

    remediation = (
        "Leg kritieke flows vast in testcases, valideer server-side en voorkom dubbele kortingen of privilege-escalatie."
    )
    impact = (
        "Onvoldoende checks op kortings- of rolvelden kunnen leiden tot financieel verlies of ongeautoriseerde toegang."
        if risky_inputs
        else "Gedocumenteerde business-logic controles verkleinen misbruik van speciale flows."
    )
    details = {
        "flow_indicators": flow_indicators[:15],
        "risky_inputs": risky_inputs[:15],
    }
    return _build_result(
        id="business_logic",
        title="Business-logic heuristiek",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        impact=impact,
        details=details,
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


@dataclass
class RegisteredCheck:
    name: str
    func: Callable[[ScanContext], CheckResult]
    source: str = "core"


class CheckRegistry:
    def __init__(self) -> None:
        self._categories: Dict[str, List[RegisteredCheck]] = {
            "critical": [],
            "important": [],
            "pentest": [],
            "nice_to_have": [],
        }
        self._lock = threading.RLock()

    def register(self, category: str, func: Callable[[ScanContext], CheckResult], *, source: str = "core") -> None:
        if category not in self._categories:
            raise ValueError(f"Onbekende check-categorie: {category}")
        entry = RegisteredCheck(name=getattr(func, "__name__", repr(func)), func=func, source=source)
        with self._lock:
            self._categories[category].append(entry)

    def register_many(
        self,
        category: str,
        funcs: Iterable[Callable[[ScanContext], CheckResult]],
        *,
        source: str = "core",
    ) -> None:
        for func in funcs:
            self.register(category, func, source=source)

    def iter_checks(
        self, category: str, *, disabled: Optional[Set[str]] = None
    ) -> Iterable[Callable[[ScanContext], CheckResult]]:
        disabled_lookup = {name.lower() for name in (disabled or set())}
        with self._lock:
            entries = list(self._categories.get(category, []))
        for entry in entries:
            if entry.name.lower() in disabled_lookup:
                continue
            yield entry.func

    def describe(self, *, disabled: Optional[Set[str]] = None) -> Dict[str, List[Dict[str, Any]]]:
        disabled_lookup = {name.lower() for name in (disabled or set())}
        snapshot: Dict[str, List[RegisteredCheck]]
        with self._lock:
            snapshot = {key: list(value) for key, value in self._categories.items()}
        description: Dict[str, List[Dict[str, Any]]] = {}
        for category, entries in snapshot.items():
            description[category] = [
                {
                    "name": entry.name,
                    "source": entry.source,
                    "enabled": entry.name.lower() not in disabled_lookup,
                }
                for entry in entries
            ]
        return description


CHECK_REGISTRY = CheckRegistry()


def register_check(category: str, func: Callable[[ScanContext], CheckResult], *, source: str = "plugin") -> None:
    CHECK_REGISTRY.register(category, func, source=source)


def _resolve_disabled_checks() -> Set[str]:
    raw = os.getenv("WEAKPOINT_DISABLE_CHECKS")
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def _load_check_plugins() -> None:
    plugin_spec = os.getenv("WEAKPOINT_PLUGINS")
    if not plugin_spec:
        return
    for module_name in plugin_spec.split(","):
        name = module_name.strip()
        if not name:
            continue
        try:
            importlib.import_module(name)
            logger.info("Pluginmodule geladen: %s", name)
        except Exception as exc:
            logger.error("Kon plugin %s niet laden: %s", name, exc)


_PLUGINS_INITIALIZED = False


def _ensure_plugins_loaded() -> None:
    global _PLUGINS_INITIALIZED
    if _PLUGINS_INITIALIZED:
        return
    _load_check_plugins()
    _PLUGINS_INITIALIZED = True


CHECK_REGISTRY.register_many(
    "critical",
    [
        _check_tls,
        _check_dns_surface,
        _check_security_headers,
        _check_csp_strength,
        _check_cache_control,
        _check_mixed_content,
        _check_redirects_and_canonical,
        _check_cors,
        _check_cookies,
        _check_forms,
    ],
)

CHECK_REGISTRY.register_many(
    "important",
    [
        _check_api_surface,
        _check_xss,
        _check_reflection_probes,
        _check_sql_errors,
        _check_auth_session,
        _check_access_control,
        _check_server_versions,
        _check_backup_files,
        _check_supply_chain,
        _check_ssrf_parameters,
        _check_directory_listing,
        _check_outdated_js_libraries,
        _check_file_uploads,
        _check_business_logic,
        _check_rate_limiting,
        _check_error_handling,
        _check_insecure_design_hints,
        _check_graphql_introspection,
        _check_http_methods,
        _check_security_txt,
        _check_sri,
    ],
)

CHECK_REGISTRY.register("pentest", _check_active_form_attacks)
CHECK_REGISTRY.register("pentest", _check_owasp_top10_quickscan)

CHECK_REGISTRY.register_many(
    "nice_to_have",
    [
        _check_performance,
        _check_accessibility,
        _check_seo,
        _check_mobile,
        _check_third_party,
        _check_privacy,
    ],
)


def run_scan(
    target_url: str,
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_pages_override: Optional[int] = None,
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

    max_pages, max_depth = _get_scan_limits(max_pages_override)
    sitemap_limit = _resolve_sitemap_limit(max_pages)
    sitemap_pages = _collect_sitemap_pages(
        base,
        parsed_response.hostname,
        robots_txt,
        url_limit=sitemap_limit,
    )
    sitemap_found = bool(sitemap_pages)
    seed_limit = _resolve_seed_limit(max_pages)

    initial_page = PageSnapshot(
        url=resp.url,
        status_code=resp.status_code,
        html=html,
        soup=soup,
        headers={k: v for k, v in resp.headers.items()},
    )
    seed_urls = _build_seed_urls(
        base,
        parsed_response.hostname,
        robots_txt,
        sitemap_pages,
        seed_limit=seed_limit,
    )
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
        auth=AUTH_CONTEXT,
    )

    _ensure_plugins_loaded()
    disabled_checks = _resolve_disabled_checks()
    active_checks = {
        "critical": list(CHECK_REGISTRY.iter_checks("critical", disabled=disabled_checks)),
        "important": list(CHECK_REGISTRY.iter_checks("important", disabled=disabled_checks)),
        "pentest": list(CHECK_REGISTRY.iter_checks("pentest", disabled=disabled_checks)),
        "nice_to_have": list(
            CHECK_REGISTRY.iter_checks("nice_to_have", disabled=disabled_checks)
        ),
    }

    critical_results = [check(context) for check in active_checks["critical"]]
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "security", "progress": 72},
    )
    important_results = [check(context) for check in active_checks["important"]]
    _notify_progress(
        progress_callback,
        {"type": "phase", "phase": "pentest", "progress": 80},
    )
    pentest_results = [check(context) for check in active_checks["pentest"]]
    nice_results = [check(context) for check in active_checks["nice_to_have"]]

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
             "crawl_budget_hit": len(crawled_pages) >= max_pages,
             "seed_limit": seed_limit,
             "sitemap_url_limit": sitemap_limit,
            "seed_urls": seed_urls[:10],
            "auth_mode": AUTH_CONTEXT,
            "checks": {
                "disabled": sorted(disabled_checks),
                "registered": CHECK_REGISTRY.describe(disabled=disabled_checks),
            },
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
    parser.add_argument(
        "--max-pages",
        type=int,
        default=None,
        help="Maximale aantal pagina's dat wordt gecrawld (standaard automatisch 50).",
    )
    args = parser.parse_args()
    report = run_scan(args.url, max_pages_override=args.max_pages)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2)
    print(f"Rapport opgeslagen in {args.output}")


if __name__ == "__main__":
    main()
