"""Domain-specific web security crawler following strict discovery rules.

This module implements a crawler and lightweight vulnerability scanner that
follows the behavioural requirements described in the user instructions.  It
only visits URLs that were discovered through in-page references, robots.txt or
sitemap.xml entries provided by the target host.  No heuristic guessing of paths
is performed.

The crawler collects per-page metadata (status code, response time, parent
relations, discovered links) and performs a couple of non-intrusive security
checks that surface common misconfigurations.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Deque, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import requests
from bs4 import BeautifulSoup
from requests import Response
from xml.etree import ElementTree

MAX_VISITS = 500
REQUEST_TIMEOUT = 10
RETRY_LIMIT = 2
REDIRECT_STATUSES = {301, 302, 303, 307, 308}
USER_AGENT = "WeakPoint-StrictCrawler/1.0"

DIRECTORY_LISTING_MARKERS = (
    "Index of /",
    "Directory listing",
    "Parent Directory",
)
SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
)
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


@dataclass
class PageRecord:
    url: str
    parent_urls: List[str]
    status: Optional[int]
    content_type: Optional[str]
    response_time: Optional[float]
    title: Optional[str]
    found_links: List[str]
    issues: List[str] = field(default_factory=list)


@dataclass
class Finding:
    key: str
    title: str
    severity: str
    cvss_estimate: float
    recommendation: str
    urls: List[str] = field(default_factory=list)
    evidence: Dict[str, str] = field(default_factory=dict)
    id: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        if self.id is None:
            raise ValueError("Finding id not assigned")
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "cvss_estimate": self.cvss_estimate,
            "urls": self.urls,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


class Crawler:
    def __init__(self, start_url: str, max_pages: int = MAX_VISITS) -> None:
        self.start_url = self._normalise_url(start_url)
        self.origin = self._extract_origin(self.start_url)
        self.max_visits = max_pages

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": USER_AGENT})

        self.queue: Deque[str] = deque([self.start_url])
        self.queued: Set[str] = {self.start_url}
        self.parents: Dict[str, Set[str]] = defaultdict(set)
        self.pages: List[PageRecord] = []
        self.errors: List[Dict[str, str]] = []

        self.findings: Dict[str, Finding] = {}
        self.issue_counter = 1

        self.security_headers_checked = False

        robots_url = self._normalise_url(urljoin(self.start_url, "/robots.txt"))
        if robots_url != self.start_url:
            self._enqueue(robots_url, None)

    @staticmethod
    def _extract_origin(url: str) -> Tuple[str, str]:
        parsed = urlparse(url)
        return parsed.scheme, parsed.netloc

    @staticmethod
    def _normalise_url(url: str) -> str:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path or "/"
        if path != "/":
            path = path.rstrip("/") or "/"
        query = parsed.query
        return urlunsplit((scheme, netloc, path, query, ""))

    def _same_origin(self, url: str) -> bool:
        scheme, netloc = self._extract_origin(url)
        return (scheme, netloc) == self.origin

    def _enqueue(self, url: str, parent: Optional[str]) -> None:
        normalised = self._normalise_url(url)
        if not self._same_origin(normalised):
            return
        if normalised in self.queued:
            if parent:
                self.parents[normalised].add(parent)
            return
        self.queue.append(normalised)
        self.queued.add(normalised)
        if parent:
            self.parents[normalised].add(parent)

    def _request_with_retries(self, url: str) -> Optional[Response]:
        for attempt in range(1, RETRY_LIMIT + 2):
            try:
                return self.session.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=False)
            except requests.RequestException as exc:
                if attempt > RETRY_LIMIT:
                    self.errors.append({"url": url, "error": "request_exception", "details": str(exc)})
                    return None
        return None

    def _register_page(
        self,
        url: str,
        response: Optional[Response],
        response_time: Optional[float],
        found_links: Iterable[str],
        title: Optional[str],
    ) -> PageRecord:
        parents = sorted(parent for parent in self.parents.get(url, set()) if parent)
        content_type = response.headers.get("Content-Type") if response is not None else None
        if content_type:
            content_type = content_type.split(";")[0].strip()
        page = PageRecord(
            url=url,
            parent_urls=parents,
            status=response.status_code if response is not None else None,
            content_type=content_type,
            response_time=response_time,
            title=title,
            found_links=sorted(dict.fromkeys(found_links)),
        )
        self.pages.append(page)
        return page

    def _assign_finding_id(self, finding: Finding) -> None:
        if finding.id is None:
            finding.id = f"F-{self.issue_counter:03d}"
            self.issue_counter += 1

    def _record_finding(self, finding: Finding, page: PageRecord) -> None:
        self._assign_finding_id(finding)
        if page.url not in finding.urls:
            finding.urls.append(page.url)
        if finding.id not in page.issues:
            page.issues.append(finding.id)

    def _add_or_get_finding(self, finding: Finding, page: PageRecord) -> Finding:
        existing = self.findings.get(finding.key)
        if existing is None:
            self.findings[finding.key] = finding
            existing = finding
        self._record_finding(existing, page)
        return existing

    def _check_security_headers(self, response: Response, page: PageRecord) -> None:
        if self.security_headers_checked:
            return
        missing = [header for header in SECURITY_HEADERS if header not in response.headers]
        if missing:
            finding = Finding(
                key="missing_security_headers",
                title="Belangrijke security headers ontbreken",
                severity="Medium",
                cvss_estimate=5.3,
                evidence={"missing": ", ".join(missing)},
                recommendation=(
                    "Stel HTTP security headers in zoals HSTS, Content-Security-Policy, "
                    "X-Frame-Options en Referrer-Policy om clickjacking en downgrade-aanvallen te beperken."
                ),
            )
            self._add_or_get_finding(finding, page)
        self.security_headers_checked = True

    @staticmethod
    def _html_title(soup: BeautifulSoup) -> Optional[str]:
        if soup.title and soup.title.string:
            return soup.title.string.strip()
        return None

    def _detect_directory_listing(self, response_text: str, page: PageRecord) -> None:
        for marker in DIRECTORY_LISTING_MARKERS:
            if marker.lower() in response_text.lower():
                finding = Finding(
                    key=f"directory_listing::{page.url}",
                    title="Directory listing openbaar toegankelijk",
                    severity="High",
                    cvss_estimate=7.5,
                    evidence={
                        "snippet": marker,
                    },
                    recommendation="Schakel directory listing uit op de webserver of voeg een indexpagina toe.",
                )
                self._add_or_get_finding(finding, page)
                break

    def _detect_information_headers(self, response: Response, page: PageRecord) -> None:
        server_header = response.headers.get("Server")
        powered_by = response.headers.get("X-Powered-By")
        if server_header:
            finding = Finding(
                key="server_header_exposed",
                title="Server header onthult softwareversie",
                severity="Low",
                cvss_estimate=3.7,
                evidence={"server": server_header},
                recommendation="Verberg of anonimiseer de Server-header om fingerprinting te beperken.",
            )
            self._add_or_get_finding(finding, page)
        if powered_by:
            finding = Finding(
                key="x_powered_by_exposed",
                title="X-Powered-By header onthult framework",
                severity="Low",
                cvss_estimate=3.5,
                evidence={"x_powered_by": powered_by},
                recommendation="Verwijder de X-Powered-By header om informatielekken te verminderen.",
            )
            self._add_or_get_finding(finding, page)

    def _parse_html_links(self, base_url: str, response_text: str, page: PageRecord) -> List[str]:
        soup = BeautifulSoup(response_text, "html.parser")
        title = self._html_title(soup)
        discovered: Set[str] = set()

        def handle_link(raw_url: Optional[str], tag_name: str) -> None:
            if not raw_url:
                return
            raw_url = raw_url.strip()
            if not raw_url or raw_url.startswith("javascript:"):
                return
            absolute = urljoin(base_url, raw_url)
            normalised = self._normalise_url(absolute)
            if not self._same_origin(normalised):
                return
            discovered.add(normalised)
            self._enqueue(normalised, page.url)

        for tag in soup.find_all("a"):
            handle_link(tag.get("href"), "a")
        for tag in soup.find_all("link"):
            handle_link(tag.get("href"), "link")
        for tag in soup.find_all("area"):
            handle_link(tag.get("href"), "area")
        for form in soup.find_all("form"):
            action = form.get("action") or base_url
            handle_link(action, "form")

        page.title = title
        return list(discovered)

    def _discover_from_robots(self, response: Response, page: PageRecord) -> None:
        sitemap_urls: List[str] = []
        text = response.text
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.lower().startswith("sitemap:"):
                sitemap_url = line.split(":", 1)[1].strip()
                absolute = urljoin(page.url, sitemap_url)
                sitemap_urls.append(absolute)
        if sitemap_urls:
            evidence = ", ".join(sorted(set(sitemap_urls)))
            finding = Finding(
                key="sitemaps_discovered",
                title="Sitemap vermeld in robots.txt",
                severity="Low",
                cvss_estimate=0.0,
                evidence={"sitemaps": evidence},
                recommendation="Controleer dat de sitemap geen interne of niet-openbare URL's bevat.",
            )
            self._add_or_get_finding(finding, page)
        for sitemap in sitemap_urls:
            self._enqueue(sitemap, page.url)
        if sitemap_urls:
            page.found_links = sorted(dict.fromkeys(page.found_links + sitemap_urls))

    def _parse_sitemap(self, response: Response, page: PageRecord) -> List[str]:
        urls: List[str] = []
        try:
            tree = ElementTree.fromstring(response.content)
        except ElementTree.ParseError as exc:
            self.errors.append({"url": page.url, "error": "parse_error", "details": str(exc)})
            return urls
        namespace = ""
        if tree.tag.startswith("{"):
            namespace = tree.tag.split("}", 1)[0] + "}"
        if tree.tag.endswith("sitemapindex"):
            for child in tree.findall(f"{namespace}sitemap/{namespace}loc"):
                url = child.text.strip() if child.text else None
                if not url:
                    continue
                self._enqueue(url, page.url)
                urls.append(url)
        else:
            for child in tree.findall(f"{namespace}url/{namespace}loc"):
                url = child.text.strip() if child.text else None
                if not url:
                    continue
                self._enqueue(url, page.url)
                urls.append(url)
        return urls

    def run(self) -> Dict[str, object]:
        visits = 0
        while self.queue and visits < self.max_visits:
            current_url = self.queue.popleft()
            if visits >= self.max_visits:
                break
            visits += 1

            start_time = time.monotonic()
            response = self._request_with_retries(current_url)
            duration = time.monotonic() - start_time if response is not None else None

            found_links: List[str] = []
            title: Optional[str] = None

            if response is None:
                page = self._register_page(current_url, response, duration, found_links, title)
                continue

            status = response.status_code

            if status in REDIRECT_STATUSES:
                location = response.headers.get("Location")
                if location:
                    absolute = urljoin(current_url, location)
                    normalised = self._normalise_url(absolute)
                    if self._same_origin(normalised):
                        self._enqueue(normalised, current_url)
                    else:
                        self.errors.append(
                            {
                                "url": current_url,
                                "error": "external_redirect",
                                "details": absolute,
                            }
                        )
                    found_links.append(normalised if self._same_origin(normalised) else absolute)
                page = self._register_page(current_url, response, duration, found_links, title)
                continue

            content_type = response.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if content_type == "text/html" and response.text:
                found_links = self._parse_html_links(current_url, response.text, page := PageRecord(
                    url=current_url,
                    parent_urls=sorted(parent for parent in self.parents.get(current_url, set()) if parent),
                    status=status,
                    content_type="text/html",
                    response_time=duration,
                    title=None,
                    found_links=[],
                ))
                self.pages.append(page)
                self._check_security_headers(response, page)
                self._detect_directory_listing(response.text, page)
                self._detect_information_headers(response, page)
                if current_url.endswith("robots.txt"):
                    self._discover_from_robots(response, page)
                elif current_url.lower().endswith(".xml") and "sitemap" in current_url.lower():
                    sitemap_links = self._parse_sitemap(response, page)
                    found_links.extend(sitemap_links)
                    page.found_links = sorted(dict.fromkeys(found_links))
                else:
                    page.found_links = sorted(dict.fromkeys(found_links))
                if page.title is None:
                    page.title = self._html_title(BeautifulSoup(response.text, "html.parser"))
                continue

            page = self._register_page(current_url, response, duration, found_links, title)
            textual_content = content_type.startswith("text") or "xml" in content_type
            if textual_content:
                text = response.text[:2048]
                if current_url.endswith("robots.txt"):
                    self._discover_from_robots(response, page)
                elif current_url.lower().endswith(".xml") and "sitemap" in current_url.lower():
                    sitemap_links = self._parse_sitemap(response, page)
                    page.found_links = sorted(dict.fromkeys(page.found_links + sitemap_links))
                if any(marker.lower() in text.lower() for marker in DIRECTORY_LISTING_MARKERS):
                    self._detect_directory_listing(text, page)
            self._detect_information_headers(response, page)

        status = "COMPLETED" if not self.queue else "PARTIAL"
        return {
            "status": status,
            "pages": self.pages,
            "errors": self.errors,
            "findings": sorted(
                (finding for finding in self.findings.values()),
                key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.id or ""),
            ),
        }


def build_report(start_url: str, max_pages: int = MAX_VISITS) -> Tuple[Dict[str, object], Dict[str, object]]:
    crawler = Crawler(start_url, max_pages=max_pages)
    start_time = datetime.now(timezone.utc)
    result = crawler.run()
    end_time = datetime.now(timezone.utc)

    pages_payload = [
        {
            "url": page.url,
            "parent_urls": page.parent_urls,
            "status": page.status,
            "content_type": page.content_type,
            "response_time": page.response_time,
            "title": page.title,
            "found_links": page.found_links,
            "issues": page.issues,
        }
        for page in crawler.pages
    ]

    findings_payload = [finding.to_dict() for finding in result["findings"]]

    scan_status = "COMPLETED" if result["status"] == "COMPLETED" else "PARTIAL"

    report = {
        "scan_meta": {
            "start_time": start_time.isoformat(),
            "end_time": end_time.isoformat(),
            "start_url": crawler.start_url,
            "status": scan_status,
            "pages_visited": len(crawler.pages),
            "errors": crawler.errors,
        },
        "top_findings": findings_payload[:10],
        "pages": pages_payload,
    }

    summary_lines = [
        f"Scanstatus: {scan_status}",
        f"Start-URL: {crawler.start_url}",
        f"Scan start: {start_time.isoformat()}",
        f"Scan einde: {end_time.isoformat()}",
        f"Bezochte pagina's: {len(crawler.pages)} / {max_pages}",
        "Top 10 bevindingen:",
    ]

    if not findings_payload:
        summary_lines.append("  Geen bevindingen gevonden.")
    else:
        for idx, finding in enumerate(findings_payload[:10], start=1):
            evidence = finding.get("evidence", {})
            evidence_summary = ", ".join(f"{k}: {v}" for k, v in evidence.items())
            urls = finding.get("urls", [])
            url_display = urls[0] if urls else crawler.start_url
            summary_lines.append(
                f"  {idx}. {finding['title']} (Severity: {finding['severity']}) — {evidence_summary or 'geen bewijs'} — {url_display}"
            )

    summary = "\n".join(summary_lines)
    return report, {"summary": summary}


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Voer een strikte domeinscan uit.")
    parser.add_argument("start_url", help="De start-URL voor de scan")
    parser.add_argument("--max-pages", type=int, default=MAX_VISITS, help="Maximaal aantal unieke URLs om te bezoeken")
    parser.add_argument(
        "--output",
        type=str,
        help="Pad naar bestand om JSON-rapport naar weg te schrijven",
    )
    args = parser.parse_args(argv)

    report, summary = build_report(args.start_url, max_pages=min(args.max_pages, MAX_VISITS))

    print(summary["summary"])
    print()
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False)

    return 0


if __name__ == "__main__":
    sys.exit(main())
