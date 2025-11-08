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
import random
import re
import socket
import ssl
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urljoin, urlparse

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

SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT, "Accept": "*/*"})


@dataclass
class CheckResult:
    id: str
    title: str
    severity: str
    status: str
    summary: str
    remediation: str
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

    @property
    def parsed_url(self):
        return urlparse(self.response.url)


def _safe_request(
    url: str, method: str = "GET", timeout: int = DEFAULT_TIMEOUT, **kwargs
) -> Optional[requests.Response]:
    try:
        resp = SESSION.request(method, url, timeout=timeout, **kwargs)
        return resp
    except Exception:
        return None


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
    details: Optional[Dict[str, Any]] = None,
) -> CheckResult:
    return CheckResult(
        id=id,
        title=title,
        severity=severity,
        status=status,
        summary=summary,
        remediation=remediation,
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

    days_remaining = details.get("days_remaining")
    if isinstance(days_remaining, int) and days_remaining < 0:
        status = STATUS_FAIL
        summary = "Certificaat is verlopen."
        remediation = "Vernieuw het certificaat en controleer automatische vernieuwing."
    elif isinstance(days_remaining, int) and days_remaining < 30:
        status = STATUS_WARN
        summary = "Certificaat verloopt binnen 30 dagen."
        remediation = "Plan vernieuwing via ACME (Let's Encrypt) of eigen CA."
    if legacy:
        status = STATUS_WARN
        summary = (
            "Server accepteert legacy TLS-versies (" + ", ".join(legacy) + "); schakel ze uit."
        )
        remediation = "Sta alleen TLS1.2+ toe met ECDHE/ECDSA-ciphers."

    return _build_result(
        id="tls",
        title="HTTPS / TLS",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
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
            details=details,
        )
    return _build_result(
        id="security_headers",
        title="Security headers",
        severity=SEVERITY_CRITICAL,
        status=STATUS_PASS,
        summary="Essentiële beveiligingsheaders zijn aanwezig.",
        remediation="Controleer periodiek of policies up-to-date zijn.",
        details=details,
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
            details={"items": mixed[:25]},
        )
    return _build_result(
        id="mixed_content",
        title="Mixed content",
        severity=SEVERITY_CRITICAL,
        status=STATUS_PASS,
        summary="Geen mixed-content risico's gevonden.",
        remediation="Blijf CI/CD checks inzetten om HTTP-assets te blokkeren.",
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
    return _build_result(
        id="redirects",
        title="Redirects & canonical",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
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
        )
    return _build_result(
        id="cors",
        title="CORS configuratie",
        severity=SEVERITY_CRITICAL,
        status=STATUS_INFO,
        summary=f"CORS staat {acao} toe; controleer of dit gewenst is.",
        remediation="Synchroniseer Access-Control-Allow-Origin met toegestane clients.",
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
    return _build_result(
        id="cookies",
        title="Cookies & sessies",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"cookies_tested": len(cookies), "issues": issues},
    )


def _check_forms(context: ScanContext) -> CheckResult:
    forms = context.soup.find_all("form")
    insecure = []
    for idx, form in enumerate(forms, start=1):
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
                        "form": idx,
                        "input": field.get("name") or field.get("id"),
                        "reason": "Geen verplichting/patroon; validering ontbreekt mogelijk server-side.",
                    }
                )
        if method != "post" and any(inp.get("type") == "password" for inp in text_inputs):
            insecure.append(
                {"form": idx, "reason": "Wachtwoordformulier gebruikt GET i.p.v. POST."}
            )
    status = STATUS_PASS if not insecure else STATUS_WARN
    summary = (
        "Formulieren ogen gezond."
        if not insecure
        else f"{len(insecure)} formulieren vertonen ontbrekende validatie."
    )
    remediation = "Valideer server-side, markeer verplichte velden en gebruik POST voor gevoelige data."
    return _build_result(
        id="forms",
        title="Forms & input validatie",
        severity=SEVERITY_CRITICAL,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"issues": insecure[:10]},
    )


def _check_xss(context: ScanContext) -> CheckResult:
    html = context.html
    inline_handlers = re.findall(r"on\w+=", html, flags=re.IGNORECASE)
    reflections = []
    parsed = urlparse(context.response.url)
    for key, value in parse_qsl(parsed.query):
        if value and value in html:
            reflections.append({"param": key, "value": value})
    inline_scripts = [
        script
        for script in context.soup.find_all("script")
        if not script.get("src") and script.string and "innerHTML" in script.string
    ]
    suspicious = bool(inline_handlers or reflections or inline_scripts)
    status = STATUS_WARN if suspicious else STATUS_INFO
    summary = (
        "Inline event handlers of reflecties kunnen XSS mogelijk maken."
        if suspicious
        else "Geen directe aanwijzingen voor reflectieve XSS."
    )
    remediation = "Escape user input, gebruik CSP en vermijd inline event handlers."
    return _build_result(
        id="xss",
        title="XSS detectie (oppervlakkig)",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        details={
            "inline_event_handlers": len(inline_handlers),
            "reflections": reflections[:5],
            "inline_scripts": len(inline_scripts),
        },
    )


def _check_sql_errors(context: ScanContext) -> CheckResult:
    html = context.html.lower()
    patterns = [
        "sql syntax",
        "mysql_fetch",
        "sqlstate",
        "odbc",
        "ora-",
        "pg::",
        "fatal error",
    ]
    hits = [pattern for pattern in patterns if pattern in html]
    status = STATUS_FAIL if hits else STATUS_INFO
    summary = (
        "Database foutmeldingen zichtbaar voor bezoekers."
        if hits
        else "Geen DB foutmeldingen gevonden in response."
    )
    remediation = "Zet debug-modes uit en toon generieke fouten; gebruik parameterized queries."
    return _build_result(
        id="sql_injection",
        title="SQL/command injection (passief)",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"patterns_detected": hits},
    )


def _check_auth_session(context: ScanContext) -> CheckResult:
    soup = context.soup
    login_forms = [
        form
        for form in soup.find_all("form")
        if form.find("input", {"type": "password"})
    ]
    issues = []
    for idx, form in enumerate(login_forms, start=1):
        method = (form.get("method") or "get").lower()
        if method != "post":
            issues.append(f"Loginformulier #{idx} gebruikt {method.upper()} i.p.v. POST.")
        if not form.find("input", {"type": "hidden", "name": re.compile("csrf", re.I)}):
            issues.append(f"Loginformulier #{idx} lijkt geen CSRF-token te bevatten.")
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    rate_headers = [k for k in headers if "ratelimit" in k]
    if not rate_headers:
        issues.append("Geen rate-limit headers aangetroffen; beperk aanmeldpogingen.")
    text = soup.get_text(" ", strip=True).lower()
    if login_forms and not any(term in text for term in ("mfa", "twee-factor", "2fa")):
        issues.append("Geen mention van MFA/twee-factor authenticatie.")
    status = STATUS_WARN if issues else STATUS_PASS
    summary = (
        "; ".join(issues)
        if issues
        else "Login-flow gebruikt POST en lijkt CSRF/rate-limit te ondersteunen."
    )
    remediation = "Forceer POST, voeg CSRF-tokens toe, implementeer rate limiting en bied MFA aan."
    return _build_result(
        id="auth",
        title="Authenticatie & sessiebeheer",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation="Versterk login-, reset- en MFA-processen.",
        details={"login_forms": len(login_forms), "issues": issues},
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
    return _build_result(
        id="server_banner",
        title="Outdated software / server info",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
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
    return _build_result(
        id="backup_files",
        title="Backup/sensitive files",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"exposed": exposed},
    )


def _check_rate_limiting(context: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in context.response.headers.items()}
    rate_limit_headers = {
        key: value
        for key, value in headers.items()
        if "ratelimit" in key or "retry-after" in key
    }
    status = STATUS_INFO if rate_limit_headers else STATUS_WARN
    summary = (
        "Rate-limit headers aanwezig."
        if rate_limit_headers
        else "Geen rate-limit headers; implementeer throttling voor API/login."
    )
    remediation = "Expose X-RateLimit headers en voer server-side throttling in."
    return _build_result(
        id="rate_limiting",
        title="Rate limiting / DoS",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"headers": rate_limit_headers},
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
    return _build_result(
        id="error_handling",
        title="Error handling",
        severity=SEVERITY_IMPORTANT,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"sample": snippet},
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
    return _build_result(
        id="performance",
        title="Performance / Core Web Vitals (indicatief)",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
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
    return _build_result(
        id="accessibility",
        title="Toegankelijkheid (basis)",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
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
    else:
        status = STATUS_PASS
        summary = "Basis SEO metadata aanwezig."
    remediation = "Zorg voor unieke titles/descriptions en publiceer sitemap/robots."
    return _build_result(
        id="seo",
        title="SEO basics",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        details=details,
    )


def _check_mobile(context: ScanContext) -> CheckResult:
    viewport = context.soup.find("meta", attrs={"name": re.compile("viewport", re.I)})
    status = STATUS_PASS if viewport else STATUS_WARN
    summary = "Responsive viewport meta aanwezig." if viewport else "Geen meta viewport -> slechte mobile ervaring."
    remediation = "Gebruik <meta name='viewport' content='width=device-width, initial-scale=1'>."
    return _build_result(
        id="mobile",
        title="Mobile responsiveness",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
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
    return _build_result(
        id="third_party",
        title="Third-party scripts / privacy",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"third_party_hosts": unique_hosts},
    )


def _check_privacy(context: ScanContext) -> CheckResult:
    text = context.html.lower()
    keywords_found = [word for word in PRIVACY_KEYWORDS if word in text]
    status = STATUS_PASS if keywords_found else STATUS_WARN
    summary = (
        "Privacy/cookie informatie lijkt aanwezig."
        if keywords_found
        else "Geen verwijzing naar privacy/cookiebeleid gevonden."
    )
    remediation = "Link duidelijk naar privacy- en cookiebeleid en implementeer consentbanner."
    return _build_result(
        id="privacy",
        title="Privacy & compliance",
        severity=SEVERITY_NICE,
        status=status,
        summary=summary,
        remediation=remediation,
        details={"keywords_found": keywords_found},
    )


CRITICAL_CHECKS = [
    _check_tls,
    _check_security_headers,
    _check_mixed_content,
    _check_redirects_and_canonical,
    _check_cors,
    _check_cookies,
    _check_forms,
]

IMPORTANT_CHECKS = [
    _check_xss,
    _check_sql_errors,
    _check_auth_session,
    _check_server_versions,
    _check_backup_files,
    _check_rate_limiting,
    _check_error_handling,
]

NICE_CHECKS = [
    _check_performance,
    _check_accessibility,
    _check_seo,
    _check_mobile,
    _check_third_party,
    _check_privacy,
]


def run_scan(target_url: str) -> Dict[str, Any]:
    resp = _safe_request(target_url, allow_redirects=True)
    if resp is None:
        raise RuntimeError(f"Kan {target_url} niet bereiken.")

    html = resp.text or ""
    soup = BeautifulSoup(html, "html.parser")
    base = f"{urlparse(resp.url).scheme}://{urlparse(resp.url).netloc}"

    robots_resp = _safe_request(urljoin(base, "/robots.txt"), timeout=6)
    robots_txt = robots_resp.text if robots_resp and robots_resp.status_code == 200 else None
    sitemap_resp = _safe_request(urljoin(base, "/sitemap.xml"), method="HEAD", timeout=6)
    sitemap_found = bool(sitemap_resp and sitemap_resp.status_code < 400)

    context = ScanContext(
        target_url=target_url,
        response=resp,
        html=html,
        soup=soup,
        robots_txt=robots_txt,
        sitemap_found=sitemap_found,
    )

    critical_results = [check(context).to_dict() for check in CRITICAL_CHECKS]
    important_results = [check(context).to_dict() for check in IMPORTANT_CHECKS]
    nice_results = [check(context).to_dict() for check in NICE_CHECKS]

    return {
        "meta": {
            "target": target_url,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "history": [r.status_code for r in resp.history],
            "sitemap_found": sitemap_found,
            "robots_present": bool(robots_txt),
        },
        "critical": critical_results,
        "important": important_results,
        "nice_to_have": nice_results,
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
