from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from html.parser import HTMLParser
import re
import ssl
from typing import Iterable
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, HTTPSHandler
from urllib.error import HTTPError, URLError

ALLOWED_HOST = "stopfraud.gov.ua"
DEFAULT_URLS = (
    "https://stopfraud.gov.ua/",
    "https://stopfraud.gov.ua/en",
    "https://stopfraud.gov.ua/privacy-policy",
)
MAX_BYTES = 2_000_000
TIMEOUT_SECONDS = 10
UA = "BRAMA-Assurance-Boundary/0.1 (+https://altru.dev/contact)"


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise HTTPError(req.full_url, code, "redirect denied by policy", headers, fp)


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.text_parts: list[str] = []
        self.hrefs: list[str] = []

    def handle_data(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.text_parts.append(text)

    def handle_starttag(self, tag: str, attrs) -> None:
        if tag.lower() != "a":
            return
        for key, value in attrs:
            if key.lower() == "href" and value:
                self.hrefs.append(value)

    @property
    def text(self) -> str:
        return "\n".join(self.text_parts)


@dataclass(frozen=True)
class PageEvidence:
    url: str
    observed_at: str
    sha256: str
    bytes: int
    latest_date: str | None
    ukrainian_specific_chars: int
    russian_locale_links: int


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: str
    url: str
    message: str
    evidence_sha256: str


def validate_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError("only HTTPS is allowed")
    if parsed.hostname != ALLOWED_HOST:
        raise ValueError("host is not allowlisted")
    if parsed.username or parsed.password or parsed.port:
        raise ValueError("credentials and custom ports are not allowed")


def fetch(url: str) -> bytes:
    validate_url(url)
    ctx = ssl.create_default_context()
    opener = build_opener(NoRedirect(), HTTPSHandler(context=ctx))
    req = Request(
        url,
        method="GET",
        headers={
            "User-Agent": UA,
            "Accept": "text/html,application/xhtml+xml",
            "Cache-Control": "no-cache",
        },
    )
    with opener.open(req, timeout=TIMEOUT_SECONDS) as response:
        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            raise ValueError("unexpected content type")
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("response exceeds byte limit")
    return data


def parse_page(url: str, body: bytes) -> tuple[PageEvidence, str, list[str]]:
    parser = PageParser()
    text = body.decode("utf-8", errors="replace")
    parser.feed(text)
    visible = parser.text
    dates = []
    for dd, mm, yyyy in re.findall(r"\b(\d{2})/(\d{2})/(20\d{2})\b", visible):
        try:
            dates.append(datetime(int(yyyy), int(mm), int(dd), tzinfo=timezone.utc))
        except ValueError:
            pass
    latest = max(dates).date().isoformat() if dates else None
    ukrainian_chars = len(re.findall(r"[іїєґІЇЄҐ]", visible))
    russian_locale_links = sum(
        1
        for href in parser.hrefs
        if re.search(r"(^|[/_-])ru(?:[-_/]|$)", href, flags=re.IGNORECASE)
        or re.search(r"lang(?:uage)?=ru(?:[-_][A-Z]{2})?", href, flags=re.IGNORECASE)
    )
    evidence = PageEvidence(
        url=url,
        observed_at=datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        sha256=sha256(body).hexdigest(),
        bytes=len(body),
        latest_date=latest,
        ukrainian_specific_chars=ukrainian_chars,
        russian_locale_links=russian_locale_links,
    )
    return evidence, visible, parser.hrefs


def analyze(pages: dict[str, bytes]) -> tuple[list[PageEvidence], list[Finding]]:
    evidences: list[PageEvidence] = []
    findings: list[Finding] = []
    parsed: dict[str, tuple[PageEvidence, str, list[str]]] = {}

    for url, body in pages.items():
        validate_url(url)
        evidence, visible, hrefs = parse_page(url, body)
        parsed[url] = (evidence, visible, hrefs)
        evidences.append(evidence)
        if evidence.russian_locale_links:
            findings.append(Finding(
                "UNEXPECTED_RUSSIAN_LOCALE",
                "high",
                url,
                "A Russian-language locale surface appears to be linked from the public portal.",
                evidence.sha256,
            ))

    home_url = "https://stopfraud.gov.ua/"
    en_url = "https://stopfraud.gov.ua/en"
    privacy_url = "https://stopfraud.gov.ua/privacy-policy"

    if home_url in parsed:
        evidence, visible, _ = parsed[home_url]
        if "Портал в режимі тестування та наповнення" in visible:
            findings.append(Finding(
                "PUBLIC_TESTING_MODE",
                "info",
                home_url,
                "The production public portal declares testing/filling mode.",
                evidence.sha256,
            ))

    if en_url in parsed:
        evidence, visible, _ = parsed[en_url]
        if "The portal is in testing and filling mode" in visible:
            findings.append(Finding(
                "PUBLIC_TESTING_MODE_EN",
                "info",
                en_url,
                "The English public portal declares testing/filling mode.",
                evidence.sha256,
            ))
        if evidence.ukrainian_specific_chars >= 3:
            findings.append(Finding(
                "EN_MIXED_LANGUAGE_SIGNAL",
                "medium",
                en_url,
                "The English route contains a material Ukrainian-language signal; review translation synchronization.",
                evidence.sha256,
            ))

    if home_url in parsed and en_url in parsed:
        ua_ev = parsed[home_url][0]
        en_ev = parsed[en_url][0]
        if ua_ev.latest_date and en_ev.latest_date:
            ua_date = datetime.fromisoformat(ua_ev.latest_date)
            en_date = datetime.fromisoformat(en_ev.latest_date)
            drift_days = (ua_date - en_date).days
            if drift_days > 180:
                findings.append(Finding(
                    "UA_EN_FRESHNESS_DRIFT",
                    "medium",
                    en_url,
                    f"English-route latest dated item trails Ukrainian route by {drift_days} days.",
                    en_ev.sha256,
                ))

    if privacy_url in parsed:
        evidence, visible, _ = parsed[privacy_url]
        if "https://stopfraud.com.ua" in visible:
            findings.append(Finding(
                "PRIVACY_CANONICAL_DOMAIN_DRIFT",
                "medium",
                privacy_url,
                "Privacy-policy text names the legacy .com.ua domain while served from the .gov.ua portal.",
                evidence.sha256,
            ))
        normalized = visible.casefold()
        if "мас адреса" in normalized or "mac address" in normalized:
            findings.append(Finding(
                "PRIVACY_MAC_COLLECTION_DECLARATION",
                "medium",
                privacy_url,
                "Privacy-policy text declares automatic MAC-address collection; implementation and wording should be verified.",
                evidence.sha256,
            ))

    return evidences, findings


def run_live(urls: Iterable[str] = DEFAULT_URLS) -> tuple[list[PageEvidence], list[Finding], list[dict]]:
    pages: dict[str, bytes] = {}
    errors: list[dict] = []
    for url in urls:
        try:
            pages[url] = fetch(url)
        except (ValueError, HTTPError, URLError, TimeoutError) as exc:
            errors.append({"url": url, "error": type(exc).__name__, "message": str(exc)[:300]})
    evidence, findings = analyze(pages)
    return evidence, findings, errors


def serialize(evidence: list[PageEvidence], findings: list[Finding], errors: list[dict]) -> dict:
    return {
        "project": "BRAMA Assurance Boundary",
        "version": "0.1.0",
        "evidence": [asdict(item) for item in evidence],
        "findings": [asdict(item) for item in findings],
        "errors": errors,
    }
