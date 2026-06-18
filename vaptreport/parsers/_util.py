"""Shared helpers for parsers (HTML stripping, URL/target extraction)."""

from __future__ import annotations

import html as _html
import re
from typing import List, Optional
from urllib.parse import urlparse

from ..models import Target

_TAG_RE = re.compile(r"<[^>]+>")
_URL_RE = re.compile(r"https?://[^\s\"'<>)]+")
_DEFAULT_PORTS = {"https": 443, "http": 80}


def strip_html(text: Optional[str]) -> str:
    """Convert an HTML fragment (as Burp/ZAP emit) to clean plain text."""
    if not text:
        return ""
    text = re.sub(r"<\s*br\s*/?>", "\n", text, flags=re.I)
    text = re.sub(r"</\s*(p|li|div|tr|h\d)\s*>", "\n", text, flags=re.I)
    text = re.sub(r"<\s*li\s*>", "- ", text, flags=re.I)
    text = _TAG_RE.sub("", text)
    text = _html.unescape(text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n[ \t]*\n+", "\n\n", text)
    return text.strip()


def extract_urls(text: Optional[str]) -> List[str]:
    """Return a de-duplicated, order-preserving list of URLs found in text."""
    seen, out = set(), []
    for u in _URL_RE.findall(text or ""):
        u = u.rstrip(".,);")
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out


def as_list(value) -> List[str]:
    """Coerce None / str / list into a list of stripped strings."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    return [str(v) for v in value if str(v).strip()]


def target_from_uri(
    uri: Optional[str],
    fallback_host: Optional[str] = None,
    fallback_port=None,
) -> Target:
    """Build a Target from a URL or ``host:port`` string."""
    uri = (uri or "").strip()
    if "://" in uri:
        u = urlparse(uri)
        host = u.hostname or fallback_host or uri
        port = u.port or _DEFAULT_PORTS.get(u.scheme)
        return Target(host=host, port=port, service=u.scheme or None)
    if uri and ":" in uri and not uri.startswith("/"):
        host, _, port = uri.partition(":")
        return Target(host=host or (fallback_host or "unknown"),
                      port=int(port) if port.isdigit() else None)
    host = uri or fallback_host or "unknown"
    fp = int(fallback_port) if str(fallback_port).isdigit() else None
    return Target(host=host, port=fp)
