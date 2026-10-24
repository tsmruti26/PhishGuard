import ipaddress
import socket
from urllib.parse import urlparse, urljoin

import requests

MAX_REDIRECTS = 5
TIMEOUT = 5
HEADERS = {"User-Agent": "PhishGuard/1.0"}


class UnsafeURL(Exception):
    pass


def validate_url(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeURL("Only http/https URLs with a host are allowed")
    try:
        infos = socket.getaddrinfo(p.hostname, None)
    except socket.gaierror:
        raise UnsafeURL("Host does not resolve")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            raise UnsafeURL(f"Blocked address: {ip}")


def expand_url(url: str) -> list:
    """Follow redirects manually, validating every hop. Returns the chain."""
    chain = [url]
    for _ in range(MAX_REDIRECTS):
        validate_url(url)
        r = requests.head(url, allow_redirects=False, timeout=TIMEOUT, headers=HEADERS)
        if r.status_code in (405, 501):  # some shorteners reject HEAD
            r = requests.get(url, allow_redirects=False, timeout=TIMEOUT,
                             headers=HEADERS, stream=True)
            r.close()
        if r.is_redirect and "Location" in r.headers:
            url = urljoin(url, r.headers["Location"])
            chain.append(url)
        else:
            break
    return chain
