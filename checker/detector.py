"""
detector.py — Classify an IOC string into its type.
Supports: ipv4, ipv6, domain, url, md5, sha1, sha256
"""

import re

_IPV4    = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_IPV6    = re.compile(r"^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$")
_DOMAIN  = re.compile(r"^(?!http)[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$")
_URL     = re.compile(r"^https?://", re.IGNORECASE)
_MD5     = re.compile(r"^[a-fA-F0-9]{32}$")
_SHA1    = re.compile(r"^[a-fA-F0-9]{40}$")
_SHA256  = re.compile(r"^[a-fA-F0-9]{64}$")


def detect(ioc: str) -> str:
    """
    Return a string label for the IOC type:
      'ipv4' | 'ipv6' | 'domain' | 'url' | 'md5' | 'sha1' | 'sha256' | 'unknown'
    """
    ioc = ioc.strip()

    if _URL.match(ioc):
        return "url"
    if _IPV4.match(ioc):
        return "ipv4"
    if _IPV6.match(ioc):
        return "ipv6"
    if _SHA256.match(ioc):
        return "sha256"
    if _SHA1.match(ioc):
        return "sha1"
    if _MD5.match(ioc):
        return "md5"
    if _DOMAIN.match(ioc):
        return "domain"

    return "unknown"


def is_ip(ioc_type: str) -> bool:
    return ioc_type in ("ipv4", "ipv6")


def is_hash(ioc_type: str) -> bool:
    return ioc_type in ("md5", "sha1", "sha256")