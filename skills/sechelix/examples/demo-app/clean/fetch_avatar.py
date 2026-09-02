"""Outbound request: only allowlisted hosts over https are reachable."""

import ipaddress
import socket
import urllib.parse
import urllib.request

ALLOWED_HOSTS = frozenset({"cdn.example.com", "avatars.example.com"})


def fetch_avatar(profile_url):
    parts = urllib.parse.urlsplit(profile_url)
    if parts.scheme != "https" or parts.hostname not in ALLOWED_HOSTS:
        raise ValueError("avatar host is not allowlisted")
    # Resolve and re-check: an allowlisted name that resolves to a private
    # address is still a request into the internal network.
    for info in socket.getaddrinfo(parts.hostname, 443):
        address = ipaddress.ip_address(info[4][0])
        if address.is_private or address.is_loopback or address.is_link_local:
            raise ValueError("avatar host resolves to a non-public address")
    with urllib.request.urlopen(profile_url, timeout=5) as response:
        return response.read()
