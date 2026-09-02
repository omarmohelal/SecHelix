"""Outbound request: the destination is entirely caller-controlled."""

import urllib.request


def fetch_avatar(profile_url):
    # Any URL the caller supplies is fetched from the server, including
    # loopback and link-local addresses that are only reachable from inside.
    with urllib.request.urlopen(profile_url, timeout=5) as response:
        return response.read()
