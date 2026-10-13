"""Malware feeds: external sources that describe malware samples.

Every feed turns its own API format into the same `MalwareRecord`, so the code
that writes to the graph database never needs to know where a record came from.
To add a source, subclass `MalwareFeed`, yield records, and register it below.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Iterator

PLATFORMS = ("windows", "linux", "macos", "android", "ios")


@dataclass
class MalwareRecord:
    source: str                                   # feed name, e.g. "virustotal"
    sample: str = ""                              # sha256 of the file; empty for catalogue feeds
    family: str | None = None                     # best family name, None if unknown
    labels: list = field(default_factory=list)    # other names the source gave
    types: list = field(default_factory=list)     # ransomware, trojan, rootkit ...
    platforms: list = field(default_factory=list)
    hashes: dict = field(default_factory=dict)    # {"md5": ..., "sha1": ..., "sha256": ...}
    ips: list = field(default_factory=list)
    cves: list = field(default_factory=list)
    actors: list = field(default_factory=list)    # [{"name": ..., "aliases": [...]}]
    techniques: list = field(default_factory=list)  # [{"id": "T1059", "name": ..., "tactics": [...]}]
    aliases: list = field(default_factory=list)   # other names of the family
    attack_id: str = ""                           # MITRE ATT&CK software id, e.g. S0013
    category: str = ""                            # "malware" or "tool"
    description: str = ""
    detections: int = 0                           # engines calling it malicious
    engines: int = 0
    first_seen: str = ""
    link: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class MalwareFeed(ABC):
    name = "feed"

    @abstractmethod
    def lookup(self, hashes, platform=None) -> Iterator:
        """Yield (hash, MalwareRecord or None) for known file hashes."""

    def search(self, platform=None, limit=50, **options) -> Iterator:
        """Yield MalwareRecord for recent malware on a platform, if the feed can search."""
        raise NotImplementedError(f"{self.name} cannot search; give it hashes instead")


def get_feed(name: str, **options) -> MalwareFeed:
    from .mitre import MitreFeed
    from .virustotal import VirusTotalFeed

    feeds = {"virustotal": VirusTotalFeed, "mitre": MitreFeed}
    if name not in feeds:
        raise SystemExit(f"Unknown feed '{name}'. Available: {', '.join(feeds)}")
    return feeds[name](**options)
