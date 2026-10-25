"""Adapter contract: list a vendor's advisories, turn one into Vulnerability objects."""

import logging
from dataclasses import dataclass, field

from ..http import HttpClient


@dataclass
class AdvisoryRef:
    id: str
    url: str = None
    updated: str = None            # ISO date when the source gives one (skip unchanged advisories)
    extra: dict = field(default_factory=dict)


class Adapter:
    vendor = None        # slug used in file names
    vendor_name = None   # display name

    def __init__(self, conn_config, http=None):
        self.cfg = conn_config
        self.http = http or HttpClient(conn_config)
        self.log = logging.getLogger(f"advisory_cpe_generator.{self.vendor}")

    def list_advisories(self, since=None):
        """[AdvisoryRef], newest data the source offers; `since` is a datetime or None."""
        raise NotImplementedError

    def fetch(self, ref):
        """[Vulnerability] for one advisory (one per CVE)."""
        raise NotImplementedError

    def parse_file(self, path):
        """(advisory id, [Vulnerability]) from a local file, for offline runs."""
        raise NotImplementedError
