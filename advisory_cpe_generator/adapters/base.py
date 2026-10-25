# Copyright 2026 ellipse2v
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Adapter contract. Phase 1 (network): list a vendor's advisories and download
each one's files as published. Phase 2 (offline): parse a downloaded file into
Vulnerability objects.
"""

import logging
from dataclasses import dataclass, field

from ..http import HttpClient


@dataclass
class AdvisoryRef:
    id: str
    url: str = None
    updated: str = None            # ISO date when the source gives one (skip unchanged advisories)
    # Kept in the download manifest and given back to parse_file() (e.g. the
    # Stormshield product list, which is on the home page, not the advisory page).
    details: dict = field(default_factory=dict)


class Adapter:
    vendor = None        # slug used in file names
    vendor_name = None   # display name

    def __init__(self, conn_config, http=None):
        self.cfg = conn_config
        self.http = http or HttpClient(conn_config)
        self.log = logging.getLogger(f"advisory_cpe_generator.{self.vendor}")
        # {file name: bytes} of the list read by list_advisories(), saved with the downloads.
        self.listing = {}

    def list_advisories(self, since=None, history=False):
        """
        [AdvisoryRef], newest data the source offers; `since` is a datetime or None.
        history: also list what the usual list leaves out (Fortinet: the RSS feed
        has the latest advisories only, the PSIRT pages have them all).
        """
        raise NotImplementedError

    def download(self, ref):
        """{file name: bytes}: the advisory's source files, unchanged ({} if it has none)."""
        raise NotImplementedError

    def parse_file(self, path, details=None):
        """(advisory id, [Vulnerability], one per CVE) from a downloaded file."""
        raise NotImplementedError
