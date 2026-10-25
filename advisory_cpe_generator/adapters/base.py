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
