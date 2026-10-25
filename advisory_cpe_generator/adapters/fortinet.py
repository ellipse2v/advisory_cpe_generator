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
Fortinet: FortiGuard PSIRT RSS feed (latest advisories), then for each
advisory its CSAF document (<csaf:link>) or, when it has none, its CVRF 1.2
document (<cvrf:link>).

The feed lists only the most recent advisories (50 when this was written), so
a first run covers those; regular runs then keep up. --file reads CSAF (.json)
or CVRF (.xml) files already on disk.
"""

import json
import re
import xml.etree.ElementTree as ET
from email.utils import parsedate_to_datetime

from ..csaf_reader import parse_csaf
from ..cvrf_reader import parse_cvrf
from .base import Adapter, AdvisoryRef

_ID = re.compile(r"FG-IR-\d{2}-\d+", re.I)


class FortinetAdapter(Adapter):
    vendor = "fortinet"
    vendor_name = "Fortinet"

    def list_advisories(self, since=None):
        raw = self.http.get(self.cfg["rss_url"]).content
        self.listing = {"_list.xml": raw}
        root = ET.fromstring(raw)
        refs = []
        for item in root.iter("item"):
            links = {}
            for child in item:
                ns, _, local = child.tag.rpartition("}")
                key = "csaf" if "csaf" in ns else "cvrf" if "cvrf" in ns else local
                if child.text:
                    links[key] = child.text.strip()
            match = _ID.search(links.get("link", "") + " " + links.get("guid", "") + " " + links.get("title", ""))
            if not match:
                continue
            updated = None
            if links.get("pubDate"):
                try:
                    updated = parsedate_to_datetime(links["pubDate"]).date().isoformat()
                except (TypeError, ValueError):
                    pass
            if since and updated and updated < since.strftime("%Y-%m-%d"):
                continue
            url = links.get("csaf") or links.get("cvrf")
            if not url:
                self.log.warning("%s has neither CSAF nor CVRF link: skipped", match.group(0))
                continue
            refs.append(AdvisoryRef(id=match.group(0).upper(), url=url, updated=updated,
                                    details={"format": "csaf" if links.get("csaf") else "cvrf"}))
        self.log.info("%d advisories listed", len(refs))
        return refs

    def download(self, ref):
        extension = "json" if ref.details.get("format") == "csaf" else "xml"
        return {f"{ref.id}.{extension}": self.http.get(ref.url).content}

    def parse_file(self, path, details=None):
        with open(path, "rb") as fh:
            data = fh.read()
        if str(path).lower().endswith(".json"):
            return parse_csaf(json.loads(data), self.vendor, self.vendor_name)
        return parse_cvrf(data, self.vendor, self.vendor_name)
