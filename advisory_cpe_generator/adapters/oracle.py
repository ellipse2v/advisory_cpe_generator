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
Oracle: Critical Patch Update advisories, which Oracle publishes as CSAF 2.0
(one document per quarter, all CVEs of that quarter, CPEs included).

The list comes from the Security Alerts page (links to cpu<mon><year>.html);
each CPU page links its CSAF file ("CSAF JSON version of the risk matrices").
Out-of-band Security Alerts and the Linux/Solaris bulletins have no CSAF and
are not covered. A CPU document is fetched once; use --full to fetch revised
documents again.
"""

import json
import re
from datetime import datetime
from urllib.parse import urljoin

from ..csaf_reader import parse_csaf
from .base import Adapter, AdvisoryRef

_CPU = re.compile(r'href="([^"]*/(cpu([a-z]{3})(\d{4}))\.html)"', re.I)
_CSAF = re.compile(r'href="([^"]+csaf\.json)"', re.I)
_MONTHS = {m: i for i, m in enumerate(("jan", "feb", "mar", "apr", "may", "jun",
                                        "jul", "aug", "sep", "oct", "nov", "dec"), 1)}


class OracleAdapter(Adapter):
    vendor = "oracle"
    vendor_name = "Oracle"

    def list_advisories(self, since=None):
        page = self.cfg["alerts_url"]
        html = self.http.get(page).text
        self.listing = {"_list.html": html.encode("utf-8")}
        refs, seen = [], set()
        for url, name, month, year in _CPU.findall(html):
            name = name.lower()
            if name in seen:
                continue
            seen.add(name)
            published = datetime(int(year), _MONTHS.get(month.lower(), 1), 1)
            if since and published < since.replace(day=1, hour=0, minute=0, second=0, microsecond=0):
                continue
            refs.append(AdvisoryRef(id=name, url=urljoin(page, url)))
        self.log.info("%d CPU advisories listed", len(refs))
        return sorted(refs, key=lambda r: r.id)

    def download(self, ref):
        match = _CSAF.search(self.http.get(ref.url).text)
        if not match:
            self.log.info("%s has no CSAF document: skipped", ref.id)
            return {}
        url = urljoin(ref.url, match.group(1))
        ref.details["csaf_url"] = url
        return {f"{ref.id}.json": self.http.get(url).content}

    def parse_file(self, path, details=None):
        with open(path, encoding="utf-8") as fh:
            return parse_csaf(json.load(fh), self.vendor, self.vendor_name)
