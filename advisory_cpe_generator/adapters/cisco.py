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
Cisco: openVuln API (https://developer.cisco.com/docs/psirt/), then the CSAF
document of each advisory.

Credentials come from the environment variables named in config.json
(CISCO_CLIENT_ID / CISCO_CLIENT_SECRET by default), never from a file in the
repository. Advisories listed by the API are expected to carry a "csafUrl";
an advisory without one is skipped with a warning.

Only the listing needs credentials: the CSAF documents are public, and
parse_file() reads them from disk (including files downloaded with
cisco_csaf_dowloader, given with --file).
"""

import json
import os
from datetime import datetime

from ..csaf_reader import parse_csaf
from .base import Adapter, AdvisoryRef


class CiscoAdapter(Adapter):
    vendor = "cisco"
    vendor_name = "Cisco"

    def __init__(self, conn_config, http=None):
        super().__init__(conn_config, http)
        self._token = None

    def _authenticate(self):
        client_id = os.environ.get(self.cfg.get("client_id_env", "CISCO_CLIENT_ID"))
        secret = os.environ.get(self.cfg.get("client_secret_env", "CISCO_CLIENT_SECRET"))
        if not client_id or not secret:
            raise RuntimeError(f"Cisco credentials missing: set {self.cfg.get('client_id_env')} "
                               f"and {self.cfg.get('client_secret_env')}")
        response = self.http.session.post(
            self.cfg["token_url"], timeout=self.http.timeout,
            data={"client_id": client_id, "client_secret": secret, "grant_type": "client_credentials"})
        response.raise_for_status()
        self._token = response.json()["access_token"]

    def _api(self, url):
        if not self._token:
            self._authenticate()
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self._token}"}
        try:
            return self.http.get_json(url, headers=headers)
        except Exception as e:
            if getattr(getattr(e, "response", None), "status_code", None) in (401, 403):
                self._authenticate()   # token expired: one retry
                headers["Authorization"] = f"Bearer {self._token}"
                return self.http.get_json(url, headers=headers)
            raise

    def list_advisories(self, since=None):
        base = self.cfg["api_url"].rstrip("/")
        if since:
            url = (f"{base}/all/lastpublished?startDate={since:%Y-%m-%d}"
                   f"&endDate={datetime.now():%Y-%m-%d}")
        else:
            url = f"{base}/all"
        data = self._api(url)
        self.listing = {"_list.json": json.dumps(data, indent=1).encode("utf-8")}
        items = data.get("advisories", []) if isinstance(data, dict) else data
        refs = []
        for item in items:
            if not item.get("advisoryId"):
                continue
            if not item.get("csafUrl"):
                self.log.warning("%s has no csafUrl: skipped", item["advisoryId"])
                continue
            refs.append(AdvisoryRef(id=item["advisoryId"], url=item["csafUrl"],
                                    updated=item.get("lastUpdated")))
        self.log.info("%d advisories listed", len(refs))
        return refs

    def download(self, ref):
        return {f"{ref.id}.json": self.http.get(ref.url).content}

    def parse_file(self, path, details=None):
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        if "document" not in doc:
            # An openVuln advisory saved by cisco_csaf_dowloader, not a CSAF document.
            self.log.warning("%s is not a CSAF document: skipped", path)
            return None, []
        return parse_csaf(doc, self.vendor, self.vendor_name)
