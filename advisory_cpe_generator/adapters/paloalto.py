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
Palo Alto Networks: https://security.paloaltonetworks.com/api

GET /json lists the advisories, GET /json/{ID} returns one. Palo Alto is the
CNA of its CVEs and publishes them as CVE JSON 5 records (the same records as
in CVEProject/cvelistV5); this adapter reads that format, including the
"cpes" list of affected products when the record has one.

Not verified from this project's environment: the exact shape of the /json
list (the parser accepts the usual id/updated field names) and whether
PAN-SA-* bulletins (third-party components) also come as CVE records; those
that do not are skipped with a warning.
"""

import json

from .. import cpe as cpe_lib
from ..model import (FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED, UNDER_INVESTIGATION, Note,
                     Product, Reference, Remediation, Score, Vulnerability)
from ..versions import VersionRange
from .base import Adapter, AdvisoryRef

_STATUS = {"affected": KNOWN_AFFECTED, "unaffected": KNOWN_NOT_AFFECTED, "unknown": UNDER_INVESTIGATION}
_CVSS = (("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"), ("cvssV2_0", "2.0"))


def _first(d, *paths):
    for path in paths:
        cur = d
        for key in path.split("."):
            cur = cur.get(key) if isinstance(cur, dict) else None
        if cur:
            return cur
    return None


def _english(items):
    for item in items or []:
        if item.get("lang", "en").lower().startswith("en"):
            return item.get("value")
    return (items or [{}])[0].get("value")


class PaloAltoAdapter(Adapter):
    vendor = "paloalto"
    vendor_name = "Palo Alto Networks"

    def list_advisories(self, since=None):
        data = self.http.get_json(self.cfg["list_url"])
        items = data if isinstance(data, list) else data.get("advisories") or data.get("data") or []
        refs = []
        for item in items:
            if isinstance(item, str):
                refs.append(AdvisoryRef(id=item))
                continue
            adv_id = _first(item, "ID", "id", "cveId", "cveMetadata.cveId")
            if not adv_id:
                continue
            updated = _first(item, "updated", "dateUpdated", "cveMetadata.dateUpdated", "date")
            if since and updated and updated[:10] < since.strftime("%Y-%m-%d"):
                continue
            extra = {"record": item} if "containers" in item else {}
            refs.append(AdvisoryRef(id=adv_id, updated=updated, extra=extra))
        self.log.info("%d advisories listed", len(refs))
        return refs

    def fetch(self, ref):
        record = ref.extra.get("record") or self.http.get_json(self.cfg["detail_url"].format(id=ref.id))
        return self.parse_record(record, ref.id)

    def parse_file(self, path):
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
        adv_id = _first(record, "cveMetadata.cveId") or str(path)
        return adv_id, self.parse_record(record, adv_id)

    def parse_record(self, record, advisory_id):
        cna = _first(record, "containers.cna")
        cve = _first(record, "cveMetadata.cveId")
        if not cna or not cve:
            self.log.warning("%s is not a CVE JSON 5 record: skipped", advisory_id)
            return []

        vuln = Vulnerability(vendor=self.vendor, vendor_name=self.vendor_name, cve=cve.upper(),
                             title=cna.get("title"), advisory_ids=[advisory_id],
                             release_date=cna.get("datePublic") or _first(record, "cveMetadata.datePublished"))
        description = _english(cna.get("descriptions"))
        if description:
            vuln.notes.append(Note("description", description, "Description"))
        for title, key, category in (("Required configuration for exposure", "configurations", "details"),
                                     ("Exploitation status", "exploits", "other")):
            text = _english(cna.get(key))
            if text:
                vuln.notes.append(Note(category, text, title))

        for pt in cna.get("problemTypes", []):
            for d in pt.get("descriptions", []):
                if d.get("cweId"):
                    name = d.get("description", "").replace(d["cweId"], "", 1).strip() or d["cweId"]
                    vuln.cwes.append((d["cweId"], name))

        for metric in cna.get("metrics", []):
            for key, version in _CVSS:
                m = metric.get(key)
                if m and m.get("vectorString") and m.get("baseScore") is not None:
                    vuln.scores.append(Score(version, m["vectorString"], float(m["baseScore"])))
            v4 = metric.get("cvssV4_0")
            if v4 and v4.get("vectorString"):
                # CSAF 2.0 has no CVSS v4 field: kept as text.
                vuln.notes.append(Note("other", f"{v4['vectorString']} (base score {v4.get('baseScore')})",
                                       "CVSS v4.0"))

        for affected in cna.get("affected", []):
            vuln.products.extend(self._products(affected))

        for key, category in (("solutions", "vendor_fix"), ("workarounds", "workaround")):
            text = _english(cna.get(key))
            if text:
                vuln.remediations.append(Remediation(category, text))
        for r in cna.get("references", []):
            if r.get("url"):
                vuln.references.append(Reference(r["url"], r.get("name") or r["url"]))
        return [vuln]

    def _products(self, affected):
        vendor = affected.get("vendor") or self.vendor_name
        name = affected.get("product")
        if not name:
            return []
        products = []
        for c in affected.get("cpes", []):
            version = cpe_lib.cpe_version(c)
            if version:
                products.append(Product(vendor, name, version=version, cpe=c))
        for v in affected.get("versions", []):
            status = _STATUS.get(v.get("status"), UNDER_INVESTIGATION)
            version = (v.get("version") or "").strip()
            upper = v.get("lessThan") or v.get("lessThanOrEqual")
            if upper:
                rng = VersionRange(introduced=version if version not in ("", "0", "*") else None)
                if v.get("lessThan"):
                    rng.fixed = v["lessThan"]
                else:
                    rng.last_affected = v["lessThanOrEqual"]
                products.append(Product(vendor, name, version_range=rng, status=status))
            elif version.lower() in ("all", "*", ""):
                products.append(Product(vendor, name, status=status))
            else:
                products.append(Product(vendor, name, version=version, status=status))
            for change in v.get("changes", []):
                if change.get("status") == "unaffected" and change.get("at"):
                    products.append(Product(vendor, name, version=change["at"], status=FIXED))
        return products
