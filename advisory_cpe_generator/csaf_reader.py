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
CSAF 2.0 document -> Vulnerability objects (one per CVE).

Used for vendors that already publish CSAF (Cisco). Product identity is
taken from the product_tree path: vendor branch, product_name (or
product_family) branch, and the deepest version-like branch as the version.
CPE/PURL from product_identification_helper are kept as the source's.
"""

from .model import (FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED, UNDER_INVESTIGATION, Note,
                    Product, Reference, Remediation, Score, Vulnerability)

_STATUS = {
    "known_affected": KNOWN_AFFECTED, "first_affected": KNOWN_AFFECTED, "last_affected": KNOWN_AFFECTED,
    "fixed": FIXED, "first_fixed": FIXED,
    "known_not_affected": KNOWN_NOT_AFFECTED,
    "under_investigation": UNDER_INVESTIGATION,
}
_VERSION_CATEGORIES = ("product_version", "service_pack", "patch_level", "product_version_range")


def _product(full, path, default_vendor):
    vendor = next((n for c, n in reversed(path) if c == "vendor"), default_vendor)
    name = next((n for c, n in reversed(path) if c == "product_name"), None) \
        or next((n for c, n in reversed(path) if c == "product_family"), None) \
        or full.get("name")
    version_branch = next(((c, n) for c, n in reversed(path) if c in _VERSION_CATEGORIES), None)
    helper = full.get("product_identification_helper", {})
    p = Product(vendor=vendor, name=name, cpe=helper.get("cpe"), purl=helper.get("purl"))
    if version_branch:
        category, value = version_branch
        if category == "product_version_range":
            p.raw_range = value
        else:
            p.version = value
    return p


def products_by_id(doc, default_vendor):
    tree = doc.get("product_tree", {})
    found = {}

    def walk(branches, path):
        for b in branches or []:
            here = path + [(b.get("category"), b.get("name"))]
            if "product" in b:
                found[b["product"]["product_id"]] = _product(b["product"], here, default_vendor)
            walk(b.get("branches"), here)

    walk(tree.get("branches"), [])
    for full in tree.get("full_product_names", []):
        found.setdefault(full["product_id"], _product(full, [], default_vendor))
    for rel in tree.get("relationships", []):
        full = rel.get("full_product_name")
        if full:
            found.setdefault(full["product_id"], _product(full, [], default_vendor))
    return found


def parse_csaf(doc, vendor, vendor_name):
    document = doc.get("document", {})
    tracking = document.get("tracking", {})
    advisory_id = tracking.get("id", "")
    catalog = products_by_id(doc, vendor_name)
    doc_refs = [Reference(r["url"], r.get("summary") or r["url"]) for r in document.get("references", [])]

    out = []
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cve")
        if not cve:
            continue
        vuln = Vulnerability(vendor=vendor, vendor_name=vendor_name, cve=cve.upper(),
                             title=v.get("title") or document.get("title"), advisory_ids=[advisory_id],
                             release_date=v.get("release_date") or tracking.get("initial_release_date"))
        by_pid = {}
        for status, pids in v.get("product_status", {}).items():
            target = _STATUS.get(status)
            if not target:
                continue   # "recommended" is advice, not a status of exposure
            for pid in pids:
                if pid in catalog:
                    p = Product(**{**catalog[pid].__dict__, "status": target})
                    by_pid.setdefault(pid, p)
                    vuln.products.append(p)
        if v.get("cwe"):
            vuln.cwes.append((v["cwe"]["id"], v["cwe"]["name"]))
        for n in v.get("notes", []):
            vuln.notes.append(Note(n["category"], n["text"], n.get("title")))
        for s in v.get("scores", []):
            for key in ("cvss_v3", "cvss_v2"):
                c = s.get(key)
                if c and c.get("vectorString"):
                    vuln.scores.append(Score(c["version"], c["vectorString"], float(c["baseScore"])))
        for r in v.get("remediations", []):
            keys = [by_pid[pid].key() for pid in r.get("product_ids", []) if pid in by_pid]
            vuln.remediations.append(Remediation(r["category"], r["details"], r.get("url"), keys))
        refs = [Reference(r["url"], r.get("summary") or r["url"]) for r in v.get("references", [])]
        seen = set()
        vuln.references = [r for r in doc_refs + refs if not (r.url in seen or seen.add(r.url))]
        out.append(vuln)
    return advisory_id, out
