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

import logging
import re

from .model import (FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED, UNDER_INVESTIGATION, Note,
                    Product, Reference, Remediation, Score, Vulnerability)
from .versions import VersionRange, next_branch

log = logging.getLogger(__name__)

_STATUS = {
    "known_affected": KNOWN_AFFECTED, "first_affected": KNOWN_AFFECTED, "last_affected": KNOWN_AFFECTED,
    "fixed": FIXED, "first_fixed": FIXED,
    "known_not_affected": KNOWN_NOT_AFFECTED,
    "under_investigation": UNDER_INVESTIGATION,
}
_VERSION_CATEGORIES = ("product_version", "service_pack", "patch_level", "product_version_range")


def _version_text(branch_name, product_name):
    """
    Version branches sometimes repeat the product name (Oracle: "Oracle APEX
    Version 24.1", "X(X_Component) Version 11.4.0"; Fortinet: "FortiSIEM/7.5.0",
    "FortiSIEM/ 7.6 all versions"): keep what follows.
    """
    if " Version " in branch_name:
        return branch_name.rsplit(" Version ", 1)[1].strip()
    if product_name:
        m = re.match(rf"^{re.escape(product_name)}\s*[/ ]\s*(\S.*)$", branch_name, re.I)
        if m:
            return m.group(1).strip()
    return branch_name


def _branch_range(text):
    """'7.6 all versions' (Fortinet) -> the range of the 7.6 branch; None otherwise."""
    m = re.match(r"^(\d+(?:\.\d+)*)\s+all versions$", text.strip(), re.I)
    return VersionRange(introduced=m.group(1), fixed=next_branch(m.group(1))) if m else None


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
        value = _version_text(value, name)
        if category == "product_version_range":
            p.version_range = _branch_range(value)
            if not p.version_range:
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

    # The document title describes the vulnerability only in a one-CVE advisory
    # (not in Oracle's quarterly CPU).
    single_title = document.get("title") if len(doc.get("vulnerabilities", [])) == 1 else None
    out = []
    for v in doc.get("vulnerabilities", []):
        cve = v.get("cve")
        if not cve:
            continue
        vuln = Vulnerability(vendor=vendor, vendor_name=vendor_name, cve=cve.upper(),
                             title=v.get("title") or single_title, advisory_ids=[advisory_id],
                             release_date=v.get("release_date") or tracking.get("initial_release_date"))
        by_pid = {}
        for status, pids in v.get("product_status", {}).items():
            target = _STATUS.get(status)
            if not target:
                continue   # "recommended" is advice, not a status of exposure
            for pid in pids:
                if pid not in catalog:
                    # e.g. Fortinet's FG-IR-26-180: known_not_affected "FortiSIEM-7.5.1", not in the tree
                    log.warning("%s %s: product %r is not in the product tree: ignored", advisory_id, cve, pid)
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
