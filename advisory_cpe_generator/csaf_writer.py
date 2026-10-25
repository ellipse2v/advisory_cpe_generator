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
Vulnerability -> CSAF 2.0 document (profile csaf_security_advisory).

Only fields of the CSAF 2.0 standard are written. The CPE goes in
product_identification_helper.cpe; a version range is a product_version_range
branch named with a 'vers' expression and carries no CPE.
"""

import re

from . import __version__
from .model import KNOWN_AFFECTED, STATUSES

SEVERITY_V3 = ((9.0, "CRITICAL"), (7.0, "HIGH"), (4.0, "MEDIUM"), (0.1, "LOW"), (0.0, "NONE"))


def tracking_id(vendor, cve):
    """'stormshield', 'CVE-2024-1234' -> 'stormshield_cve_2024_1234' (also the file name)."""
    return re.sub(r"[^a-z0-9]+", "_", f"{vendor}_{cve}".lower())


def file_name(tracking):
    """CSAF 2.0 section 5.1: lower case, characters outside [+-a-z0-9] -> '_'."""
    return re.sub(r"[^+\-a-z0-9]+", "_", tracking.lower()) + ".json"


def _severity_v3(score):
    return next(label for floor, label in SEVERITY_V3 if score >= floor)


def _cvss(score):
    if score.version.startswith("3"):
        return "cvss_v3", {"version": score.version, "vectorString": score.vector,
                           "baseScore": score.base_score, "baseSeverity": _severity_v3(score.base_score)}
    return "cvss_v2", {"version": "2.0", "vectorString": score.vector, "baseScore": score.base_score}


def _product_tree(vuln):
    """(product_tree, {product key: product_id}) with stable ids in sorted order."""
    ordered = sorted(vuln.products, key=lambda p: (p.vendor.lower(), p.name.lower(),
                                                   p.label() or "", p.status))
    ids, vendors, loose = {}, {}, []
    for product in ordered:
        if product.key() in ids:
            continue
        pid = f"CSAFPID-{len(ids) + 1:04d}"
        ids[product.key()] = pid
        vendor_prefix = None if product.name.lower().startswith(product.vendor.lower()) else product.vendor
        full = {"name": " ".join(x for x in (vendor_prefix, product.name, product.label()) if x),
                "product_id": pid}
        helper = {k: v for k, v in (("cpe", product.cpe), ("purl", product.purl)) if v}
        if helper:
            full["product_identification_helper"] = helper
        if product.version or product.version_range or product.raw_range:
            category = "product_version" if product.version else "product_version_range"
            names = vendors.setdefault(product.vendor, {})
            leaves = names.setdefault(product.name, {})
            # Same version listed under two statuses (rare): one leaf per id.
            leaf_name = product.label()
            if leaf_name in leaves:
                loose.append(full)
                continue
            leaves[leaf_name] = {"category": category, "name": leaf_name, "product": full}
        else:
            # A product without version cannot sit next to version branches.
            loose.append(full)

    tree = {}
    if vendors:
        tree["branches"] = [
            {"category": "vendor", "name": vendor, "branches": [
                {"category": "product_name", "name": name, "branches": list(leaves.values())}
                for name, leaves in names.items()]}
            for vendor, names in vendors.items()]
    if loose:
        tree["full_product_names"] = loose
    return tree, ids


def build_document(vuln, config, tracking):
    """CSAF document for one (vendor, CVE). `tracking` comes from storage (versioning)."""
    product_tree, ids = _product_tree(vuln)

    status = {}
    for product in vuln.products:
        status.setdefault(product.status, [])
        pid = ids[product.key()]
        if pid not in status[product.status]:
            status[product.status].append(pid)
    affected = status.get(KNOWN_AFFECTED, [])

    v = {"cve": vuln.cve}
    if vuln.title:
        v["title"] = vuln.title
    if vuln.cwes:
        cwe_id, cwe_name = vuln.cwes[0]
        v["cwe"] = {"id": cwe_id, "name": cwe_name}
    notes = [{"category": n.category, "text": n.text, **({"title": n.title} if n.title else {})}
             for n in vuln.notes]
    for cwe_id, cwe_name in vuln.cwes[1:]:
        notes.append({"category": "other", "title": "Additional CWE", "text": f"{cwe_id} {cwe_name}"})
    if notes:
        v["notes"] = notes
    if vuln.release_date:
        v["release_date"] = vuln.release_date
    v["product_status"] = {s: status[s] for s in STATUSES if status.get(s)}
    if vuln.scores and affected:
        scores = {}
        for score in vuln.scores:
            key, body = _cvss(score)
            scores.setdefault(key, body)   # CSAF: one cvss_v3 and one cvss_v2 per score object
        v["scores"] = [{"products": affected, **scores}]
    remediations = []
    for r in vuln.remediations:
        pids = list(dict.fromkeys(ids[k] for k in r.product_keys if k in ids)) or affected
        if not pids:
            continue
        item = {"category": r.category, "details": r.details, "product_ids": pids}
        if r.url:
            item["url"] = r.url
        remediations.append(item)
    if remediations:
        v["remediations"] = remediations
    v["references"] = [{"category": r.category, "summary": r.summary, "url": r.url}
                       for r in vuln.references]
    if not v["references"]:
        del v["references"]

    publisher = config["publisher"]
    advisories = ", ".join(vuln.advisory_ids)
    document = {
        "category": "csaf_security_advisory",
        "csaf_version": "2.0",
        "lang": "en",
        "title": f"{vuln.vendor_name} - {vuln.cve}" + (f": {vuln.title}" if vuln.title else ""),
        "publisher": {"category": publisher["category"], "name": publisher["name"],
                      "namespace": publisher["namespace"]},
        "distribution": {"tlp": {"label": config.get("tlp", "WHITE")}},
        "notes": [{
            "category": "general",
            "title": "Source",
            "text": (f"Translated from {vuln.vendor_name} advisory {advisories} by advisory_cpe_generator. "
                     "CPE identifiers not published by the vendor were taken from the NVD CPE dictionary "
                     "or a manually maintained mapping."),
        }],
        "references": [{"category": r.category, "summary": r.summary, "url": r.url}
                       for r in vuln.references] or [{
            "category": "external", "summary": f"NVD entry for {vuln.cve}",
            "url": f"https://nvd.nist.gov/vuln/detail/{vuln.cve}"}],
        "tracking": {
            **tracking,
            "generator": {"engine": {"name": "advisory_cpe_generator", "version": __version__}},
        },
    }
    if not config.get("tlp"):
        del document["distribution"]
    return {"document": document, "product_tree": product_tree, "vulnerabilities": [v]}
