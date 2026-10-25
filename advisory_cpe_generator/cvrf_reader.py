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
CVRF 1.2 document (XML) -> Vulnerability objects (one per CVE).

Elements are matched by local name, so documents that put ProductTree and
Vulnerability in their own default namespace (as the OASIS examples do) or in
none read the same. Branch types map to the CSAF categories of the same name
("Product Version" -> product_version, ...), and statuses likewise
("Known Affected" -> known_affected).
"""

import xml.etree.ElementTree as ET

from .csaf_reader import _STATUS, _VERSION_CATEGORIES, _version_text
from .model import Note, Product, Reference, Remediation, Score, Vulnerability


def _local(tag):
    return tag.rsplit("}", 1)[-1]


def _children(elem, name):
    return [c for c in elem if _local(c.tag) == name]


def _child(elem, name):
    return next(iter(_children(elem, name)), None)


def _text(elem, name):
    c = _child(elem, name) if elem is not None else None
    return c.text.strip() if c is not None and c.text and c.text.strip() else None


def _category(value):
    """'Product Version' -> 'product_version' (CVRF and CSAF use the same vocabulary)."""
    return (value or "").strip().lower().replace(" ", "_")


def parse_xml(data):
    """ElementTree root; with lxml installed, a slightly malformed file is recovered."""
    try:
        return ET.fromstring(data)
    except ET.ParseError:
        try:
            from lxml import etree
        except ImportError:
            raise
        root = etree.fromstring(data, parser=etree.XMLParser(recover=True))
        return ET.fromstring(etree.tostring(root))


def products_by_id(root, default_vendor):
    found = {}
    tree = _child(root, "ProductTree")
    if tree is None:
        return found

    def walk(branch, path):
        here = path + [(_category(branch.get("Type")), branch.get("Name"))]
        for full in _children(branch, "FullProductName"):
            found[full.get("ProductID")] = _product(full, here, default_vendor)
        for sub in _children(branch, "Branch"):
            walk(sub, here)

    for branch in _children(tree, "Branch"):
        walk(branch, [])
    for full in _children(tree, "FullProductName"):
        found.setdefault(full.get("ProductID"), _product(full, [], default_vendor))
    for rel in _children(tree, "Relationship"):
        for full in _children(rel, "FullProductName"):
            found.setdefault(full.get("ProductID"), _product(full, [], default_vendor))
    return found


def _product(full, path, default_vendor):
    vendor = next((n for c, n in reversed(path) if c == "vendor"), default_vendor)
    name = next((n for c, n in reversed(path) if c == "product_name"), None) \
        or next((n for c, n in reversed(path) if c == "product_family"), None) \
        or (full.text or "").strip()
    cpe = full.get("CPE")
    p = Product(vendor=vendor, name=name, cpe=cpe if cpe and cpe.startswith("cpe:2.3:") else None)
    version = next(((c, n) for c, n in reversed(path) if c in _VERSION_CATEGORIES), None)
    if version:
        category, value = version
        value = _version_text(value, name)
        if category == "product_version_range":
            p.raw_range = value
        else:
            p.version = value
    return p


def parse_cvrf(data, vendor, vendor_name):
    root = parse_xml(data)
    tracking = _child(root, "DocumentTracking")
    advisory_id = _text(_child(tracking, "Identification"), "ID") if tracking is not None else None
    release = _text(tracking, "InitialReleaseDate")
    catalog = products_by_id(root, vendor_name)
    doc_refs = []
    refs_elem = _child(root, "DocumentReferences")
    for r in _children(refs_elem, "Reference") if refs_elem is not None else []:
        url = _text(r, "URL")
        if url and url.startswith("http"):
            doc_refs.append(Reference(url, _text(r, "Description") or url))

    single = len(_children(root, "Vulnerability")) == 1   # see csaf_reader
    out = []
    for v in _children(root, "Vulnerability"):
        cve = _text(v, "CVE")
        if not cve:
            continue
        vuln = Vulnerability(vendor=vendor, vendor_name=vendor_name, cve=cve.upper(),
                             title=_text(v, "Title") or (_text(root, "DocumentTitle") if single else None),
                             advisory_ids=[advisory_id] if advisory_id else [],
                             release_date=_text(v, "ReleaseDate") or release)
        by_pid = {}
        statuses = _child(v, "ProductStatuses")
        for status in _children(statuses, "Status") if statuses is not None else []:
            target = _STATUS.get(_category(status.get("Type")))
            if not target:
                continue
            for pid_elem in _children(status, "ProductID"):
                pid = (pid_elem.text or "").strip()
                if pid in catalog:
                    p = Product(**{**catalog[pid].__dict__, "status": target})
                    by_pid.setdefault(pid, p)
                    vuln.products.append(p)
        cwe = _child(v, "CWE")
        if cwe is not None and cwe.get("ID"):
            vuln.cwes.append((cwe.get("ID"), (cwe.text or cwe.get("ID")).strip()))
        notes = _child(v, "Notes")
        for n in _children(notes, "Note") if notes is not None else []:
            if n.text and n.text.strip():
                vuln.notes.append(Note(_category(n.get("Type")) or "other", n.text.strip(), n.get("Title")))
        scores = _child(v, "CVSSScoreSets")
        for name, base, vector in (("ScoreSetV3", "BaseScoreV3", "VectorV3"),
                                   ("ScoreSetV2", "BaseScoreV2", "VectorV2")):
            for s in _children(scores, name) if scores is not None else []:
                vec, score = _text(s, vector), _text(s, base)
                if not vec or score is None:
                    continue
                if vec.startswith("CVSS:3."):
                    vuln.scores.append(Score(vec.split("/", 1)[0][5:], vec, float(score)))
                elif name == "ScoreSetV2":
                    vuln.scores.append(Score("2.0", vec, float(score)))
        rems = _child(v, "Remediations")
        for r in _children(rems, "Remediation") if rems is not None else []:
            details = _text(r, "Description")
            if not details:
                continue
            keys = [by_pid[(p.text or "").strip()].key() for p in _children(r, "ProductID")
                    if (p.text or "").strip() in by_pid]
            category = _category(r.get("Type"))
            category = {"will_not_fix": "no_fix_planned"}.get(category, category)
            vuln.remediations.append(Remediation(category, details, _text(r, "URL"), keys))
        refs = _child(v, "References")
        vrefs = []
        for r in _children(refs, "Reference") if refs is not None else []:
            url = _text(r, "URL")
            if url and url.startswith("http"):
                vrefs.append(Reference(url, _text(r, "Description") or url))
        seen = set()
        vuln.references = [r for r in doc_refs + vrefs if not (r.url in seen or seen.add(r.url))]
        out.append(vuln)
    return advisory_id, out
