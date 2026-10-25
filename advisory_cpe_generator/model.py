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
Vendor-neutral model filled by the adapters and turned into CSAF by csaf_writer.

One Vulnerability = one CVE as one vendor describes it. Vulnerabilities from
several advisories of the same vendor for the same CVE are merged.
"""

from dataclasses import asdict, dataclass, field

from .versions import VersionRange

KNOWN_AFFECTED = "known_affected"
FIXED = "fixed"
KNOWN_NOT_AFFECTED = "known_not_affected"
UNDER_INVESTIGATION = "under_investigation"
STATUSES = (KNOWN_AFFECTED, FIXED, KNOWN_NOT_AFFECTED, UNDER_INVESTIGATION)


@dataclass
class Product:
    vendor: str                       # vendor name as published, e.g. "Palo Alto Networks"
    name: str                         # product name, e.g. "PAN-OS"
    version: str = None               # one version
    version_range: VersionRange = None  # or a range of versions
    raw_range: str = None             # a range kept verbatim when it cannot be parsed
    status: str = KNOWN_AFFECTED
    cpe: str = None
    purl: str = None
    cpe_origin: str = None            # source | mapping | nvd-dictionary | nvd-range | nvd-matcher

    def label(self):
        if self.version:
            return self.version
        if self.version_range:
            return self.version_range.vers()
        return self.raw_range

    def key(self):
        return (self.vendor.lower(), self.name.lower(), (self.label() or "").lower(), self.status)


@dataclass
class Score:
    version: str          # CVSS "2.0", "3.0" or "3.1" (the versions CSAF 2.0 supports)
    vector: str
    base_score: float


@dataclass
class Reference:
    url: str
    summary: str
    category: str = "external"


@dataclass
class Remediation:
    category: str         # vendor_fix | workaround | mitigation | no_fix_planned | none_available
    details: str
    url: str = None
    # Product keys it applies to; empty = every known_affected product.
    product_keys: list = field(default_factory=list)


@dataclass
class Note:
    category: str         # CSAF note category: description, summary, details, general, other
    text: str
    title: str = None


@dataclass
class Vulnerability:
    vendor: str           # connector slug used in file names, e.g. "paloalto"
    vendor_name: str      # e.g. "Palo Alto Networks"
    cve: str
    title: str = None
    cwes: list = field(default_factory=list)          # [(id, name)]
    scores: list = field(default_factory=list)        # [Score]
    products: list = field(default_factory=list)      # [Product]
    references: list = field(default_factory=list)    # [Reference]
    remediations: list = field(default_factory=list)  # [Remediation]
    notes: list = field(default_factory=list)         # [Note]
    advisory_ids: list = field(default_factory=list)
    release_date: str = None                          # vendor publication date (ISO 8601)

    def merge(self, other):
        """Fold another advisory's view of the same CVE into this one."""
        def extend(target, items, key):
            seen = {key(i) for i in target}
            for item in items:
                if key(item) not in seen:
                    target.append(item)
                    seen.add(key(item))

        self.title = self.title or other.title
        extend(self.cwes, other.cwes, lambda c: tuple(c))
        extend(self.scores, other.scores, lambda s: s.vector)
        extend(self.products, other.products, lambda p: p.key())
        extend(self.references, other.references, lambda r: r.url)
        extend(self.remediations, other.remediations, lambda r: (r.category, r.details))
        extend(self.notes, other.notes, lambda n: (n.category, n.text))
        extend(self.advisory_ids, other.advisory_ids, lambda a: a)
        if other.release_date and (not self.release_date or other.release_date < self.release_date):
            self.release_date = other.release_date
        return self

    # -- cache (de)serialisation ------------------------------------------

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        d = dict(d)
        d["cwes"] = [tuple(c) for c in d.get("cwes", [])]
        d["scores"] = [Score(**s) for s in d.get("scores", [])]
        d["products"] = [_product_from_dict(p) for p in d.get("products", [])]
        d["references"] = [Reference(**r) for r in d.get("references", [])]
        d["remediations"] = [Remediation(**{**r, "product_keys": [tuple(k) for k in r.get("product_keys", [])]})
                             for r in d.get("remediations", [])]
        d["notes"] = [Note(**n) for n in d.get("notes", [])]
        return cls(**d)


def _product_from_dict(d):
    d = dict(d)
    if d.get("version_range"):
        d["version_range"] = VersionRange(**d["version_range"])
    return Product(**d)


def merge_by_cve(vulnerabilities):
    """{(vendor, CVE): merged Vulnerability}"""
    merged = {}
    for v in vulnerabilities:
        key = (v.vendor, v.cve.upper())
        if key in merged:
            merged[key].merge(v)
        else:
            merged[key] = Vulnerability.from_dict(v.to_dict())
    return merged
