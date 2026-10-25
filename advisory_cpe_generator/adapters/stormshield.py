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
Stormshield: https://advisories.stormshield.eu (HTML, no API).

The advisory list is the `advisories_list` JavaScript array of the home page
(id, link, products); each advisory page has a key/value table (Advisory ID,
CVE ID, CVSS score, ...) and sections titled Description, Workaround,
Impacted versions, Resolution. Listing and page fetching come from
stormshieldParser; the version parsing is new.

Versions are attached to a product only when the advisory names a single
product or the line names it (full name, name without "Stormshield", or its
initials such as SNS). A CVSS score is written as a CSAF score only when the
page gives the full vector with its version prefix (CVSS:3.x/...); otherwise
the score is kept as text.
"""

import json
import re
from pathlib import Path

from bs4 import BeautifulSoup

from ..model import (FIXED, KNOWN_AFFECTED, Note, Product, Reference, Remediation, Score,
                     Vulnerability)
from ..versions import VersionRange
from .base import Adapter, AdvisoryRef

_V = r"\d+(?:\.\d+)+(?:[.\-][a-z0-9]+)*"
_RANGE = re.compile(rf"(?:from\s+)?(?:version\s+)?({_V})\s*(?:to|through|-|–)\s*(?:version\s+)?({_V})", re.I)
_BEFORE = re.compile(rf"(?:prior to|before|lower than|earlier than|older than|<)\s*(?:version\s+)?({_V})", re.I)
_SINCE = re.compile(rf"({_V})\s*(?:and (?:later|above|higher|newer)|or (?:later|higher|newer)|\+)", re.I)
_SINGLE = re.compile(rf"(?<![\w.]){_V}(?![\w.])", re.I)
_VECTOR = re.compile(r"CVSS:(3\.[01]|2\.0)/[A-Za-z]{1,3}:[A-Za-z](?:/[A-Za-z]{1,3}:[A-Za-z])+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)


def parse_versions(text):
    """[('exact', '4.3.1') | ('range', VersionRange)] found in a line of text."""
    found = []
    rest = text
    for pattern, make in ((_RANGE, lambda m: VersionRange(introduced=m.group(1), last_affected=m.group(2))),
                          (_BEFORE, lambda m: VersionRange(fixed=m.group(1))),
                          (_SINCE, lambda m: VersionRange(introduced=m.group(1)))):
        for m in pattern.finditer(rest):
            found.append(("range", make(m)))
        rest = pattern.sub(" ", rest)
    for m in _SINGLE.finditer(rest):
        found.append(("exact", m.group(0)))
    return found


def _mentions(line, product):
    low = line.lower()
    name = product.lower()
    short = re.sub(r"^stormshield\s+", "", name)
    words = [w for w in re.findall(r"[a-z0-9]+", name)]
    initials = "".join(w[0] for w in words) if len(words) >= 2 else None
    return name in low or short in low or (initials and re.search(rf"\b{initials}\b", low))


class StormshieldAdapter(Adapter):
    vendor = "stormshield"
    vendor_name = "Stormshield"

    def list_advisories(self, since=None):
        base_url = self.cfg["base_url"]
        home = self.http.get(base_url).content
        self.listing = {"_list.html": home}
        soup = BeautifulSoup(home, "html.parser")
        script = soup.find("script", string=re.compile(r"var advisories_list = \["))
        if not script:
            self.log.error("advisories_list not found on %s", base_url)
            return []
        match = re.search(r"var advisories_list = (.*\]);", script.string, re.DOTALL)
        js = match.group(1)
        # JS object literal -> JSON (as in stormshieldParser)
        js = re.sub(r"([{,]\s*)(\w+)(\s*:)", r'\1"\2"\3', js)
        js = js.replace("'", '"')
        js = re.sub(r",\s*([}\]])", r"\1", js)
        refs, seen = [], set()
        for adv in json.loads(js):
            if adv["ID"] in seen:
                continue
            seen.add(adv["ID"])
            refs.append(AdvisoryRef(id=adv["ID"], url=adv["link"],
                                    details={"products": [p[0] for p in adv.get("products", [])]}))
        self.log.info("%d advisories listed", len(refs))
        return sorted(refs, key=lambda r: r.id)

    def download(self, ref):
        return {f"{ref.id}.html": self.http.get(ref.url).content}

    def parse_file(self, path, details=None):
        """details: the manifest entry (url, products from the home page)."""
        details = details or {}
        with open(path, "rb") as fh:
            html = fh.read()
        adv_id = re.sub(r"^.*?(\d{4}-\d{3,}).*$", r"\1", Path(path).name)
        return adv_id, self.parse_page(html, adv_id, details.get("url") or f"{self.cfg['base_url']}/{adv_id}/",
                                       details.get("products") or [])

    def parse_page(self, html, advisory_id, url, products):
        soup = BeautifulSoup(html, "html.parser")
        content = soup.find("div", class_="entry-content") or soup.find("article")
        if not content:
            self.log.warning("%s: no advisory content", advisory_id)
            return []
        meta = {}
        for row in content.find_all("div", class_="div_table_row"):
            cols = row.find_all("div", class_="div_table_col")
            if len(cols) >= 2:
                meta[cols[0].get_text(strip=True).lower()] = cols[1].get_text(" ", strip=True)
        sections = {}
        for h2 in content.find_all("h2"):
            if "product" in (h2.get("class") or []):
                continue
            parts = []
            for sib in h2.find_next_siblings():
                if sib.name == "h2":
                    break
                parts.append(sib)
            sections[h2.get_text(strip=True).lower()] = parts
        text = content.get_text("\n", strip=True)

        cves = sorted({c.upper() for c in _CVE.findall(meta.get("cve id", "") or text)})
        if not cves:
            self.log.info("%s: no CVE, skipped", advisory_id)
            return []
        title_elem = soup.find("h1", class_="entry-title")
        date_elem = soup.find("time", class_="entry-date")
        public_id = meta.get("advisory id") or advisory_id

        base = Vulnerability(vendor=self.vendor, vendor_name=self.vendor_name, cve="",
                             title=title_elem.get_text(strip=True) if title_elem else None,
                             advisory_ids=[public_id],
                             release_date=date_elem.get("datetime") if date_elem else None,
                             references=[Reference(url, f"Stormshield advisory {public_id}")])
        description = self._section_text(sections, "description")
        if description:
            base.notes.append(Note("description", description, "Description"))
        self._scores(base, meta, text)
        for key, category in (("workaround", "workaround"), ("resolution", "vendor_fix"),
                              ("solution", "vendor_fix")):
            details = self._section_text(sections, key)
            if details:
                base.remediations.append(Remediation(category, details))
        if meta.get("recommandation") or meta.get("recommendation"):
            base.remediations.append(Remediation("mitigation", meta.get("recommandation") or meta["recommendation"]))

        base.products = self._products(content, sections, products)

        out = []
        for cve in cves:
            v = Vulnerability.from_dict(base.to_dict())
            v.cve = cve
            out.append(v)
        return out

    @staticmethod
    def _section_text(sections, prefix):
        for title, parts in sections.items():
            if title.startswith(prefix):
                return "\n".join(p.get_text(" ", strip=True) for p in parts).strip() or None
        return None

    @staticmethod
    def _lines(parts):
        """One line per list item, otherwise one per text line."""
        lines = []
        for p in parts:
            items = p.find_all("li")
            if items:
                lines.extend(li.get_text(" ", strip=True) for li in items)
            else:
                lines.extend(t for t in p.get_text("\n", strip=True).split("\n") if t)
        return lines

    def _scores(self, vuln, meta, text):
        vector = _VECTOR.search(text)
        score_text = next((v for k, v in meta.items() if "cvss" in k and "score" in k), None)
        score = None
        if score_text:
            m = re.search(r"\d+(?:\.\d+)?", score_text)
            score = float(m.group(0)) if m else None
        if vector and score is not None:
            vuln.scores.append(Score(vector.group(1), vector.group(0), score))
        elif score is not None:
            vuln.notes.append(Note("other", f"CVSS score published by Stormshield: {score_text}", "CVSS"))

    def _products(self, content, sections, names):
        names = names or []
        products = []

        def attach(lines, status):
            for line in lines:
                targets = [n for n in names if _mentions(line, n)] or (names if len(names) == 1 else [])
                for name in targets:
                    for kind, value in parse_versions(line):
                        if kind == "exact":
                            products.append(Product(self.vendor_name, name, version=value, status=status))
                        elif status == KNOWN_AFFECTED:
                            products.append(Product(self.vendor_name, name, version_range=value, status=status))

        impacted = next((p for t, p in sections.items() if t.startswith("impacted") or t.startswith("affected")), [])
        attach(self._lines(impacted), KNOWN_AFFECTED)
        attach(self._legacy_tables(content, names), KNOWN_AFFECTED)
        resolution = next((p for t, p in sections.items() if t.startswith(("resolution", "solution"))), [])
        attach(self._lines(resolution), FIXED)

        affected_names = {p.name for p in products if p.status == KNOWN_AFFECTED}
        for name in names:
            if name not in affected_names:
                # Named as affected by the advisory, versions not found on the page.
                products.append(Product(self.vendor_name, name, status=KNOWN_AFFECTED))
        return products

    @staticmethod
    def _legacy_tables(content, names):
        """Older pages: <h2 class="product"> then a table with an 'Impacted version' column."""
        lines = []
        for section in content.find_all("h2", class_="product"):
            name = section.get_text(strip=True)
            table = section.find_parent("table")
            table = table.find_next_sibling("table") if table else None
            header = table.find("tr") if table else None
            if not header:
                continue
            heads = [h.get_text() for h in header.find_all("h2")]
            col = next((i for i, h in enumerate(heads) if "Impacted version" in h), -1)
            row = header.find_next_sibling("tr")
            if col == -1 or not row or col >= len(row.find_all("td")):
                continue
            for li in row.find_all("td")[col].find_all("li"):
                lines.append(f"{name} {li.get_text(strip=True)}")
        return lines
