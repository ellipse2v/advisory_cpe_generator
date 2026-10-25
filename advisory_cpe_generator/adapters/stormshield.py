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

Older pages (2014-2016) have another layout: an "Impacted products" table,
then one block per product (name, "CVSS v2 Overall Score", then tables with
Analysis / Impacted version, Workaround solution / Solution, and the CVSS
metrics). Each block gives that product's versions, remediations and CVSS
base score; versions named in its Solution as correcting the issue are fixed
versions.
"""

import copy
import json
import re
from datetime import datetime
from pathlib import Path

from bs4 import BeautifulSoup, NavigableString

from ..model import (FIXED, KNOWN_AFFECTED, Note, Product, Reference, Remediation, Score,
                     Vulnerability)
from ..versions import VersionRange
from .base import Adapter, AdvisoryRef

_V = r"\d+(?:\.\d+)+(?:/\d+)?(?:[.\-][a-z0-9]+)*"   # Fast360 builds: 5.0/16
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


_ROW, _CELL, _END = "\u241eROW\u241e", "\u241eCELL\u241e", "\u241eEND\u241e"   # markers, not page text
_OVERALL = re.compile(r"^CVSS v(\d(?:\.\d)?) Overall Score\s*:\s*(\d+(?:\.\d+)?)", re.I)
_BASE = re.compile(r"CVSS Base score\s*:\s*(\d+(?:\.\d+)?)\s*CVSS Vector\s*:\s*\(?\s*"
                   r"((?:CVSS:3\.[01]/)?[A-Za-z]{1,3}:[A-Za-z](?:/[A-Za-z]{1,3}:[A-Za-z])*)", re.I)
_HEADERS = {"analysis": "analysis", "impacted version": "impacted", "impacted versions": "impacted",
            "workaround solution": "workaround", "workaround": "workaround", "solution": "solution"}
_FIX_WORDS = re.compile(r"\b(correct|fix|patch|resolv|address)", re.I)
_NO_WORKAROUND = re.compile(r"^there is no workaround", re.I)


def _rows(content):
    """
    The page text as rows of cells of lines. A table row is one row; text
    outside tables is one row of one cell per line.
    """
    content = copy.copy(content)
    for table in content.find_all("table"):
        table.append(NavigableString(f"\n{_END}\n"))
    for tr in content.find_all("tr"):
        tr.insert(0, NavigableString(f"\n{_ROW}\n"))
    for cell in content.find_all(["td", "th"]):
        cell.insert(0, NavigableString(f"\n{_CELL}\n"))
    rows, row = [], None
    for line in (t.strip() for t in content.get_text("\n").split("\n")):
        if not line:
            continue
        if line == _END:
            row = None
        elif line == _ROW:
            row = []
            rows.append(row)
        elif line == _CELL:
            if row is None:
                row = []
                rows.append(row)
            row.append([])
        elif row:
            row[-1].append(line)
        else:
            rows.append([[line]])
    return [r for r in rows if any(r)]


def _row_text(row):
    return [" ".join(cell) for cell in row]


def _table_after(rows, header):
    """Rows following the row whose cells are `header` (case-insensitive), up to a row of another width."""
    header = [h.lower() for h in header]
    for i, row in enumerate(rows):
        if [t.lower() for t in _row_text(row)] == header:
            out = []
            for nxt in rows[i + 1:]:
                if len(nxt) != len(header):
                    break
                out.append(_row_text(nxt))
            return out
    return []


def _us_date(text):
    try:
        return datetime.strptime(text.strip(), "%m/%d/%Y").strftime("%Y-%m-%dT00:00:00Z")
    except ValueError:
        return None


def _blocks(rows):
    """[(product name, [rows])] of an old layout page; [] for the current layout."""
    flat = [(i, line) for i, row in enumerate(rows) for cell in row for line in cell]
    starts = []
    for k, (i, line) in enumerate(flat):
        if k and _OVERALL.match(line):
            starts.append((flat[k - 1][0], flat[k - 1][1]))
    blocks = []
    for n, (row_index, name) in enumerate(starts):
        end = starts[n + 1][0] if n + 1 < len(starts) else len(rows)
        blocks.append((name, rows[row_index:end]))
    return blocks


def _block_cells(block_rows):
    """{analysis|impacted|workaround|solution: [lines]} from header rows and the row under them."""
    cells = {}
    for i, row in enumerate(block_rows):
        if len(row) < 2:
            continue   # text outside a table: see _block_lines_fallback
        heads = [_HEADERS.get(cell[0].lower()) if cell else None for cell in row]
        if not any(heads):
            continue
        for j, (head, cell) in enumerate(zip(heads, row)):
            if head and len(cell) > 1:          # header and content in the same cell
                cells.setdefault(head, []).extend(cell[1:])
        if all(heads) and all(len(c) == 1 for c in row) and i + 1 < len(block_rows):
            for head, cell in zip(heads, block_rows[i + 1]):
                cells.setdefault(head, []).extend(cell)
    return cells


def _block_lines_fallback(block_rows):
    """Same as _block_cells for a block without tables: text between the headings."""
    lines = [line for row in block_rows for cell in row for line in cell]
    cells, current = {}, None
    for line in lines:
        low = line.lower()
        if low in _HEADERS:
            current = _HEADERS[low]
            continue
        if low.startswith(("access vector", "cvss")):
            current = None
            continue
        if current:
            cells.setdefault(current, []).append(line)
    # Headings side by side give their texts one after the other, under the
    # last heading: split them back by what the text says.
    solution = cells.pop("solution", [])
    for line in solution:
        fix = _FIX_WORDS.search(line) or re.search(r"\b(new version|update|release)", line, re.I)
        cells.setdefault("solution" if fix else "workaround", []).append(line)
    return cells


class StormshieldAdapter(Adapter):
    vendor = "stormshield"
    vendor_name = "Stormshield"

    def list_advisories(self, since=None, history=False):
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
        rows = _rows(content)
        blocks = _blocks(rows)
        if blocks:
            # Old layout: horizontal key/value table and revision table.
            for values in _table_after(rows, ["Advisory ID", "CVE Number", "Date discovered", "Severity",
                                              "Advisory revision"])[:1]:
                meta.update({"advisory id": values[0], "cve id": values[1]})

        cves = sorted({c.upper() for c in _CVE.findall(meta.get("cve id", "") or text)})
        if not cves:
            self.log.info("%s: no CVE, skipped", advisory_id)
            return []
        title_elem = soup.find("h1", class_="entry-title")
        date_elem = soup.find("time", class_="entry-date")
        public_id = meta.get("advisory id") or advisory_id
        release = date_elem.get("datetime") if date_elem else None
        if not release:
            revisions = _table_after(rows, ["Version", "Date", "Description"])
            release = _us_date(revisions[0][1]) if revisions else None

        base = Vulnerability(vendor=self.vendor, vendor_name=self.vendor_name, cve="",
                             title=title_elem.get_text(strip=True) if title_elem else None,
                             advisory_ids=[public_id],
                             release_date=release,
                             references=[Reference(url, f"Stormshield advisory {public_id}")])
        if blocks:
            self._old_layout(base, rows, blocks)
        else:
            self._current_layout(base, content, sections, meta, text, products)

        out = []
        for cve in cves:
            v = Vulnerability.from_dict(base.to_dict())
            v.cve = cve
            out.append(v)
        return out

    def _current_layout(self, base, content, sections, meta, text, products):
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

    def _old_layout(self, base, rows, blocks):
        lines = [" ".join(cell) for row in rows[:rows.index(blocks[0][1][0])] for cell in row]
        low = [line.lower() for line in lines]
        if "vulnerability details" in low:
            start = low.index("vulnerability details") + 1
            end = next((k for k in range(start, len(low)) if low[k] in ("impacted products", "products")), len(low))
            description = "\n".join(lines[start:end]).strip()
            if description:
                base.notes.append(Note("description", description, "Description"))
        impacted = _table_after(rows, ["Products", "Severity", "Detail"])
        if impacted:
            base.notes.append(Note("other", "\n".join(f"{n}: {sev} severity. {detail}" for n, sev, detail in impacted),
                                   "Impacted products"))
        for name, block_rows in blocks:
            self._old_block(base, name, block_rows)

    def _old_block(self, base, name, block_rows):
        cells = _block_cells(block_rows)
        table_layout = "impacted" in cells
        if not table_layout:
            cells = _block_lines_fallback(block_rows)
        text = "\n".join(line for row in block_rows for cell in row for line in cell)

        found = []
        for line in cells.get("impacted", []):
            # Without the table cells, the analysis text is mixed in: keep the lines naming the product.
            if len(line) <= 100 and (table_layout or _mentions(line, name)):
                found += parse_versions(line)
        for kind, value in found:
            if kind == "exact":
                base.products.append(Product(self.vendor_name, name, version=value))
            else:
                base.products.append(Product(self.vendor_name, name, version_range=value))
        if not found:
            base.products.append(Product(self.vendor_name, name))   # named as affected, versions not found
        fixed = [v for line in cells.get("solution", []) if _FIX_WORDS.search(line)
                 for kind, v in parse_versions(line) if kind == "exact"]
        for version in fixed:
            base.products.append(Product(self.vendor_name, name, version=version, status=FIXED))

        workaround = "\n".join(l for l in cells.get("workaround", []) if not _NO_WORKAROUND.match(l)).strip()
        if workaround:
            base.remediations.append(Remediation("workaround", workaround, product_names=[name]))
        solution = "\n".join(cells.get("solution", [])).strip()
        if solution:
            # A fix announced without a version is not available yet.
            base.remediations.append(Remediation("vendor_fix" if fixed else "none_available", solution,
                                                 product_names=[name]))
        if cells.get("analysis"):
            base.notes.append(Note("details", "\n".join(cells["analysis"]), f"Analysis: {name}"))

        base_score = _BASE.search(text)
        if base_score:
            score, vector = float(base_score.group(1)), base_score.group(2)
            version = vector[5:8] if vector.startswith("CVSS:3") else "2.0"
            base.scores.append(Score(version, vector, score, product_names=[name]))
        overall = next((m for m in map(_OVERALL.match, text.split("\n")) if m), None)
        if overall:
            base.notes.append(Note("other", f"CVSS v{overall.group(1)} overall score published by Stormshield "
                                            f"for {name}: {overall.group(2)}", f"CVSS: {name}"))

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
