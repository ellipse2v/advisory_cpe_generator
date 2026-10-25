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
Fortinet: FortiGuard PSIRT.

Listing: the RSS feed (latest advisories, 50 when this was written), or with
--history every page of the PSIRT list (https://www.fortiguard.com/psirt?page=N).

Each advisory is downloaded in the first format it has, in the order of the
connector's "formats" (default csaf, html, cvrf): its CSAF document (the RSS
<csaf:link>, else https://www.fortiguard.com/psirt/{id}/csaf, which every
advisory page has), its HTML page, or its CVRF 1.2 document. FortiGuard
answers these URLs with a browser User-Agent (connector "http" block). CVRF gives products and fixes as prose, the
HTML page as a Version / Affected / Solution table:

  FortiOS 7.4 | 7.4.0 through 7.4.2 | Upgrade to 7.4.3 or above
  FortiOS 6.0 | 6.0 all versions    | Migrate to a fixed release
  FortiOS 7.6 | Not affected        | Not Applicable

"7.4.0 through 7.4.2" is a range, "6.0 all versions" the range of the 6.0
branch (>=6.0|<6.1), "Upgrade to 7.4.3" a fixed version. The CVSS vector is
taken from the page when it is there (FortiGuard links the score to the FIRST
calculator), otherwise the score is kept as a note.

--file reads CSAF (.json), HTML (.html) or CVRF (.xml) files.
"""

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from email.utils import parsedate_to_datetime
from pathlib import Path

from bs4 import BeautifulSoup

from ..csaf_reader import parse_csaf
from ..cvrf_reader import parse_cvrf
from ..model import (FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED, Note, Product, Reference, Remediation,
                     Score, Vulnerability)
from ..versions import VersionRange
from .base import Adapter, AdvisoryRef

_ID = re.compile(r"FG-IR-\d{2}-\d+", re.I)
_V = r"\d+(?:\.\d+)+(?:[.\-][a-z0-9]+)*"
_THROUGH = re.compile(rf"({_V})\s*(?:through|to|-|–)\s*({_V})", re.I)
_ALL = re.compile(r"(?:(\d+(?:\.\d+)*)\s+)?all versions", re.I)
_SINGLE = re.compile(rf"(?<![\w.]){_V}(?![\w.])")
_FIXED = re.compile(rf"(?:upgrade|update|migrate)\s+to\s+(?:version\s+)?(?:[A-Za-z][\w-]*\s+)?({_V})", re.I)
_BRANCH = re.compile(r"^(.*?)\s+(\d+(?:\.\d+)*)$")
_VECTOR = re.compile(r"CVSS:3\.[01]/[A-Za-z]{1,3}:[A-Za-z](?:/[A-Za-z]{1,3}:[A-Za-z])+")
_CVE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_EXTENSIONS = {"csaf": "json", "html": "html", "cvrf": "xml"}


def _next_branch(branch):
    """'6.0' -> '6.1': the first version after a whole branch."""
    parts = branch.split(".")
    parts[-1] = str(int(parts[-1]) + 1)
    return ".".join(parts)


def _date(text):
    for fmt in ("%b %d, %Y", "%B %d, %Y", "%Y-%m-%d"):
        try:
            return datetime.strptime(text.strip(), fmt).strftime("%Y-%m-%dT00:00:00Z")
        except ValueError:
            pass
    return None


def parse_affected(text, branch):
    """[(status, version or VersionRange)] from an Affected cell."""
    low = text.lower()
    if "not affected" in low:
        if branch:
            return [(KNOWN_NOT_AFFECTED, VersionRange(introduced=branch, fixed=_next_branch(branch)))]
        return [(KNOWN_NOT_AFFECTED, None)]
    found, rest = [], text
    for m in _THROUGH.finditer(rest):
        found.append((KNOWN_AFFECTED, VersionRange(introduced=m.group(1), last_affected=m.group(2))))
    rest = _THROUGH.sub(" ", rest)
    for m in _ALL.finditer(rest):
        start = m.group(1) or branch
        if start:
            found.append((KNOWN_AFFECTED, VersionRange(introduced=start, fixed=_next_branch(start))))
        else:
            found.append((KNOWN_AFFECTED, None))   # every version of the product
    rest = _ALL.sub(" ", rest)
    found += [(KNOWN_AFFECTED, m.group(0)) for m in _SINGLE.finditer(rest)]
    return found


class FortinetAdapter(Adapter):
    vendor = "fortinet"
    vendor_name = "Fortinet"

    # -- listing --------------------------------------------------------------

    def list_advisories(self, since=None, history=False):
        refs = self._list_pages() if history else self._list_rss(since)
        self.log.info("%d advisories listed", len(refs))
        return refs

    def _csaf_url(self, adv_id):
        return self.cfg.get("csaf_url", "https://www.fortiguard.com/psirt/{id}/csaf").format(id=adv_id)

    def _page_url(self, adv_id):
        return self.cfg.get("page_url", "https://www.fortiguard.com/psirt/{id}").format(id=adv_id)

    def _list_rss(self, since):
        raw = self.http.get(self.cfg["rss_url"]).content
        self.listing = {"_list.xml": raw}
        root = ET.fromstring(raw)
        refs = []
        for item in root.iter("item"):
            links = {}
            for child in item:
                ns, _, local = child.tag.rpartition("}")
                key = "csaf" if "csaf" in ns else "cvrf" if "cvrf" in ns else local
                if child.text:
                    links[key] = child.text.strip()
            match = _ID.search(links.get("link", "") + " " + links.get("guid", "") + " " + links.get("title", ""))
            if not match:
                continue
            adv_id = match.group(0).upper()
            updated = None
            if links.get("pubDate"):
                try:
                    updated = parsedate_to_datetime(links["pubDate"]).date().isoformat()
                except (TypeError, ValueError):
                    pass
            if since and updated and updated < since.strftime("%Y-%m-%d"):
                continue
            page = links.get("link") if _ID.search(links.get("link", "")) else self._page_url(adv_id)
            urls = {"csaf": links.get("csaf") or self._csaf_url(adv_id), "html": page, "cvrf": links.get("cvrf")}
            refs.append(AdvisoryRef(id=adv_id, url=page, updated=updated,
                                    details={"urls": {k: v for k, v in urls.items() if v}}))
        return refs

    def _list_pages(self):
        """Every advisory of the PSIRT list, page by page until a page brings nothing new."""
        template = self.cfg.get("list_page_url", "https://www.fortiguard.com/psirt?page={page}")
        seen, refs = set(), []
        for page in range(1, int(self.cfg.get("max_pages", 500)) + 1):
            html = self.http.get(template.format(page=page)).content
            if page == 1:
                self.listing = {"_list_page1.html": html}
            new = [i.upper() for i in _ID.findall(html.decode("utf-8", "replace")) if i.upper() not in seen]
            new = list(dict.fromkeys(new))
            if not new:
                break
            for adv_id in new:
                seen.add(adv_id)
                refs.append(AdvisoryRef(id=adv_id, url=self._page_url(adv_id), details={"urls": {
                    "csaf": self._csaf_url(adv_id),
                    "html": self._page_url(adv_id),
                    "cvrf": self.cfg.get("cvrf_url", "https://www.fortiguard.com/psirt/cvrf/{id}").format(id=adv_id)}}))
        return refs

    # -- download ---------------------------------------------------------------

    def download(self, ref):
        urls = ref.details.get("urls") or {ref.details.get("format", "cvrf"): ref.url}
        errors = []
        for fmt in self.cfg.get("formats", ["csaf", "html", "cvrf"]):
            if not urls.get(fmt):
                continue
            try:
                data = self.http.get(urls[fmt]).content
            except Exception as e:   # try the next format
                errors.append(f"{fmt}: {e}")
                continue
            ref.details["format"] = fmt
            return {f"{ref.id}.{_EXTENSIONS[fmt]}": data}
        raise RuntimeError("no format could be downloaded (" + "; ".join(errors) + ")")

    # -- parsing ----------------------------------------------------------------

    def parse_file(self, path, details=None):
        with open(path, "rb") as fh:
            data = fh.read()
        suffix = str(path).lower().rsplit(".", 1)[-1]
        if suffix == "json":
            return parse_csaf(json.loads(data), self.vendor, self.vendor_name)
        if suffix in ("html", "htm"):
            match = _ID.search(Path(path).name)
            return self.parse_page(data, match.group(0).upper() if match else Path(path).stem,
                                   (details or {}).get("url"))
        return parse_cvrf(data, self.vendor, self.vendor_name)

    def parse_page(self, html, advisory_id, url=None):
        soup = BeautifulSoup(html, "html.parser")
        meta, table = {}, []
        for tr in soup.find_all("tr"):
            cells = [c.get_text(" ", strip=True) for c in tr.find_all(["td", "th"])]
            if [c.lower() for c in cells] == ["version", "affected", "solution"]:
                for row in tr.find_next_siblings("tr"):
                    values = [c.get_text("\n", strip=True) for c in row.find_all(["td", "th"])]
                    if len(values) == 3:
                        table.append(values)
            elif len(cells) == 2 and cells[0]:
                meta.setdefault(cells[0].rstrip(":").lower(), cells[1])
        sections = self._sections(soup)
        advisory_id = (_ID.search(meta.get("ir number", "")) or _ID.search(advisory_id) or
                       re.search(r".+", advisory_id)).group(0).upper()
        cves = sorted({c.upper() for c in _CVE.findall(meta.get("cve id", ""))}) or \
            sorted({c.upper() for c in _CVE.findall(soup.get_text(" "))})
        if not cves:
            self.log.info("%s: no CVE, skipped", advisory_id)
            return advisory_id, []

        url = url or self._page_url(advisory_id)
        base = Vulnerability(vendor=self.vendor, vendor_name=self.vendor_name, cve="",
                             title=self._title(soup), advisory_ids=[advisory_id],
                             release_date=_date(meta.get("published date", "") or meta.get("date", "")),
                             references=[Reference(url, f"Fortinet advisory {advisory_id}")])
        summary = sections.get("summary", [])
        description = [t for t in summary if not t.lower().startswith("workaround")]
        if description:
            base.notes.append(Note("description", "\n".join(description), "Summary"))
        # The workaround is a "Workaround: ..." paragraph of the summary, or a section of its own.
        workaround = [re.sub(r"^workarounds?\s*:?\s*", "", t, flags=re.I) for t in summary
                      if t.lower().startswith("workaround")]
        workaround += sections.get("workaround", []) + sections.get("workarounds", [])
        workaround = "\n".join(t for t in workaround if t).strip()
        if workaround:
            base.remediations.append(Remediation("workaround", workaround))
        if sections.get("virtual patch"):
            base.remediations.append(Remediation("mitigation", "\n".join(sections["virtual patch"])))
        if meta.get("impact"):
            base.notes.append(Note("summary", meta["impact"], "Impact"))
        self._score(base, meta, str(soup))
        self._products(base, table)

        out = []
        for cve in cves:
            v = Vulnerability.from_dict(base.to_dict())
            v.cve = cve
            out.append(v)
        return advisory_id, out

    @staticmethod
    def _title(soup):
        og = soup.find("meta", attrs={"property": "og:title"})
        if og and og.get("content"):
            return og["content"].strip()
        h1 = soup.find("h1")
        if h1 and h1.get_text(strip=True):
            return h1.get_text(" ", strip=True)
        title = soup.find("title")
        return re.split(r"\s+\|\s+", title.get_text(strip=True))[0] if title else None

    @staticmethod
    def _sections(soup):
        """{heading (lower case): [paragraph texts]} for h2/h3 headings; tables are not text."""
        sections = {}
        for head in soup.find_all(["h2", "h3"]):
            texts = []
            for sib in head.find_next_siblings():
                if sib.name in ("h2", "h3"):
                    break
                if sib.name == "table" or sib.find("table"):
                    continue
                texts += [t for t in sib.get_text("\n", strip=True).split("\n") if t]
            sections.setdefault(head.get_text(" ", strip=True).lower(), texts)
        return sections

    def _score(self, base, meta, html):
        score_text = meta.get("cvssv3 score")
        m = re.search(r"\d+(?:\.\d+)?", score_text or "")
        vector = _VECTOR.search(html)
        if m and vector:
            base.scores.append(Score(vector.group(0)[5:8], vector.group(0), float(m.group(0))))
        elif m:
            base.notes.append(Note("other", f"CVSSv3 score published by Fortinet: {score_text}", "CVSS"))

    def _products(self, base, table):
        for version_cell, affected, solution in table:
            m = _BRANCH.match(version_cell.strip())
            name, branch = (m.group(1), m.group(2)) if m else (version_cell.strip(), None)
            keys = []
            for status, value in parse_affected(affected, branch):
                p = Product(self.vendor_name, name, status=status)
                if isinstance(value, VersionRange):
                    p.version_range = value
                elif value:
                    p.version = value
                base.products.append(p)
                if status == KNOWN_AFFECTED:
                    keys.append(p.key())
            if not keys:
                continue
            for version in _FIXED.findall(solution):
                base.products.append(Product(self.vendor_name, name, version=version, status=FIXED))
            if solution and solution.strip().lower() not in ("not applicable", "n/a"):
                same = next((r for r in base.remediations if r.details == solution.strip()), None)
                if same:   # one remediation per solution text, for all its rows
                    same.product_keys += keys
                else:
                    base.remediations.append(Remediation("vendor_fix", solution.strip(), product_keys=keys))
