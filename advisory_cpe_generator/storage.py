"""
Output directory:

  <output_dir>/<vendor>/<vendor>_cve_YYYY_NNNN.json   one CSAF document per CVE
  <output_dir>/<vendor>/index.txt, changes.csv        CSAF provider index files (section 7.1.13/7.1.14)
  <output_dir>/.cache/<vendor>/<advisory>.json        parsed advisories, to rebuild without network

A document is rewritten only when its content changes; tracking.version is
then incremented and a revision_history entry added.
"""

import copy
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from .model import Vulnerability


def now_iso():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def safe_path(directory, filename):
    """Path inside directory; identifiers come from remote data (from stormshieldParser)."""
    safe_name = re.sub(r"[^A-Za-z0-9._+-]", "_", str(filename)).lstrip(".")
    if not safe_name:
        raise ValueError(f"Invalid output filename: {filename!r}")
    base = Path(directory).resolve()
    target = (base / safe_name).resolve()
    if target.parent != base:
        raise ValueError(f"Output path escapes directory: {filename!r}")
    return target


class Storage:
    def __init__(self, output_dir):
        self.root = Path(output_dir)

    # -- advisory cache ------------------------------------------------------

    def _cache_dir(self, vendor):
        d = self.root / ".cache" / vendor
        d.mkdir(parents=True, exist_ok=True)
        return d

    def cached_ids(self, vendor):
        return {p.stem: json.loads(p.read_text(encoding="utf-8")).get("updated")
                for p in self._cache_dir(vendor).glob("*.json")}

    def save_advisory(self, vendor, advisory_id, vulnerabilities, updated=None):
        path = safe_path(self._cache_dir(vendor), f"{advisory_id}.json")
        payload = {"advisory_id": advisory_id, "updated": updated,
                   "vulnerabilities": [v.to_dict() for v in vulnerabilities]}
        path.write_text(json.dumps(payload, indent=1, ensure_ascii=False), encoding="utf-8")

    def load_vulnerabilities(self, vendor, cves=None):
        """Every cached vulnerability of a vendor, optionally only some CVEs."""
        out = []
        for p in sorted(self._cache_dir(vendor).glob("*.json")):
            for d in json.loads(p.read_text(encoding="utf-8"))["vulnerabilities"]:
                if cves is None or d["cve"].upper() in cves:
                    out.append(Vulnerability.from_dict(d))
        return out

    # -- CSAF documents ----------------------------------------------------

    def vendor_dir(self, vendor):
        d = self.root / vendor
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write_document(self, vendor, filename, build):
        """
        build(tracking) -> CSAF dict. Returns 'new', 'updated' or 'unchanged'.
        """
        path = safe_path(self.vendor_dir(vendor), filename)
        previous = json.loads(path.read_text(encoding="utf-8")) if path.exists() else None
        now = now_iso()
        if previous is None:
            tracking = {"id": None, "status": "final", "version": "1",
                        "initial_release_date": now, "current_release_date": now,
                        "revision_history": [{"number": "1", "date": now, "summary": "Initial version."}]}
            state = "new"
        else:
            tracking = copy.deepcopy(previous["document"]["tracking"])
            tracking.pop("generator", None)
            state = "unchanged"

        doc = build(tracking)
        if previous is not None:
            if _comparable(doc) == _comparable(previous):
                return "unchanged"
            number = str(int(tracking["version"]) + 1)
            tracking.update(version=number, current_release_date=now)
            tracking["revision_history"].append(
                {"number": number, "date": now, "summary": "Content updated."})
            doc = build(tracking)
            state = "updated"
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return state

    def write_indexes(self, vendor):
        """index.txt and changes.csv as a CSAF provider directory has them."""
        d = self.vendor_dir(vendor)
        entries = []
        for p in sorted(d.glob("*.json")):
            tracking = json.loads(p.read_text(encoding="utf-8"))["document"]["tracking"]
            entries.append((p.name, tracking["current_release_date"]))
        (d / "index.txt").write_text("".join(f"{name}\n" for name, _ in entries), encoding="utf-8")
        with open(d / "changes.csv", "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh, quoting=csv.QUOTE_ALL)
            for name, date in sorted(entries, key=lambda e: e[1], reverse=True):
                writer.writerow([name, date])


def _comparable(doc):
    """The document without the fields that change at every generation."""
    d = copy.deepcopy(doc)
    d["document"].pop("tracking", None)
    return d
