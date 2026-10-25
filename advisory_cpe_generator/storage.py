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
Two directories:

  <download_dir>/<vendor>/          phase 1: the vendors' files as published
      <advisory>.html|.json|.xml    one or more files per advisory
      _list.*                       the advisory list the files were found in
      manifest.json                 advisory id -> url, updated, files, details

  <output_dir>/<vendor>/            phase 2: the generated CSAF documents
      <vendor>_cve_YYYY_NNNN.json   one per CVE
      index.txt, changes.csv        CSAF provider index files (section 7.1.13/7.1.14)

A document is rewritten only when its content changes; tracking.version is
then incremented and a revision_history entry added.
"""

import copy
import csv
import json
import re
from datetime import datetime, timezone
from pathlib import Path


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


class Downloads:
    """Raw source files of each vendor, and what is known about each advisory."""

    MANIFEST = "manifest.json"

    def __init__(self, download_dir):
        self.root = Path(download_dir)

    def vendor_dir(self, vendor):
        d = self.root / vendor
        d.mkdir(parents=True, exist_ok=True)
        return d

    def manifest(self, vendor):
        path = self.vendor_dir(vendor) / self.MANIFEST
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}

    def _write_manifest(self, vendor, manifest):
        path = self.vendor_dir(vendor) / self.MANIFEST
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(manifest, indent=1, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(path)   # an interrupted run keeps what it already downloaded

    def save_file(self, vendor, name, data):
        path = safe_path(self.vendor_dir(vendor), name)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
        return path

    def save(self, vendor, advisory_id, files, url=None, updated=None, details=None):
        """files: {file name: bytes}. An advisory with no file (e.g. no CSAF) is still recorded."""
        names = [self.save_file(vendor, name, data).name for name, data in files.items()]
        manifest = self.manifest(vendor)
        manifest[advisory_id] = {"url": url, "updated": updated, "downloaded": now_iso(),
                                 "files": names, **(details or {})}
        self._write_manifest(vendor, manifest)

    def entries(self, vendor):
        """[(advisory id, manifest entry, [paths])] sorted by id."""
        d = self.vendor_dir(vendor)
        return [(adv_id, entry, [d / name for name in entry.get("files", [])])
                for adv_id, entry in sorted(self.manifest(vendor).items())]


class Storage:
    """Output directory of the CSAF documents."""

    def __init__(self, output_dir):
        self.root = Path(output_dir)

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
