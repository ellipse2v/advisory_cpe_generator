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
Two phases, each over every selected vendor:

1. download: list each vendor's advisories and save the new or updated ones,
   as published, in <download_dir>/<vendor>/ (network only here).
2. enrich: parse the downloaded files, merge the advisories of a vendor per
   CVE, add CPEs and write one CSAF document per CVE in <output_dir>/<vendor>/,
   with the provider index files (no network).

A full run does phase 2 only for the CVEs of the advisories phase 1 got;
--step enrich redoes every CVE (e.g. after editing cpe_mapping.csv).
"""

import logging
from datetime import datetime, timedelta
from pathlib import Path

from . import csaf_writer
from .adapters import ADAPTERS
from .config import connector_config, resolve_path
from .enricher import CpeEnricher
from .model import merge_by_cve
from .storage import Downloads, Storage

log = logging.getLogger(__name__)

STEPS = ("all", "download", "enrich")


def _document_counts():
    return {"new": 0, "updated": 0, "unchanged": 0, "skipped": 0}


def download(adapter, downloads, since=None, full=False, max_advisories=None, history=False):
    """Phase 1 for one vendor: save advisories not downloaded yet (or updated). Returns their ids."""
    known = downloads.manifest(adapter.vendor)
    refs = adapter.list_advisories(since=since, history=history)
    for name, data in adapter.listing.items():
        downloads.save_file(adapter.vendor, name, data)
    todo = [r for r in refs if full or r.id not in known
            or (r.updated and r.updated != known[r.id].get("updated"))]
    if max_advisories:
        todo = todo[:max_advisories]
    log.info("%s: %d advisories to download (%d already downloaded)", adapter.vendor, len(todo), len(known))
    done = set()
    for ref in todo:
        try:
            files = adapter.download(ref)
        except Exception as e:
            log.error("%s %s: %s", adapter.vendor, ref.id, e)
            continue
        downloads.save(adapter.vendor, ref.id, files, ref.url, ref.updated, ref.details)
        done.add(ref.id)
    return done


def import_files(adapter, downloads, paths):
    """Phase 1 from local files: copy them into the download directory. Returns their ids."""
    done = set()
    for path in map(Path, paths):
        adv_id = path.stem
        downloads.save(adapter.vendor, adv_id, {path.name: path.read_bytes()},
                       details={"imported_from": str(path)})
        done.add(adv_id)
    return done


def parse_downloads(adapter, downloads):
    """[Vulnerability] of every downloaded advisory, and {advisory id: CVEs}."""
    vulns, cves = [], {}
    for adv_id, entry, paths in downloads.entries(adapter.vendor):
        for path in paths:
            if not path.exists():
                log.warning("%s %s: %s missing", adapter.vendor, adv_id, path.name)
                continue
            try:
                _, found = adapter.parse_file(path, entry)
            except Exception as e:
                log.error("%s %s: cannot parse %s: %s", adapter.vendor, adv_id, path.name, e)
                continue
            vulns.extend(found)
            cves.setdefault(adv_id, set()).update(v.cve.upper() for v in found)
    return vulns, cves


def enrich(adapter, downloads, storage, enricher, config, advisory_ids=None):
    """
    Phase 2 for one vendor: documents of the CVEs of `advisory_ids` (every CVE
    if None). Every downloaded advisory is parsed: a CVE merges all advisories
    of the vendor that name it, and their CPEs serve as examples.
    """
    vendor = adapter.vendor
    counts = _document_counts()
    vulns, cves_of = parse_downloads(adapter, downloads)
    enricher.learn(vulns)
    wanted = None
    if advisory_ids is not None:
        wanted = set().union(*(cves_of.get(a, set()) for a in advisory_ids))
    for (_, cve), vuln in sorted(merge_by_cve(vulns).items()):
        if wanted is not None and cve not in wanted:
            continue
        if not vuln.products:
            # CSAF requires at least one product; nothing to say without one.
            log.warning("%s %s: no product in %s, not written", vendor, cve, ", ".join(vuln.advisory_ids))
            counts["skipped"] += 1
            continue
        enricher.enrich(vuln)
        tid = csaf_writer.tracking_id(vendor, cve)
        state = storage.write_document(
            vendor, csaf_writer.file_name(tid),
            lambda tracking: csaf_writer.build_document(vuln, config, {**tracking, "id": tid}))
        counts[state] += 1
    storage.write_indexes(vendor)
    return counts


def run(config, vendors=None, since_days=None, full=False, step="all", max_advisories=None, files=None,
        history=False):
    downloads = Downloads(resolve_path(config, config["download_dir"]))
    storage = Storage(resolve_path(config, config["output_dir"]))
    since = datetime.now() - timedelta(days=since_days) if since_days else None
    names = vendors or [n for n, c in config["connectors"].items() if c.get("enabled")]
    adapters = {name: ADAPTERS[name](connector_config(config, name)) for name in names}
    summary = {name: {"downloaded": 0, **_document_counts()} for name in names}

    # Phase 1: every vendor's files first.
    got = {name: None for name in names}   # None: every CVE in phase 2
    if step in ("all", "download"):
        for name, adapter in adapters.items():
            try:
                got[name] = (import_files(adapter, downloads, files) if files
                             else download(adapter, downloads, since, full, max_advisories, history))
            except Exception as e:   # listing failed: the other vendors go on
                log.error("%s: download failed: %s", name, e)
                got[name] = set()
            summary[name]["downloaded"] = len(got[name])
    if step == "download":
        return summary

    # Phase 2: CPEs and CSAF documents.
    enricher = CpeEnricher(config)
    for name, adapter in adapters.items():
        if got[name] is not None and not got[name]:
            log.info("%s: nothing new", name)
            continue
        summary[name].update(enrich(adapter, downloads, storage, enricher, config, got[name]))
        log.info("%s: %s", name, summary[name])
    review = resolve_path(config, config["cpe"].get("review_csv"))
    if review:
        enricher.write_review(review)
        log.info("%d products without CPE listed in %s", len(enricher.review), review)
    return summary
