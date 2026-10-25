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
Run: fetch new advisories per connector, cache them, rebuild the CSAF document
of every CVE they touch (all advisories of that vendor for the CVE are merged),
add CPEs, write the files and the provider indexes.
"""

import logging
from datetime import datetime, timedelta

from . import csaf_writer
from .adapters import ADAPTERS
from .config import connector_config, resolve_path
from .enricher import CpeEnricher
from .model import merge_by_cve
from .storage import Storage

log = logging.getLogger(__name__)


def collect(adapter, storage, since=None, full=False, max_advisories=None):
    """Fetch advisories not cached yet (or updated since); returns the CVEs they touch."""
    cached = storage.cached_ids(adapter.vendor)
    refs = adapter.list_advisories(since=since)
    todo = [r for r in refs if full or r.id not in cached or (r.updated and r.updated != cached[r.id])]
    if max_advisories:
        todo = todo[:max_advisories]
    log.info("%s: %d advisories to fetch (%d already cached)", adapter.vendor, len(todo), len(cached))
    touched = set()
    for ref in todo:
        try:
            vulns = adapter.fetch(ref)
        except Exception as e:
            log.error("%s %s: %s", adapter.vendor, ref.id, e)
            continue
        storage.save_advisory(adapter.vendor, ref.id, vulns, ref.updated)
        touched.update(v.cve.upper() for v in vulns)
    return touched


def import_files(adapter, storage, paths):
    """Cache advisories from local files (offline mode)."""
    touched = set()
    for path in paths:
        adv_id, vulns = adapter.parse_file(path)
        if not vulns:
            continue
        storage.save_advisory(adapter.vendor, adv_id, vulns)
        touched.update(v.cve.upper() for v in vulns)
    return touched


def build(vendor, storage, enricher, config, cves=None):
    """Write the documents of `cves` (all cached CVEs if None). Returns {state: count}."""
    counts = {"new": 0, "updated": 0, "unchanged": 0, "skipped": 0}
    merged = merge_by_cve(storage.load_vulnerabilities(vendor, cves))
    for (_, cve), vuln in sorted(merged.items()):
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


def run(config, vendors=None, since_days=None, full=False, rebuild=False, max_advisories=None,
        files=None):
    storage = Storage(resolve_path(config, config["output_dir"]))
    enricher = CpeEnricher(config)
    since = datetime.now() - timedelta(days=since_days) if since_days else None
    names = vendors or [n for n, c in config["connectors"].items() if c.get("enabled")]
    summary = {}
    for name in names:
        adapter = ADAPTERS[name](connector_config(config, name))
        if files:
            touched = import_files(adapter, storage, files)
        elif rebuild:
            touched = None
        else:
            touched = collect(adapter, storage, since, full, max_advisories)
        if touched is not None and not touched:
            log.info("%s: nothing new", name)
            summary[name] = {"new": 0, "updated": 0, "unchanged": 0, "skipped": 0}
            continue
        summary[name] = build(name, storage, enricher, config, touched)
        log.info("%s: %s", name, summary[name])
    review = resolve_path(config, config["cpe"].get("review_csv"))
    if review:
        enricher.write_review(review)
        log.info("%d products without CPE listed in %s", len(enricher.review), review)
    return summary
