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
CPE resolution for every product of a vulnerability, in this order:

1. CPE given by the source (kept if it is a valid CPE 2.3 string)
2. example: the vendor gave a CPE for another version of the same product, in
   this advisory or in another downloaded advisory of the vendor; that CPE is
   reused with the version replaced
3. manual table cpe_mapping.csv (vendor, product -> part, cpe vendor, cpe product)
4. NVD dictionary, exact product name (cpeMiniLLMLevenshtein's cache and aliases)
5. cpeMiniLLMLevenshtein's semantic matcher (skipped when sentence-transformers
   is not installed)
6. otherwise no CPE: the product goes to cpe_review.csv, nothing is guessed

A product with no exact version (range, or no version at all) never gets a
wildcard CPE, which would mark every version as affected. When the NVD
product is known, the range can instead be expanded into the versions the
dictionary lists (one product per version, each with its own CPE).
"""

import csv
import gzip
import json
import logging
import re
import sys
from pathlib import Path

from . import cpe as cpe_lib
from .config import resolve_path
from .model import Product

log = logging.getLogger(__name__)


def _norm(text):
    return re.sub(r"[^a-z0-9]+", " ", str(text).lower()).strip()


def load_mapping(path):
    """{(normalized vendor, normalized product): (part, cpe_vendor, cpe_product)}"""
    mapping = {}
    if not path or not Path(path).exists():
        return mapping
    with open(path, newline="", encoding="utf-8") as fh:
        rows = (r for r in csv.DictReader(fh) if r.get("vendor") and not r["vendor"].startswith("#"))
        for r in rows:
            mapping[(_norm(r["vendor"]), _norm(r["product"]))] = (
                r["cpe_part"].strip(), r["cpe_vendor"].strip(), r["cpe_product"].strip())
    return mapping


class Examples:
    """
    CPEs a vendor published for some versions of a product, used as templates
    for its other versions: (vendor, product name) -> CPE (part, vendor, product).
    A name the vendor published under two different CPE products is ambiguous
    and not used.
    """

    def __init__(self):
        self.templates = {}   # (vendor, name) -> {(part, cpe vendor, cpe product): splits update}

    def add(self, products):
        for p in products:
            if not (p.cpe and p.version and cpe_lib.is_valid_cpe23(p.cpe)):
                continue
            parts = cpe_lib.split_cpe(p.cpe)
            if parts[5] in ("*", "-"):
                continue   # a CPE for every version is not an example of one version
            keys = self.templates.setdefault((_norm(p.vendor), _norm(p.name)), {})
            key = tuple(parts[2:5])
            # Palo Alto writes the hotfix in the update field (11.2.2 + h1, 11.2.3 + -).
            keys[key] = keys.get(key, False) or parts[6] != "*"
        return self

    def get(self, product):
        """(part, vendor, product, splits update) or None."""
        keys = self.templates.get((_norm(product.vendor), _norm(product.name)))
        if not keys or len(keys) > 1:
            return None
        [(key, splits)] = keys.items()
        return (*key, splits)

    @staticmethod
    def cpe(template, version):
        part, vendor, product, splits = template
        if not splits:
            return cpe_lib.build(part, vendor, product, version)
        m = re.match(r"^(.+?)-([a-z][a-z0-9]*)$", version, re.I)
        version, update = (m.group(1), m.group(2).lower()) if m else (version, "-")
        return cpe_lib.build(part, vendor, product, version, cpe_lib.escape(update))


class NvdDictionary:
    """
    Exact lookups in the NVD CPE dictionary through cpeMiniLLMLevenshtein's
    ProductIndex (no embeddings, no model).
    """

    def __init__(self, index, matcher_module):
        self.index = index
        self.m = matcher_module

    @classmethod
    def load(cls, matcher_path):
        m = import_matcher(matcher_path)
        root = Path(matcher_path)
        data_path = root / "cpe_data.json.gz"
        log.info("Loading NVD CPE dictionary from %s", data_path)
        with gzip.open(data_path, "rb") as fh:
            data = json.loads(fh.read().decode("utf-8"))
        index = m.ProductIndex(data["cpe_items"], data.get("titles", []))
        index.set_aliases(m.load_aliases(str(root / "cpe_aliases.csv")))
        log.info("NVD dictionary: %d products", len(index))
        return cls(index, m)

    def identify(self, vendor, product):
        """NVD (part, vendor, product) keys whose product name matches exactly and vendor agrees."""
        idx = self.index
        aliased = idx.alias_targets(vendor, product)
        # With and without the vendor prefix, and without a trailing "Software"
        # ("Cisco IOS XE Software" -> ios_xe).
        variants = self.m.product_variants(vendor, product)
        variants += [re.sub(r"\s+software$", "", v, flags=re.I) for v in variants
                     if re.search(r"\s+software$", v, re.I)]
        exact = {idx.keys[pid] for pid in aliased}
        candidates = set()
        for v in variants:
            candidates |= idx.lexical_candidates(vendor, v)
        for pid in candidates:
            _, cpe_vendor, cpe_product = idx.keys[pid]
            if self.m.vendor_similarity(vendor, cpe_vendor) < 0.8:
                continue
            if any(self.m.product_similarity(v, cpe_product) >= 0.999 for v in variants):
                exact.add(idx.keys[pid])
        return sorted(exact)

    def resolve(self, key, version):
        """Dictionary CPE for that version, or the product CPE with the version substituted."""
        pid = self.index.key_to_id[key]
        cpe, _, _, _ = self.index.resolve_version(pid, version)
        return cpe

    def versions(self, key):
        """[(readable version, CPE)] for every non-wildcard CPE of that product."""
        pid = self.index.key_to_id[key]
        out = []
        for bucket in self.index.versions[pid].values():
            for i in bucket:
                cpe = self.index.cpe_items[i]
                version = cpe_lib.cpe_version(cpe)
                if version:
                    out.append((version, cpe))
        return out


def import_matcher(matcher_path):
    src = Path(matcher_path) / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))
    from cpe_matcher import cpe_matcher  # noqa: E402  (cpeMiniLLMLevenshtein)
    return cpe_matcher


class SemanticMatcher:
    """cpeMiniLLMLevenshtein's CPEMatcher (sentence-transformers model + embeddings)."""

    def __init__(self, matcher_path, min_score):
        m = import_matcher(matcher_path)
        self.matcher = m.CPEMatcher()
        self.matcher.load_data()
        self.min_score = min_score

    def match(self, queries):
        """queries: [(vendor, product, version)] -> [cpe or None, best score]"""
        results = self.matcher.search_batch(queries, num_results=2)
        out = []
        for res in results:
            if res and res[0]["score"] >= self.min_score:
                out.append((res[0]["cpe"], res[0]["score"]))
            else:
                out.append((None, res[0]["score"] if res else 0.0))
        return out


class CpeEnricher:
    def __init__(self, config, dictionary=None, semantic=None, mapping=None):
        self.cfg = config["cpe"]
        self.mapping = mapping if mapping is not None else load_mapping(
            resolve_path(config, self.cfg.get("mapping_csv")))
        matcher_path = resolve_path(config, self.cfg.get("matcher_path"))
        self._dictionary = dictionary
        self._semantic = semantic
        self._matcher_path = matcher_path
        self.examples = Examples()   # vendor-wide, filled by learn()
        self.review = []   # rows for cpe_review.csv

    def learn(self, vulns):
        """Remember the CPEs the vendor published, as examples for other versions."""
        if self.cfg.get("use_examples", True):
            for vuln in vulns:
                self.examples.add(vuln.products)

    # Heavy resources are loaded only when a product actually needs them.
    @property
    def dictionary(self):
        if self._dictionary is None and self.cfg.get("use_dictionary") and self._matcher_path:
            try:
                self._dictionary = NvdDictionary.load(self._matcher_path)
            except Exception as e:  # missing checkout, missing numpy/Levenshtein...
                log.warning("NVD dictionary unavailable (%s): step skipped", e)
                self._dictionary = False
        return self._dictionary or None

    @property
    def semantic(self):
        if self._semantic is None and self.cfg.get("use_semantic_matcher") and self._matcher_path:
            try:
                self._semantic = SemanticMatcher(self._matcher_path, float(self.cfg.get("min_score", 0.65)))
            except ImportError as e:
                log.warning("LLM matcher skipped: %s (pip install sentence-transformers torch)", e)
                self._semantic = False
            except Exception as e:
                log.warning("LLM matcher unavailable (%s): step skipped", e)
                self._semantic = False
        return self._semantic or None

    def enrich(self, vuln):
        """Set product.cpe / cpe_origin in place; may add expanded range products."""
        pending = []
        named_with_source_cpe = {(p.vendor.lower(), p.name.lower()) for p in vuln.products
                                 if p.cpe and cpe_lib.is_valid_cpe23(p.cpe)}
        local = Examples().add(vuln.products) if self.cfg.get("use_examples", True) else Examples()
        added = []
        for product in vuln.products:
            if product.cpe:
                if cpe_lib.is_valid_cpe23(product.cpe):
                    product.cpe_origin = "source"
                    continue
                self._report(vuln, product, "invalid CPE from source dropped: " + product.cpe)
                product.cpe = None
            key = self._identify(product, local)
            if key and product.version:
                product.cpe = key[1](product.version)
                product.cpe_origin = key[0]
            elif key and product.version_range and self.cfg.get("expand_ranges") \
                    and (product.vendor.lower(), product.name.lower()) not in named_with_source_cpe:
                added.extend(self._expand(vuln, product, key[2]))
            elif not key and product.version:
                pending.append(product)
            elif not product.version:
                self._report(vuln, product, "no exact version: no CPE")
            else:
                self._report(vuln, product, "product not found")
        vuln.products.extend(added)
        self._semantic_pass(vuln, pending)
        return vuln

    def _identify(self, product, local):
        """(origin, version -> CPE function, CPE product key), or None."""
        template = local.get(product) or self.examples.get(product)
        if template:
            return "source-example", (lambda v: Examples.cpe(template, v)), template[:3]
        mapped = self.mapping.get((_norm(product.vendor), _norm(product.name)))
        if mapped:
            part, vendor, name = mapped
            return "mapping", (lambda v: cpe_lib.build(part, vendor, name, v)), (part, vendor, name)
        dictionary = self.dictionary
        if dictionary:
            keys = dictionary.identify(product.vendor, product.name)
            if len(keys) == 1:
                key = keys[0]
                return "nvd-dictionary", (lambda v: dictionary.resolve(key, v)), key
            if len(keys) > 1:
                log.info("%s %s: ambiguous in NVD (%s)", product.vendor, product.name,
                         ", ".join(":".join(k) for k in keys))
        return None

    def _expand(self, vuln, product, key):
        dictionary = self.dictionary
        if not dictionary or key not in dictionary.index.key_to_id:
            self._report(vuln, product, "range not expanded (product not in NVD dictionary)")
            return []
        expanded = []
        for version, cpe in dictionary.versions(key):
            if product.version_range.contains(version):
                expanded.append(Product(vendor=product.vendor, name=product.name, version=version,
                                        status=product.status, cpe=cpe, cpe_origin="nvd-range"))
        if not expanded:
            self._report(vuln, product, "range not expanded (no NVD version in range)")
        return expanded

    def _semantic_pass(self, vuln, products):
        if not products:
            return
        matcher = self.semantic
        if not matcher:
            for p in products:
                self._report(vuln, p, "product not found")
            return
        results = matcher.match([(p.vendor, p.name, p.version) for p in products])
        for p, (cpe, score) in zip(products, results):
            if cpe and cpe_lib.is_valid_cpe23(cpe):
                p.cpe, p.cpe_origin = cpe, "nvd-matcher"
            else:
                self._report(vuln, p, f"matcher below threshold (best score {score:.2f})")

    def _report(self, vuln, product, reason):
        self.review.append({
            "vendor": vuln.vendor, "cve": vuln.cve, "product_vendor": product.vendor,
            "product": product.name, "version": product.label() or "", "status": product.status,
            "reason": reason,
        })

    def write_review(self, path):
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["vendor", "cve", "product_vendor", "product",
                                                    "version", "status", "reason"])
            writer.writeheader()
            writer.writerows(self.review)
