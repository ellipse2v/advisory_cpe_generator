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
import json

from advisory_cpe_generator import csaf_writer
from advisory_cpe_generator.adapters import CiscoAdapter, PaloAltoAdapter, StormshieldAdapter
from advisory_cpe_generator.config import connector_config
from advisory_cpe_generator.enricher import CpeEnricher
from advisory_cpe_generator.model import Product, Vulnerability, merge_by_cve
from advisory_cpe_generator.storage import Storage

from conftest import FIXTURES


def _vulns(config):
    yield StormshieldAdapter(connector_config(config, "stormshield")).parse_file(
        FIXTURES / "stormshield_2025-006.html", products=["Stormshield Network VPN Client"])[1][0]
    for name in ("pan_cve_2024_0012.json", "pan_cve_2024_3400.json"):
        yield PaloAltoAdapter(connector_config(config, "paloalto")).parse_file(FIXTURES / name)[1][0]
    yield CiscoAdapter(connector_config(config, "cisco")).parse_file(
        FIXTURES / "cisco-sa-20180328-smi2.json")[1][0]


def _tracking(tid):
    return {"id": tid, "status": "final", "version": "1",
            "initial_release_date": "2026-10-25T10:00:00Z", "current_release_date": "2026-10-25T10:00:00Z",
            "revision_history": [{"number": "1", "date": "2026-10-25T10:00:00Z", "summary": "Initial version."}]}


def test_documents_validate_against_csaf_schema(config, csaf_validator):
    enricher = CpeEnricher(config, mapping={})
    for vuln in _vulns(config):
        enricher.enrich(vuln)
        tid = csaf_writer.tracking_id(vuln.vendor, vuln.cve)
        doc = csaf_writer.build_document(vuln, config, _tracking(tid))
        errors = sorted(csaf_validator.iter_errors(doc), key=str)
        assert not errors, f"{tid}: {errors[0].message} at {list(errors[0].absolute_path)}"
        # every product_id used is defined in the product tree
        defined = set()

        def walk(branches):
            for b in branches:
                if "product" in b:
                    defined.add(b["product"]["product_id"])
                walk(b.get("branches", []))
        walk(doc["product_tree"].get("branches", []))
        defined |= {p["product_id"] for p in doc["product_tree"].get("full_product_names", [])}
        used = {pid for ids in doc["vulnerabilities"][0]["product_status"].values() for pid in ids}
        assert used <= defined


def test_file_name_matches_tracking_id():
    tid = csaf_writer.tracking_id("stormshield", "CVE-2024-1234")
    assert tid == "stormshield_cve_2024_1234"
    assert csaf_writer.file_name(tid) == "stormshield_cve_2024_1234.json"


def test_range_has_no_cpe_and_cpe_is_in_helper(config):
    v = Vulnerability("paloalto", "Palo Alto Networks", "CVE-2024-0012", products=[
        Product("Palo Alto Networks", "PAN-OS", version="11.2.3", cpe="cpe:2.3:o:paloaltonetworks:pan-os:11.2.3:-:*:*:*:*:*:*")])
    doc = csaf_writer.build_document(v, config, _tracking("paloalto_cve_2024_0012"))
    leaf = doc["product_tree"]["branches"][0]["branches"][0]["branches"][0]
    assert leaf["category"] == "product_version"
    assert leaf["product"]["product_identification_helper"]["cpe"].endswith(":11.2.3:-:*:*:*:*:*:*")


def test_merge_two_advisories_same_cve():
    a = Vulnerability("stormshield", "Stormshield", "CVE-2024-1", advisory_ids=["2024-001"],
                      products=[Product("Stormshield", "SNS", version="4.3.1")])
    b = Vulnerability("stormshield", "Stormshield", "CVE-2024-1", advisory_ids=["2024-002"],
                      products=[Product("Stormshield", "SNS", version="4.3.1"),
                                Product("Stormshield", "SMC", version="3.0")])
    [merged] = merge_by_cve([a, b]).values()
    assert merged.advisory_ids == ["2024-001", "2024-002"]
    assert len(merged.products) == 2


def test_storage_versioning(tmp_path, config):
    storage = Storage(tmp_path)
    v = Vulnerability("stormshield", "Stormshield", "CVE-2024-1", advisory_ids=["2024-001"],
                      products=[Product("Stormshield", "SNS", version="4.3.1")])
    tid = csaf_writer.tracking_id(v.vendor, v.cve)
    build = lambda t: csaf_writer.build_document(v, config, {**t, "id": tid})  # noqa: E731
    name = csaf_writer.file_name(tid)
    assert storage.write_document("stormshield", name, build) == "new"
    assert storage.write_document("stormshield", name, build) == "unchanged"
    v.products.append(Product("Stormshield", "SNS", version="4.3.2"))
    assert storage.write_document("stormshield", name, build) == "updated"
    doc = json.loads((tmp_path / "stormshield" / name).read_text())
    assert doc["document"]["tracking"]["version"] == "2"
    assert len(doc["document"]["tracking"]["revision_history"]) == 2
    storage.write_indexes("stormshield")
    assert (tmp_path / "stormshield" / "index.txt").read_text() == name + "\n"
    assert name in (tmp_path / "stormshield" / "changes.csv").read_text()
