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

from advisory_cpe_generator.pipeline import run

from conftest import FIXTURES
from test_adapters import FakeHttp


def test_run_offline_files(config, tmp_path, csaf_validator):
    summary = run(config, vendors=["paloalto"],
                  files=[FIXTURES / "pan_cve_2024_0012.json", FIXTURES / "pan_cve_2024_3400.json"])
    assert summary["paloalto"]["new"] == 2
    # phase 1: the files as given, phase 2: the CSAF documents, in separate directories
    raw = tmp_path / "download" / "paloalto"
    assert (raw / "pan_cve_2024_0012.json").read_bytes() == (FIXTURES / "pan_cve_2024_0012.json").read_bytes()
    assert set(json.loads((raw / "manifest.json").read_text())) == {"pan_cve_2024_0012", "pan_cve_2024_3400"}
    out = tmp_path / "output" / "paloalto"
    for name in ("paloalto_cve_2024_0012.json", "paloalto_cve_2024_3400.json"):
        doc = json.loads((out / name).read_text())
        assert not list(csaf_validator.iter_errors(doc))
    assert (out / "index.txt").read_text().splitlines() == ["paloalto_cve_2024_0012.json",
                                                             "paloalto_cve_2024_3400.json"]
    # enrich again from the downloads: nothing changes
    assert run(config, vendors=["paloalto"], step="enrich")["paloalto"]["unchanged"] == 2
    assert (tmp_path / "cpe_review.csv").exists()


def test_cpe_example_from_another_advisory(config, tmp_path):
    """CVE-2024-3400's record has no cpes; PAN-OS versions get CVE-2024-0012's PAN-OS CPE."""
    run(config, vendors=["paloalto"],
        files=[FIXTURES / "pan_cve_2024_0012.json", FIXTURES / "pan_cve_2024_3400.json"])
    doc = json.loads((tmp_path / "output" / "paloalto" / "paloalto_cve_2024_3400.json").read_text())
    cpes = []

    def walk(branches):
        for b in branches:
            if "product" in b:
                cpes.append((b["name"], b["product"].get("product_identification_helper", {}).get("cpe")))
            walk(b.get("branches", []))
    walk(doc["product_tree"]["branches"])
    fixed = dict(cpes)
    assert fixed["11.1.2-h3"] == "cpe:2.3:o:paloaltonetworks:pan-os:11.1.2:h3:*:*:*:*:*:*"


def test_download_then_enrich(config, tmp_path):
    record = (FIXTURES / "pan_cve_2024_0012.json").read_text()
    pages = {"https://security.paloaltonetworks.com/json": '[{"ID": "CVE-2024-0012", "updated": "2025-01-01"}]',
             "https://security.paloaltonetworks.com/json/CVE-2024-0012": record}
    from advisory_cpe_generator import pipeline
    from advisory_cpe_generator.adapters.paloalto import PaloAltoAdapter

    class Offline(PaloAltoAdapter):
        def __init__(self, conn_config, http=None):
            super().__init__(conn_config, http=FakeHttp(pages))

    pipeline.ADAPTERS = {**pipeline.ADAPTERS, "paloalto": Offline}
    try:
        summary = run(config, vendors=["paloalto"], step="download")
        assert summary["paloalto"]["downloaded"] == 1
        raw = tmp_path / "download" / "paloalto"
        assert (raw / "CVE-2024-0012.json").read_text() == record
        assert (raw / "_list.json").exists()
        assert not (tmp_path / "output").exists()
        assert run(config, vendors=["paloalto"], step="enrich")["paloalto"]["new"] == 1
        # already downloaded, same date: nothing to do
        assert run(config, vendors=["paloalto"])["paloalto"] == {
            "downloaded": 0, "new": 0, "updated": 0, "unchanged": 0, "skipped": 0}
    finally:
        pipeline.ADAPTERS = {**pipeline.ADAPTERS, "paloalto": PaloAltoAdapter}


def test_advisory_without_product_is_not_written(config, tmp_path):
    # A Stormshield page given alone has no product list (it comes from the home page).
    summary = run(config, vendors=["stormshield"], files=[FIXTURES / "stormshield_2025-006.html"])
    assert summary["stormshield"]["skipped"] == 1
    assert not list((tmp_path / "output" / "stormshield").glob("*_cve_*.json"))
