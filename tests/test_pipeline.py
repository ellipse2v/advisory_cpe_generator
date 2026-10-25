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


def test_run_offline_files(config, tmp_path, csaf_validator):
    summary = run(config, vendors=["paloalto"],
                  files=[FIXTURES / "pan_cve_2024_0012.json", FIXTURES / "pan_cve_2024_3400.json"])
    assert summary["paloalto"]["new"] == 2
    out = tmp_path / "output" / "paloalto"
    for name in ("paloalto_cve_2024_0012.json", "paloalto_cve_2024_3400.json"):
        doc = json.loads((out / name).read_text())
        assert not list(csaf_validator.iter_errors(doc))
    assert (out / "index.txt").read_text().splitlines() == ["paloalto_cve_2024_0012.json",
                                                             "paloalto_cve_2024_3400.json"]
    # a rebuild from the cache changes nothing
    assert run(config, vendors=["paloalto"], rebuild=True)["paloalto"]["unchanged"] == 2
    assert (tmp_path / "cpe_review.csv").exists()


def test_advisory_without_product_is_not_written(config, tmp_path):
    # A saved Stormshield page has no product list (it comes from the home page).
    summary = run(config, vendors=["stormshield"], files=[FIXTURES / "stormshield_2025-006.html"])
    assert summary["stormshield"]["skipped"] == 1
    assert not list((tmp_path / "output" / "stormshield").glob("*_cve_*.json"))
