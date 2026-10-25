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
from advisory_cpe_generator.adapters import CiscoAdapter, PaloAltoAdapter, StormshieldAdapter
from advisory_cpe_generator.adapters.stormshield import parse_versions
from advisory_cpe_generator.config import connector_config
from advisory_cpe_generator.model import FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED

from conftest import FIXTURES


def test_stormshield_page(config):
    adapter = StormshieldAdapter(connector_config(config, "stormshield"))
    adv_id, vulns = adapter.parse_file(FIXTURES / "stormshield_2025-006.html",
                                       products=["Stormshield Network VPN Client"])
    assert adv_id == "2025-006"
    [v] = vulns
    assert v.cve == "CVE-2025-11955"
    assert v.advisory_ids == ["STORM-2025-006"]
    assert v.release_date == "2025-11-27T12:00:00+01:00"
    assert [(p.name, p.version, p.status) for p in v.products] == [
        ("Stormshield Network VPN Client", "7.5.109", KNOWN_AFFECTED)]
    # Score without vector: kept as text, not as a CSAF score
    assert v.scores == []
    assert any("8.1" in n.text for n in v.notes)
    assert {r.category for r in v.remediations} == {"workaround", "vendor_fix", "mitigation"}


def test_stormshield_version_parsing():
    kinds = parse_versions("SNS 4.3.0 to 4.3.20 and 4.6.0")
    assert kinds[0][0] == "range"
    assert (kinds[0][1].introduced, kinds[0][1].last_affected) == ("4.3.0", "4.3.20")
    assert kinds[1] == ("exact", "4.6.0")
    [(kind, rng)] = parse_versions("versions prior to 3.11.24")
    assert kind == "range" and rng.fixed == "3.11.24"
    assert parse_versions("published 2025-11-27") == []


def test_paloalto_cve_record(config):
    adapter = PaloAltoAdapter(connector_config(config, "paloalto"))
    adv_id, [v] = adapter.parse_file(FIXTURES / "pan_cve_2024_0012.json")
    assert adv_id == v.cve == "CVE-2024-0012"
    assert v.cwes == [("CWE-306", "Missing Authentication for Critical Function")]
    panos = [p for p in v.products if p.name == "PAN-OS"]
    with_cpe = [p for p in panos if p.cpe]
    assert with_cpe and all(p.cpe.startswith("cpe:2.3:o:paloaltonetworks:pan-os:") for p in with_cpe)
    assert any(p.version == "11.2.2-h1" for p in with_cpe)       # update field folded into the version
    ranges = [p for p in panos if p.version_range]
    assert any(r.version_range.vers() == "vers:generic/>=11.2.0|<11.2.4-h1" for r in ranges)
    assert any(p.status == FIXED and p.version == "11.2.4-h1" for p in panos)
    assert any(p.name == "Cloud NGFW" and p.status == KNOWN_NOT_AFFECTED and not p.version for p in v.products)
    # CVSS v4 is not a CSAF 2.0 score: kept as a note
    assert any(n.title == "CVSS v4.0" for n in v.notes)


def test_paloalto_record_without_cpes(config):
    adapter = PaloAltoAdapter(connector_config(config, "paloalto"))
    _, [v] = adapter.parse_file(FIXTURES / "pan_cve_2024_3400.json")
    assert v.scores[0].version == "3.1" and v.scores[0].base_score == 10.0
    assert not any(p.cpe for p in v.products)


def test_paloalto_not_a_cve_record(config):
    adapter = PaloAltoAdapter(connector_config(config, "paloalto"))
    assert adapter.parse_record({"id": "PAN-SA-2024-0001"}, "PAN-SA-2024-0001") == []


def test_cisco_csaf(config):
    adapter = CiscoAdapter(connector_config(config, "cisco"))
    adv_id, [v] = adapter.parse_file(FIXTURES / "cisco-sa-20180328-smi2.json")
    assert adv_id == "cisco-sa-20180328-smi2"
    assert v.cve == "CVE-2018-0171"
    assert v.scores[0].version == "3.0" and v.scores[0].base_score == 9.8
    ios = {p.version for p in v.products if p.name == "IOS"}
    assert "12.2(55)SE" in ios
    assert all(p.vendor == "Cisco" for p in v.products)


class FakeHttp:
    """Serves fixtures instead of the network."""

    def __init__(self, pages):
        self.pages = pages

    def get(self, url, **kwargs):
        return type("R", (), {"content": self.pages[url]})()

    def get_json(self, url, **kwargs):
        import json
        return json.loads(self.pages[url])


def test_stormshield_list_and_fetch(config):
    home = b"""<html><script>var advisories_list = [
        {ID: '2025-006', link: 'https://advisories.stormshield.eu/2025-006/',
         products: [['Stormshield Network VPN Client', 'vpn'],],},
        {ID: '2025-006', link: 'https://advisories.stormshield.eu/2025-006/', products: []},
    ];</script></html>"""
    http = FakeHttp({"https://advisories.stormshield.eu": home,
                     "https://advisories.stormshield.eu/2025-006/":
                         (FIXTURES / "stormshield_2025-006.html").read_bytes()})
    adapter = StormshieldAdapter(connector_config(config, "stormshield"), http=http)
    [ref] = adapter.list_advisories()
    assert ref.extra["products"] == ["Stormshield Network VPN Client"]
    [v] = adapter.fetch(ref)
    assert v.products[0].version == "7.5.109"


def test_paloalto_list_and_fetch(config):
    record = (FIXTURES / "pan_cve_2024_0012.json").read_text()
    http = FakeHttp({"https://security.paloaltonetworks.com/json": '[{"ID": "CVE-2024-0012", "updated": "2025-01-01"}]',
                     "https://security.paloaltonetworks.com/json/CVE-2024-0012": record})
    adapter = PaloAltoAdapter(connector_config(config, "paloalto"), http=http)
    [ref] = adapter.list_advisories()
    [v] = adapter.fetch(ref)
    assert v.cve == "CVE-2024-0012"
