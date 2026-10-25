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
import re

from advisory_cpe_generator.adapters import (CiscoAdapter, FortinetAdapter, OracleAdapter, PaloAltoAdapter,
                                             StormshieldAdapter)
from advisory_cpe_generator.adapters.stormshield import parse_versions
from advisory_cpe_generator.config import connector_config
from advisory_cpe_generator.model import FIXED, KNOWN_AFFECTED, KNOWN_NOT_AFFECTED, Score

from conftest import FIXTURES


def test_stormshield_page(config):
    adapter = StormshieldAdapter(connector_config(config, "stormshield"))
    adv_id, vulns = adapter.parse_file(FIXTURES / "stormshield_2025-006.html",
                                       {"products": ["Stormshield Network VPN Client"]})
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
        body = self.pages[url]
        body = body.encode() if isinstance(body, str) else body
        return type("R", (), {"content": body, "text": body.decode("utf-8")})()

    def get_json(self, url, **kwargs):
        import json
        return json.loads(self.pages[url])


def fetch(adapter, ref, directory):
    """Phase 1 then phase 2 on one advisory, as the pipeline does."""
    vulns = []
    for name, data in adapter.download(ref).items():
        path = directory / name
        path.write_bytes(data)
        vulns += adapter.parse_file(path, {"url": ref.url, **ref.details})[1]
    return vulns


def test_stormshield_list_and_fetch(config, tmp_path):
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
    assert ref.details["products"] == ["Stormshield Network VPN Client"]
    assert adapter.listing == {"_list.html": home}
    [v] = fetch(adapter, ref, tmp_path)
    assert v.products[0].version == "7.5.109"


def test_paloalto_list_and_fetch(config, tmp_path):
    record = (FIXTURES / "pan_cve_2024_0012.json").read_text()
    http = FakeHttp({"https://security.paloaltonetworks.com/json": '[{"ID": "CVE-2024-0012", "updated": "2025-01-01"}]',
                     "https://security.paloaltonetworks.com/json/CVE-2024-0012": record})
    adapter = PaloAltoAdapter(connector_config(config, "paloalto"), http=http)
    [ref] = adapter.list_advisories()
    [v] = fetch(adapter, ref, tmp_path)
    assert v.cve == "CVE-2024-0012"
    assert (tmp_path / "CVE-2024-0012.json").read_text() == record   # saved as published


def test_oracle_cpu_csaf(config):
    adapter = OracleAdapter(connector_config(config, "oracle"))
    adv_id, vulns = adapter.parse_file(FIXTURES / "oracle_cpujul2026_excerpt.json")
    assert adv_id == "CPUJul2026csaf"
    by_cve = {v.cve: v for v in vulns}
    v = by_cve["CVE-2014-3643"]
    [p] = v.products
    # "Oracle Enterprise Manager for Fusion Middleware(...) Version 13.5" -> 13.5
    assert (p.name, p.version) == ("Oracle Enterprise Manager for Fusion Middleware", "13.5")
    assert p.cpe == "cpe:2.3:a:oracle:enterprise_manager_for_fusion_middleware:13.5:*:*:*:*:*:*:*"
    assert v.scores[0].vector.startswith("CVSS:3.1/")
    assert by_cve["CVE-2020-8908"].products[0].status == KNOWN_NOT_AFFECTED


def test_oracle_list_and_fetch(config, tmp_path):
    alerts = '<a href="/security-alerts/cpujul2026.html">July 2026</a><a href="/security-alerts/cpujul2026.html">x</a>'
    cpu = '<a href="https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json">CSAF</a>'
    http = FakeHttp({"https://www.oracle.com/security-alerts/": alerts,
                     "https://www.oracle.com/security-alerts/cpujul2026.html": cpu,
                     "https://www.oracle.com/docs/tech/security-alerts/cpujul2026csaf.json":
                         (FIXTURES / "oracle_cpujul2026_excerpt.json").read_text()})
    adapter = OracleAdapter(connector_config(config, "oracle"), http=http)
    [ref] = adapter.list_advisories()
    assert ref.id == "cpujul2026"
    assert len(fetch(adapter, ref, tmp_path)) == 3
    assert ref.details["csaf_url"].endswith("cpujul2026csaf.json")


def test_cvrf_matches_csaf_of_same_advisory(config):
    """
    OASIS publishes cisco-sa-20180328-smi2 in both formats (not the same revision,
    so the version lists differ a little): same CVE, product names, score.
    """
    cvrf_id, [from_cvrf] = FortinetAdapter(connector_config(config, "fortinet")).parse_file(
        FIXTURES / "cisco-sa-20180328-smi2_cvrf.xml")
    _, [from_csaf] = CiscoAdapter(connector_config(config, "cisco")).parse_file(
        FIXTURES / "cisco-sa-20180328-smi2.json")
    assert cvrf_id == "cisco-sa-20180328-smi2"
    assert from_cvrf.cve == from_csaf.cve
    assert {p.name for p in from_cvrf.products} == {p.name for p in from_csaf.products}
    common = {(p.name, p.version) for p in from_cvrf.products} & {(p.name, p.version) for p in from_csaf.products}
    assert ("IOS", "12.2(55)SE") in common and len(common) > 150
    assert from_cvrf.scores[0] == from_csaf.scores[0]
    assert from_cvrf.remediations[0].category == "workaround"


# RSS item shape as described for filestore.fortinet.com/fortiguard/rss/ir.xml (not a copy of the feed).
RSS = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:csaf="https://fortiguard.fortinet.com/rss/ns/csaf"
     xmlns:cvrf="https://fortiguard.fortinet.com/rss/ns/cvrf"><channel>
<item><title>Example with CSAF</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-26-186</link>
<pubDate>Wed, 21 Oct 2026 00:00:00 -0700</pubDate>
<csaf:link>https://filestore.fortinet.com/fortiguard/psirt/csaf_example_fg-ir-26-186.json</csaf:link>
<cvrf:link>https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-26-186</cvrf:link></item>
<item><title>Example with CVRF only</title><link>https://fortiguard.fortinet.com/psirt/FG-IR-20-005</link>
<pubDate>Tue, 13 Oct 2026 00:00:00 -0700</pubDate>
<cvrf:link>https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-20-005</cvrf:link></item>
</channel></rss>"""


def test_fortinet_rss_prefers_csaf_then_html_then_cvrf(config, tmp_path):
    http = FakeHttp({
        "https://filestore.fortinet.com/fortiguard/rss/ir.xml": RSS,
        "https://filestore.fortinet.com/fortiguard/psirt/csaf_example_fg-ir-26-186.json":
            (FIXTURES / "cisco-sa-20180328-smi2.json").read_text(),
        "https://fortiguard.fortinet.com/psirt/cvrf/FG-IR-20-005":
            (FIXTURES / "cisco-sa-20180328-smi2_cvrf.xml").read_bytes()})
    adapter = FortinetAdapter(connector_config(config, "fortinet"), http=http)
    a, b = adapter.list_advisories()
    assert (a.id, a.updated) == ("FG-IR-26-186", "2026-10-21")
    assert a.details["urls"]["csaf"].endswith("csaf_example_fg-ir-26-186.json")              # RSS link first
    assert b.details["urls"]["csaf"] == "https://www.fortiguard.com/psirt/FG-IR-20-005/csaf"  # else the page's
    assert list(adapter.download(a)) == ["FG-IR-26-186.json"]
    # b: neither its CSAF nor its HTML page can be fetched (not served here): CVRF
    assert list(adapter.download(b)) == ["FG-IR-20-005.xml"] and b.details["format"] == "cvrf"
    http.pages["https://fortiguard.fortinet.com/psirt/FG-IR-20-005"] = FORTI_PAGE.read_bytes()
    assert list(adapter.download(b)) == ["FG-IR-20-005.html"]
    http.pages["https://www.fortiguard.com/psirt/FG-IR-20-005/csaf"] = (FIXTURES / "cisco-sa-20180328-smi2.json").read_text()
    assert list(adapter.download(b)) == ["FG-IR-20-005.json"]
    assert fetch(adapter, a, tmp_path)[0].vendor == fetch(adapter, b, tmp_path)[0].vendor == "fortinet"


FORTI_PAGE = FIXTURES / "fortinet_FG-IR-24-015_reconstructed.html"


def test_fortinet_html_page(config):
    adapter = FortinetAdapter(connector_config(config, "fortinet"))
    adv_id, [v] = adapter.parse_file(FORTI_PAGE)
    assert (adv_id, v.cve, v.title) == ("FG-IR-24-015", "CVE-2024-21762", "Out-of-bound Write in sslvpnd")
    assert v.release_date == "2024-02-08T00:00:00Z"
    assert v.scores == [Score("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8)]
    rows = {(p.name, p.label(), p.status) for p in v.products}
    assert ("FortiOS", "vers:generic/>=7.4.0|<=7.4.2", KNOWN_AFFECTED) in rows
    assert ("FortiOS", "7.4.3", FIXED) in rows
    assert ("FortiOS", "vers:generic/>=7.6|<7.7", KNOWN_NOT_AFFECTED) in rows       # "Not affected"
    assert ("FortiProxy", "vers:generic/>=1.2|<1.3", KNOWN_AFFECTED) in rows       # "1.2 all versions"
    assert not any(p.status == FIXED and p.name == "FortiProxy" and p.version.startswith("1.") for p in v.products
                   if p.version)                                                    # "Migrate to a fixed release"
    assert len(v.products) == 24
    rem = {r.category: r for r in v.remediations}
    assert rem["workaround"].details.startswith("disable SSL VPN")
    assert "HTTP.Chunk.Length.Invalid" in rem["mitigation"].details
    fix = next(r for r in v.remediations if r.details == "Upgrade to 7.4.3 or above")
    assert len(fix.product_keys) == 2                                              # FortiOS 7.4 and FortiProxy 7.4 rows
    assert v.notes[0].text.startswith("A out-of-bounds write")


def test_fortinet_affected_cell():
    from advisory_cpe_generator.adapters.fortinet import parse_affected
    assert parse_affected("7.2.5, 7.2.6", "7.2") == [(KNOWN_AFFECTED, "7.2.5"), (KNOWN_AFFECTED, "7.2.6")]
    [(_, r)] = parse_affected("7.0 all versions", "7.0")
    assert r.vers() == "vers:generic/>=7.0|<7.1"


def test_fortinet_history_pages(config):
    pages = {f"https://www.fortiguard.com/psirt?page={n}": body for n, body in (
        (1, "<a>FG-IR-26-182 Double free</a> <a>FG-IR-26-181 x</a>"),
        (2, "<a>FG-IR-26-181 x</a> <a>FG-IR-25-010 y</a>"),
        (3, "<a>FG-IR-25-010 y</a>"))}   # nothing new: the end
    adapter = FortinetAdapter(connector_config(config, "fortinet"), http=FakeHttp(pages))
    refs = adapter.list_advisories(history=True)
    assert [r.id for r in refs] == ["FG-IR-26-182", "FG-IR-26-181", "FG-IR-25-010"]
    assert refs[0].details["urls"] == {"csaf": "https://www.fortiguard.com/psirt/FG-IR-26-182/csaf",
                                       "html": "https://www.fortiguard.com/psirt/FG-IR-26-182",
                                       "cvrf": "https://www.fortiguard.com/psirt/cvrf/FG-IR-26-182"}

OLD_PAGE = FIXTURES / "stormshield_2014-003_reconstructed.html"


def _old_page_checks(v):
    by_name = {}
    for p in v.products:
        by_name.setdefault(p.name, []).append((p.label(), p.status))
    assert by_name == {
        "Stormshield Network Security": [("vers:generic/>=1.0.0|<=1.1.3", KNOWN_AFFECTED)],
        "Stormshield Endpoint Security": [("6.0.15", KNOWN_AFFECTED), ("7.1.02", KNOWN_AFFECTED),
                                          ("6.0.17", "fixed"), ("7.1.04", "fixed")],
        "Fast360": [("vers:generic/>=5.0/16|<=5.0/32", KNOWN_AFFECTED),
                    ("vers:generic/>=6.0/1|<=6.0/6", KNOWN_AFFECTED)],
        "Netasq": [("vers:generic/>=9.0.0|<=9.1.3", KNOWN_AFFECTED)],
    }
    # one CVSS v2 base score per product, the overall scores (2.8, 4.3...) are not versions
    assert [(s.product_names, s.base_score, s.vector) for s in v.scores][2] == (
        ["Fast360"], 6.1, "AV:A/AC:L/Au:N/C:N/I:N/A:C")
    rem = {(r.product_names[0], r.category) for r in v.remediations}
    assert ("Stormshield Endpoint Security", "vendor_fix") in rem
    assert ("Stormshield Endpoint Security", "workaround") not in rem    # "There is no workaround solution."
    assert ("Fast360", "none_available") in rem and ("Fast360", "workaround") in rem


def test_stormshield_old_layout(config):
    """Pre-2017 page: one block per product (STORM-2014-003, CVE-2014-3567)."""
    adapter = StormshieldAdapter(connector_config(config, "stormshield"))
    _, [v] = adapter.parse_file(OLD_PAGE, {"url": "https://advisories.stormshield.eu/424/"})
    assert v.advisory_ids == ["STORM-2014-003"] and v.release_date == "2014-10-23T00:00:00Z"
    assert v.notes[0].text.startswith("A memory leak allows")
    _old_page_checks(v)


def test_stormshield_old_layout_without_tables(config, tmp_path):
    """Same page with the tables flattened into paragraphs: same products and remediations."""
    html = OLD_PAGE.read_text()
    html = re.sub(r"</?(table|tr|ul)>", "", html)
    html = re.sub(r"<(td|th|li)>", "<p>", re.sub(r"</(td|th|li)>", "</p>", html))
    (tmp_path / "2014-003.html").write_text(html)
    _, [v] = StormshieldAdapter(connector_config(config, "stormshield")).parse_file(tmp_path / "2014-003.html")
    _old_page_checks(v)


def test_fortinet_browser_user_agent(config):
    from advisory_cpe_generator.http import HttpClient
    assert HttpClient(connector_config(config, "fortinet")).session.headers["User-Agent"].startswith("Mozilla/5.0")
    assert HttpClient(connector_config(config, "oracle")).session.headers["User-Agent"].startswith("advisory_cpe")
