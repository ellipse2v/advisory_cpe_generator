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
from advisory_cpe_generator import cpe as cpe_lib
from advisory_cpe_generator.enricher import CpeEnricher
from advisory_cpe_generator.model import Product, Vulnerability
from advisory_cpe_generator.versions import VersionRange


class FakeDictionary:
    """Same interface as NvdDictionary, on a handful of CPEs."""

    def __init__(self, cpes):
        self.cpes = cpes
        self.index = type("I", (), {"key_to_id": {cpe_lib.product_key(c): 0 for c in cpes}})()

    def identify(self, vendor, product):
        wanted = product.lower().replace(" ", "_")
        return sorted({cpe_lib.product_key(c) for c in self.cpes if cpe_lib.product_key(c)[2] == wanted})

    def resolve(self, key, version):
        return cpe_lib.build(*key, version)

    def versions(self, key):
        return [(cpe_lib.cpe_version(c), c) for c in self.cpes if cpe_lib.product_key(c) == key]


NVD = FakeDictionary([
    "cpe:2.3:a:stormshield:stormshield_network_security:4.3.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:stormshield:stormshield_network_security:4.3.5:*:*:*:*:*:*:*",
    "cpe:2.3:a:stormshield:stormshield_network_security:4.4.0:*:*:*:*:*:*:*",
])


def _vuln(*products):
    return Vulnerability("stormshield", "Stormshield", "CVE-2024-1", products=list(products))


def test_source_cpe_kept(config):
    p = Product("Palo Alto Networks", "PAN-OS", version="11.2.3",
                cpe="cpe:2.3:o:paloaltonetworks:pan-os:11.2.3:-:*:*:*:*:*:*")
    CpeEnricher(config, dictionary=NVD, mapping={}).enrich(_vuln(p))
    assert p.cpe_origin == "source"


def test_invalid_source_cpe_dropped(config):
    p = Product("X", "Y", version="1.0", cpe="not a cpe")
    enricher = CpeEnricher(config, dictionary=False, mapping={})
    enricher.enrich(_vuln(p))
    assert p.cpe is None and enricher.review


def test_mapping_before_dictionary(config):
    p = Product("Stormshield", "SNS", version="4.3.1")
    mapping = {("stormshield", "sns"): ("a", "stormshield", "stormshield_network_security")}
    CpeEnricher(config, dictionary=NVD, mapping=mapping).enrich(_vuln(p))
    assert p.cpe == "cpe:2.3:a:stormshield:stormshield_network_security:4.3.1:*:*:*:*:*:*:*"
    assert p.cpe_origin == "mapping"


def test_dictionary_exact_name(config):
    p = Product("Stormshield", "Stormshield Network Security", version="4.3.5")
    CpeEnricher(config, dictionary=NVD, mapping={}).enrich(_vuln(p))
    assert p.cpe_origin == "nvd-dictionary" and ":4.3.5:" in p.cpe


def test_range_expanded_with_dictionary_versions(config):
    p = Product("Stormshield", "Stormshield Network Security",
                version_range=VersionRange(introduced="4.3.0", last_affected="4.3.20"))
    v = _vuln(p)
    CpeEnricher(config, dictionary=NVD, mapping={}).enrich(v)
    assert p.cpe is None    # the range itself never gets a wildcard CPE
    expanded = sorted(x.version for x in v.products if x.cpe_origin == "nvd-range")
    assert expanded == ["4.3.0", "4.3.5"]


def test_unknown_product_reported_not_guessed(config):
    p = Product("Stormshield", "Stormshield Network VPN Client", version="7.5.109")
    enricher = CpeEnricher(config, dictionary=NVD, mapping={})
    enricher.enrich(_vuln(p))
    assert p.cpe is None
    assert enricher.review[0]["reason"] == "product not found"


def test_semantic_matcher_threshold(config):
    class Matcher:
        def match(self, queries):
            return [("cpe:2.3:a:thegreenbow:vpn_client:7.5.109:*:*:*:*:*:*:*", 0.9), (None, 0.4)]
    a = Product("Stormshield", "VPN Client", version="7.5.109")
    b = Product("Stormshield", "Unknown thing", version="1.0")
    enricher = CpeEnricher(config, dictionary=False, semantic=Matcher(), mapping={})
    enricher.enrich(_vuln(a, b))
    assert a.cpe_origin == "nvd-matcher"
    assert b.cpe is None and "0.40" in enricher.review[0]["reason"]


def test_example_from_same_advisory(config):
    """A version the vendor gave no CPE for reuses the CPE of another version, version replaced."""
    known = Product("Palo Alto Networks", "PAN-OS", version="11.2.2-h1",
                    cpe="cpe:2.3:o:paloaltonetworks:pan-os:11.2.2:h1:*:*:*:*:*:*")
    fixed = Product("Palo Alto Networks", "PAN-OS", version="11.2.4-h1", status="fixed")
    plain = Product("Palo Alto Networks", "PAN-OS", version="10.1.0", status="known_not_affected")
    CpeEnricher(config, dictionary=False, mapping={}).enrich(_vuln(known, fixed, plain))
    assert (fixed.cpe, fixed.cpe_origin) == ("cpe:2.3:o:paloaltonetworks:pan-os:11.2.4:h1:*:*:*:*:*:*",
                                             "source-example")
    assert plain.cpe == "cpe:2.3:o:paloaltonetworks:pan-os:10.1.0:-:*:*:*:*:*:*"


def test_example_from_another_advisory_before_mapping(config):
    enricher = CpeEnricher(config, dictionary=NVD, mapping={
        ("oracle", "oracle mysql server"): ("a", "x", "y")})
    enricher.learn([Vulnerability("oracle", "Oracle", "CVE-2024-2", products=[
        Product("Oracle", "Oracle MySQL Server", version="8.0.40",
                cpe="cpe:2.3:a:oracle:mysql_server:8.0.40:*:*:*:*:*:*:*")])])
    p = Product("Oracle", "Oracle MySQL Server", version="8.4.3")
    enricher.enrich(_vuln(p))
    assert (p.cpe, p.cpe_origin) == ("cpe:2.3:a:oracle:mysql_server:8.4.3:*:*:*:*:*:*:*", "source-example")


def test_ambiguous_example_not_used(config):
    enricher = CpeEnricher(config, dictionary=False, mapping={})
    enricher.learn([Vulnerability("oracle", "Oracle", "CVE-2024-2", products=[
        Product("Oracle", "Database", version="19", cpe="cpe:2.3:a:oracle:database_server:19:*:*:*:*:*:*:*"),
        Product("Oracle", "Database", version="21", cpe="cpe:2.3:a:oracle:database:21:*:*:*:*:*:*:*")])])
    p = Product("Oracle", "Database", version="23")
    enricher.enrich(_vuln(p))
    assert p.cpe is None and enricher.review[-1]["reason"] == "product not found"
