import json

from advisory_cpe_generator.config import connector_config, load_config
from advisory_cpe_generator.http import RateLimiter, proxies_from
from advisory_cpe_generator.versions import VersionRange, compare


def test_version_compare():
    assert compare("10.2.9", "10.2.9-h1") < 0
    assert compare("10.2.10", "10.2.9") > 0
    assert compare("12.2(55)SE3", "12.2(55)SE") > 0
    assert VersionRange(introduced="11.2.0", fixed="11.2.4-h1").contains("11.2.4")
    assert not VersionRange(introduced="11.2.0", fixed="11.2.4-h1").contains("11.2.4-h1")


def test_config_proxy_global_and_override(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "proxy": {"https": "http://global:3128"},
        "connectors": {"cisco": {"proxy": {"https": "http://cisco:8080"}}}}))
    cfg = load_config(path)
    assert proxies_from(connector_config(cfg, "stormshield")["proxy"]) == {"https": "http://global:3128"}
    assert proxies_from(connector_config(cfg, "cisco")["proxy"]) == {"https": "http://cisco:8080"}
    assert cfg["connectors"]["paloalto"]["enabled"] is True     # defaults kept


def test_rate_limiter_waits():
    now = [0.0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    limiter = RateLimiter({"per_second": 2}, clock=lambda: now[0], sleep=sleep)
    for _ in range(3):
        limiter.wait()
    assert slept and abs(slept[0] - 1.0) < 1e-9
