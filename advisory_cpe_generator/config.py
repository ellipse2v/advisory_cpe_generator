"""
config.json loading.

Every key has a default, so config.json only needs the values you change.
A global "proxy" block applies to every connector; a connector's own "proxy"
block overrides it key by key. Secrets are never read from config.json:
connectors name the environment variables that hold them.
"""

import copy
import json
from pathlib import Path

DEFAULTS = {
    "output_dir": "output",
    "publisher": {
        # CSAF publisher of the generated documents. "translator" is the CSAF
        # category for a party that converts advisories it did not author.
        "category": "translator",
        "name": "advisory_cpe_generator",
        "namespace": "https://github.com/ellipse2v/advisory_cpe_generator",
    },
    "tlp": "WHITE",
    "proxy": {"http": "", "https": "", "no_proxy": ""},
    "http": {"timeout": 30, "retries": 3, "user_agent": "advisory_cpe_generator/0.1"},
    "logging": {"level": "INFO", "file": ""},
    "cpe": {
        # Manual table: vendor,product,cpe_part,cpe_vendor,cpe_product
        "mapping_csv": "cpe_mapping.csv",
        # cpeMiniLLMLevenshtein checkout: its NVD cache (cpe_data.json.gz) and
        # cpe_aliases.csv are used for exact lookups, its matcher for the rest.
        "matcher_path": "",
        "use_dictionary": True,
        "use_semantic_matcher": False,
        "min_score": 0.65,
        # Expand a version range into the versions the NVD dictionary lists.
        "expand_ranges": True,
        "review_csv": "cpe_review.csv",
    },
    "connectors": {
        "stormshield": {
            "enabled": True,
            "base_url": "https://advisories.stormshield.eu",
            "delay": 1.0,
        },
        "cisco": {
            "enabled": False,
            "token_url": "https://id.cisco.com/oauth2/default/v1/token",
            "api_url": "https://apix.cisco.com/security/advisories/v2",
            "client_id_env": "CISCO_CLIENT_ID",
            "client_secret_env": "CISCO_CLIENT_SECRET",
            "rate_limit": {"per_second": 5, "per_minute": 30, "per_day": 5000},
        },
        "paloalto": {
            "enabled": True,
            "list_url": "https://security.paloaltonetworks.com/json",
            "detail_url": "https://security.paloaltonetworks.com/json/{id}",
            "delay": 0.5,
        },
    },
}


def _merge(base, override):
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            _merge(base[key], value)
        else:
            base[key] = value
    return base


def load_config(path=None):
    """Defaults merged with config.json (if given); relative paths stay relative to it."""
    config = copy.deepcopy(DEFAULTS)
    base_dir = Path.cwd()
    if path:
        path = Path(path)
        with open(path, encoding="utf-8") as fh:
            _merge(config, json.load(fh))
        base_dir = path.resolve().parent
    config["_base_dir"] = str(base_dir)
    return config


def resolve_path(config, value):
    """Path from config.json, relative to the config file's directory."""
    if not value:
        return None
    p = Path(value).expanduser()
    return p if p.is_absolute() else Path(config["_base_dir"]) / p


def connector_config(config, name):
    """A connector's block with the global proxy/http settings folded in."""
    conn = copy.deepcopy(config["connectors"].get(name, {}))
    proxy = dict(config.get("proxy", {}))
    proxy.update({k: v for k, v in conn.get("proxy", {}).items() if v is not None})
    conn["proxy"] = proxy
    conn["http"] = _merge(copy.deepcopy(config.get("http", {})), conn.get("http", {}))
    return conn
