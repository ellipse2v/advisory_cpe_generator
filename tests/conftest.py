import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"
SCHEMAS = HERE / "schemas"


@pytest.fixture(scope="session")
def csaf_validator():
    """CSAF 2.0 JSON schema with the FIRST CVSS schemas it references, offline."""
    schema = json.loads((SCHEMAS / "csaf_json_schema.json").read_text(encoding="utf-8"))
    resources = []
    for v in ("2.0", "3.0", "3.1"):
        cvss = json.loads((SCHEMAS / f"cvss-v{v}.json").read_text(encoding="utf-8"))
        resources.append((f"https://www.first.org/cvss/cvss-v{v}.json", Resource.from_contents(cvss)))
    registry = Registry().with_resources(resources)
    return Draft202012Validator(schema, registry=registry)


@pytest.fixture
def config(tmp_path):
    from advisory_cpe_generator.config import load_config
    cfg = load_config()
    cfg["_base_dir"] = str(tmp_path)
    cfg["cpe"]["matcher_path"] = ""
    return cfg
