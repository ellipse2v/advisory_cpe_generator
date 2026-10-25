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
"""python -m advisory_cpe_generator --config config.json [options]"""

import argparse
import logging
import sys

from .adapters import ADAPTERS
from .config import load_config, resolve_path
from .pipeline import run


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="advisory_cpe_generator",
        description="One CSAF 2.0 document per vendor and CVE, with CPE identifiers.")
    parser.add_argument("--config", help="config.json (defaults are used for missing keys)")
    parser.add_argument("--vendor", help=f"comma-separated, among {', '.join(ADAPTERS)} "
                                         "(default: connectors enabled in config.json)")
    parser.add_argument("--since", type=int, metavar="DAYS", help="only advisories updated in the last DAYS")
    parser.add_argument("--max", type=int, help="fetch at most N advisories per vendor (testing)")
    parser.add_argument("--full", action="store_true", help="fetch every advisory again")
    parser.add_argument("--rebuild", action="store_true",
                        help="no network: rebuild every document from the cache (e.g. after editing cpe_mapping.csv)")
    parser.add_argument("--file", nargs="+", metavar="PATH",
                        help="parse local files instead of fetching (one --vendor required)")
    args = parser.parse_args(argv)

    config = load_config(args.config)
    handlers = [logging.StreamHandler()]
    if config["logging"].get("file"):
        handlers.append(logging.FileHandler(resolve_path(config, config["logging"]["file"]), encoding="utf-8"))
    logging.basicConfig(level=config["logging"].get("level", "INFO").upper(), handlers=handlers,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    vendors = [v.strip() for v in args.vendor.split(",")] if args.vendor else None
    unknown = [v for v in vendors or [] if v not in ADAPTERS]
    if unknown:
        parser.error(f"unknown vendor(s): {', '.join(unknown)}")
    if args.file and (not vendors or len(vendors) != 1):
        parser.error("--file needs exactly one --vendor")

    summary = run(config, vendors, args.since, args.full, args.rebuild, args.max, args.file)
    for vendor, counts in summary.items():
        print(f"{vendor}: {counts['new']} new, {counts['updated']} updated, {counts['unchanged']} unchanged, {counts['skipped']} skipped (no product)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
