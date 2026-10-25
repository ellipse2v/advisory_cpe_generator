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
"""CPE 2.3 formatted-string helpers (no dependency on the matcher)."""

import re

# Pattern of the CSAF 2.0 schema (product_identification_helper.cpe), CPE 2.3 branch.
CPE23_RE = re.compile(
    r"^cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+"
    r"(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)"
    r"([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#\$%&'\(\)\+,/:;<=>@\[\]\^`\{\|\}~]))+(\?*|\*?))|[\*\-])){4}$"
)


def is_valid_cpe23(value):
    return bool(value) and bool(CPE23_RE.match(value))


def split_cpe(cpe):
    """Split on ':' honouring backslash escapes."""
    parts, buf, escaped = [], [], False
    for ch in cpe:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            buf.append(ch)
            escaped = True
        elif ch == ":":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    parts.append("".join(buf))
    return parts


def unescape(value):
    return re.sub(r"\\(.)", r"\1", value)


def escape(value):
    """Free text -> CPE 2.3 component: lower case, spaces -> '_', other specials escaped."""
    value = re.sub(r"\s+", "_", str(value).strip().lower())
    if not value:
        return "*"
    return "".join(ch if re.match(r"[a-z0-9._\-]", ch) else "\\" + ch for ch in value)


def build(part, vendor, product, version, update="*"):
    return ":".join(["cpe", "2.3", part, vendor, product, escape(version), update] + ["*"] * 6)


def cpe_version(cpe):
    """Readable version of a CPE: '11.2.2' + update 'h1' -> '11.2.2-h1'; None for '*' / '-'."""
    parts = split_cpe(cpe)
    if len(parts) < 7 or parts[5] in ("*", "-"):
        return None
    version = unescape(parts[5])
    if parts[6] not in ("*", "-"):
        version += "-" + unescape(parts[6])
    return version


def product_key(cpe):
    parts = split_cpe(cpe)
    return tuple(parts[2:5]) if len(parts) >= 5 else None
