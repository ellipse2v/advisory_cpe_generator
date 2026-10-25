"""
Version comparison and version ranges.

Vendor versions are compared token by token ('10.2.9-h1' -> 10, 2, 9, 'h', 1;
'12.2(55)SE' -> 12, 2, 55, 'se'); a version that is a prefix of another sorts
first ('10.2.9' < '10.2.9-h1'). Pre-release suffixes such as 'rc1' are not
special-cased.
"""

import re
from dataclasses import dataclass

_TOKEN = re.compile(r"\d+|[a-z]+")


def version_key(version):
    return tuple((0, int(t), "") if t.isdigit() else (1, 0, t)
                 for t in _TOKEN.findall(str(version).lower()))


def compare(a, b):
    ka, kb = version_key(a), version_key(b)
    return (ka > kb) - (ka < kb)


@dataclass
class VersionRange:
    """
    introduced: first affected version (inclusive)
    fixed:      first version that is no longer affected (exclusive bound)
    last_affected: last affected version (inclusive bound)
    """
    introduced: str = None
    fixed: str = None
    last_affected: str = None

    def contains(self, version):
        if self.introduced and compare(version, self.introduced) < 0:
            return False
        if self.fixed and compare(version, self.fixed) >= 0:
            return False
        if self.last_affected and compare(version, self.last_affected) > 0:
            return False
        return True

    def vers(self):
        """The range as a 'vers' expression (https://github.com/package-url/vers-spec)."""
        constraints = []
        if self.introduced:
            constraints.append(f">={self.introduced}")
        if self.fixed:
            constraints.append(f"<{self.fixed}")
        if self.last_affected:
            constraints.append(f"<={self.last_affected}")
        return "vers:generic/" + ("|".join(constraints) if constraints else "*")

    def is_empty(self):
        return not (self.introduced or self.fixed or self.last_affected)
