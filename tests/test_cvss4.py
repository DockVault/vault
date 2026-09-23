"""The CVSS v4.0 base scorer the upgrade-matrix validator uses to check an advisory's severity.

The scorer is a port of FIRST's reference implementation, so the property that matters is that it
agrees with that reference. It was compared on every possible base vector (4 x 2 x 2 x 3^8 =
104,976 of them) and agreed on all; the digest below is of that whole table, so any change to any
score -- a mistyped lookup entry, a rounding change, a reordered sum -- fails here rather than
quietly re-rating an advisory. The named examples beside it make the table readable.
"""

from __future__ import annotations

import hashlib
import importlib.util
import itertools
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _load():
    spec = importlib.util.spec_from_file_location("cvss4_under_test",
                                                  ROOT / ".github" / "scripts" / "cvss4.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["cvss4_under_test"] = module
    spec.loader.exec_module(module)
    return module


cvss4 = _load()

#: SHA-256 of "<vector> <score to one decimal>\n" for every base vector, in the order the metrics and
#: their values are listed in BASE_METRICS -- produced by FIRST's reference calculator
#: (github.com/FIRSTdotorg/cvss-v4-calculator, cvss_score.js) and reproduced exactly by the port.
_REFERENCE_TABLE_SHA256 = "d8527962b6e6ed845ba0fe32a43c2b91386a89607e9e32c9cbff380e7a7a2db3"


def _every_base_vector():
    names = [name for name, _ in cvss4.BASE_METRICS]
    for values in itertools.product(*(allowed for _, allowed in cvss4.BASE_METRICS)):
        yield cvss4.PREFIX + "/".join(f"{n}:{v}" for n, v in zip(names, values))


def test_every_base_vector_scores_as_the_reference_does():
    lines = [f"{vector} {cvss4.base_score(vector):.1f}\n" for vector in _every_base_vector()]
    assert len(lines) == 104_976
    digest = hashlib.sha256("".join(lines).encode("ascii")).hexdigest()
    assert digest == _REFERENCE_TABLE_SHA256


@pytest.mark.parametrize("vector, score", [
    # The specification's own example: network, no privileges, full impact on the system.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
    # The strongest vector there is.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H", 10.0),
    # The weakest ones that are still vulnerabilities score 1.0. No base vector scores between 0.0 and
    # 1.0: the lookup's lower entries all need an unfavourable threat metric, which a base vector does
    # not carry (the table digest above covers all 3,213 vectors that tie here).
    ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:L", 1.0),
    # No impact on anything: scored 0.0 outright.
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    # The two SFTP advisories' ratings.
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", 5.9),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N", 7.1),
    # Unrounded this is 5.05. The reference rounds a half UP (JavaScript's Math.round); Python's
    # round() would give 5.0, so this is the vector that pins the rounding rule by name.
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:L/VI:L/VA:L/SC:H/SI:H/SA:N", 5.1),
])
def test_named_examples(vector, score):
    assert cvss4.base_score(vector) == score


@pytest.mark.parametrize("score, band", [
    (0.0, "none"), (0.1, "low"), (3.9, "low"), (4.0, "medium"), (6.9, "medium"),
    (7.0, "high"), (8.9, "high"), (9.0, "critical"), (10.0, "critical"),
])
def test_the_rating_scale_boundaries(score, band):
    assert cvss4.severity_band(score) == band


def test_band_of_scores_then_bands():
    assert cvss4.band_of("CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N") == "high"


@pytest.mark.parametrize("vector", [
    None,
    7.1,
    "",
    "CVSS:4.0/",
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cvss:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    # One base metric short, one metric over (threat and environmental metrics are not accepted).
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/CR:L",
    # Out of the specification's order, or a metric repeated in place of another.
    "CVSS:4.0/AC:L/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AV:N/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    # A value the metric does not have ("S" exists only for the modified MSI/MSA).
    "CVSS:4.0/AV:X/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N",
    # Separators: a missing colon, an empty metric, a trailing slash.
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N//VI:H/VA:H/SC:N/SI:N/SA:N",
    "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/",
])
def test_only_a_canonical_base_vector_is_accepted(vector):
    with pytest.raises(cvss4.CvssError):
        cvss4.base_score(vector)
