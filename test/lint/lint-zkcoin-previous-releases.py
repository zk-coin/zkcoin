#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that previous-release validation does not silently use Litecoin."""

import json
from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
MANIFEST = ROOT_DIR / "test" / "previous_releases.json"
GET_PREVIOUS_RELEASES = ROOT_DIR / "test" / "get_previous_releases.py"
CI_BEFORE_SCRIPT = ROOT_DIR / "ci" / "test" / "05_before_script.sh"
UPSTREAM_FLAG = "--upstream-litecoin-compat"
REQUIRED_ARTIFACT_FIELDS = {
    "version",
    "platform",
    "filename",
    "sha256",
    "url",
    "binary_names",
}


def fail(message):
    print("{}: {}".format(MANIFEST, message), file=sys.stderr)
    return 1


def main():
    manifest = json.loads(MANIFEST.read_text(encoding="utf8"))

    if manifest.get("project") != "zkcoin":
        return fail("project must be zkcoin")
    if manifest.get("schema_version") != 1:
        return fail("schema_version must be 1")

    zkcoin_releases = manifest.get("zkcoin_releases")
    if not isinstance(zkcoin_releases, list):
        return fail("zkcoin_releases must be an array")
    if not zkcoin_releases and manifest.get("status") != "no_zkcoin_previous_release_artifacts":
        return fail("empty zkcoin_releases must use no_zkcoin_previous_release_artifacts status")

    for index, release in enumerate(zkcoin_releases):
        if not isinstance(release, dict):
            return fail("zkcoin_releases[{}] must be an object".format(index))
        missing = sorted(REQUIRED_ARTIFACT_FIELDS - set(release))
        if missing:
            return fail(
                "zkcoin_releases[{}] missing fields: {}".format(
                    index,
                    ", ".join(missing),
                )
            )

    compat = manifest.get("inherited_litecoin_compatibility")
    if not isinstance(compat, dict):
        return fail("inherited_litecoin_compatibility must be an object")
    if compat.get("requires_flag") != UPSTREAM_FLAG:
        return fail("inherited Litecoin compatibility must require {}".format(UPSTREAM_FLAG))

    helper_text = GET_PREVIOUS_RELEASES.read_text(encoding="utf8")
    if UPSTREAM_FLAG not in helper_text:
        return fail("get_previous_releases.py must expose {}".format(UPSTREAM_FLAG))
    if "not zkCoin previous-release validation" not in helper_text:
        return fail("get_previous_releases.py must warn about inherited Litecoin compatibility")
    if "zkCoin previous-release artifacts are not configured yet" not in helper_text:
        return fail("get_previous_releases.py must fail closed when zkCoin artifacts are absent")

    ci_text = CI_BEFORE_SCRIPT.read_text(encoding="utf8")
    if "test/get_previous_releases.py" in ci_text and UPSTREAM_FLAG not in ci_text:
        return fail("CI previous-release downloads must pass {}".format(UPSTREAM_FLAG))

    return 0


if __name__ == "__main__":
    sys.exit(main())
