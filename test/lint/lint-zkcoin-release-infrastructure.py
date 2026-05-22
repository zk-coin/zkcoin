#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that inherited release infrastructure stays explicit and fail-closed."""

import json
from pathlib import Path
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
MANIFEST = ROOT_DIR / "contrib" / "devtools" / "zkcoin_release_infrastructure_manifest.json"
RELEASE_DOC = ROOT_DIR / "doc" / "release-process.md"
VERIFY_SCRIPT = ROOT_DIR / "contrib" / "verifybinaries" / "verify.sh"
VERIFY_README = ROOT_DIR / "contrib" / "verifybinaries" / "README.md"
GITIAN_BUILD = ROOT_DIR / "contrib" / "gitian-build.py"
CONFIGURE = ROOT_DIR / "configure.ac"
MAKEFILE_AM = ROOT_DIR / "Makefile.am"
UPSTREAM_VERIFY_ENV = "ZKCOIN_ALLOW_BITCOIN_VERIFYBINARIES"
UPSTREAM_GITIAN_ENV = "ZKCOIN_ALLOW_BITCOIN_GITIAN_BUILD"
REQUIRED_BLOCKERS = {
    "zkcoin_release_signing_key",
    "gitian_sigs_repo",
    "detached_sigs_repo",
    "artifact_download_host",
    "descriptor_source_repo",
    "binary_namespace_decision",
    "macos_signing_identity",
    "windows_signing_key",
    "verifybinaries_replacement",
}


def fail(message):
    print("{}: {}".format(MANIFEST, message), file=sys.stderr)
    return 1


def require_text(path, needle, description):
    text = path.read_text(encoding="utf8")
    if needle not in text:
        return "{} missing {}: {}".format(path.relative_to(ROOT_DIR), description, needle)
    return None


def main():
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf8"))
    except json.JSONDecodeError as exc:
        return fail("invalid JSON: {}".format(exc))

    if manifest.get("project") != "zkcoin":
        return fail("project must be zkcoin")
    if manifest.get("schema_version") != 1:
        return fail("schema_version must be 1")
    if manifest.get("status") != "release_infrastructure_not_ready":
        return fail("status must stay release_infrastructure_not_ready until release keys, repos, and hosts are configured")

    blockers = manifest.get("production_blockers")
    if not isinstance(blockers, list):
        return fail("production_blockers must be an array")
    blocker_ids = {blocker.get("id") for blocker in blockers if isinstance(blocker, dict)}
    missing_blockers = sorted(REQUIRED_BLOCKERS - blocker_ids)
    if missing_blockers:
        return fail("production_blockers missing ids: {}".format(", ".join(missing_blockers)))

    namespace = manifest.get("temporary_binary_namespace")
    if not isinstance(namespace, dict):
        return fail("temporary_binary_namespace must be an object")
    if namespace.get("status") != "litecoin_compatibility_names_retained":
        return fail("temporary_binary_namespace.status must document retained Litecoin compatibility names")
    for binary_name in ("litecoind", "litecoin-cli", "litecoin-qt", "litecoin-${VERSION}"):
        if binary_name not in namespace.get("names", []):
            return fail("temporary_binary_namespace.names must include {}".format(binary_name))
    error = require_text(
        CONFIGURE,
        "Keep the tarname and executable names on litecoin",
        "temporary namespace comment",
    )
    if error:
        return fail(error)

    inherited_surfaces = manifest.get("current_inherited_release_surfaces")
    if not isinstance(inherited_surfaces, list) or not inherited_surfaces:
        return fail("current_inherited_release_surfaces must be a non-empty array")
    for index, surface in enumerate(inherited_surfaces):
        if not isinstance(surface, dict):
            return fail("current_inherited_release_surfaces[{}] must be an object".format(index))
        relpath = surface.get("path")
        contains = surface.get("contains")
        reason = surface.get("reason")
        if not relpath or not contains or not reason:
            return fail("current_inherited_release_surfaces[{}] must include path, contains, and reason".format(index))
        path = ROOT_DIR / relpath
        if not path.exists():
            return fail("{} does not exist".format(relpath))
        if contains not in path.read_text(encoding="utf8"):
            return fail("{} no longer contains manifest marker {!r}; update the manifest with the release-infra change".format(relpath, contains))

    release_doc_checks = (
        ("zkCoin release infrastructure is not production-ready", "fail-closed release status warning"),
        ("zkcoin_release_infrastructure_manifest.json", "release infrastructure manifest reference"),
        ("Do not publish zkCoin artifacts from this process", "publish blocker warning"),
        ("temporary compatibility namespace", "temporary binary namespace explanation"),
    )
    for needle, description in release_doc_checks:
        error = require_text(RELEASE_DOC, needle, description)
        if error:
            return fail(error)

    verify_checks = (
        (VERIFY_SCRIPT, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in env"),
        (VERIFY_SCRIPT, "verifies Bitcoin Core artifacts, not zkCoin", "Bitcoin-only verifier warning"),
        (VERIFY_README, "Bitcoin Core-only", "Bitcoin-only README warning"),
        (VERIFY_README, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in docs"),
        (GITIAN_BUILD, UPSTREAM_GITIAN_ENV, "legacy Bitcoin Gitian helper opt-in env"),
        (GITIAN_BUILD, "builds Bitcoin Core artifacts, not zkCoin", "Bitcoin-only Gitian helper warning"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_release_infrastructure_manifest.json", "release manifest dist packaging"),
    )
    for path, needle, description in verify_checks:
        error = require_text(path, needle, description)
        if error:
            return fail(error)

    return 0


if __name__ == "__main__":
    sys.exit(main())
