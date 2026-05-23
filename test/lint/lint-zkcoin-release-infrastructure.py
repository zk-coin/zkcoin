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
DEVTOOLS_README = ROOT_DIR / "contrib" / "devtools" / "README.md"
RELEASE_CANDIDATE_VALIDATION = ROOT_DIR / "contrib" / "devtools" / "zkcoin_release_candidate_validation.sh"
SOURCE_DIST_SMOKE = ROOT_DIR / "contrib" / "devtools" / "zkcoin_source_dist_smoke.sh"
SOURCE_DIST_REALPROOF_SMOKE = ROOT_DIR / "contrib" / "devtools" / "zkcoin_source_dist_realproof_smoke.sh"
RELEASE_DOC = ROOT_DIR / "doc" / "release-process.md"
VERIFY_SCRIPT = ROOT_DIR / "contrib" / "verifybinaries" / "verify.sh"
ZKCOIN_VERIFY_SCRIPT = ROOT_DIR / "contrib" / "verifybinaries" / "verify-zkcoin-release.py"
VERIFY_README = ROOT_DIR / "contrib" / "verifybinaries" / "README.md"
CONTRIB_README = ROOT_DIR / "contrib" / "README.md"
GITIAN_BUILD = ROOT_DIR / "contrib" / "gitian-build.py"
GITIAN_SOURCE_DESCRIPTORS = (
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-linux.yml",
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-win.yml",
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-osx.yml",
)
GITIAN_SIGNER_DESCRIPTORS = (
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-win-signer.yml",
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-osx-signer.yml",
)
CONFIGURE = ROOT_DIR / "configure.ac"
MAKEFILE_AM = ROOT_DIR / "Makefile.am"
SRC_MAKEFILE_AM = ROOT_DIR / "src" / "Makefile.am"
UPSTREAM_VERIFY_ENV = "ZKCOIN_ALLOW_BITCOIN_VERIFYBINARIES"
UPSTREAM_GITIAN_ENV = "ZKCOIN_ALLOW_BITCOIN_GITIAN_BUILD"
ZKCOIN_SOURCE_REPO = "https://github.com/zk-coin/zkcoin.git"
UPSTREAM_LITECOIN_SOURCE_REPO = "https://github.com/litecoin-project/litecoin.git"
DETACHED_SIGS_NOT_CONFIGURED_REPO = "https://example.invalid/zkcoin-detached-sigs-not-configured.git"
UPSTREAM_LITECOIN_DETACHED_SIGS_REPO = "https://github.com/litecoin-project/litecoin-detached-sigs.git"
UPSTREAM_LITECOIN_GITIAN_SIGS_REPO = "https://github.com/litecoin-project/gitian.sigs.ltc.git"
UPSTREAM_LITECOIN_GITHUB_RELEASE_URL = "https://github.com/litecoin-project/litecoin/releases/new"
UPSTREAM_LITECOIN_MACOS_BUNDLE_ID = "org.litecoin.Litecoin-Qt"
REQUIRED_BLOCKERS = {
    "zkcoin_release_signing_key",
    "gitian_sigs_repo",
    "detached_sigs_repo",
    "artifact_download_host",
    "binary_namespace_decision",
    "macos_signing_identity",
    "windows_signing_key",
}
REQUIRED_BLAKE3_DIST = (
    "BLAKE3_DIST",
    "$(BLAKE3_DIST)",
    "crypto/blake3/blake3.c",
    "crypto/blake3/blake3.h",
    "crypto/blake3/blake3_dispatch.c",
    "crypto/blake3/blake3_impl.h",
    "crypto/blake3/blake3_portable.c",
)
REQUIRED_RUST_SHIELDED_VERIFIER_DIST = (
    "RUST_SHIELDED_VERIFIER_DIST",
    "$(RUST_SHIELDED_VERIFIER_DIST)",
    "rust/shielded-verifier/Cargo.lock",
    "rust/shielded-verifier/Cargo.toml",
    "rust/shielded-verifier/README.md",
    "rust/shielded-verifier/examples/orchard_mint_vector.rs",
    "rust/shielded-verifier/examples/orchard_spend_vector.rs",
    "rust/shielded-verifier/include/zkc_shielded_verifier.h",
    "rust/shielded-verifier/scripts/abi-smoke.sh",
    "rust/shielded-verifier/scripts/fixture-consensus-smoke.sh",
    "rust/shielded-verifier/scripts/orchard-consensus-smoke.sh",
    "rust/shielded-verifier/scripts/unsupported-consensus-smoke.sh",
    "rust/shielded-verifier/src/lib.rs",
    "rust/shielded-verifier/tests/abi_smoke.c",
    "rust/shielded-verifier/tests/cxx_abi_smoke.cpp",
    "rust/shielded-verifier/tests/cxx_fixture_consensus_smoke.cpp",
    "rust/shielded-verifier/tests/cxx_orchard_consensus_smoke.cpp",
    "rust/shielded-verifier/tests/cxx_unsupported_consensus_smoke.cpp",
    "rust/shielded-verifier/tests/vectors/orchard_mint_vector.txt",
    "rust/shielded-verifier/tests/vectors/orchard_spend_vector.txt",
)
REQUIRED_LIBMW_DIST = (
    "LIBMW_DIST",
    "$(LIBMW_DIST)",
    "libmw/deps/caches/include/caches/Cache.h",
    "libmw/deps/ghc/include/ghc/filesystem.hpp",
    "libmw/deps/mio/include/mio/mmap.hpp",
    "libmw/include/mw/consensus/Params.h",
    "libmw/include/mw/models/crypto/Hash.h",
    "libmw/src/crypto/Context.h",
    "libmw/src/db/common/Database.h",
    "libmw/src/node/CoinActions.h",
    "libmw/test/framework/include/test_framework/TestMWEB.h",
)
REQUIRED_WALLET_INTERFACE_DIST = (
    "wallet/txlist.h",
    "wallet/txrecord.h",
)
REQUIRED_VERIFYBINARIES_DIST = (
    "contrib/verifybinaries/README.md",
    "contrib/verifybinaries/verify-zkcoin-release.py",
    "contrib/verifybinaries/verify.sh",
)


def fail(message):
    print("{}: {}".format(MANIFEST, message), file=sys.stderr)
    return 1


def require_text(path, needle, description):
    text = path.read_text(encoding="utf8")
    if needle not in text:
        return "{} missing {}: {}".format(path.relative_to(ROOT_DIR), description, needle)
    return None


def require_absent_text(path, needle, description):
    text = path.read_text(encoding="utf8")
    if needle in text:
        return "{} must not contain {}: {}".format(path.relative_to(ROOT_DIR), description, needle)
    return None


def require_src_dist_entries():
    text = SRC_MAKEFILE_AM.read_text(encoding="utf8")
    missing = [entry for entry in REQUIRED_RUST_SHIELDED_VERIFIER_DIST if entry not in text]
    if missing:
        return "{} missing Rust shielded verifier dist entries: {}".format(
            SRC_MAKEFILE_AM.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    dist_lines = [line for line in text.splitlines() if line.startswith("RUST_SHIELDED_VERIFIER_DIST")]
    if any("rust/shielded-verifier/target" in line for line in dist_lines):
        return "{} must not ship Cargo target build outputs".format(SRC_MAKEFILE_AM.relative_to(ROOT_DIR))
    return None


def require_blake3_dist_entries():
    text = SRC_MAKEFILE_AM.read_text(encoding="utf8")
    missing = [entry for entry in REQUIRED_BLAKE3_DIST if entry not in text]
    if missing:
        return "{} missing BLAKE3 source dist entries: {}".format(
            SRC_MAKEFILE_AM.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    blake3_dist_lines = [line for line in text.splitlines() if line.startswith("BLAKE3_DIST")]
    forbidden = (".deps", ".dirstamp", ".o")
    for line in blake3_dist_lines:
        if any(marker in line for marker in forbidden):
            return "{} must not ship BLAKE3 build outputs".format(SRC_MAKEFILE_AM.relative_to(ROOT_DIR))
    return None


def require_libmw_dist_entries():
    text = SRC_MAKEFILE_AM.read_text(encoding="utf8")
    missing = [entry for entry in REQUIRED_LIBMW_DIST if entry not in text]
    if missing:
        return "{} missing libmw/MWEB source dist entries: {}".format(
            SRC_MAKEFILE_AM.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    libmw_dist_lines = [line for line in text.splitlines() if line.startswith("LIBMW_DIST")]
    forbidden = (".deps", ".dirstamp", ".o")
    for line in libmw_dist_lines:
        if any(marker in line for marker in forbidden):
            return "{} must not ship libmw build outputs".format(SRC_MAKEFILE_AM.relative_to(ROOT_DIR))
    return None


def require_wallet_interface_dist_entries():
    text = SRC_MAKEFILE_AM.read_text(encoding="utf8")
    missing = [entry for entry in REQUIRED_WALLET_INTERFACE_DIST if entry not in text]
    if missing:
        return "{} missing wallet interface dist entries: {}".format(
            SRC_MAKEFILE_AM.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    return None


def require_source_dist_smoke_entries():
    text = SOURCE_DIST_SMOKE.read_text(encoding="utf8")
    required_entries = [
        entry
        for entry in REQUIRED_RUST_SHIELDED_VERIFIER_DIST
        if entry.startswith("rust/shielded-verifier/")
    ]
    required_entries.extend(
        entry
        for entry in REQUIRED_BLAKE3_DIST
        if entry.startswith("crypto/blake3/")
    )
    required_entries.extend(
        entry
        for entry in REQUIRED_LIBMW_DIST
        if entry.startswith("libmw/")
    )
    required_entries.extend(REQUIRED_WALLET_INTERFACE_DIST)
    required_entries.extend(REQUIRED_VERIFYBINARIES_DIST)
    missing = [entry for entry in required_entries if entry not in text]
    if missing:
        return "{} missing release-critical tarball checks: {}".format(
            SOURCE_DIST_SMOKE.relative_to(ROOT_DIR),
            ", ".join(missing),
        )
    return None


def require_gitian_source_descriptors():
    for descriptor in GITIAN_SOURCE_DESCRIPTORS:
        text = descriptor.read_text(encoding="utf8")
        if ZKCOIN_SOURCE_REPO not in text:
            return "{} must fetch zkCoin source repo: {}".format(
                descriptor.relative_to(ROOT_DIR),
                ZKCOIN_SOURCE_REPO,
            )
        if UPSTREAM_LITECOIN_SOURCE_REPO in text:
            return "{} must not fetch inherited Litecoin source repo".format(descriptor.relative_to(ROOT_DIR))
        if '"dir": "litecoin"' not in text:
            return "{} must retain the litecoin input directory until namespace migration is decided".format(
                descriptor.relative_to(ROOT_DIR)
            )
    return None


def require_gitian_signer_descriptors():
    for descriptor in GITIAN_SIGNER_DESCRIPTORS:
        text = descriptor.read_text(encoding="utf8")
        if DETACHED_SIGS_NOT_CONFIGURED_REPO not in text:
            return "{} must default to fail-closed detached-signatures URL: {}".format(
                descriptor.relative_to(ROOT_DIR),
                DETACHED_SIGS_NOT_CONFIGURED_REPO,
            )
        if UPSTREAM_LITECOIN_DETACHED_SIGS_REPO in text:
            return "{} must not fetch inherited Litecoin detached signatures".format(
                descriptor.relative_to(ROOT_DIR)
            )
        if '"dir": "signature"' not in text:
            return "{} must keep the Gitian signature input directory".format(descriptor.relative_to(ROOT_DIR))
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

    notes = manifest.get("notes")
    if not isinstance(notes, list):
        return fail("notes must be an array")
    notes_text = "\n".join(note for note in notes if isinstance(note, str))
    if "source release-candidate validation gate proves source tarball real-proof readiness only" not in notes_text:
        return fail("notes must keep source release-candidate validation separate from binary release readiness")
    if "verify-zkcoin-release.py" not in notes_text:
        return fail("notes must document parameterized zkCoin binary artifact verification")
    if "example.invalid detached-signatures URL" not in notes_text:
        return fail("notes must document fail-closed detached-signatures signer descriptors")
    if "ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" not in notes_text:
        return fail("notes must document parameterized zkCoin release checksum signing key")
    if "ZKCOIN_RELEASE_ARTIFACT_BASE_URL" not in notes_text:
        return fail("notes must document parameterized zkCoin artifact publication targets")
    if "ZKCOIN_MACOS_BUNDLE_ID" not in notes_text:
        return fail("notes must document parameterized zkCoin macOS notarization identity")
    if "ZKCOIN_WINDOWS_CODESIGN_KEY_PATH" not in notes_text:
        return fail("notes must document parameterized zkCoin Windows signing key custody")

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

    error = require_gitian_source_descriptors()
    if error:
        return fail(error)

    error = require_gitian_signer_descriptors()
    if error:
        return fail(error)

    release_doc_checks = (
        ("zkCoin release infrastructure is not production-ready", "fail-closed release status warning"),
        ("zkcoin_release_infrastructure_manifest.json", "release infrastructure manifest reference"),
        ("Do not publish zkCoin artifacts from this process", "publish blocker warning"),
        ("temporary compatibility namespace", "temporary binary namespace explanation"),
        ("zkcoin_release_candidate_validation.sh", "source release-candidate validation gate"),
        ("It is not binary release readiness", "source-vs-binary readiness boundary"),
        ("does not authorize publishing binaries", "binary publication blocker"),
        ("git clone https://github.com/zk-coin/zkcoin.git litecoin", "zkCoin source clone"),
        ("verify-zkcoin-release.py", "zkCoin binary artifact verification"),
        ("not embed production signing keys", "parameterized binary verification boundary"),
        ("ZKCOIN_GITIAN_SIGS_REPO_URL", "parameterized Gitian signatures repository"),
        ("ZKCOIN_DETACHED_SIGS_REPO_URL", "parameterized detached-signatures repository"),
        ('--url "signature=../${ZKCOIN_DETACHED_SIGS_DIR}"', "explicit detached-signatures Gitian override"),
        ("zkcoin-detached-sigs", "zkCoin detached-signatures local directory"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT", "parameterized release signing key fingerprint"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_ID", "parameterized release signing local key id"),
        ("--with-colons --fingerprint", "release signing key fingerprint validation"),
        ('--local-user "$ZKCOIN_RELEASE_SIGNING_KEY_ID"', "explicit zkCoin release signing key invocation"),
        ("ZKCOIN_RELEASE_ARTIFACT_BASE_URL", "parameterized artifact host"),
        ("ZKCOIN_RELEASE_CHECKSUMS_URL", "parameterized checksum publication URL"),
        ("ZKCOIN_RELEASE_GITHUB_REPO_URL", "parameterized GitHub release repository"),
        ("verify-zkcoin-release.py", "post-publication artifact verification"),
        ("resolved zkCoin artifact host", "zkCoin artifact upload target"),
        ("ZKCOIN_MACOS_BUNDLE_ID", "parameterized macOS bundle identifier"),
        ("ZKCOIN_MACOS_APPLE_ID", "parameterized macOS notarization Apple ID"),
        ("ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM", "parameterized macOS notarization keychain item"),
        ("ZKCOIN_MACOS_ASC_PROVIDER", "parameterized macOS Apple provider"),
        ('--primary-bundle-id "$ZKCOIN_MACOS_BUNDLE_ID"', "zkCoin macOS notarization bundle id"),
        ("ZKCOIN_WINDOWS_CODESIGN_KEY_PATH", "parameterized Windows code-signing key path"),
        ("ZKCOIN_WINDOWS_CODESIGN_KEY_CUSTODY", "parameterized Windows code-signing key custody"),
        ('./detached-sig-create.sh -key "$ZKCOIN_WINDOWS_CODESIGN_KEY_PATH"', "zkCoin Windows signing key invocation"),
    )
    for needle, description in release_doc_checks:
        error = require_text(RELEASE_DOC, needle, description)
        if error:
            return fail(error)

    verify_checks = (
        (VERIFY_SCRIPT, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in env"),
        (VERIFY_SCRIPT, "verifies Bitcoin Core artifacts, not zkCoin", "Bitcoin-only verifier warning"),
        (ZKCOIN_VERIFY_SCRIPT, "--trusted-fingerprint", "zkCoin trusted fingerprint argument"),
        (ZKCOIN_VERIFY_SCRIPT, "--download-base", "zkCoin artifact download base argument"),
        (ZKCOIN_VERIFY_SCRIPT, "VALIDSIG", "zkCoin GPG fingerprint validation"),
        (ZKCOIN_VERIFY_SCRIPT, "Verified {} zkCoin release artifact", "zkCoin artifact verification success message"),
        (VERIFY_README, "Bitcoin Core-only", "Bitcoin-only README warning"),
        (VERIFY_README, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in docs"),
        (VERIFY_README, "verify-zkcoin-release.py", "zkCoin verifier documentation"),
        (VERIFY_README, "ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT", "zkCoin verifier fingerprint documentation"),
        (VERIFY_README, "ZKCOIN_RELEASE_ARTIFACT_BASE_URL", "zkCoin verifier download base documentation"),
        (CONTRIB_README, "Tools for verifying signed zkCoin release checksums", "zkCoin contrib verifier summary"),
        (GITIAN_BUILD, UPSTREAM_GITIAN_ENV, "legacy Bitcoin Gitian helper opt-in env"),
        (GITIAN_BUILD, "builds Bitcoin Core artifacts, not zkCoin", "Bitcoin-only Gitian helper warning"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_release_infrastructure_manifest.json", "release manifest dist packaging"),
        (MAKEFILE_AM, "contrib/verifybinaries/verify-zkcoin-release.py", "zkCoin verifier dist packaging"),
        (MAKEFILE_AM, "contrib/verifybinaries/verify.sh", "legacy verifier dist packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_release_candidate_validation.sh", "release-candidate validation packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_source_dist_realproof_smoke.sh", "source dist real-proof smoke packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_source_dist_smoke.sh", "source dist smoke packaging"),
        (GITIAN_SIGNER_DESCRIPTORS[0], DETACHED_SIGS_NOT_CONFIGURED_REPO, "Windows signer fail-closed detached-signatures remote"),
        (GITIAN_SIGNER_DESCRIPTORS[1], DETACHED_SIGS_NOT_CONFIGURED_REPO, "macOS signer fail-closed detached-signatures remote"),
        (DEVTOOLS_README, "zkcoin_release_candidate_validation.sh", "release-candidate validation documentation"),
        (DEVTOOLS_README, "zkcoin_source_dist_realproof_smoke.sh", "source dist real-proof smoke documentation"),
        (DEVTOOLS_README, "zkcoin_source_dist_smoke.sh", "source dist smoke documentation"),
        (SOURCE_DIST_SMOKE, "zkcoin_release_candidate_validation.sh", "release-candidate validation tarball entry"),
        (SOURCE_DIST_SMOKE, "zkcoin_source_dist_realproof_smoke.sh", "source dist real-proof smoke tarball entry"),
        (SOURCE_DIST_SMOKE, "make dist-gzip", "source tarball build command"),
        (SOURCE_DIST_SMOKE, "tar -tf", "source tarball listing command"),
        (SOURCE_DIST_SMOKE, "rust/shielded-verifier/target", "Cargo target exclusion check"),
        (RELEASE_CANDIDATE_VALIDATION, "zkcoin_launch_validation.sh", "release-candidate canonical launch validation command"),
        (RELEASE_CANDIDATE_VALIDATION, "zkcoin_source_dist_realproof_smoke.sh", "release-candidate source artifact proof command"),
        (SOURCE_DIST_REALPROOF_SMOKE, "make dist-gzip", "source real-proof tarball build command"),
        (SOURCE_DIST_REALPROOF_SMOKE, "--enable-rust-orchard-verifier", "source real-proof Orchard verifier configure"),
        (SOURCE_DIST_REALPROOF_SMOKE, "ZKCOIN_REQUIRE_ORCHARD_VERIFIER=1", "source real-proof required functional regression"),
        (SOURCE_DIST_REALPROOF_SMOKE, "feature_orchard_auxpow_realproof.py", "source real-proof AuxPoW functional regression"),
    )
    for path, needle, description in verify_checks:
        error = require_text(path, needle, description)
        if error:
            return fail(error)

    absent_checks = (
        (ZKCOIN_VERIFY_SCRIPT, "bitcoin-core-", "Bitcoin Core artifact prefix"),
        (ZKCOIN_VERIFY_SCRIPT, "bitcoincore.org", "Bitcoin Core download host"),
        (ZKCOIN_VERIFY_SCRIPT, "bitcoin.org", "Bitcoin download host"),
        (GITIAN_SIGNER_DESCRIPTORS[0], UPSTREAM_LITECOIN_DETACHED_SIGS_REPO, "Litecoin detached-signatures repository"),
        (GITIAN_SIGNER_DESCRIPTORS[1], UPSTREAM_LITECOIN_DETACHED_SIGS_REPO, "Litecoin detached-signatures repository"),
        (RELEASE_DOC, UPSTREAM_LITECOIN_DETACHED_SIGS_REPO, "Litecoin detached-signatures repository"),
        (RELEASE_DOC, UPSTREAM_LITECOIN_GITIAN_SIGS_REPO, "Litecoin Gitian signatures repository"),
        (RELEASE_DOC, UPSTREAM_LITECOIN_GITHUB_RELEASE_URL, "Litecoin GitHub release URL"),
        (RELEASE_DOC, "gitian.sigs.ltc", "Litecoin Gitian signatures directory"),
        (RELEASE_DOC, "litecoin-detached-sigs", "Litecoin detached-signatures directory"),
        (RELEASE_DOC, "litecoin.org server", "Litecoin artifact publication host"),
        (RELEASE_DOC, "Update litecoin.org version", "Litecoin website update"),
        (RELEASE_DOC, "blog.litecoin.org", "Litecoin blog target"),
        (RELEASE_DOC, "bitcoincore.org", "Bitcoin Core website target"),
        (RELEASE_DOC, "org.bitcoincore.bitcoin-qt", "Bitcoin Core Flatpak target"),
        (RELEASE_DOC, "bitcoin-core-snap", "Bitcoin Core snap target"),
        (RELEASE_DOC, UPSTREAM_LITECOIN_MACOS_BUNDLE_ID, "Litecoin macOS bundle identifier"),
        (RELEASE_DOC, "<apple-id-email>", "placeholder Apple ID"),
        (RELEASE_DOC, "<apple-id-notarisation-app-specific-password>", "placeholder Apple keychain item"),
        (RELEASE_DOC, "<team-id-shortcode>", "placeholder Apple provider shortcode"),
        (RELEASE_DOC, "/path/to/codesign.key", "placeholder Windows signing key path"),
        (RELEASE_DOC, "gpg --digest-algo sha256 --clearsign SHA256SUMS # outputs SHA256SUMS.asc", "unqualified release checksum signing command"),
    )
    for path, needle, description in absent_checks:
        error = require_absent_text(path, needle, description)
        if error:
            return fail(error)

    error = require_src_dist_entries()
    if error:
        return fail(error)

    error = require_blake3_dist_entries()
    if error:
        return fail(error)

    error = require_libmw_dist_entries()
    if error:
        return fail(error)

    error = require_wallet_interface_dist_entries()
    if error:
        return fail(error)

    error = require_source_dist_smoke_entries()
    if error:
        return fail(error)

    return 0


if __name__ == "__main__":
    sys.exit(main())
