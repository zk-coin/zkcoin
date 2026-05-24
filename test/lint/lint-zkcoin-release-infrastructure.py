#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that inherited release infrastructure stays explicit and fail-closed."""

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace


ROOT_DIR = Path(__file__).resolve().parents[2]
MANIFEST = ROOT_DIR / "contrib" / "devtools" / "zkcoin_release_infrastructure_manifest.json"
DEVTOOLS_README = ROOT_DIR / "contrib" / "devtools" / "README.md"
RELEASE_CANDIDATE_VALIDATION = ROOT_DIR / "contrib" / "devtools" / "zkcoin_release_candidate_validation.sh"
SOURCE_DIST_SMOKE = ROOT_DIR / "contrib" / "devtools" / "zkcoin_source_dist_smoke.sh"
SOURCE_DIST_REALPROOF_SMOKE = ROOT_DIR / "contrib" / "devtools" / "zkcoin_source_dist_realproof_smoke.sh"
GITIAN_RUST_TOOLCHAIN_CHECK = ROOT_DIR / "contrib" / "devtools" / "zkcoin_gitian_rust_toolchain_check.sh"
RELEASE_DOC = ROOT_DIR / "doc" / "release-process.md"
VERIFY_SCRIPT = ROOT_DIR / "contrib" / "verifybinaries" / "verify.sh"
ZKCOIN_VERIFY_SCRIPT = ROOT_DIR / "contrib" / "verifybinaries" / "verify-zkcoin-release.py"
RUST_SHIELDED_VERIFIER_CARGO_CONFIG = ROOT_DIR / "src" / "rust" / "shielded-verifier" / ".cargo" / "config.toml"
RUST_SHIELDED_VERIFIER_VENDOR = ROOT_DIR / "src" / "rust" / "shielded-verifier" / "vendor"
VERIFY_README = ROOT_DIR / "contrib" / "verifybinaries" / "README.md"
CONTRIB_README = ROOT_DIR / "contrib" / "README.md"
GITIAN_BUILD = ROOT_DIR / "contrib" / "gitian-build.py"
GITIAN_SOURCE_DESCRIPTORS = (
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-linux.yml",
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-win.yml",
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-osx.yml",
)
GITIAN_SOURCE_DESCRIPTOR_RUST_TOOLCHAINS = {
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-linux.yml": (
        "zkcoin-gitian-rust-toolchain-linux.env",
        "x86_64-unknown-linux-gnu arm-unknown-linux-gnueabihf aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu",
    ),
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-win.yml": (
        "zkcoin-gitian-rust-toolchain-win.env",
        "x86_64-pc-windows-gnu",
    ),
    ROOT_DIR / "contrib" / "gitian-descriptors" / "gitian-osx.yml": (
        "zkcoin-gitian-rust-toolchain-osx.env",
        "x86_64-apple-darwin",
    ),
}
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
    "source_tag_version_provenance",
    "zkcoin_release_signing_key",
    "gitian_sigs_repo",
    "gitian_rust_toolchain_provenance",
    "detached_sigs_repo",
    "artifact_download_host",
    "release_announcement_channels",
    "release_notes_archive",
    "github_release_metadata",
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
    "rust/shielded-verifier/.cargo/config.toml",
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
    "rust/shielded-verifier/vendor",
    "rust/shielded-verifier/vendor/halo2_proofs/.cargo-checksum.json",
    "rust/shielded-verifier/vendor/halo2_proofs/Cargo.toml",
    "rust/shielded-verifier/vendor/orchard/.cargo-checksum.json",
    "rust/shielded-verifier/vendor/orchard/Cargo.toml",
    "rust/shielded-verifier/vendor/sha2/.cargo-checksum.json",
    "rust/shielded-verifier/vendor/sha2/Cargo.toml",
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
REQUIRED_GITIAN_RUST_TOOLCHAIN_DIST = (
    "contrib/devtools/zkcoin_gitian_rust_toolchain_check.sh",
)
REQUIRED_RUST_SHIELDED_VERIFIER_TARGETS = (
    "x86_64-unknown-linux-gnu",
    "arm-unknown-linux-gnueabihf",
    "armv7-unknown-linux-gnueabihf",
    "aarch64-unknown-linux-gnu",
    "riscv64gc-unknown-linux-gnu",
    "x86_64-pc-windows-gnu",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
)


class DuplicateJSONFieldError(ValueError):
    pass


def reject_duplicate_json_fields(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DuplicateJSONFieldError(field)
        result[field] = value
    return result


def parse_manifest_json(text):
    try:
        return json.loads(text, object_pairs_hook=reject_duplicate_json_fields)
    except DuplicateJSONFieldError as exc:
        raise ValueError("contains duplicate field: {}".format(exc)) from exc
    except json.JSONDecodeError as exc:
        raise ValueError("invalid JSON: {}".format(exc)) from exc


def check_manifest_json_loader():
    try:
        parse_manifest_json('{"status": "ready", "status": "release_infrastructure_not_ready"}')
    except ValueError as exc:
        if "contains duplicate field: status" not in str(exc):
            return "duplicate-field guard reported the wrong error"
    else:
        return "duplicate-field guard accepted shadowed JSON"
    return None


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


def require_ordered_text(path, needles, description):
    text = path.read_text(encoding="utf8")
    offset = 0
    for needle in needles:
        found = text.find(needle, offset)
        if found == -1:
            return "{} missing or misordered {}: {}".format(path.relative_to(ROOT_DIR), description, needle)
        offset = found + len(needle)
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


def require_rust_shielded_verifier_target_mapping():
    configure_text = CONFIGURE.read_text(encoding="utf8")
    makefile_text = SRC_MAKEFILE_AM.read_text(encoding="utf8")
    for needle in (
        "with-rust-shielded-verifier-target",
        "RUST_SHIELDED_VERIFIER_TARGET",
        "cannot derive Rust shielded verifier target",
        "rustc does not support target",
        "rust std library for target",
    ):
        if needle not in configure_text:
            return "configure scripts missing Rust shielded verifier target mapping guard: {}".format(needle)
    for target in REQUIRED_RUST_SHIELDED_VERIFIER_TARGETS:
        if target not in configure_text:
            return "configure scripts missing Rust shielded verifier target mapping: {}".format(target)
    for needle in (
        "target/@RUST_SHIELDED_VERIFIER_TARGET@/release/libzkc_shielded_verifier.a",
        "RUST_SHIELDED_VERIFIER_TARGET_ARG = --target @RUST_SHIELDED_VERIFIER_TARGET@",
        "$(CARGO) build --locked --release --lib $(RUST_SHIELDED_VERIFIER_TARGET_ARG)",
    ):
        if needle not in makefile_text:
            return "{} missing Rust target-specific verifier build rule: {}".format(
                SRC_MAKEFILE_AM.relative_to(ROOT_DIR),
                needle,
            )
    return None


def require_rust_shielded_verifier_vendor():
    config_text = RUST_SHIELDED_VERIFIER_CARGO_CONFIG.read_text(encoding="utf8")
    for needle in (
        '[source.crates-io]',
        'replace-with = "vendored-sources"',
        '[source.vendored-sources]',
        'directory = "vendor"',
    ):
        if needle not in config_text:
            return "{} missing vendored Cargo source config: {}".format(
                RUST_SHIELDED_VERIFIER_CARGO_CONFIG.relative_to(ROOT_DIR),
                needle,
            )
    for crate in ("orchard", "halo2_proofs", "sha2"):
        crate_dir = RUST_SHIELDED_VERIFIER_VENDOR / crate
        for required in ("Cargo.toml", ".cargo-checksum.json"):
            if not (crate_dir / required).is_file():
                return "{} missing vendored crate file: {}/{}".format(
                    RUST_SHIELDED_VERIFIER_VENDOR.relative_to(ROOT_DIR),
                    crate,
                    required,
                )
    vendor_crates = [path for path in RUST_SHIELDED_VERIFIER_VENDOR.iterdir() if path.is_dir()]
    vendor_checksums = list(RUST_SHIELDED_VERIFIER_VENDOR.glob("*/.cargo-checksum.json"))
    if len(vendor_crates) < 90:
        return "{} has too few vendored crates: {}".format(
            RUST_SHIELDED_VERIFIER_VENDOR.relative_to(ROOT_DIR),
            len(vendor_crates),
        )
    if len(vendor_crates) != len(vendor_checksums):
        return "{} must have one cargo checksum per vendored crate".format(
            RUST_SHIELDED_VERIFIER_VENDOR.relative_to(ROOT_DIR)
        )
    return None


def require_gitian_rust_toolchain_check():
    text = GITIAN_RUST_TOOLCHAIN_CHECK.read_text(encoding="utf8")
    for needle in (
        "load_required_field",
        "validate_commit_hash_field",
        "awk -F=",
        "cut -d= -f2-",
        "ZKCOIN_GITIAN_RUSTC_VERSION",
        "ZKCOIN_GITIAN_RUSTC_COMMIT_HASH",
        "ZKCOIN_GITIAN_CARGO_VERSION",
        "ZKCOIN_GITIAN_CARGO_COMMIT_HASH",
        "ZKCOIN_GITIAN_RUST_TARGETS",
        "missing required Gitian Rust toolchain provenance field",
        "multiple values for Gitian Rust toolchain provenance field",
        "ZKCOIN_GITIAN_RUST toolchain provenance fields must not be placeholders",
        "ZKCOIN_GITIAN_RUST commit-hash fields must be lowercase hexadecimal",
        "ZKCOIN_GITIAN_RUST commit-hash fields must be full 40-character hashes",
        "rustc version does not match ZKCOIN_GITIAN_RUSTC_VERSION",
        "rustc commit hash does not match ZKCOIN_GITIAN_RUSTC_COMMIT_HASH",
        "cargo version does not match ZKCOIN_GITIAN_CARGO_VERSION",
        "cargo commit hash does not match ZKCOIN_GITIAN_CARGO_COMMIT_HASH",
        "ZKCOIN_GITIAN_RUST_TARGETS does not match descriptor Rust targets",
        "rustc target-list does not include Gitian Rust target",
        "rust std library is not installed for Gitian Rust target",
        "rustc --print target-libdir",
    ):
        if needle not in text:
            return "{} missing Gitian Rust toolchain gate: {}".format(
                GITIAN_RUST_TOOLCHAIN_CHECK.relative_to(ROOT_DIR),
                needle,
            )
    for forbidden in (
        "source \"$toolchain_file\"",
        ". \"$toolchain_file\"",
    ):
        if forbidden in text:
            return "{} must parse provenance input without sourcing it: {}".format(
                GITIAN_RUST_TOOLCHAIN_CHECK.relative_to(ROOT_DIR),
                forbidden,
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
    required_entries.extend(REQUIRED_GITIAN_RUST_TOOLCHAIN_DIST)
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
        toolchain_file, rust_targets = GITIAN_SOURCE_DESCRIPTOR_RUST_TOOLCHAINS[descriptor]
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
        for package in ('- "cargo"', '- "rustc"'):
            if package not in text:
                return "{} must install Rust toolchain package for real Orchard verifier builds: {}".format(
                    descriptor.relative_to(ROOT_DIR),
                    package,
                )
        for configure_flag in ("--enable-rust-shielded-verifier", "--enable-rust-orchard-verifier"):
            if configure_flag not in text:
                return "{} must enable real Orchard verifier Gitian builds: {}".format(
                    descriptor.relative_to(ROOT_DIR),
                    configure_flag,
                )
        for needle, description in (
            ('- "{}"'.format(toolchain_file), "Rust toolchain provenance input file"),
            ('RUST_TARGETS="{}"'.format(rust_targets), "descriptor Rust target list"),
            ('RUST_TOOLCHAIN_FILE="${{BUILD_DIR}}/{}"'.format(toolchain_file), "descriptor Rust toolchain input path"),
            (
                'contrib/devtools/zkcoin_gitian_rust_toolchain_check.sh "${RUST_TOOLCHAIN_FILE}" "${RUST_TARGETS}"',
                "Rust toolchain provenance gate",
            ),
        ):
            if needle not in text:
                return "{} missing {}: {}".format(
                    descriptor.relative_to(ROOT_DIR),
                    description,
                    needle,
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


def require_zkcoin_verifier_rejects_duplicate_artifacts():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        manifest = Path(tempdir) / "SHA256SUMS"
        manifest.write_text(
            "{}  litecoin-1.0.tar.gz\n{}  litecoin-1.0.tar.gz\n".format("00" * 32, "11" * 32),
            encoding="utf8",
        )
        try:
            verifier.parse_checksum_manifest(manifest)
        except verifier.VerifyError as exc:
            if "duplicate artifact path in checksum manifest: litecoin-1.0.tar.gz" not in str(exc):
                return "zkCoin verifier reported the wrong duplicate artifact error"
        else:
            return "zkCoin verifier accepted a duplicate checksum artifact path"

    return None


def require_zkcoin_verifier_rejects_nonportable_artifact_paths():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    invalid_manifests = (
        "{}  zkcoin\\windows.zip\n".format("00" * 32),
        "{}  zkcoin\tlinux.tar.gz\n".format("00" * 32),
    )
    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        manifest = Path(tempdir) / "SHA256SUMS"
        for manifest_text in invalid_manifests:
            manifest.write_text(manifest_text, encoding="utf8")
            try:
                verifier.parse_checksum_manifest(manifest)
            except verifier.VerifyError as exc:
                if "artifact path contains backslashes or control characters in checksum manifest" not in str(exc):
                    return "zkCoin verifier reported the wrong non-portable artifact path error"
            else:
                return "zkCoin verifier accepted a non-portable checksum artifact path"

    return None


def require_zkcoin_verifier_rejects_nonnormalized_artifact_paths():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    invalid_manifests = (
        "{}  ./zkcoin-linux.tar.gz\n".format("00" * 32),
        "{}  releases//zkcoin-linux.tar.gz\n".format("00" * 32),
    )
    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        manifest = Path(tempdir) / "SHA256SUMS"
        for manifest_text in invalid_manifests:
            manifest.write_text(manifest_text, encoding="utf8")
            try:
                verifier.parse_checksum_manifest(manifest)
            except verifier.VerifyError as exc:
                if "artifact path must be a normalized POSIX path in checksum manifest" not in str(exc):
                    return "zkCoin verifier reported the wrong non-normalized artifact path error"
            else:
                return "zkCoin verifier accepted a non-normalized checksum artifact path"

    return None


def require_zkcoin_verifier_rejects_symlink_artifacts():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        artifacts_dir.mkdir()
        external_artifact = Path(tempdir) / "external-artifact"
        external_artifact.write_bytes(b"not a release artifact")
        (artifacts_dir / "litecoin-1.0.tar.gz").symlink_to(external_artifact)

        args = SimpleNamespace(
            artifacts_dir=artifacts_dir,
            download_base=None,
            download_timeout=1,
        )
        try:
            verifier.verify_artifacts(args, [("00" * 32, "litecoin-1.0.tar.gz")])
        except verifier.VerifyError as exc:
            if "artifact path must not be a symlink: litecoin-1.0.tar.gz" not in str(exc):
                return "zkCoin verifier reported the wrong symlink artifact error"
        else:
            return "zkCoin verifier accepted a symlinked release artifact"

    return None


def require_zkcoin_verifier_rejects_insecure_download_base():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    invalid_urls = (
        "http://downloads.example.invalid/zkcoin/",
        "https://downloads.example.invalid/zkcoin/?mirror=1",
    )
    for url in invalid_urls:
        try:
            verifier.validate_download_base(url)
        except verifier.VerifyError as exc:
            if "--download-base must be an HTTPS base URL without parameters, query, or fragment" not in str(exc):
                return "zkCoin verifier reported the wrong download-base error"
        else:
            return "zkCoin verifier accepted insecure or malformed download base: {}".format(url)

    try:
        verifier.validate_download_base("https://downloads.example.invalid/zkcoin")
    except verifier.VerifyError as exc:
        return "zkCoin verifier rejected a well-formed HTTPS download base: {}".format(exc)

    return None


def require_zkcoin_verifier_rejects_invalid_download_timeout():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    for timeout in (0, -1):
        try:
            verifier.validate_download_timeout(timeout)
        except verifier.VerifyError as exc:
            if "--download-timeout must be a positive number of seconds" not in str(exc):
                return "zkCoin verifier reported the wrong download-timeout error"
        else:
            return "zkCoin verifier accepted invalid download timeout: {}".format(timeout)

    try:
        verifier.validate_download_timeout(1)
    except verifier.VerifyError as exc:
        return "zkCoin verifier rejected a valid download timeout: {}".format(exc)

    return None


def require_zkcoin_verifier_rejects_https_downgrade_redirects():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    class DowngradedResponse:
        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

        def geturl(self):
            return "http://downloads.example.invalid/zkcoin/zkcoin-1.0.tar.gz"

        def read(self, _size=-1):
            return b"unexpected payload"

    def downgraded_urlopen(_url, timeout):
        if timeout != 1:
            raise AssertionError("unexpected timeout")
        return DowngradedResponse()

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        target = artifacts_dir / "zkcoin-1.0.tar.gz"
        original_urlopen = verifier.urlopen
        verifier.urlopen = downgraded_urlopen
        try:
            try:
                verifier.download_artifact(
                    "https://downloads.example.invalid/zkcoin",
                    "zkcoin-1.0.tar.gz",
                    target,
                    1,
                )
            except verifier.VerifyError as exc:
                if "artifact download redirected away from HTTPS: zkcoin-1.0.tar.gz" not in str(exc):
                    return "zkCoin verifier reported the wrong HTTPS redirect error"
            else:
                return "zkCoin verifier accepted an HTTP artifact redirect"
        finally:
            verifier.urlopen = original_urlopen

        if target.exists():
            return "zkCoin verifier left an artifact after an HTTP redirect"
        leftovers = list(artifacts_dir.iterdir()) if artifacts_dir.exists() else []
        if leftovers:
            return "zkCoin verifier left temporary download files after an HTTP redirect"

    return None


def require_zkcoin_verifier_downloads_atomically():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    class FailingResponse:
        def __init__(self):
            self._read_once = False

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

        def geturl(self):
            return "https://downloads.example.invalid/zkcoin/zkcoin-1.0.tar.gz"

        def read(self, _size=-1):
            if not self._read_once:
                self._read_once = True
                return b"partial artifact payload"
            raise OSError("simulated interrupted download")

    def failing_urlopen(_url, timeout):
        if timeout != 1:
            raise AssertionError("unexpected timeout")
        return FailingResponse()

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        target = artifacts_dir / "zkcoin-1.0.tar.gz"
        original_urlopen = verifier.urlopen
        verifier.urlopen = failing_urlopen
        try:
            try:
                verifier.download_artifact(
                    "https://downloads.example.invalid/zkcoin",
                    "zkcoin-1.0.tar.gz",
                    target,
                    1,
                )
            except verifier.VerifyError as exc:
                if "failed to download artifact zkcoin-1.0.tar.gz" not in str(exc):
                    return "zkCoin verifier reported the wrong interrupted-download error"
            else:
                return "zkCoin verifier accepted an interrupted artifact download"
        finally:
            verifier.urlopen = original_urlopen

        if target.exists():
            return "zkCoin verifier left a partial artifact after an interrupted download"
        leftovers = list(artifacts_dir.iterdir()) if artifacts_dir.exists() else []
        if leftovers:
            return "zkCoin verifier left temporary download files after failure"

    return None


def require_zkcoin_verifier_rejects_raced_download_targets():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    class RacingResponse:
        def __init__(self, target):
            self.target = target
            self.sent = False

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

        def geturl(self):
            return "https://downloads.example.invalid/zkcoin/zkcoin-1.0.tar.gz"

        def read(self, _size=-1):
            if self.sent:
                return b""
            self.sent = True
            self.target.write_bytes(b"operator-provided artifact")
            return b"downloaded artifact payload"

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        target = artifacts_dir / "zkcoin-1.0.tar.gz"

        def racing_urlopen(_url, timeout):
            if timeout != 1:
                raise AssertionError("unexpected timeout")
            return RacingResponse(target)

        original_urlopen = verifier.urlopen
        verifier.urlopen = racing_urlopen
        try:
            try:
                verifier.download_artifact(
                    "https://downloads.example.invalid/zkcoin",
                    "zkcoin-1.0.tar.gz",
                    target,
                    1,
                )
            except verifier.VerifyError as exc:
                if "artifact path appeared during download: zkcoin-1.0.tar.gz" not in str(exc):
                    return "zkCoin verifier reported the wrong raced-download target error"
            else:
                return "zkCoin verifier overwrote an artifact path that appeared during download"
        finally:
            verifier.urlopen = original_urlopen

        if target.read_bytes() != b"operator-provided artifact":
            return "zkCoin verifier modified an artifact path that appeared during download"
        leftovers = [
            entry
            for entry in artifacts_dir.iterdir()
            if entry.name != "zkcoin-1.0.tar.gz"
        ]
        if leftovers:
            return "zkCoin verifier left temporary download files after a raced final artifact path"

    return None


def require_zkcoin_verifier_removes_hash_mismatched_downloads():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    class StaticResponse:
        def __init__(self, payload):
            self.payload = payload
            self.sent = False

        def __enter__(self):
            return self

        def __exit__(self, _exc_type, _exc, _traceback):
            return False

        def geturl(self):
            return "https://downloads.example.invalid/zkcoin/zkcoin-1.0.tar.gz"

        def read(self, _size=-1):
            if self.sent:
                return b""
            self.sent = True
            return self.payload

    def static_urlopen(_url, timeout):
        if timeout != 1:
            raise AssertionError("unexpected timeout")
        return StaticResponse(b"wrong artifact payload")

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        target = artifacts_dir / "zkcoin-1.0.tar.gz"
        args = SimpleNamespace(
            artifacts_dir=artifacts_dir,
            download_base="https://downloads.example.invalid/zkcoin",
            download_timeout=1,
        )
        original_urlopen = verifier.urlopen
        verifier.urlopen = static_urlopen
        try:
            try:
                verifier.verify_artifacts(args, [("00" * 32, "zkcoin-1.0.tar.gz")])
            except verifier.VerifyError as exc:
                if "artifact hash verification failed" not in str(exc):
                    return "zkCoin verifier reported the wrong mismatched-download error"
            else:
                return "zkCoin verifier accepted a hash-mismatched downloaded artifact"
        finally:
            verifier.urlopen = original_urlopen

        if target.exists():
            return "zkCoin verifier left a hash-mismatched downloaded artifact"

    with tempfile.TemporaryDirectory(prefix="zkcoin-verify-lint-") as tempdir:
        artifacts_dir = Path(tempdir) / "artifacts"
        artifacts_dir.mkdir()
        target = artifacts_dir / "zkcoin-1.0.tar.gz"
        target.write_bytes(b"pre-existing wrong artifact payload")
        args = SimpleNamespace(
            artifacts_dir=artifacts_dir,
            download_base=None,
            download_timeout=1,
        )
        try:
            verifier.verify_artifacts(args, [("00" * 32, "zkcoin-1.0.tar.gz")])
        except verifier.VerifyError as exc:
            if "artifact hash verification failed" not in str(exc):
                return "zkCoin verifier reported the wrong local mismatch error"
        else:
            return "zkCoin verifier accepted a hash-mismatched local artifact"
        if not target.is_file():
            return "zkCoin verifier removed a pre-existing hash-mismatched local artifact"

    return None


def require_zkcoin_verifier_rejects_malformed_trusted_fingerprints():
    spec = importlib.util.spec_from_file_location("zkcoin_verify_release", ZKCOIN_VERIFY_SCRIPT)
    if spec is None or spec.loader is None:
        return "cannot import {}".format(ZKCOIN_VERIFY_SCRIPT.relative_to(ROOT_DIR))

    verifier = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verifier)

    for fingerprint in ("1234", "TODO", "g" * 40):
        try:
            verifier.validate_trusted_fingerprints([fingerprint])
        except verifier.VerifyError as exc:
            if "trusted fingerprint must be a full 40-character hex fingerprint" not in str(exc):
                return "zkCoin verifier reported the wrong trusted fingerprint error"
        else:
            return "zkCoin verifier accepted malformed trusted fingerprint: {}".format(fingerprint)

    try:
        verifier.validate_trusted_fingerprints(["0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567"])
    except verifier.VerifyError as exc:
        return "zkCoin verifier rejected a well-formed trusted fingerprint: {}".format(exc)

    return None


def main():
    loader_error = check_manifest_json_loader()
    if loader_error:
        return fail(loader_error)

    try:
        manifest = parse_manifest_json(MANIFEST.read_text(encoding="utf8"))
    except ValueError as exc:
        return fail(str(exc))

    if manifest.get("project") != "zkcoin":
        return fail("project must be zkcoin")
    if manifest.get("schema_version") != 1:
        return fail("schema_version must be 1")
    if manifest.get("status") != "release_infrastructure_not_ready":
        return fail("status must stay release_infrastructure_not_ready until release keys, repos, and hosts are configured")

    error = require_zkcoin_verifier_rejects_duplicate_artifacts()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_nonportable_artifact_paths()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_nonnormalized_artifact_paths()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_symlink_artifacts()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_insecure_download_base()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_invalid_download_timeout()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_https_downgrade_redirects()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_downloads_atomically()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_raced_download_targets()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_removes_hash_mismatched_downloads()
    if error:
        return fail(error)
    error = require_zkcoin_verifier_rejects_malformed_trusted_fingerprints()
    if error:
        return fail(error)

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
    if "ZKCOIN_RELEASE_VERSION" not in notes_text:
        return fail("notes must document parameterized zkCoin release version provenance")
    if "ZKCOIN_RELEASE_TAG" not in notes_text:
        return fail("notes must document parameterized zkCoin release tag provenance")
    if "ZKCOIN_RELEASE_SOURCE_COMMIT" not in notes_text:
        return fail("notes must document parameterized zkCoin source commit provenance")
    if "source release-candidate validation gate proves source tarball real-proof readiness only" not in notes_text:
        return fail("notes must keep source release-candidate validation separate from binary release readiness")
    if "Gitian binary descriptors install rustc and cargo" not in notes_text:
        return fail("notes must document Rust toolchain requirement for Gitian binary descriptors")
    if "--enable-rust-shielded-verifier plus --enable-rust-orchard-verifier" not in notes_text:
        return fail("notes must document real Orchard verifier flags for Gitian binary descriptors")
    if "zkcoin-gitian-rust-toolchain-*.env" not in notes_text:
        return fail("notes must document descriptor-specific Gitian Rust toolchain provenance files")
    if "ZKCOIN_GITIAN_RUSTC_COMMIT_HASH" not in notes_text:
        return fail("notes must document Gitian Rust compiler commit-hash binding")
    if "ZKCOIN_GITIAN_CARGO_COMMIT_HASH" not in notes_text:
        return fail("notes must document Gitian Cargo commit-hash binding")
    if "commit-hash fields to be full lowercase 40-character hashes" not in notes_text:
        return fail("notes must document Gitian Rust commit-hash shape validation")
    if "verify every Rust target standard library before building real Orchard binaries" not in notes_text:
        return fail("notes must document Gitian Rust target stdlib verification before binary builds")
    if "derive or require an explicit Rust target triple from the configured host" not in notes_text:
        return fail("notes must document Rust verifier target mapping")
    if "target-specific libzkc_shielded_verifier.a" not in notes_text:
        return fail("notes must document target-specific Rust verifier staticlib linkage")
    if "Cargo config replaces crates.io with committed vendored sources" not in notes_text:
        return fail("notes must document vendored Cargo sources")
    if "vendor checksums for Orchard, halo2_proofs, and sha2" not in notes_text:
        return fail("notes must document vendored Rust verifier checksum sentinels")
    if "ZKCOIN_RELEASE_BINARY_NAMESPACE" not in notes_text:
        return fail("notes must document parameterized zkCoin binary namespace decision")
    if "ZKCOIN_GITIAN_SIGNER_QUORUM" not in notes_text:
        return fail("notes must document parameterized zkCoin Gitian signer quorum")
    if "ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" not in notes_text:
        return fail("notes must document published zkCoin Gitian authorized signer list")
    if "non-HTTPS release repository URLs" not in notes_text:
        return fail("notes must document HTTPS validation for zkCoin release repository URLs")
    if "Gitian signatures and detached-signatures repositories to be distinct" not in notes_text:
        return fail("notes must document distinct Gitian and detached-signatures repositories")
    if "reject placeholder detached-signatures release refs before clone" not in notes_text:
        return fail("notes must document detached-signatures release ref placeholder rejection before clone")
    if "ZKCOIN_DETACHED_SIGS_RELEASE_REF as a branch name" not in notes_text:
        return fail("notes must document detached-signatures release branch shape validation")
    if "ZKCOIN_DETACHED_SIGS_RELEASE_TAG as a tag name" not in notes_text:
        return fail("notes must document detached-signatures release tag shape validation")
    if "ZKCOIN_GITIAN_BUILDER_COMMIT" not in notes_text:
        return fail("notes must document pinned zkCoin Gitian builder commit provenance")
    if "instead of using git pull" not in notes_text:
        return fail("notes must document pinned Gitian builder updates")
    if "local Gitian signatures origin matches ZKCOIN_GITIAN_SIGS_REPO_URL" not in notes_text:
        return fail("notes must document Gitian signatures remote verification")
    if "git pull --ff-only" not in notes_text:
        return fail("notes must document fast-forward-only Gitian signatures updates")
    if "verify-zkcoin-release.py" not in notes_text:
        return fail("notes must document parameterized zkCoin binary artifact verification")
    if "example.invalid detached-signatures URL" not in notes_text:
        return fail("notes must document fail-closed detached-signatures signer descriptors")
    if "ZKCOIN_DETACHED_SIGS_RELEASE_REF" not in notes_text:
        return fail("notes must document parameterized zkCoin detached-signatures release ref")
    if "ZKCOIN_DETACHED_SIGS_CUSTODY_RECORD" not in notes_text:
        return fail("notes must document zkCoin detached-signatures custody record")
    if "ZKCOIN_DETACHED_SIGS_CUSTODY_OWNER" not in notes_text:
        return fail("notes must document zkCoin detached-signatures custody owner")
    if "ZKCOIN_DETACHED_SIGS_PAYLOAD_APPROVAL" not in notes_text:
        return fail("notes must document zkCoin detached-signatures payload approval")
    if "local detached-signatures origin matches ZKCOIN_DETACHED_SIGS_REPO_URL" not in notes_text:
        return fail("notes must document detached-signatures payload repo origin verification")
    if "before replacing payload contents" not in notes_text:
        return fail("notes must document detached-signatures clean checkout guards")
    if "ZKCOIN_DETACHED_SIGS_OSX_PAYLOAD_ARCHIVE" not in notes_text:
        return fail("notes must document detached-signatures macOS payload archive path")
    if "absolute existing tar archives outside the detached-signatures repository" not in notes_text:
        return fail("notes must document detached-signatures payload archive path validation")
    if "absolute paths, parent traversal, and unexpected top-level entries" not in notes_text:
        return fail("notes must document detached-signatures payload archive member path validation")
    if "hidden payload entries while preserving .git" not in notes_text:
        return fail("notes must document full detached-signatures payload cleanup")
    if "reject an existing ZKCOIN_DETACHED_SIGS_RELEASE_TAG" not in notes_text:
        return fail("notes must document detached-signatures release tag reuse rejection")
    if "signed tag to resolve to the detached-signatures payload commit" not in notes_text:
        return fail("notes must document detached-signatures release tag commit binding")
    if "ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" not in notes_text:
        return fail("notes must document parameterized zkCoin release checksum signing key")
    if "ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_RECORD" not in notes_text:
        return fail("notes must document zkCoin release signing key custody record")
    if "ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_OWNER" not in notes_text:
        return fail("notes must document zkCoin release signing key custody owner")
    if "ZKCOIN_RELEASE_SIGNING_KEY_REVOCATION_PLAN" not in notes_text:
        return fail("notes must document zkCoin release signing key revocation plan")
    if "ZKCOIN_RELEASE_ARTIFACTS" not in notes_text:
        return fail("notes must document explicit zkCoin release artifact checksum set")
    if "local pre-upload verify-zkcoin-release.py check" not in notes_text:
        return fail("notes must document local pre-upload zkCoin artifact verification")
    if "ZKCOIN_RELEASE_ARTIFACT_BASE_URL" not in notes_text:
        return fail("notes must document parameterized zkCoin artifact publication targets")
    if "non-HTTPS publication URLs" not in notes_text:
        return fail("notes must document HTTPS validation for zkCoin artifact publication targets")
    if "ZKCOIN_RELEASE_CHECKSUMS_URL to publish SHA256SUMS.asc" not in notes_text:
        return fail("notes must document checksum publication URL shape validation")
    if "ZKCOIN_PUBLIC_VERIFY_DIR" not in notes_text:
        return fail("notes must document public zkCoin post-upload checksum verification")
    if "ZKCOIN_RELEASE_WEBSITE_REPO_URL" not in notes_text:
        return fail("notes must document parameterized zkCoin release metadata publication targets")
    if "non-HTTPS metadata URLs" not in notes_text:
        return fail("notes must document HTTPS validation for zkCoin metadata publication targets")
    if "ZKCOIN_RELEASE_ANNOUNCEMENT_CHANNELS" not in notes_text:
        return fail("notes must document parameterized zkCoin release announcement targets")
    if "placeholder announcement fields" not in notes_text:
        return fail("notes must document placeholder rejection for zkCoin release announcement targets")
    if "ZKCOIN_RELEASE_NOTES_PATH" not in notes_text:
        return fail("notes must document parameterized zkCoin release notes archival targets")
    if "ZKCOIN_RELEASE_NOTES_BRANCH" not in notes_text:
        return fail("notes must document parameterized zkCoin release notes archival branch")
    if "ZKCOIN_RELEASE_NOTES_OWNER" not in notes_text:
        return fail("notes must document parameterized zkCoin release notes archival owner")
    if "git cat-file -e" not in notes_text or "git diff --quiet" not in notes_text:
        return fail("notes must document zkCoin release notes archive existence and content verification")
    if "ZKCOIN_RELEASE_GITHUB_TAG" not in notes_text:
        return fail("notes must document parameterized zkCoin GitHub release metadata")
    if "placeholder GitHub release metadata fields" not in notes_text:
        return fail("notes must document placeholder rejection for zkCoin GitHub release metadata")
    if "GitHub release title to include ZKCOIN_RELEASE_VERSION" not in notes_text:
        return fail("notes must document GitHub release title version binding")
    if "ZKCOIN_MACOS_BUNDLE_ID" not in notes_text:
        return fail("notes must document parameterized zkCoin macOS notarization identity")
    if "ZKCOIN_MACOS_CODESIGN_IDENTITY" not in notes_text:
        return fail("notes must document zkCoin macOS code-signing identity")
    if "ZKCOIN_MACOS_CODESIGN_CERT_CUSTODY" not in notes_text:
        return fail("notes must document zkCoin macOS signing certificate custody")
    if "ZKCOIN_MACOS_CODESIGN_CERT_OWNER" not in notes_text:
        return fail("notes must document zkCoin macOS signing certificate custody owner")
    if "ZKCOIN_MACOS_CODESIGN_PAYLOAD_APPROVAL" not in notes_text:
        return fail("notes must document zkCoin macOS signing payload approval")
    if "ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD_SOURCE" not in notes_text:
        return fail("notes must document zkCoin macOS app-specific password source")
    if "ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID" not in notes_text:
        return fail("notes must document zkCoin macOS notarization request UUID")
    if "ZKCOIN_MACOS_NOTARIZATION_STATUS_LOG" not in notes_text:
        return fail("notes must document zkCoin macOS notarization status log")
    if "stapler validation" not in notes_text or "spctl assessment" not in notes_text:
        return fail("notes must document zkCoin macOS notarization completion validation")
    if "ZKCOIN_WINDOWS_CODESIGN_KEY_PATH" not in notes_text:
        return fail("notes must document parameterized zkCoin Windows signing key custody")
    if "ZKCOIN_WINDOWS_CODESIGN_KEY_OWNER" not in notes_text:
        return fail("notes must document zkCoin Windows signing key custody owner")
    if "ZKCOIN_WINDOWS_CODESIGN_PAYLOAD_APPROVAL" not in notes_text:
        return fail("notes must document zkCoin Windows signing payload approval")

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

    error = require_gitian_rust_toolchain_check()
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
        ("ZKCOIN_RELEASE_BINARY_NAMESPACE", "parameterized binary namespace decision"),
        ("ZKCOIN_RELEASE_BINARY_NAMESPACE=zkcoin requires binary and artifact namespace migration before signing", "zkcoin namespace migration guard"),
        ("must be litecoin-compatibility or zkcoin", "binary namespace decision validation"),
        ("zkcoin_release_candidate_validation.sh", "source release-candidate validation gate"),
        ("It is not binary release readiness", "source-vs-binary readiness boundary"),
        ("does not authorize publishing binaries", "binary publication blocker"),
        ("git clone https://github.com/zk-coin/zkcoin.git litecoin", "zkCoin source clone"),
        ("ZKCOIN_RELEASE_VERSION", "parameterized release version"),
        ("ZKCOIN_RELEASE_TAG", "parameterized release source tag"),
        ("ZKCOIN_RELEASE_SOURCE_COMMIT", "parameterized release source commit"),
        ("ZKCOIN_RELEASE_VERSION must be a bare version without v, slashes, spaces, or repeated dots", "release version shape validation"),
        ("ZKCOIN_RELEASE_TAG must be v${ZKCOIN_RELEASE_VERSION}", "release tag version binding"),
        ('git check-ref-format "refs/tags/$ZKCOIN_RELEASE_TAG"', "release tag ref validation"),
        ('git tag -s "$ZKCOIN_RELEASE_TAG" "$ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED"', "signed release source tag creation"),
        ('git verify-tag "$ZKCOIN_RELEASE_TAG"', "release source tag signature verification"),
        ('ZKCOIN_RELEASE_TAG_COMMIT="$(git rev-list -n 1 "$ZKCOIN_RELEASE_TAG")"', "release source tag commit resolution"),
        ("ZKCOIN_RELEASE_TAG does not point at ZKCOIN_RELEASE_SOURCE_COMMIT", "release tag commit binding failure"),
        ('export VERSION="$ZKCOIN_RELEASE_VERSION"', "Gitian version derived from zkCoin release version"),
        ('git checkout --detach "$ZKCOIN_RELEASE_TAG^{commit}"', "Gitian checkout from signed release source tag"),
        ("Gitian checkout does not match ZKCOIN_RELEASE_SOURCE_COMMIT", "Gitian source commit binding failure"),
        ("Resolve approved Rust Gitian toolchain provenance", "Gitian Rust toolchain provenance boundary"),
        ("zkcoin-gitian-rust-toolchain-linux.env", "Linux Rust toolchain provenance input"),
        ("zkcoin-gitian-rust-toolchain-win.env", "Windows Rust toolchain provenance input"),
        ("zkcoin-gitian-rust-toolchain-osx.env", "macOS Rust toolchain provenance input"),
        ("ZKCOIN_GITIAN_RUSTC_VERSION", "Gitian Rust compiler version provenance"),
        ("ZKCOIN_GITIAN_RUSTC_COMMIT_HASH", "Gitian Rust compiler commit provenance"),
        ("ZKCOIN_GITIAN_CARGO_VERSION", "Gitian Cargo version provenance"),
        ("ZKCOIN_GITIAN_CARGO_COMMIT_HASH", "Gitian Cargo commit provenance"),
        ("ZKCOIN_GITIAN_RUST_TARGETS", "Gitian Rust target list provenance"),
        ("non-lowercase or non-40-character commit hashes", "Gitian Rust commit-hash shape guard"),
        ("x86_64-unknown-linux-gnu arm-unknown-linux-gnueabihf aarch64-unknown-linux-gnu riscv64gc-unknown-linux-gnu", "Linux Gitian Rust target list"),
        ("x86_64-pc-windows-gnu", "Windows Gitian Rust target list"),
        ("x86_64-apple-darwin", "macOS Gitian Rust target list"),
        ("mismatched `rustc` and `cargo` versions or commit hashes", "Gitian Rust toolchain mismatch guard"),
        ("missing Rust standard libraries for every descriptor target", "Gitian Rust target stdlib guard"),
        ('--commit "litecoin=${ZKCOIN_RELEASE_TAG}"', "Gitian build source tag input"),
        ("verify-zkcoin-release.py", "zkCoin binary artifact verification"),
        ("not embed production signing keys", "parameterized binary verification boundary"),
        ("ZKCOIN_GITIAN_SIGS_REPO_URL", "parameterized Gitian signatures repository"),
        ("ZKCOIN_RELEASE_REPO_URL", "release repository URL validation loop"),
        ("ZKCOIN release repository URLs must not be placeholders", "release repository URL placeholder rejection"),
        ("ZKCOIN release repository URLs must use HTTPS and point at the zk-coin GitHub org", "release repository URL HTTPS and org validation"),
        ("ZKCOIN_GITIAN_SIGS_REPO_URL and ZKCOIN_DETACHED_SIGS_REPO_URL must be distinct repositories", "distinct release repository validation"),
        ("ZKCOIN_GITIAN_BUILDER_REPO_URL", "parameterized Gitian builder repository"),
        ("ZKCOIN_GITIAN_BUILDER_COMMIT", "pinned Gitian builder commit"),
        ("ZKCOIN_GITIAN_BUILDER_REPO_URL must not be a placeholder", "Gitian builder repository placeholder rejection"),
        ("ZKCOIN_GITIAN_BUILDER_REPO_URL must be an HTTPS GitHub repository URL", "Gitian builder repository URL validation"),
        ("ZKCOIN_GITIAN_BUILDER_COMMIT must be a full 40-character commit id", "Gitian builder commit length validation"),
        ('git clone "$ZKCOIN_GITIAN_BUILDER_REPO_URL" gitian-builder', "parameterized Gitian builder clone"),
        ('git checkout --detach "$ZKCOIN_GITIAN_BUILDER_COMMIT"', "pinned Gitian builder checkout"),
        ("Gitian builder checkout does not match ZKCOIN_GITIAN_BUILDER_COMMIT", "Gitian builder checkout binding failure"),
        ("Ensure gitian-builder is still on the pinned zkCoin release build commit", "pinned Gitian builder refresh boundary"),
        ("Ensure your zkCoin Gitian signatures repository remote is the resolved zkCoin", "Gitian signatures update boundary"),
        ('git remote get-url origin', "Gitian signatures origin verification"),
        ("Gitian signatures origin does not match ZKCOIN_GITIAN_SIGS_REPO_URL", "Gitian signatures origin mismatch failure"),
        ("git status --porcelain", "Gitian signatures clean checkout check"),
        ("Gitian signatures repository must be clean before update", "Gitian signatures dirty checkout guard"),
        ("git pull --ff-only", "Gitian signatures fast-forward-only update"),
        ("ZKCOIN_GITIAN_SIGNER", "parameterized Gitian signer id"),
        ("ZKCOIN_GITIAN_SIGNER_FINGERPRINT", "parameterized Gitian signer fingerprint"),
        ("ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE", "published Gitian authorized signers file"),
        ("ZKCOIN_GITIAN_SIGNER must be a single authorized signer id", "Gitian signer id validation"),
        ("ZKCOIN_GITIAN_SIGNER_FINGERPRINT must be at least 40 hex characters", "Gitian signer fingerprint length validation"),
        ("ZKCOIN_GITIAN_SIGNER and fingerprint are not in the authorized zkCoin Gitian signer list", "Gitian signer authorization validation"),
        ('export SIGNER="$ZKCOIN_GITIAN_SIGNER"', "Gitian signer derived from authorized zkCoin signer"),
        ("ZKCOIN_GITIAN_SIGNER_QUORUM", "parameterized Gitian signer quorum"),
        ("ZKCOIN_GITIAN_UNAUTHORIZED_SIGNERS", "unauthorized Gitian signer detection"),
        ("contains unauthorized Gitian signer directories", "unauthorized Gitian signer failure"),
        ("ZKCOIN_GITIAN_AUTHORIZED_SIGNER_COUNT", "authorized Gitian signer quorum count"),
        ("authorized Gitian signers; require", "authorized Gitian signer quorum failure"),
        ("published zkCoin Gitian signer quorum", "zkCoin Gitian signer quorum boundary"),
        ("ZKCOIN_GITIAN_RELEASE", "Gitian signer quorum release loop"),
        ("${VERSION}-win-signed", "Gitian signed Windows quorum check"),
        ("${VERSION}-osx-signed", "Gitian signed macOS quorum check"),
        ("ZKCOIN_DETACHED_SIGS_REPO_URL", "parameterized detached-signatures repository"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_REF", "parameterized detached-signatures release branch"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_TAG", "parameterized detached-signatures release tag"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_FIELD", "detached-signatures release ref validation loop"),
        ("ZKCOIN_DETACHED_SIGS release refs must not be placeholders", "detached-signatures release ref placeholder rejection"),
        ('git check-ref-format --branch "$ZKCOIN_DETACHED_SIGS_RELEASE_REF"', "detached-signatures release branch shape validation"),
        ('git check-ref-format "refs/tags/$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"', "detached-signatures release tag shape validation"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_REF and ZKCOIN_DETACHED_SIGS_RELEASE_TAG must be distinct", "detached-signatures release ref/tag distinct validation"),
        ("ZKCOIN_DETACHED_SIGS_CUSTODY_RECORD", "detached-signatures custody record"),
        ("ZKCOIN_DETACHED_SIGS_CUSTODY_OWNER", "detached-signatures custody owner"),
        ("ZKCOIN_DETACHED_SIGS_PAYLOAD_APPROVAL", "detached-signatures payload approval record"),
        ("ZKCOIN_DETACHED_SIGS_OSX_PAYLOAD_ARCHIVE", "detached-signatures macOS payload archive"),
        ("ZKCOIN_DETACHED_SIGS_WIN_PAYLOAD_ARCHIVE", "detached-signatures Windows payload archive"),
        ("ZKCOIN_DETACHED_SIGS custody fields must not be placeholders", "detached-signatures custody placeholder rejection"),
        ("ZKCOIN_DETACHED_SIGS_REPO_ROOT", "detached-signatures repository root resolution"),
        ("ZKCOIN_DETACHED_SIGS payload archives must use absolute paths", "detached-signatures payload archive absolute path validation"),
        ("ZKCOIN_DETACHED_SIGS payload archives must be outside the detached-signatures repository", "detached-signatures payload archive outside-repo validation"),
        ("ZKCOIN_DETACHED_SIGS payload archive does not exist", "detached-signatures payload archive existence validation"),
        ("ZKCOIN_DETACHED_SIGS_PAYLOAD_ARCHIVE_RESOLVED", "detached-signatures payload archive physical path resolution"),
        ('tar -tf "$ZKCOIN_DETACHED_SIGS_PAYLOAD_ARCHIVE_RESOLVED" >/dev/null', "detached-signatures payload archive tar validation"),
        ("ZKCOIN_DETACHED_SIGS_PAYLOAD_MEMBER", "detached-signatures payload archive member loop"),
        ("ZKCOIN_DETACHED_SIGS payload archive contains unsafe path", "detached-signatures payload archive unsafe path rejection"),
        ("ZKCOIN_DETACHED_SIGS_PAYLOAD_MEMBER_TOP", "detached-signatures payload archive top-level member normalization"),
        ("ZKCOIN_DETACHED_SIGS payload archive contains unexpected top-level path", "detached-signatures payload archive unexpected top-level rejection"),
        ("Detached signatures origin does not match ZKCOIN_DETACHED_SIGS_REPO_URL", "detached-signatures origin mismatch failure"),
        ("Detached signatures repository must be clean before payload replacement", "detached-signatures dirty checkout guard"),
        ("Detached signatures release branch must be clean before payload replacement", "detached-signatures release branch dirty guard"),
        ('git fetch origin "$ZKCOIN_DETACHED_SIGS_RELEASE_REF:$ZKCOIN_DETACHED_SIGS_RELEASE_REF" --tags', "detached-signatures release branch fetch"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_TAG already exists; choose a new signed payload tag", "detached-signatures release tag reuse rejection"),
        ('rev-parse --verify --quiet "$ZKCOIN_DETACHED_SIGS_RELEASE_REF^{commit}"', "detached-signatures release ref validation"),
        ("find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +", "detached-signatures full payload cleanup"),
        ('git tag -s "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG" HEAD', "detached-signatures release tag creation"),
        ('git verify-tag "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"', "detached-signatures release tag verification"),
        ('ZKCOIN_DETACHED_SIGS_RELEASE_TAG_COMMIT="$(git rev-list -n 1 "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG")"', "detached-signatures release tag commit resolution"),
        ("ZKCOIN_DETACHED_SIGS_RELEASE_TAG does not point at the detached-signatures payload commit", "detached-signatures release tag commit binding failure"),
        ('tar xf "$ZKCOIN_DETACHED_SIGS_OSX_PAYLOAD_ARCHIVE"', "detached-signatures macOS payload archive extraction"),
        ('tar xf "$ZKCOIN_DETACHED_SIGS_WIN_PAYLOAD_ARCHIVE"', "detached-signatures Windows payload archive extraction"),
        ('--commit "signature=${ZKCOIN_DETACHED_SIGS_RELEASE_TAG}"', "detached-signatures signed tag Gitian input"),
        ('--url "signature=../${ZKCOIN_DETACHED_SIGS_DIR}"', "explicit detached-signatures Gitian override"),
        ("zkcoin-detached-sigs", "zkCoin detached-signatures local directory"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT", "parameterized release signing key fingerprint"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_ID", "parameterized release signing local key id"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_RECORD", "release signing key custody record"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_OWNER", "release signing key custody owner"),
        ("ZKCOIN_RELEASE_SIGNING_KEY_REVOCATION_PLAN", "release signing key revocation plan"),
        ("ZKCOIN_RELEASE_SIGNING_KEY custody fields must not be placeholders", "release signing key custody placeholder rejection"),
        ("--with-colons --fingerprint", "release signing key fingerprint validation"),
        ('--local-user "$ZKCOIN_RELEASE_SIGNING_KEY_ID"', "explicit zkCoin release signing key invocation"),
        ("ZKCOIN_RELEASE_ARTIFACTS=(", "explicit release artifact checksum list"),
        ("ZKCOIN_EXPECTED_ARTIFACTS", "expected release artifact set"),
        ("ZKCOIN_ACTUAL_ARTIFACTS", "actual release artifact set"),
        ("Release artifact set does not match the expected zkCoin non-debug artifacts", "release artifact set mismatch failure"),
        ('sha256sum "${ZKCOIN_RELEASE_ARTIFACTS[@]}" > SHA256SUMS', "explicit release artifact checksum command"),
        ("Verify the local signed checksum manifest and artifacts before uploading", "pre-upload local artifact verification"),
        ("--artifacts-dir .", "pre-upload local artifact directory verification"),
        ("ZKCOIN_RELEASE_ARTIFACT_BASE_URL", "parameterized artifact host"),
        ("ZKCOIN_RELEASE_CHECKSUMS_URL", "parameterized checksum publication URL"),
        ("ZKCOIN_RELEASE_GITHUB_REPO_URL", "parameterized GitHub release repository"),
        ("ZKCOIN_RELEASE_PUBLICATION_URL", "release publication URL validation loop"),
        ("ZKCOIN_RELEASE publication URLs must not be placeholders", "release publication URL placeholder rejection"),
        ("ZKCOIN_RELEASE publication URLs must use HTTPS", "release publication URL HTTPS validation"),
        ("ZKCOIN_RELEASE_ARTIFACT_BASE_URL must end with /", "artifact base URL directory validation"),
        ("ZKCOIN_RELEASE_CHECKSUMS_URL must publish SHA256SUMS.asc", "checksum publication URL filename validation"),
        ("ZKCOIN_RELEASE_GITHUB_REPO_URL must point at the zk-coin GitHub org", "GitHub release repository organization validation"),
        ("ZKCOIN_PUBLIC_VERIFY_DIR", "clean public artifact verification directory"),
        ("Keep this in a clean directory so local build outputs cannot satisfy the", "public post-publication isolation"),
        ("curl --fail --location --show-error --silent", "public checksum fetch"),
        ('--output "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc"', "public checksum fetch output"),
        ('"$ZKCOIN_RELEASE_CHECKSUMS_URL"', "public checksum URL fetch"),
        ('cmp -s ./SHA256SUMS.asc "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc"', "public checksum manifest comparison"),
        ("Published SHA256SUMS.asc does not match the locally signed manifest", "public checksum mismatch failure"),
        ('--checksums "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc"', "post-publication public checksum verification"),
        ('--artifacts-dir "$ZKCOIN_PUBLIC_VERIFY_DIR"', "clean public artifact verification"),
        ("ZKCOIN_RELEASE_WEBSITE_REPO_URL", "parameterized website repository URL"),
        ("ZKCOIN_RELEASE_WEBSITE_OWNER", "parameterized website publication owner"),
        ("ZKCOIN_RELEASE_INDEX_REPO_URL", "parameterized release index repository URL"),
        ("ZKCOIN_RELEASE_INDEX_OWNER", "parameterized release index publication owner"),
        ("ZKCOIN_RELEASE_METADATA_URL", "release metadata URL validation loop"),
        ("ZKCOIN_RELEASE metadata URLs must not be placeholders", "release metadata URL placeholder rejection"),
        ("ZKCOIN_RELEASE metadata URLs must use HTTPS", "release metadata URL HTTPS validation"),
        ("ZKCOIN_RELEASE metadata URLs must point at the zk-coin GitHub org", "release metadata URL organization validation"),
        ("ZKCOIN_RELEASE_METADATA_OWNER", "release metadata owner validation loop"),
        ("ZKCOIN_RELEASE metadata owners must not be placeholders", "release metadata owner placeholder rejection"),
        ("Resolve the zkCoin release-index and website publication targets", "release metadata publication boundary"),
        ("ZKCOIN_RELEASE_ANNOUNCEMENT_CHANNELS", "parameterized announcement channels"),
        ("ZKCOIN_RELEASE_ANNOUNCEMENT_OWNER", "parameterized announcement owner"),
        ("ZKCOIN_RELEASE_ANNOUNCEMENT_FIELD", "release announcement field validation loop"),
        ("ZKCOIN_RELEASE announcement fields must not be placeholders", "release announcement placeholder rejection"),
        ("Resolve the zkCoin release announcement channels", "release announcement boundary"),
        ("ZKCOIN_RELEASE_NOTES_PATH", "parameterized release notes path"),
        ("ZKCOIN_RELEASE_NOTES_BRANCH", "parameterized release notes branch"),
        ("ZKCOIN_RELEASE_NOTES_OWNER", "parameterized release notes owner"),
        ('ZKCOIN_EXPECTED_RELEASE_NOTES_PATH="doc/release-notes/release-notes-${ZKCOIN_RELEASE_VERSION}.md"', "version-aligned release notes path"),
        ("ZKCOIN_RELEASE_NOTES_PATH must match $ZKCOIN_EXPECTED_RELEASE_NOTES_PATH", "release notes archive path validation"),
        ('git check-ref-format --branch "$ZKCOIN_RELEASE_NOTES_BRANCH"', "release notes branch validation"),
        ('rev-parse --verify --quiet "$ZKCOIN_RELEASE_NOTES_BRANCH^{commit}"', "release notes branch commit validation"),
        ('git cat-file -e "master:$ZKCOIN_RELEASE_NOTES_PATH"', "master release notes archive existence"),
        ('git cat-file -e "$ZKCOIN_RELEASE_NOTES_BRANCH:$ZKCOIN_RELEASE_NOTES_PATH"', "release branch notes archive existence"),
        ("git diff --quiet --no-ext-diff", "release notes archive content comparison"),
        ("Archived zkCoin release notes differ between master and $ZKCOIN_RELEASE_NOTES_BRANCH", "release notes archive divergence failure"),
        ("Resolve the zkCoin release-notes archival targets", "release notes archival boundary"),
        ("ZKCOIN_RELEASE_GITHUB_TAG", "parameterized GitHub release tag"),
        ("ZKCOIN_RELEASE_GITHUB_TITLE", "parameterized GitHub release title"),
        ("ZKCOIN_RELEASE_GITHUB_OWNER", "parameterized GitHub release owner"),
        ("ZKCOIN_RELEASE_GITHUB_METADATA_FIELD", "GitHub release metadata validation loop"),
        ("ZKCOIN_RELEASE_GITHUB metadata fields must not be placeholders", "GitHub release metadata placeholder rejection"),
        ("ZKCOIN_RELEASE_GITHUB_REPO_URL must point at the zk-coin GitHub org", "GitHub release repository organization validation"),
        ("ZKCOIN_RELEASE_GITHUB_TAG must match ZKCOIN_RELEASE_TAG", "GitHub release tag binding"),
        ("ZKCOIN_RELEASE_VERSION:?set the zkCoin release version for the GitHub release title", "GitHub release title version input"),
        ("ZKCOIN_RELEASE_GITHUB_TITLE must include ZKCOIN_RELEASE_VERSION", "GitHub release title version binding"),
        ("Resolve the zkCoin GitHub release metadata", "GitHub release metadata boundary"),
        ("verify-zkcoin-release.py", "post-publication artifact verification"),
        ("resolved zkCoin artifact host", "zkCoin artifact upload target"),
        ("ZKCOIN_MACOS_BUNDLE_ID", "parameterized macOS bundle identifier"),
        ("ZKCOIN_MACOS_APPLE_ID", "parameterized macOS notarization Apple ID"),
        ("ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM", "parameterized macOS notarization keychain item"),
        ("ZKCOIN_MACOS_ASC_PROVIDER", "parameterized macOS Apple provider"),
        ("ZKCOIN_MACOS_CODESIGN_IDENTITY", "parameterized macOS code-signing identity"),
        ("ZKCOIN_MACOS_CODESIGN_CERT_CUSTODY", "macOS signing certificate custody record"),
        ("ZKCOIN_MACOS_CODESIGN_CERT_OWNER", "macOS signing certificate custody owner"),
        ("ZKCOIN_MACOS_CODESIGN_PAYLOAD_APPROVAL", "macOS signing payload approval record"),
        ("ZKCOIN_MACOS_CODESIGN custody fields must not be placeholders", "macOS signing custody placeholder rejection"),
        ('./detached-sig-create.sh -s "$ZKCOIN_MACOS_CODESIGN_IDENTITY"', "zkCoin macOS signing identity invocation"),
        ("ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD_SOURCE", "macOS notarization app-specific password source"),
        ("ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD_SOURCE must not be a placeholder", "macOS app-specific password source placeholder rejection"),
        ('read -r -s ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD', "macOS app-specific password secret prompt"),
        ('unset ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD', "macOS app-specific password cleanup"),
        ("ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID", "macOS notarization request UUID"),
        ("ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID must not be a placeholder", "macOS notarization request UUID placeholder rejection"),
        ("ZKCOIN_MACOS_NOTARIZATION_STATUS_LOG", "macOS notarization status log"),
        ("ZKCOIN_MACOS_NOTARIZATION_STATUS_LOG must not be a placeholder", "macOS notarization status log placeholder rejection"),
        ('tee "$ZKCOIN_MACOS_NOTARIZATION_STATUS_LOG"', "macOS notarization status log capture"),
        ("grep -E 'Status: (success|accepted)'", "macOS notarization success status check"),
        ('--notarization-info "$ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID"', "macOS notarization request lookup"),
        ("xcrun stapler validate dist/Litecoin-Qt.app", "macOS stapled ticket validation"),
        ("spctl --assess --type execute --verbose=4 dist/Litecoin-Qt.app", "macOS Gatekeeper assessment"),
        ('--primary-bundle-id "$ZKCOIN_MACOS_BUNDLE_ID"', "zkCoin macOS notarization bundle id"),
        ("ZKCOIN_WINDOWS_CODESIGN_KEY_PATH", "parameterized Windows code-signing key path"),
        ("ZKCOIN_WINDOWS_CODESIGN_KEY_CUSTODY", "parameterized Windows code-signing key custody"),
        ("ZKCOIN_WINDOWS_CODESIGN_KEY_OWNER", "Windows code-signing key custody owner"),
        ("ZKCOIN_WINDOWS_CODESIGN_PAYLOAD_APPROVAL", "Windows code-signing payload approval"),
        ("ZKCOIN_WINDOWS_CODESIGN custody fields must not be placeholders", "Windows signing custody placeholder rejection"),
        ('./detached-sig-create.sh -key "$ZKCOIN_WINDOWS_CODESIGN_KEY_PATH"', "zkCoin Windows signing key invocation"),
    )
    for needle, description in release_doc_checks:
        error = require_text(RELEASE_DOC, needle, description)
        if error:
            return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "First time / New builders",
            "ZKCOIN_DETACHED_SIGS_RELEASE_FIELD",
            "ZKCOIN_DETACHED_SIGS release refs must not be placeholders",
            'git check-ref-format --branch "$ZKCOIN_DETACHED_SIGS_RELEASE_REF"',
            'git check-ref-format "refs/tags/$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"',
            "ZKCOIN_DETACHED_SIGS_RELEASE_REF and ZKCOIN_DETACHED_SIGS_RELEASE_TAG must be distinct",
            "ZKCOIN_RELEASE_REPO_URL",
            "ZKCOIN release repository URLs must use HTTPS and point at the zk-coin GitHub org",
            "ZKCOIN_GITIAN_SIGS_REPO_URL and ZKCOIN_DETACHED_SIGS_REPO_URL must be distinct repositories",
            "ZKCOIN_GITIAN_BUILDER_REPO_URL",
            "ZKCOIN_GITIAN_BUILDER_COMMIT must be a full 40-character commit id",
            'git clone "$ZKCOIN_GITIAN_SIGS_REPO_URL" "$GITIAN_SIGS_DIR"',
            'git clone "$ZKCOIN_DETACHED_SIGS_REPO_URL" "$ZKCOIN_DETACHED_SIGS_DIR"',
            'git clone "$ZKCOIN_GITIAN_BUILDER_REPO_URL" gitian-builder',
            'git checkout --detach "$ZKCOIN_GITIAN_BUILDER_COMMIT"',
            "Resolve and sign the zkCoin release source tag before any Gitian build",
        ),
        "release repository URL validation before cloning release infrastructure",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Resolve and sign the zkCoin release source tag before any Gitian build",
            'git verify-tag "$ZKCOIN_RELEASE_TAG"',
            "Setup Gitian descriptors",
            "ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE",
            'export SIGNER="$ZKCOIN_GITIAN_SIGNER"',
            'export VERSION="$ZKCOIN_RELEASE_VERSION"',
            'git checkout --detach "$ZKCOIN_RELEASE_TAG^{commit}"',
            "Ensure your zkCoin Gitian signatures repository remote is the resolved zkCoin",
            'git remote get-url origin',
            "git status --porcelain",
            "git pull --ff-only",
            "Ensure gitian-builder is still on the pinned zkCoin release build commit",
            "git fetch origin",
            'git checkout --detach "$ZKCOIN_GITIAN_BUILDER_COMMIT"',
            "Resolve approved Rust Gitian toolchain provenance",
            "ZKCOIN_GITIAN_RUSTC_COMMIT_HASH",
            "zkcoin-gitian-rust-toolchain-linux.env",
            "missing Rust standard libraries for every descriptor target",
            '--commit "litecoin=${ZKCOIN_RELEASE_TAG}"',
            "After the published zkCoin Gitian signer quorum has built",
            "ZKCOIN_GITIAN_UNAUTHORIZED_SIGNERS",
            "ZKCOIN_GITIAN_AUTHORIZED_SIGNER_COUNT",
        ),
        "release source tag provenance and signer authorization before Gitian builds",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "First time setup for codesigner",
            "ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD_SOURCE",
            'read -r -s ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD',
            'unset ZKCOIN_MACOS_APP_SPECIFIC_PASSWORD',
            "Notarize the disk image",
            "ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID",
            "ZKCOIN_MACOS_NOTARIZATION_STATUS_LOG",
            '--notarization-info "$ZKCOIN_MACOS_NOTARIZATION_REQUEST_UUID"',
            "grep -E 'Status: (success|accepted)'",
            "Staple the notarization ticket",
            "xcrun stapler validate dist/Litecoin-Qt.app",
            "spctl --assess --type execute --verbose=4 dist/Litecoin-Qt.app",
            "#copy the notarization ticket to detached-sigs repo",
        ),
        "macOS notarization success and stapler validation before ticket copy",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Codesigner only: Sign the windows binaries",
            "ZKCOIN_WINDOWS_CODESIGN_KEY_PATH",
            "ZKCOIN_WINDOWS_CODESIGN_KEY_CUSTODY",
            "ZKCOIN_WINDOWS_CODESIGN_KEY_OWNER",
            "ZKCOIN_WINDOWS_CODESIGN_PAYLOAD_APPROVAL",
            './detached-sig-create.sh -key "$ZKCOIN_WINDOWS_CODESIGN_KEY_PATH"',
            "Codesigner only: Commit the detached codesign payloads",
        ),
        "Windows signing custody before detached signature creation",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Codesigner only: Sign the macOS binary",
            "ZKCOIN_MACOS_CODESIGN_IDENTITY",
            "ZKCOIN_MACOS_CODESIGN_CERT_CUSTODY",
            "ZKCOIN_MACOS_CODESIGN_PAYLOAD_APPROVAL",
            './detached-sig-create.sh -s "$ZKCOIN_MACOS_CODESIGN_IDENTITY"',
            "Notarize the disk image",
            '--primary-bundle-id "$ZKCOIN_MACOS_BUNDLE_ID"',
            "Codesigner only: Sign the windows binaries",
        ),
        "macOS signing custody before detached signature creation",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Codesigner only: Commit the detached codesign payloads",
            "ZKCOIN_DETACHED_SIGS_CUSTODY_RECORD",
            "ZKCOIN_DETACHED_SIGS_PAYLOAD_APPROVAL",
            "ZKCOIN_DETACHED_SIGS_OSX_PAYLOAD_ARCHIVE",
            "ZKCOIN_DETACHED_SIGS_REPO_ROOT",
            "ZKCOIN_DETACHED_SIGS payload archives must be outside the detached-signatures repository",
            "ZKCOIN_DETACHED_SIGS_PAYLOAD_ARCHIVE_RESOLVED",
            'tar -tf "$ZKCOIN_DETACHED_SIGS_PAYLOAD_ARCHIVE_RESOLVED" >/dev/null',
            "ZKCOIN_DETACHED_SIGS_PAYLOAD_MEMBER",
            "ZKCOIN_DETACHED_SIGS payload archive contains unsafe path",
            "ZKCOIN_DETACHED_SIGS payload archive contains unexpected top-level path",
            'git remote get-url origin',
            "Detached signatures origin does not match ZKCOIN_DETACHED_SIGS_REPO_URL",
            "Detached signatures repository must be clean before payload replacement",
            'git fetch origin "$ZKCOIN_DETACHED_SIGS_RELEASE_REF:$ZKCOIN_DETACHED_SIGS_RELEASE_REF" --tags',
            "ZKCOIN_DETACHED_SIGS_RELEASE_TAG already exists; choose a new signed payload tag",
            "Detached signatures release branch must be clean before payload replacement",
            "find . -mindepth 1 -maxdepth 1 ! -name .git -exec rm -rf {} +",
            'tar xf "$ZKCOIN_DETACHED_SIGS_OSX_PAYLOAD_ARCHIVE"',
            'tar xf "$ZKCOIN_DETACHED_SIGS_WIN_PAYLOAD_ARCHIVE"',
            'git tag -s "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG" HEAD',
            'git verify-tag "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"',
            "ZKCOIN_DETACHED_SIGS_RELEASE_TAG_COMMIT",
            "ZKCOIN_DETACHED_SIGS_RELEASE_TAG does not point at the detached-signatures payload commit",
            'git push origin "$ZKCOIN_DETACHED_SIGS_RELEASE_REF" "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"',
            "Non-codesigners: wait for Windows/macOS detached signatures",
        ),
        "detached-signatures custody before payload publication",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "GPG-sign it with the published zkCoin release signing key",
            "ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_RECORD",
            "ZKCOIN_RELEASE_SIGNING_KEY_REVOCATION_PLAN",
            "--with-colons --fingerprint",
            '--local-user "$ZKCOIN_RELEASE_SIGNING_KEY_ID"',
            "Verify the local signed checksum manifest and artifacts before uploading",
        ),
        "release signing key custody before checksum signing",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Resolve the zkCoin artifact publication targets before uploading anything",
            "ZKCOIN_RELEASE_PUBLICATION_URL",
            "ZKCOIN_RELEASE publication URLs must use HTTPS",
            "ZKCOIN_RELEASE_CHECKSUMS_URL must publish SHA256SUMS.asc",
            "Upload zips and installers",
            "Verify the published checksums and artifacts from the resolved public URLs",
            "curl --fail --location --show-error --silent",
            'cmp -s ./SHA256SUMS.asc "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc"',
            '--checksums "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc"',
            "Resolve the zkCoin release-index and website publication targets",
            "ZKCOIN_RELEASE_METADATA_URL",
            "ZKCOIN_RELEASE metadata URLs must use HTTPS",
            "ZKCOIN_RELEASE_METADATA_OWNER",
            "Update the resolved zkCoin website and release index",
            "Resolve the zkCoin release announcement channels",
            "ZKCOIN_RELEASE_ANNOUNCEMENT_FIELD",
        ),
        "public checksum fetch and verification before metadata publication",
    )
    if error:
        return fail(error)

    error = require_ordered_text(
        RELEASE_DOC,
        (
            "Resolve the zkCoin release-notes archival targets",
            "git cat-file -e \"master:$ZKCOIN_RELEASE_NOTES_PATH\"",
            "git diff --quiet --no-ext-diff",
            "Resolve the zkCoin GitHub release metadata",
            "ZKCOIN_RELEASE_GITHUB_METADATA_FIELD",
            "ZKCOIN_RELEASE_GITHUB_TAG must match ZKCOIN_RELEASE_TAG",
            "ZKCOIN_RELEASE_GITHUB_TITLE must include ZKCOIN_RELEASE_VERSION",
            "Create the GitHub release",
        ),
        "release notes archive verification before GitHub release creation",
    )
    if error:
        return fail(error)

    verify_checks = (
        (VERIFY_SCRIPT, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in env"),
        (VERIFY_SCRIPT, "verifies Bitcoin Core artifacts, not zkCoin", "Bitcoin-only verifier warning"),
        (ZKCOIN_VERIFY_SCRIPT, "--trusted-fingerprint", "zkCoin trusted fingerprint argument"),
        (ZKCOIN_VERIFY_SCRIPT, "trusted fingerprint must be a full 40-character hex fingerprint", "zkCoin verifier trusted fingerprint shape guard"),
        (ZKCOIN_VERIFY_SCRIPT, "--download-base", "zkCoin artifact download base argument"),
        (ZKCOIN_VERIFY_SCRIPT, "--download-base must be an HTTPS base URL", "zkCoin verifier HTTPS download base guard"),
        (ZKCOIN_VERIFY_SCRIPT, "--download-timeout must be a positive number of seconds", "zkCoin verifier download timeout guard"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact download redirected away from HTTPS", "zkCoin verifier HTTPS redirect guard"),
        (ZKCOIN_VERIFY_SCRIPT, "failed to download artifact", "zkCoin verifier interrupted download guard"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact path appeared during download", "zkCoin verifier raced artifact target guard"),
        (ZKCOIN_VERIFY_SCRIPT, "os.link", "zkCoin verifier exclusive artifact install"),
        (ZKCOIN_VERIFY_SCRIPT, "target.unlink()", "zkCoin verifier downloaded mismatch cleanup"),
        (ZKCOIN_VERIFY_SCRIPT, "VALIDSIG", "zkCoin GPG fingerprint validation"),
        (ZKCOIN_VERIFY_SCRIPT, "duplicate artifact path in checksum manifest", "zkCoin verifier duplicate artifact rejection"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact path contains backslashes or control characters", "zkCoin verifier portable artifact path guard"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact path must be a normalized POSIX path", "zkCoin verifier normalized artifact path guard"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact path must not be a symlink", "zkCoin verifier symlink artifact rejection"),
        (ZKCOIN_VERIFY_SCRIPT, "artifact path must be a regular file", "zkCoin verifier regular artifact rejection"),
        (ZKCOIN_VERIFY_SCRIPT, "Verified {} zkCoin release artifact", "zkCoin artifact verification success message"),
        (VERIFY_README, "Bitcoin Core-only", "Bitcoin-only README warning"),
        (VERIFY_README, UPSTREAM_VERIFY_ENV, "legacy Bitcoin verifier opt-in docs"),
        (VERIFY_README, "verify-zkcoin-release.py", "zkCoin verifier documentation"),
        (VERIFY_README, "ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT", "zkCoin verifier fingerprint documentation"),
        (VERIFY_README, "full 40-character hex fingerprints", "zkCoin verifier fingerprint shape documentation"),
        (VERIFY_README, "ZKCOIN_RELEASE_ARTIFACT_BASE_URL", "zkCoin verifier download base documentation"),
        (VERIFY_README, "HTTPS base URL", "zkCoin verifier HTTPS download base documentation"),
        (VERIFY_README, "redirect away from HTTPS", "zkCoin verifier HTTPS redirect documentation"),
        (VERIFY_README, "positive download timeout", "zkCoin verifier download timeout documentation"),
        (VERIFY_README, "temporary file", "zkCoin verifier atomic download documentation"),
        (VERIFY_README, "without overwriting a final artifact path that appears during the download", "zkCoin verifier raced artifact target documentation"),
        (VERIFY_README, "Downloaded artifacts that fail hash verification are removed", "zkCoin verifier mismatched download cleanup documentation"),
        (VERIFY_README, "duplicate artifact paths", "zkCoin verifier duplicate artifact documentation"),
        (VERIFY_README, "backslashes or control characters", "zkCoin verifier portable artifact path documentation"),
        (VERIFY_README, "normalized POSIX paths", "zkCoin verifier normalized artifact path documentation"),
        (VERIFY_README, "regular files, not symlinks", "zkCoin verifier regular artifact documentation"),
        (CONTRIB_README, "Tools for verifying signed zkCoin release checksums", "zkCoin contrib verifier summary"),
        (GITIAN_BUILD, UPSTREAM_GITIAN_ENV, "legacy Bitcoin Gitian helper opt-in env"),
        (GITIAN_BUILD, "builds Bitcoin Core artifacts, not zkCoin", "Bitcoin-only Gitian helper warning"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_release_infrastructure_manifest.json", "release manifest dist packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_gitian_rust_toolchain_check.sh", "Gitian Rust toolchain gate packaging"),
        (MAKEFILE_AM, "contrib/verifybinaries/verify-zkcoin-release.py", "zkCoin verifier dist packaging"),
        (MAKEFILE_AM, "contrib/verifybinaries/verify.sh", "legacy verifier dist packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_release_candidate_validation.sh", "release-candidate validation packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_source_dist_realproof_smoke.sh", "source dist real-proof smoke packaging"),
        (MAKEFILE_AM, "contrib/devtools/zkcoin_source_dist_smoke.sh", "source dist smoke packaging"),
        (GITIAN_SIGNER_DESCRIPTORS[0], DETACHED_SIGS_NOT_CONFIGURED_REPO, "Windows signer fail-closed detached-signatures remote"),
        (GITIAN_SIGNER_DESCRIPTORS[1], DETACHED_SIGS_NOT_CONFIGURED_REPO, "macOS signer fail-closed detached-signatures remote"),
        (DEVTOOLS_README, "zkcoin_release_candidate_validation.sh", "release-candidate validation documentation"),
        (DEVTOOLS_README, "zkcoin_gitian_rust_toolchain_check.sh", "Gitian Rust toolchain gate documentation"),
        (DEVTOOLS_README, "zkcoin_source_dist_realproof_smoke.sh", "source dist real-proof smoke documentation"),
        (DEVTOOLS_README, "zkcoin_source_dist_smoke.sh", "source dist smoke documentation"),
        (SOURCE_DIST_SMOKE, "zkcoin_gitian_rust_toolchain_check.sh", "Gitian Rust toolchain gate tarball entry"),
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
        (RELEASE_DOC, "git clone https://github.com/devrandom/gitian-builder.git", "hard-coded Gitian builder clone"),
        (RELEASE_DOC, "Ensure gitian-builder is up-to-date:", "unpinned Gitian builder update"),
        (RELEASE_DOC, "litecoin.org server", "Litecoin artifact publication host"),
        (RELEASE_DOC, "Update litecoin.org version", "Litecoin website update"),
        (RELEASE_DOC, "blog.litecoin.org", "Litecoin blog target"),
        (RELEASE_DOC, "bitcoincore.org", "Bitcoin Core website target"),
        (RELEASE_DOC, "org.bitcoincore.bitcoin-qt", "Bitcoin Core Flatpak target"),
        (RELEASE_DOC, "bitcoin-core-snap", "Bitcoin Core snap target"),
        (RELEASE_DOC, UPSTREAM_LITECOIN_MACOS_BUNDLE_ID, "Litecoin macOS bundle identifier"),
        (RELEASE_DOC, './detached-sig-create.sh -s "Key ID"', "placeholder macOS signing key id"),
        (RELEASE_DOC, "<app-specific-password>", "placeholder macOS app-specific password"),
        (RELEASE_DOC, "<request-uuid>", "placeholder macOS notarization request UUID"),
        (RELEASE_DOC, "<apple-id-email>", "placeholder Apple ID"),
        (RELEASE_DOC, "<apple-id-notarisation-app-specific-password>", "placeholder Apple keychain item"),
        (RELEASE_DOC, "<team-id-shortcode>", "placeholder Apple provider shortcode"),
        (RELEASE_DOC, "/path/to/codesign.key", "placeholder Windows signing key path"),
        (RELEASE_DOC, 'export SIGNER="(your Gitian key, ie bluematt, sipa, etc)"', "placeholder Gitian signer"),
        (RELEASE_DOC, "git tag -s v(new version, e.g. 0.20.0)", "placeholder source release tag"),
        (RELEASE_DOC, "export VERSION=(new version, e.g. 0.20.0)", "placeholder release version export"),
        (RELEASE_DOC, "git checkout v${VERSION}", "implicit source release tag checkout"),
        (RELEASE_DOC, "--commit litecoin=v${VERSION}", "implicit Gitian source tag input"),
        (RELEASE_DOC, "tar xf signature-osx.tar.gz", "unparameterized macOS detached-signatures payload archive"),
        (RELEASE_DOC, "tar xf signature-win.tar.gz", "unparameterized Windows detached-signatures payload archive"),
        (RELEASE_DOC, "rm -rf *", "glob-only detached-signatures payload cleanup"),
        (RELEASE_DOC, "gpg --digest-algo sha256 --clearsign SHA256SUMS # outputs SHA256SUMS.asc", "unqualified release checksum signing command"),
        (RELEASE_DOC, "After 3 or more people have gitian-built", "fixed inherited Gitian signer quorum"),
        (RELEASE_DOC, "3 matching signatures", "fixed inherited platform signing quorum"),
        (RELEASE_DOC, "#checkout the appropriate branch for this release series", "ambiguous detached-signatures release branch"),
        (RELEASE_DOC, "git tag -s v${VERSION} HEAD", "implicit detached-signatures release tag"),
        (RELEASE_DOC, "--commit signature=v${VERSION}", "implicit detached-signatures signer input tag"),
        (RELEASE_DOC, "sha256sum * > SHA256SUMS", "wildcard release checksum command"),
        (RELEASE_DOC, "--artifacts-dir ./release-artifacts", "post-publication verification against non-clean artifact directory"),
        (RELEASE_DOC, "blocked until the announcement channels and owners are explicitly documented", "prose-only announcement channel gate"),
        (RELEASE_DOC, "Archive release notes for the new version to `doc/release-notes/` on `master`", "ambiguous release notes archival"),
        (RELEASE_DOC, "Create a release in `$ZKCOIN_RELEASE_GITHUB_REPO_URL` with a link", "ambiguous GitHub release creation"),
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

    error = require_rust_shielded_verifier_target_mapping()
    if error:
        return fail(error)

    error = require_rust_shielded_verifier_vendor()
    if error:
        return fail(error)

    error = require_source_dist_smoke_entries()
    if error:
        return fail(error)

    return 0


if __name__ == "__main__":
    sys.exit(main())
