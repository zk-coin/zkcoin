#!/usr/bin/env python3
#
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
"""Validate the zkCoin public launch-profile decision manifest."""

import argparse
import errno
import hashlib
import json
import os
import re
import shlex
import stat
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = ROOT_DIR / "contrib" / "devtools" / "zkcoin_public_launch_profile_manifest.json"
NETWORKS = ("main", "testnet")
CHAINPARAMS_CLASS_BOUNDS = {
    "main": ("CMainParams", "CTestNetParams"),
    "testnet": ("CTestNetParams", "CRegTestParams"),
}
SCRIPT_RULES = ("BIP16", "BIP34", "BIP65", "BIP66", "CSV", "Segwit", "Taproot")
BASE58_FIELDS = (
    ("pubkey_address", 1),
    ("script_address", 1),
    ("script_address2", 1),
    ("secret_key", 1),
    ("ext_public_key", 4),
    ("ext_secret_key", 4),
)
LITECOIN_MESSAGE_STARTS = {
    (0xfb, 0xc0, 0xb6, 0xdb),
    (0xfd, 0xd2, 0xc8, 0xf1),
}
LITECOIN_DEFAULT_PORTS = {9333, 19335}
LITECOIN_BASE58_PREFIXES = {
    (48,),
    (111,),
    (5,),
    (196,),
    (50,),
    (58,),
    (176,),
    (239,),
    (0x04, 0x88, 0xB2, 0x1E),
    (0x04, 0x35, 0x87, 0xCF),
    (0x04, 0x88, 0xAD, 0xE4),
    (0x04, 0x35, 0x83, 0x94),
}
LITECOIN_HRPS = {"ltc", "tltc", "ltcmweb", "tmweb"}
RESERVED_DNS_SEED_SUFFIXES = {"example", "invalid", "local", "localhost", "test"}
MAX_BECH32_HRP_LENGTH = 83
PLACEHOLDER_AUXPOW_CHAIN_ID = 0x5A4B
FORBIDDEN_PARENT_VERSION_CHAIN_IDS = range(0x2000, 0x4000)
ZERO_UINT256 = "0" * 64
SNAPSHOT_TOTAL_AMOUNT_RE = re.compile(r"^(0|[1-9][0-9]*)\.[0-9]{8}$")
SNAPSHOT_COIN = 100000000
SNAPSHOT_MAX_MONEY = 84000000 * SNAPSHOT_COIN
SNAPSHOT_MAX_MONEY_TEXT = "84000000.00000000"
SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES = 64 * 1024
LAUNCH_MANIFEST_MAX_BYTES = 256 * 1024
CHAINPARAMS_INPUT_MAX_BYTES = 1024 * 1024
SNAPSHOT_SOURCE_CHAINS = {
    "main": "main",
    "testnet": "test",
}
SNAPSHOT_FIELDS = ("height", "block_hash", "import_hash")
SNAPSHOT_AUDIT_FIELDS = (
    "snapshot_hash",
    "coins",
    "base_nchaintx",
    "source_chain",
    "snapshot_file_size",
    "snapshot_file_sha256",
    "snapshot_file",
    "total_amount",
)
SNAPSHOT_AUDIT_SUMMARY_FIELDS = SNAPSHOT_FIELDS + SNAPSHOT_AUDIT_FIELDS
MANIFEST_FIELDS = ("version", "status", "purpose", "blockers", "networks")
BLOCKER_FIELDS = ("id", "description")
PROFILE_FIELDS = (
    "litecoin_snapshot",
    "auxpow",
    "script_rules",
    "shielded_pool",
    "chain_history",
    "public_network_identity",
)
AUXPOW_FIELDS = (
    "start_height",
    "chain_id",
    "strict_chain_id",
    "forbidden_parent_version_chain_id_range",
)
SCRIPT_RULES_FIELDS = ("active_at_launch", "required_rules")
SHIELDED_POOL_FIELDS = (
    "active_at_launch",
    "scaffold_proofs",
    "real_proof_backend",
    "activation_policy",
)
CHAIN_HISTORY_FIELDS = (
    "minimum_chain_work",
    "default_assume_valid",
    "checkpoints_policy",
    "chain_tx_data",
)
IDENTITY_FIELDS = (
    "message_start",
    "default_port",
    "dns_seeds",
    "fixed_seeds",
    "base58_prefixes",
    "bech32_hrp",
    "mweb_hrp",
)
SNAPSHOT_MANIFEST_FIELDS = SNAPSHOT_FIELDS + ("audit",)
BLOCKER_ORDER = (
    "main.litecoin_snapshot",
    "main.auxpow_chain_id",
    "main.public_network_identity",
    "main.dns_seeds",
    "testnet.litecoin_snapshot",
    "testnet.auxpow_chain_id",
    "testnet.public_network_identity",
    "testnet.dns_seeds",
)
REQUIRED_BLOCKERS = set(BLOCKER_ORDER)
STATUS_JSON_SCHEMA_VERSION = 1


class DuplicateJSONFieldError(ValueError):
    pass


def reject_duplicate_json_fields(pairs):
    result = {}
    for field, value in pairs:
        if field in result:
            raise DuplicateJSONFieldError(field)
        result[field] = value
    return result


def unresolved_blocker_ids(manifest):
    blockers = set()
    manifest = object_or_empty(manifest)
    networks = object_or_empty(manifest.get("networks", {}))
    for network in NETWORKS:
        profile = object_or_empty(networks.get(network, {}))
        snapshot = object_or_empty(profile.get("litecoin_snapshot", {}))
        snapshot_audit = object_or_empty(snapshot.get("audit", {}))
        if (
            any(snapshot.get(field) is None for field in SNAPSHOT_FIELDS)
            or not isinstance(snapshot_audit, dict)
            or any(snapshot_audit.get(field) is None for field in SNAPSHOT_AUDIT_FIELDS)
        ):
            blockers.add(f"{network}.litecoin_snapshot")

        auxpow = object_or_empty(profile.get("auxpow", {}))
        if auxpow.get("chain_id") is None:
            blockers.add(f"{network}.auxpow_chain_id")

        identity = object_or_empty(profile.get("public_network_identity", {}))
        base58 = object_or_empty(identity.get("base58_prefixes", {}))
        if (
            identity.get("message_start") is None
            or identity.get("default_port") is None
            or identity.get("bech32_hrp") is None
            or identity.get("mweb_hrp") is None
            or any(base58.get(field) is None for field, _ in BASE58_FIELDS)
        ):
            blockers.add(f"{network}.public_network_identity")
        if not identity.get("dns_seeds"):
            blockers.add(f"{network}.dns_seeds")
    return blockers


def ordered_unresolved_blocker_ids(manifest):
    blockers = unresolved_blocker_ids(manifest)
    return [blocker for blocker in BLOCKER_ORDER if blocker in blockers]


def is_plain_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def object_or_empty(value):
    return value if isinstance(value, dict) else {}


class Validation:
    def __init__(self, allow_blocked):
        self.allow_blocked = allow_blocked
        self.errors = []
        self.blockers = []

    def error(self, path, message):
        self.errors.append(f"{path}: {message}")

    def require_object(self, value, path):
        if not isinstance(value, dict):
            self.error(path, "must be an object")
            return {}
        return value

    def require_known_fields(self, value, path, expected_fields):
        if not isinstance(value, dict):
            return
        unexpected_fields = sorted(set(value) - set(expected_fields))
        if unexpected_fields:
            self.error(path, "contains unexpected field(s): " + ", ".join(unexpected_fields))

    def require_list(self, value, path):
        if not isinstance(value, list):
            self.error(path, "must be an array")
            return []
        return value

    def require_bool(self, value, path, expected=None):
        if type(value) is not bool:
            self.error(path, "must be a boolean")
            return
        if expected is not None and value is not expected:
            self.error(path, f"must be {str(expected).lower()}")

    def require_string(self, value, path):
        if not isinstance(value, str):
            self.error(path, "must be a string")
            return None
        if value in ("", "TODO", "TBD", "CHANGE_ME") or value.startswith("<"):
            self.error(path, "must not be a placeholder")
        return value

    def require_hex256(self, value, path, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        if not isinstance(value, str):
            self.error(path, "must be a 64-character lowercase hex string")
            return
        if re.fullmatch(r"[0-9a-f]{64}", value) is None:
            self.error(path, "must be a 64-character lowercase hex string")
        elif value == ZERO_UINT256:
            self.error(path, "must not be the null uint256")

    def require_positive_int(self, value, path, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        if not is_plain_int(value) or value <= 0:
            self.error(path, "must be a positive integer")

    def require_nonempty_string(self, value, path, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        if not isinstance(value, str) or not value:
            self.error(path, "must be a non-empty string")

    def require_snapshot_file(self, value, path, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        if not snapshot_file_valid(value):
            self.error(path, "must be an absolute non-placeholder path")

    def require_snapshot_total_amount(self, value, path, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        if not snapshot_total_amount_valid(value):
            self.error(
                path,
                f"must be a positive decimal amount with 8 fractional digits not exceeding {SNAPSHOT_MAX_MONEY_TEXT}",
            )

    def require_snapshot_source_chain(self, value, path, network, *, allow_null):
        if value is None and allow_null:
            self.blockers.append(path)
            return
        expected = SNAPSHOT_SOURCE_CHAINS[network]
        if value != expected:
            self.error(path, f"must be {expected!r} for {network}")


def dns_seed_valid(seed):
    if (
        not isinstance(seed, str)
        or len(seed) == 0
        or len(seed) > 253
        or seed[0] in "-."
        or seed[-1] in "-."
        or seed != seed.lower()
    ):
        return False
    if any(marker in seed for marker in ("litecoin", "thrasher.io", "koin-project.com")):
        return False
    labels = seed.split(".")
    if len(labels) < 2:
        return False
    if re.search(r"[a-z]", labels[-1]) is None:
        return False
    if labels[-1] in RESERVED_DNS_SEED_SUFFIXES:
        return False
    return all(
        label
        and len(label) <= 63
        and not label.startswith("-")
        and not label.endswith("-")
        and re.fullmatch(r"[a-z0-9-]+", label) is not None
        for label in labels
    )


def hrp_valid(hrp):
    return (
        isinstance(hrp, str)
        and len(hrp) > 0
        and len(hrp) <= MAX_BECH32_HRP_LENGTH
        and hrp == hrp.lower()
        and all(0x21 <= ord(c) <= 0x7e for c in hrp)
        and hrp not in LITECOIN_HRPS
    )


def message_start_valid(value):
    if not isinstance(value, list) or len(value) != 4:
        return False
    if any(not is_plain_int(byte) or byte < 0 or byte > 255 for byte in value):
        return False
    start = tuple(value)
    if start in LITECOIN_MESSAGE_STARTS:
        return False
    return not (
        all(byte == 0 for byte in start)
        or all(byte == 0xff for byte in start)
        or all(0x20 <= byte <= 0x7e for byte in start)
    )


def snapshot_file_valid(value):
    return (
        isinstance(value, str)
        and value.startswith("/")
        and value not in ("", "TODO", "TBD", "CHANGE_ME")
        and not value.startswith("<")
        and "\0" not in value
        and all(ord(char) >= 0x20 and ord(char) != 0x7f for char in value)
    )


def snapshot_total_amount_atoms(value):
    if (
        not isinstance(value, str)
        or SNAPSHOT_TOTAL_AMOUNT_RE.fullmatch(value) is None
        or value == "0.00000000"
    ):
        return None
    whole, fractional = value.split(".")
    return int(whole) * SNAPSHOT_COIN + int(fractional)


def snapshot_total_amount_valid(value):
    atoms = snapshot_total_amount_atoms(value)
    return atoms is not None and atoms <= SNAPSHOT_MAX_MONEY


def validate_snapshot(check, network, profile, allow_null):
    snapshot = check.require_object(profile.get("litecoin_snapshot"), f"{network}.litecoin_snapshot")
    check.require_known_fields(snapshot, f"{network}.litecoin_snapshot", SNAPSHOT_MANIFEST_FIELDS)
    check.require_positive_int(snapshot.get("height"), f"{network}.litecoin_snapshot.height", allow_null=allow_null)
    check.require_hex256(snapshot.get("block_hash"), f"{network}.litecoin_snapshot.block_hash", allow_null=allow_null)
    check.require_hex256(snapshot.get("import_hash"), f"{network}.litecoin_snapshot.import_hash", allow_null=allow_null)
    audit = check.require_object(snapshot.get("audit"), f"{network}.litecoin_snapshot.audit")
    check.require_known_fields(audit, f"{network}.litecoin_snapshot.audit", SNAPSHOT_AUDIT_FIELDS)
    check.require_hex256(audit.get("snapshot_hash"), f"{network}.litecoin_snapshot.audit.snapshot_hash", allow_null=allow_null)
    check.require_positive_int(audit.get("coins"), f"{network}.litecoin_snapshot.audit.coins", allow_null=allow_null)
    check.require_positive_int(audit.get("base_nchaintx"), f"{network}.litecoin_snapshot.audit.base_nchaintx", allow_null=allow_null)
    check.require_snapshot_source_chain(audit.get("source_chain"), f"{network}.litecoin_snapshot.audit.source_chain", network, allow_null=allow_null)
    check.require_positive_int(audit.get("snapshot_file_size"), f"{network}.litecoin_snapshot.audit.snapshot_file_size", allow_null=allow_null)
    check.require_hex256(audit.get("snapshot_file_sha256"), f"{network}.litecoin_snapshot.audit.snapshot_file_sha256", allow_null=allow_null)
    check.require_snapshot_file(audit.get("snapshot_file"), f"{network}.litecoin_snapshot.audit.snapshot_file", allow_null=allow_null)
    check.require_snapshot_total_amount(audit.get("total_amount"), f"{network}.litecoin_snapshot.audit.total_amount", allow_null=allow_null)


def validate_auxpow(check, network, profile, allow_null):
    auxpow = check.require_object(profile.get("auxpow"), f"{network}.auxpow")
    check.require_known_fields(auxpow, f"{network}.auxpow", AUXPOW_FIELDS)
    if not is_plain_int(auxpow.get("start_height")) or auxpow.get("start_height") != 1:
        check.error(f"{network}.auxpow.start_height", "must be 1 for first post-genesis launch block")
    chain_id = auxpow.get("chain_id")
    if chain_id is None and allow_null:
        check.blockers.append(f"{network}.auxpow.chain_id")
    elif not is_plain_int(chain_id) or not (0 < chain_id < 0x8000):
        check.error(f"{network}.auxpow.chain_id", "must be a non-zero AuxPoW-version encodable integer below 0x8000")
    elif chain_id == PLACEHOLDER_AUXPOW_CHAIN_ID:
        check.error(f"{network}.auxpow.chain_id", "must not use launch placeholder chain id 0x5a4b")
    elif chain_id in FORBIDDEN_PARENT_VERSION_CHAIN_IDS:
        check.error(f"{network}.auxpow.chain_id", "must avoid Litecoin parent versionbits chain-id range 0x2000-0x3fff")
    check.require_bool(auxpow.get("strict_chain_id"), f"{network}.auxpow.strict_chain_id", True)
    if auxpow.get("forbidden_parent_version_chain_id_range") != [0x2000, 0x3fff]:
        check.error(f"{network}.auxpow.forbidden_parent_version_chain_id_range", "must document [8192, 16383]")


def validate_script_rules(check, network, profile):
    script_rules = check.require_object(profile.get("script_rules"), f"{network}.script_rules")
    check.require_known_fields(script_rules, f"{network}.script_rules", SCRIPT_RULES_FIELDS)
    check.require_bool(script_rules.get("active_at_launch"), f"{network}.script_rules.active_at_launch", True)
    rules = check.require_list(script_rules.get("required_rules"), f"{network}.script_rules.required_rules")
    if sorted(rules) != sorted(SCRIPT_RULES):
        check.error(f"{network}.script_rules.required_rules", "must list BIP16, BIP34, BIP65, BIP66, CSV, Segwit, Taproot")


def validate_shielded_pool(check, network, profile):
    shielded = check.require_object(profile.get("shielded_pool"), f"{network}.shielded_pool")
    check.require_known_fields(shielded, f"{network}.shielded_pool", SHIELDED_POOL_FIELDS)
    check.require_bool(shielded.get("active_at_launch"), f"{network}.shielded_pool.active_at_launch", False)
    check.require_bool(shielded.get("scaffold_proofs"), f"{network}.shielded_pool.scaffold_proofs", False)
    if shielded.get("real_proof_backend") != "orchard-v1":
        check.error(f"{network}.shielded_pool.real_proof_backend", "must be orchard-v1")
    activation_policy = check.require_string(shielded.get("activation_policy"), f"{network}.shielded_pool.activation_policy")
    if activation_policy is not None and activation_policy != "post-launch-only":
        check.error(f"{network}.shielded_pool.activation_policy", "must be post-launch-only")


def validate_chain_history(check, network, profile):
    history = check.require_object(profile.get("chain_history"), f"{network}.chain_history")
    check.require_known_fields(history, f"{network}.chain_history", CHAIN_HISTORY_FIELDS)
    if history.get("minimum_chain_work") != ZERO_UINT256:
        check.error(f"{network}.chain_history.minimum_chain_work", "must be the null uint256 until public history exists")
    if history.get("default_assume_valid") != ZERO_UINT256:
        check.error(f"{network}.chain_history.default_assume_valid", "must be the null uint256 until public history exists")
    if history.get("checkpoints_policy") != "genesis-only-or-empty":
        check.error(f"{network}.chain_history.checkpoints_policy", "must be genesis-only-or-empty")
    if history.get("chain_tx_data") != "neutral":
        check.error(f"{network}.chain_history.chain_tx_data", "must be neutral")


def validate_base58_prefixes(check, network, identity, allow_null):
    prefixes = check.require_object(identity.get("base58_prefixes"), f"{network}.public_network_identity.base58_prefixes")
    check.require_known_fields(
        prefixes,
        f"{network}.public_network_identity.base58_prefixes",
        tuple(field for field, _ in BASE58_FIELDS),
    )
    seen = set()
    for field, expected_len in BASE58_FIELDS:
        path = f"{network}.public_network_identity.base58_prefixes.{field}"
        value = prefixes.get(field)
        if value is None and allow_null:
            check.blockers.append(path)
            continue
        if (
            not isinstance(value, list)
            or len(value) != expected_len
            or any(not is_plain_int(byte) or byte < 0 or byte > 255 for byte in value)
        ):
            check.error(path, f"must be an array of {expected_len} byte value(s)")
            continue
        prefix = tuple(value)
        if prefix in seen:
            check.error(path, "must be unique")
        if prefix in LITECOIN_BASE58_PREFIXES:
            check.error(path, "must not reuse a Litecoin Base58 prefix")
        seen.add(prefix)


def validate_identity(check, network, profile, allow_null):
    identity = check.require_object(profile.get("public_network_identity"), f"{network}.public_network_identity")
    check.require_known_fields(identity, f"{network}.public_network_identity", IDENTITY_FIELDS)
    message_start = identity.get("message_start")
    if message_start is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.message_start")
    elif not message_start_valid(message_start):
        check.error(f"{network}.public_network_identity.message_start", "must be 4 non-Litecoin non-printable magic bytes")

    default_port = identity.get("default_port")
    if default_port is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.default_port")
    elif not is_plain_int(default_port) or default_port <= 1024 or default_port > 65535:
        check.error(f"{network}.public_network_identity.default_port", "must be in the public TCP port range 1025-65535")
    elif default_port in LITECOIN_DEFAULT_PORTS:
        check.error(f"{network}.public_network_identity.default_port", "must not reuse a Litecoin default port")

    dns_seeds = check.require_list(identity.get("dns_seeds"), f"{network}.public_network_identity.dns_seeds")
    if not dns_seeds and allow_null:
        check.blockers.append(f"{network}.public_network_identity.dns_seeds")
    elif not dns_seeds:
        check.error(f"{network}.public_network_identity.dns_seeds", "must contain at least one zkCoin DNS seed")
    for index, seed in enumerate(dns_seeds):
        if not dns_seed_valid(seed):
            check.error(f"{network}.public_network_identity.dns_seeds[{index}]", "must be a lowercase non-Litecoin DNS hostname")

    fixed_seeds = check.require_list(identity.get("fixed_seeds"), f"{network}.public_network_identity.fixed_seeds")
    if fixed_seeds:
        check.error(f"{network}.public_network_identity.fixed_seeds", "must remain empty until fixed seeds are regenerated from zkCoin nodes")

    validate_base58_prefixes(check, network, identity, allow_null)

    bech32 = identity.get("bech32_hrp")
    mweb = identity.get("mweb_hrp")
    if bech32 is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.bech32_hrp")
    elif not hrp_valid(bech32):
        check.error(f"{network}.public_network_identity.bech32_hrp", "must be lowercase printable ASCII at most 83 characters and must not reuse Litecoin HRPs")
    if mweb is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.mweb_hrp")
    elif not hrp_valid(mweb):
        check.error(f"{network}.public_network_identity.mweb_hrp", "must be lowercase printable ASCII at most 83 characters and must not reuse Litecoin HRPs")
    if bech32 is not None and mweb is not None and bech32 == mweb:
        check.error(f"{network}.public_network_identity.mweb_hrp", "must differ from bech32_hrp")


def byte_tuple(value, expected_len):
    if (
        not isinstance(value, list)
        or len(value) != expected_len
        or any(not is_plain_int(byte) or byte < 0 or byte > 255 for byte in value)
    ):
        return None
    return tuple(value)


def require_unique_manifest_value(check, seen, path, value):
    if value in seen:
        check.error(path, f"must differ from {seen[value]}")
        return
    seen[value] = path


def validate_unique_launch_values(check, networks):
    auxpow_chain_ids = {}
    message_starts = {}
    default_ports = {}
    dns_seeds = {}
    base58_prefixes = {}
    hrps = {}

    for network in NETWORKS:
        profile = networks.get(network)
        if not isinstance(profile, dict):
            continue

        auxpow = profile.get("auxpow")
        if isinstance(auxpow, dict) and is_plain_int(auxpow.get("chain_id")):
            require_unique_manifest_value(
                check,
                auxpow_chain_ids,
                f"{network}.auxpow.chain_id",
                auxpow["chain_id"],
            )

        identity = profile.get("public_network_identity")
        if not isinstance(identity, dict):
            continue

        message_start = byte_tuple(identity.get("message_start"), 4)
        if message_start is not None:
            require_unique_manifest_value(
                check,
                message_starts,
                f"{network}.public_network_identity.message_start",
                message_start,
            )

        default_port = identity.get("default_port")
        if is_plain_int(default_port):
            require_unique_manifest_value(
                check,
                default_ports,
                f"{network}.public_network_identity.default_port",
                default_port,
            )

        seeds = identity.get("dns_seeds")
        if isinstance(seeds, list):
            for index, seed in enumerate(seeds):
                if isinstance(seed, str):
                    require_unique_manifest_value(
                        check,
                        dns_seeds,
                        f"{network}.public_network_identity.dns_seeds[{index}]",
                        seed,
                    )

        prefixes = identity.get("base58_prefixes")
        if isinstance(prefixes, dict):
            for field, expected_len in BASE58_FIELDS:
                prefix = byte_tuple(prefixes.get(field), expected_len)
                if prefix is not None:
                    require_unique_manifest_value(
                        check,
                        base58_prefixes,
                        f"{network}.public_network_identity.base58_prefixes.{field}",
                        prefix,
                    )

        for field in ("bech32_hrp", "mweb_hrp"):
            hrp = identity.get(field)
            if isinstance(hrp, str) and hrp:
                require_unique_manifest_value(
                    check,
                    hrps,
                    f"{network}.public_network_identity.{field}",
                    hrp,
                )


def validate_manifest(manifest, allow_blocked):
    check = Validation(allow_blocked)
    manifest = check.require_object(manifest, "manifest")
    check.require_known_fields(manifest, "manifest", MANIFEST_FIELDS)
    if not is_plain_int(manifest.get("version")) or manifest.get("version") != 1:
        check.error("version", "must be 1")
    check.require_string(manifest.get("purpose"), "purpose")
    status = manifest.get("status")
    if status not in ("blocked", "ready-for-chainparams"):
        check.error("status", "must be blocked or ready-for-chainparams")
    blockers = check.require_list(manifest.get("blockers"), "blockers")
    blocker_ids = set()
    for index, blocker in enumerate(blockers):
        blocker = check.require_object(blocker, f"blockers[{index}]")
        check.require_known_fields(blocker, f"blockers[{index}]", BLOCKER_FIELDS)
        blocker_id = blocker.get("id")
        if not isinstance(blocker_id, str) or not blocker_id:
            check.error(f"blockers[{index}].id", "must be a non-empty string")
            continue
        if blocker_id in blocker_ids:
            check.error(f"blockers[{index}].id", "must be unique")
        if blocker_id not in REQUIRED_BLOCKERS:
            check.error(f"blockers[{index}].id", "unknown blocker id")
        blocker_ids.add(blocker_id)
        check.require_string(blocker.get("description"), f"blockers[{index}].description")
    expected_blockers = unresolved_blocker_ids(manifest)
    missing_blockers = sorted(expected_blockers - blocker_ids)
    if status == "blocked" and missing_blockers:
        check.error("blockers", "missing required blocker ids: " + ", ".join(missing_blockers))
    stale_blockers = sorted(blocker_ids - expected_blockers)
    if status == "blocked" and stale_blockers:
        check.error("blockers", "contains resolved or unknown blocker ids: " + ", ".join(stale_blockers))
    if status == "ready-for-chainparams" and blockers:
        check.error("blockers", "must be empty when status is ready-for-chainparams")
    if status == "blocked" and not allow_blocked:
        check.error("status", "is blocked; rerun with --allow-blocked only for schema/lint checks")

    networks = check.require_object(manifest.get("networks"), "networks")
    check.require_known_fields(networks, "networks", NETWORKS)
    for network in NETWORKS:
        profile = check.require_object(networks.get(network), f"networks.{network}")
        check.require_known_fields(profile, f"networks.{network}", PROFILE_FIELDS)
        allow_null = status == "blocked"
        validate_snapshot(check, network, profile, allow_null)
        validate_auxpow(check, network, profile, allow_null)
        validate_script_rules(check, network, profile)
        validate_shielded_pool(check, network, profile)
        validate_chain_history(check, network, profile)
        validate_identity(check, network, profile, allow_null)
    validate_unique_launch_values(check, networks)

    return check


def parse_height(value):
    try:
        height = int(value)
    except ValueError:
        raise ValueError("height must be a non-negative integer")
    if height < 0:
        raise ValueError("height must be a non-negative integer")
    return height


def parse_hex256(value, label):
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a 64-character lowercase hex string")
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a 64-character lowercase hex string")
    if value == ZERO_UINT256:
        raise ValueError(f"{label} must not be the null uint256")
    return value


def require_snapshot_audit_int(audit, field):
    if field not in audit:
        raise ValueError(f"snapshot audit missing field: {field}")
    value = audit[field]
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"snapshot audit {field} must be an integer")
    if value <= 0:
        raise ValueError(f"snapshot audit {field} must be positive")
    return value


def require_snapshot_audit_hash(audit, field):
    if field not in audit:
        raise ValueError(f"snapshot audit missing field: {field}")
    value = audit[field]
    if not isinstance(value, str):
        raise ValueError(f"snapshot audit {field} must be a 64-character lowercase hex string")
    return parse_hex256(value, f"snapshot audit {field}")


def require_snapshot_audit_string(audit, field):
    if field not in audit:
        raise ValueError(f"snapshot audit missing field: {field}")
    value = audit[field]
    if not isinstance(value, str) or not value:
        raise ValueError(f"snapshot audit {field} must be a non-empty string")
    return value


def require_snapshot_audit_file(audit, field):
    value = require_snapshot_audit_string(audit, field)
    if not snapshot_file_valid(value):
        raise ValueError(
            f"snapshot audit {field} must be an absolute non-placeholder path without control characters"
        )
    return value


def require_snapshot_audit_total_amount(audit, field):
    value = require_snapshot_audit_string(audit, field)
    atoms = snapshot_total_amount_atoms(value)
    if atoms is None:
        raise ValueError(f"snapshot audit {field} must be a positive decimal amount with 8 fractional digits")
    if atoms > SNAPSHOT_MAX_MONEY:
        raise ValueError(f"snapshot audit {field} must not exceed {SNAPSHOT_MAX_MONEY_TEXT}")
    return value


def require_snapshot_audit_source_chain(audit, field):
    value = require_snapshot_audit_string(audit, field)
    if value not in SNAPSHOT_SOURCE_CHAINS.values():
        raise ValueError("snapshot audit source_chain must be main or test")
    return value


def snapshot_audit_template(network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    template = {field: None for field in SNAPSHOT_AUDIT_SUMMARY_FIELDS}
    template["source_chain"] = SNAPSHOT_SOURCE_CHAINS[network]
    return template


def snapshot_audit_template_text(network):
    return json.dumps(snapshot_audit_template(network), indent=2, sort_keys=False)


def open_direct_parent_directory_for_read(path, *, parent_symlink_error, missing_error, open_error):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0 and path.parent.is_symlink():
        raise ValueError(f"{parent_symlink_error}: {path.parent}")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | nofollow
    try:
        parent_fd = os.open(path.parent, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP or (exc.errno == errno.ENOTDIR and path.parent.is_symlink()):
            raise ValueError(f"{parent_symlink_error}: {path.parent}")
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise ValueError(f"{missing_error}: {path}")
        raise ValueError(f"{open_error}: {exc}")
    try:
        parent_stat = os.fstat(parent_fd)
    except OSError as exc:
        os.close(parent_fd)
        raise ValueError(f"{open_error}: {exc}")
    if not stat.S_ISDIR(parent_stat.st_mode):
        os.close(parent_fd)
        raise ValueError(f"{missing_error}: {path}")
    return parent_fd


def open_regular_file_no_symlink(
    path,
    *,
    symlink_error,
    missing_error,
    not_regular_error,
    open_error,
    parent_symlink_error=None,
):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    parent_fd = None
    if parent_symlink_error is not None:
        parent_fd = open_direct_parent_directory_for_read(
            path,
            parent_symlink_error=parent_symlink_error,
            missing_error=missing_error,
            open_error=open_error,
        )
    elif nofollow == 0 and path.is_symlink():
        raise ValueError(f"{symlink_error}: {path}")
    flags = os.O_RDONLY | nofollow
    try:
        if parent_fd is None:
            fd = os.open(path, flags)
        else:
            fd = os.open(path.name, flags, dir_fd=parent_fd)
    except OSError as exc:
        if parent_fd is not None:
            os.close(parent_fd)
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{symlink_error}: {path}")
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise ValueError(f"{missing_error}: {path}")
        raise ValueError(f"{open_error}: {exc}")
    if parent_fd is not None:
        os.close(parent_fd)
    try:
        file_stat = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise ValueError(f"{open_error}: {exc}")
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(fd)
        raise ValueError(f"{not_regular_error}: {path}")
    return fd, file_stat


def file_stat_fingerprint(file_stat):
    return (
        file_stat.st_dev,
        file_stat.st_ino,
        file_stat.st_size,
        file_stat.st_mtime_ns,
        file_stat.st_ctime_ns,
    )


def require_regular_file_stable(path, original_stat, fd, changed_error, parent_symlink_error=None):
    try:
        final_fd_stat = os.fstat(fd)
        final_path_stat = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"{changed_error}: {exc}") from None
    if parent_symlink_error is not None and path.parent.is_symlink():
        raise ValueError(f"{parent_symlink_error}: {path.parent}")
    original_fingerprint = file_stat_fingerprint(original_stat)
    if (
        not stat.S_ISREG(final_path_stat.st_mode)
        or file_stat_fingerprint(final_fd_stat) != original_fingerprint
        or file_stat_fingerprint(final_path_stat) != original_fingerprint
    ):
        raise ValueError(changed_error)


def require_snapshot_audit_artifact_stable(snapshot_path, original_stat, snapshot_file):
    require_regular_file_stable(
        snapshot_path,
        original_stat,
        snapshot_file.fileno(),
        "snapshot audit file artifact changed during verification",
        parent_symlink_error="snapshot audit file artifact parent directory must not be a symlink",
    )


def require_snapshot_audit_summary_stable(audit_summary_path, original_stat, fd):
    require_regular_file_stable(
        audit_summary_path,
        original_stat,
        fd,
        "snapshot audit summary changed during read",
        parent_symlink_error="snapshot audit summary parent directory must not be a symlink",
    )


def require_snapshot_audit_artifact_not_summary(audit_summary_path, snapshot_path):
    try:
        same_file = audit_summary_path.samefile(snapshot_path)
    except FileNotFoundError:
        return
    except OSError:
        return
    if same_file:
        raise ValueError("snapshot audit file artifact must differ from audit summary")


def snapshot_file_sha256(snapshot_file):
    digest = hashlib.sha256()
    for chunk in iter(lambda: snapshot_file.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_snapshot_audit_artifact(audit):
    snapshot_path = Path(audit["snapshot_file"])
    fd, initial_stat = open_regular_file_no_symlink(
        snapshot_path,
        symlink_error="snapshot audit file artifact must not be a symlink",
        missing_error="snapshot audit file artifact does not exist",
        not_regular_error="snapshot audit file artifact must be a regular file",
        open_error="cannot read snapshot audit file artifact",
        parent_symlink_error="snapshot audit file artifact parent directory must not be a symlink",
    )
    snapshot_file = None
    actual_size = initial_stat.st_size
    if actual_size != audit["snapshot_file_size"]:
        os.close(fd)
        raise ValueError(
            "snapshot audit file size mismatch: "
            f"expected={audit['snapshot_file_size']} actual={actual_size}"
        )
    try:
        snapshot_file = os.fdopen(fd, "rb")
        fd = None
        actual_sha256 = snapshot_file_sha256(snapshot_file)
        require_snapshot_audit_artifact_stable(snapshot_path, initial_stat, snapshot_file)
    except OSError as exc:
        raise ValueError(f"cannot read snapshot audit file artifact: {exc}")
    finally:
        if snapshot_file is not None:
            snapshot_file.close()
        elif fd is not None:
            os.close(fd)
    if actual_sha256 != audit["snapshot_file_sha256"]:
        raise ValueError(
            "snapshot audit file SHA-256 mismatch: "
            f"expected={audit['snapshot_file_sha256']} actual={actual_sha256}"
        )


def snapshot_audit_summary_too_large_error(audit_summary_path):
    return (
        f"snapshot audit summary must not exceed {SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES} bytes: "
        f"{audit_summary_path}"
    )


def read_snapshot_audit_summary_text(fd, audit_summary_path):
    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES:
            chunk = os.read(fd, min(65536, SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES + 1 - total_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
    except OSError as exc:
        raise ValueError(f"cannot read snapshot audit summary: {exc}")
    if total_bytes > SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES:
        raise ValueError(snapshot_audit_summary_too_large_error(audit_summary_path))
    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError("snapshot audit summary is not valid UTF-8") from None


def launch_manifest_too_large_error(manifest_path):
    return f"launch manifest must not exceed {LAUNCH_MANIFEST_MAX_BYTES} bytes: {manifest_path}"


def read_launch_manifest_text(manifest_path):
    fd, manifest_stat = open_regular_file_no_symlink(
        manifest_path,
        symlink_error="manifest path must not be a symlink",
        missing_error="cannot read manifest",
        not_regular_error="manifest path must be a regular file",
        open_error="cannot read manifest",
        parent_symlink_error="manifest parent directory must not be a symlink",
    )
    if manifest_stat.st_size > LAUNCH_MANIFEST_MAX_BYTES:
        os.close(fd)
        raise ValueError(launch_manifest_too_large_error(manifest_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= LAUNCH_MANIFEST_MAX_BYTES:
            chunk = os.read(fd, min(65536, LAUNCH_MANIFEST_MAX_BYTES + 1 - total_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > LAUNCH_MANIFEST_MAX_BYTES:
            raise ValueError(launch_manifest_too_large_error(manifest_path))
        require_regular_file_stable(
            manifest_path,
            manifest_stat,
            fd,
            "manifest changed during read",
            parent_symlink_error="manifest parent directory must not be a symlink",
        )
    except OSError as exc:
        raise ValueError(f"cannot read manifest: {exc}") from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{manifest_path} is not valid UTF-8") from None


def chainparams_input_too_large_error(chainparams_path):
    return f"chainparams input must not exceed {CHAINPARAMS_INPUT_MAX_BYTES} bytes: {chainparams_path}"


def read_chainparams_text(chainparams_path):
    fd, chainparams_stat = open_regular_file_no_symlink(
        chainparams_path,
        symlink_error="chainparams path must not be a symlink",
        missing_error="cannot read chainparams",
        not_regular_error="chainparams path must be a regular file",
        open_error="cannot read chainparams",
        parent_symlink_error="chainparams parent directory must not be a symlink",
    )
    if chainparams_stat.st_size > CHAINPARAMS_INPUT_MAX_BYTES:
        os.close(fd)
        raise ValueError(chainparams_input_too_large_error(chainparams_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= CHAINPARAMS_INPUT_MAX_BYTES:
            chunk = os.read(fd, min(65536, CHAINPARAMS_INPUT_MAX_BYTES + 1 - total_bytes))
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > CHAINPARAMS_INPUT_MAX_BYTES:
            raise ValueError(chainparams_input_too_large_error(chainparams_path))
        require_regular_file_stable(
            chainparams_path,
            chainparams_stat,
            fd,
            "chainparams input changed during read",
            parent_symlink_error="chainparams parent directory must not be a symlink",
        )
    except OSError as exc:
        raise ValueError(f"cannot read chainparams: {exc}") from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{chainparams_path} is not valid UTF-8") from None


def parse_snapshot_audit(audit_path):
    audit_summary_path = Path(audit_path)
    fd, audit_summary_stat = open_regular_file_no_symlink(
        audit_summary_path,
        symlink_error="snapshot audit summary must not be a symlink",
        missing_error="cannot read snapshot audit summary",
        not_regular_error="snapshot audit summary must be a regular file",
        open_error="cannot read snapshot audit summary",
        parent_symlink_error="snapshot audit summary parent directory must not be a symlink",
    )
    audit_summary_size = audit_summary_stat.st_size
    if audit_summary_size > SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES:
        os.close(fd)
        raise ValueError(snapshot_audit_summary_too_large_error(audit_summary_path))
    try:
        audit_summary_text = read_snapshot_audit_summary_text(fd, audit_summary_path)
        require_snapshot_audit_summary_stable(audit_summary_path, audit_summary_stat, fd)
        audit = json.loads(
            audit_summary_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(f"snapshot audit summary contains duplicate field: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"snapshot audit summary is not valid JSON: {exc}")
    finally:
        os.close(fd)

    if not isinstance(audit, dict):
        raise ValueError("snapshot audit summary must be a JSON object")
    unexpected_fields = sorted(set(audit) - set(SNAPSHOT_AUDIT_SUMMARY_FIELDS))
    if unexpected_fields:
        raise ValueError(
            "snapshot audit summary has unexpected field(s): "
            + ", ".join(unexpected_fields)
        )
    if (
        set(audit) == set(SNAPSHOT_AUDIT_SUMMARY_FIELDS)
        and list(audit) != list(SNAPSHOT_AUDIT_SUMMARY_FIELDS)
    ):
        raise ValueError(
            "snapshot audit summary field order must match --snapshot-audit-template output"
        )

    parsed = {
        "height": require_snapshot_audit_int(audit, "height"),
        "block_hash": require_snapshot_audit_hash(audit, "block_hash"),
        "import_hash": require_snapshot_audit_hash(audit, "import_hash"),
    }
    parsed["audit"] = {
        "snapshot_hash": require_snapshot_audit_hash(audit, "snapshot_hash"),
        "coins": require_snapshot_audit_int(audit, "coins"),
        "base_nchaintx": require_snapshot_audit_int(audit, "base_nchaintx"),
        "source_chain": require_snapshot_audit_source_chain(audit, "source_chain"),
        "snapshot_file_size": require_snapshot_audit_int(audit, "snapshot_file_size"),
        "snapshot_file_sha256": require_snapshot_audit_hash(audit, "snapshot_file_sha256"),
        "snapshot_file": require_snapshot_audit_file(audit, "snapshot_file"),
        "total_amount": require_snapshot_audit_total_amount(audit, "total_amount"),
    }
    require_snapshot_audit_artifact_not_summary(
        audit_summary_path,
        Path(parsed["audit"]["snapshot_file"]),
    )
    return parsed


def parse_chain_id(value):
    try:
        chain_id = int(value, 0)
    except ValueError:
        raise ValueError("chain_id must be an integer")
    if not (0 < chain_id < 0x8000):
        raise ValueError("chain_id must be non-zero and below 0x8000")
    if chain_id == PLACEHOLDER_AUXPOW_CHAIN_ID:
        raise ValueError("chain_id must not use launch placeholder chain id 0x5a4b")
    if chain_id in FORBIDDEN_PARENT_VERSION_CHAIN_IDS:
        raise ValueError("chain_id must avoid Litecoin parent versionbits chain-id range 0x2000-0x3fff")
    return chain_id


def parse_byte_token(value, label):
    token = value.strip()
    if not token:
        raise ValueError(f"{label} contains an empty byte")
    try:
        if token.lower().startswith("0x"):
            byte = int(token, 16)
        elif re.search(r"[a-fA-F]", token):
            byte = int(token, 16)
        else:
            byte = int(token, 10)
    except ValueError:
        raise ValueError(f"{label} contains an invalid byte: {token}")
    if byte < 0 or byte > 255:
        raise ValueError(f"{label} byte is outside 0..255: {token}")
    return byte


def parse_byte_sequence(value, expected_len, label):
    if "," in value:
        parsed = [parse_byte_token(token, label) for token in value.split(",")]
    elif expected_len > 1 and re.fullmatch(r"[0-9a-fA-F]{" + str(expected_len * 2) + r"}", value):
        parsed = [int(value[index:index + 2], 16) for index in range(0, len(value), 2)]
    else:
        parsed = [parse_byte_token(value, label)]
    if len(parsed) != expected_len:
        raise ValueError(f"{label} must contain {expected_len} byte value(s)")
    return parsed


def parse_default_port(value):
    try:
        port = int(value, 0)
    except ValueError:
        raise ValueError("default_port must be an integer")
    if port <= 1024 or port > 65535:
        raise ValueError("default_port must be in the public TCP port range 1025-65535")
    if port in LITECOIN_DEFAULT_PORTS:
        raise ValueError("default_port must not reuse a Litecoin default port")
    return port


def remove_blocker(manifest, blocker_id):
    require_update_manifest(manifest)
    blockers = manifest.get("blockers", [])
    if not isinstance(blockers, list):
        raise ValueError("blockers must be an array")
    manifest["blockers"] = [
        blocker
        for blocker in blockers
        if not (isinstance(blocker, dict) and blocker.get("id") == blocker_id)
    ]


def require_update_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be an object")


def update_child_object(parent, field, path):
    value = parent.get(field)
    if value is None:
        value = {}
        parent[field] = value
    elif not isinstance(value, dict):
        raise ValueError(f"{path} must be an object")
    return value


def update_network_profile(manifest, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    require_update_manifest(manifest)
    networks = update_child_object(manifest, "networks", "networks")
    return update_child_object(networks, network, f"networks.{network}")


def set_snapshot(manifest, network, height, block_hash, import_hash, audit=None):
    profile = update_network_profile(manifest, network)
    snapshot = {
        "height": parse_height(height),
        "block_hash": parse_hex256(block_hash, "block_hash"),
        "import_hash": parse_hex256(import_hash, "import_hash"),
    }
    if audit is not None:
        snapshot["audit"] = audit
    profile["litecoin_snapshot"] = snapshot
    remove_blocker(manifest, f"{network}.litecoin_snapshot")


def verified_snapshot_audit_for_network(network, audit_path):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    audit = parse_snapshot_audit(audit_path)
    expected_source_chain = SNAPSHOT_SOURCE_CHAINS[network]
    if audit["audit"]["source_chain"] != expected_source_chain:
        raise ValueError(
            f"snapshot audit source_chain {audit['audit']['source_chain']} does not match {network}; "
            f"expected {expected_source_chain}"
        )
    verify_snapshot_audit_artifact(audit["audit"])
    return audit


def candidate_next_step_text(candidate, applied_label):
    blockers = ordered_unresolved_blocker_ids(candidate)
    lines = [f"  remaining blockers after applying {applied_label}: {len(blockers)}"]
    if blockers:
        lines.append(f"  next blocker after applying {applied_label}: {blockers[0]}")
        return "\n".join(lines)
    if candidate.get("status") == "blocked":
        lines.append(
            f"  next step after applying {applied_label}: "
            "mark the complete manifest ready for chainparams"
        )
        return "\n".join(lines)
    lines.append(f"  next step after applying {applied_label}: emit and check chainparams")
    return "\n".join(lines)


def snapshot_audit_check_text(network, audit, candidate):
    audit_detail = audit["audit"]
    return "\n".join((
        f"Snapshot audit verified for {network}.",
        f"  height: {audit['height']}",
        f"  block hash: {audit['block_hash']}",
        f"  import hash: {audit['import_hash']}",
        f"  source chain: {audit_detail['source_chain']}",
        f"  snapshot hash: {audit_detail['snapshot_hash']}",
        f"  snapshot file: {audit_detail['snapshot_file']}",
        f"  snapshot file size: {audit_detail['snapshot_file_size']}",
        f"  snapshot file SHA-256: {audit_detail['snapshot_file_sha256']}",
        f"  coins: {audit_detail['coins']}",
        f"  base transactions: {audit_detail['base_nchaintx']}",
        f"  total amount: {audit_detail['total_amount']}",
        candidate_next_step_text(candidate, "audit"),
    ))


def checked_snapshot_audit_candidate(manifest, network, audit_path):
    audit = verified_snapshot_audit_for_network(network, audit_path)
    candidate = json.loads(json.dumps(manifest))
    set_snapshot(candidate, network, audit["height"], audit["block_hash"], audit["import_hash"], audit["audit"])
    check = validate_manifest(candidate, allow_blocked=True)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "Snapshot audit candidate failed validation:",
                check,
            )
        )
    return audit, candidate


def set_snapshot_from_audit(manifest, network, audit_path):
    audit = verified_snapshot_audit_for_network(network, audit_path)
    set_snapshot(manifest, network, audit["height"], audit["block_hash"], audit["import_hash"], audit["audit"])


def auxpow_profile_from_chain_id(chain_id):
    return {
        "start_height": 1,
        "chain_id": parse_chain_id(chain_id),
        "strict_chain_id": True,
        "forbidden_parent_version_chain_id_range": [
            8192,
            16383,
        ],
    }


def set_auxpow(manifest, network, chain_id):
    profile = update_network_profile(manifest, network)
    profile["auxpow"] = auxpow_profile_from_chain_id(chain_id)
    remove_blocker(manifest, f"{network}.auxpow_chain_id")


def checked_auxpow_candidate(manifest, network, chain_id):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    candidate = json.loads(json.dumps(manifest))
    set_auxpow(candidate, network, chain_id)
    check = validate_manifest(candidate, allow_blocked=True)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "AuxPoW chain id candidate failed validation:",
                check,
            )
        )
    return candidate["networks"][network]["auxpow"], candidate


def auxpow_check_text(network, auxpow, candidate):
    return "\n".join((
        f"AuxPoW chain id candidate verified for {network}.",
        f"  chain id: {auxpow['chain_id']}",
        f"  chain id hex: 0x{auxpow['chain_id']:x}",
        f"  start height: {auxpow['start_height']}",
        f"  strict chain id: {str(auxpow['strict_chain_id']).lower()}",
        "  forbidden parent-version chain-id range: 0x2000-0x3fff",
        candidate_next_step_text(candidate, "candidate"),
    ))


def parse_dns_seeds(value):
    seeds = [seed.strip() for seed in value.split(",")]
    if not seeds or any(not seed for seed in seeds):
        raise ValueError("dns_seeds must be a comma-separated list of non-empty hostnames")
    seen = set()
    for seed in seeds:
        if seed in seen:
            raise ValueError(f"duplicate DNS seed hostname: {seed}")
        if not dns_seed_valid(seed):
            raise ValueError(f"invalid DNS seed hostname: {seed}")
        seen.add(seed)
    return seeds


def set_dns_seeds(manifest, network, dns_seeds):
    profile = update_network_profile(manifest, network)
    identity = update_child_object(
        profile,
        "public_network_identity",
        f"{network}.public_network_identity",
    )
    identity["dns_seeds"] = parse_dns_seeds(dns_seeds)
    remove_blocker(manifest, f"{network}.dns_seeds")


def checked_dns_seeds_candidate(manifest, network, dns_seeds):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    candidate = json.loads(json.dumps(manifest))
    set_dns_seeds(candidate, network, dns_seeds)
    check = validate_manifest(candidate, allow_blocked=True)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "DNS seed candidate failed validation:",
                check,
            )
        )
    return candidate["networks"][network]["public_network_identity"]["dns_seeds"], candidate


def dns_seeds_check_text(network, dns_seeds, candidate):
    return "\n".join((
        f"DNS seed candidate verified for {network}.",
        f"  seed count: {len(dns_seeds)}",
        "  seeds: " + ", ".join(dns_seeds),
        candidate_next_step_text(candidate, "candidate"),
    ))


def set_identity(
    manifest,
    network,
    message_start,
    default_port,
    pubkey_address,
    script_address,
    script_address2,
    secret_key,
    ext_public_key,
    ext_secret_key,
    bech32_hrp,
    mweb_hrp,
):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    parsed_identity = identity_profile_from_args(
        message_start,
        default_port,
        pubkey_address,
        script_address,
        script_address2,
        secret_key,
        ext_public_key,
        ext_secret_key,
        bech32_hrp,
        mweb_hrp,
    )

    profile = update_network_profile(manifest, network)
    identity = update_child_object(
        profile,
        "public_network_identity",
        f"{network}.public_network_identity",
    )
    identity.update(parsed_identity)
    identity.setdefault("dns_seeds", [])
    identity.setdefault("fixed_seeds", [])
    remove_blocker(manifest, f"{network}.public_network_identity")


def identity_profile_from_args(
    message_start,
    default_port,
    pubkey_address,
    script_address,
    script_address2,
    secret_key,
    ext_public_key,
    ext_secret_key,
    bech32_hrp,
    mweb_hrp,
):
    parsed_identity = {
        "message_start": parse_byte_sequence(message_start, 4, "message_start"),
        "default_port": parse_default_port(default_port),
        "base58_prefixes": {
            "pubkey_address": parse_byte_sequence(pubkey_address, 1, "pubkey_address"),
            "script_address": parse_byte_sequence(script_address, 1, "script_address"),
            "script_address2": parse_byte_sequence(script_address2, 1, "script_address2"),
            "secret_key": parse_byte_sequence(secret_key, 1, "secret_key"),
            "ext_public_key": parse_byte_sequence(ext_public_key, 4, "ext_public_key"),
            "ext_secret_key": parse_byte_sequence(ext_secret_key, 4, "ext_secret_key"),
        },
        "bech32_hrp": bech32_hrp,
        "mweb_hrp": mweb_hrp,
    }

    if not message_start_valid(parsed_identity["message_start"]):
        raise ValueError("message_start must be 4 non-Litecoin non-printable magic bytes")
    if not hrp_valid(bech32_hrp):
        raise ValueError("bech32_hrp must be lowercase printable ASCII at most 83 characters and must not reuse Litecoin HRPs")
    if not hrp_valid(mweb_hrp):
        raise ValueError("mweb_hrp must be lowercase printable ASCII at most 83 characters and must not reuse Litecoin HRPs")
    if bech32_hrp == mweb_hrp:
        raise ValueError("mweb_hrp must differ from bech32_hrp")
    return parsed_identity


def checked_identity_candidate(manifest, network, *identity_args):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    candidate = json.loads(json.dumps(manifest))
    set_identity(candidate, network, *identity_args)
    check = validate_manifest(candidate, allow_blocked=True)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "public identity candidate failed validation:",
                check,
            )
        )
    return candidate["networks"][network]["public_network_identity"], candidate


def identity_check_text(network, identity, candidate):
    base58 = identity["base58_prefixes"]
    return "\n".join((
        f"Public identity candidate verified for {network}.",
        f"  message start: {','.join(str(byte) for byte in identity['message_start'])}",
        f"  default port: {identity['default_port']}",
        f"  pubkey address prefix: {','.join(str(byte) for byte in base58['pubkey_address'])}",
        f"  script address prefix: {','.join(str(byte) for byte in base58['script_address'])}",
        f"  script address 2 prefix: {','.join(str(byte) for byte in base58['script_address2'])}",
        f"  secret key prefix: {','.join(str(byte) for byte in base58['secret_key'])}",
        f"  extended public key prefix: {','.join(f'{byte:02x}' for byte in base58['ext_public_key'])}",
        f"  extended secret key prefix: {','.join(f'{byte:02x}' for byte in base58['ext_secret_key'])}",
        f"  bech32 HRP: {identity['bech32_hrp']}",
        f"  MWEB HRP: {identity['mweb_hrp']}",
        candidate_next_step_text(candidate, "candidate"),
    ))


def validation_failure_message(prefix, check):
    lines = [prefix]
    for error in check.errors:
        lines.append(f"  - {error}")
    if check.blockers:
        lines.append("Blocked launch-profile fields:")
        for blocker in check.blockers:
            lines.append(f"  - {blocker}")
    return "\n".join(lines)


def mark_ready(manifest):
    manifest["status"] = "ready-for-chainparams"
    manifest["blockers"] = []
    check = validate_manifest(manifest, allow_blocked=False)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "cannot mark launch profile ready for chainparams until all production fields are resolved:",
                check,
            )
        )


def demote_ready_for_review(manifest):
    if manifest.get("status") == "ready-for-chainparams":
        manifest["status"] = "blocked"


def require_manifest_parent_directory(path):
    if path.parent.is_symlink():
        raise ValueError(f"manifest parent directory must not be a symlink for in-place updates: {path.parent}")
    if not path.parent.is_dir():
        raise ValueError(f"manifest parent path must be a directory for in-place updates: {path.parent}")


def open_manifest_parent_directory(path):
    require_manifest_parent_directory(path)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        parent_fd = os.open(path.parent, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP or (exc.errno == errno.ENOTDIR and path.parent.is_symlink()):
            raise ValueError(f"manifest parent directory must not be a symlink for in-place updates: {path.parent}")
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise ValueError(f"manifest parent path must be a directory for in-place updates: {path.parent}")
        raise ValueError(f"cannot open manifest parent directory for in-place updates: {exc}")
    if not stat.S_ISDIR(os.fstat(parent_fd).st_mode):
        os.close(parent_fd)
        raise ValueError(f"manifest parent path must be a directory for in-place updates: {path.parent}")
    return parent_fd


def fsync_manifest_parent_directory(parent_fd):
    os.fsync(parent_fd)


def write_manifest(path, manifest):
    if path.is_symlink():
        raise ValueError(f"manifest path must not be a symlink for in-place updates: {path}")
    text = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    tmp_name = path.name + ".tmp"
    tmp_path = path.with_name(tmp_name)

    parent_fd = None
    fd = None
    tmp_created = False
    try:
        parent_fd = open_manifest_parent_directory(path)
        fd = os.open(
            tmp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
            dir_fd=parent_fd,
        )
        tmp_created = True
        with os.fdopen(fd, "w", encoding="utf8") as tmp_file:
            fd = None
            tmp_file.write(text)
            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_name, path.name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        tmp_created = False
        fsync_manifest_parent_directory(parent_fd)
    except FileExistsError:
        raise ValueError(f"manifest temp path already exists: {tmp_path}")
    except OSError as exc:
        if fd is not None:
            os.close(fd)
        if tmp_created and parent_fd is not None:
            try:
                os.unlink(tmp_name, dir_fd=parent_fd)
            except OSError:
                pass
        raise ValueError(f"cannot write manifest atomically: {exc}")
    finally:
        if parent_fd is not None:
            os.close(parent_fd)


def cpp_string(value):
    return json.dumps(value)


def cpp_byte(value):
    return f"0x{value:02x}"


def cpp_byte_array(values):
    return "{" + ", ".join(cpp_byte(value) for value in values) + "}"


def cpp_base58(prefix):
    if len(prefix) == 1:
        return f"std::vector<unsigned char>(1, {prefix[0]})"
    return cpp_byte_array(prefix)


def emit_network_chainparams(network, profile):
    identity = profile["public_network_identity"]
    snapshot = profile["litecoin_snapshot"]
    auxpow = profile["auxpow"]
    base58 = identity["base58_prefixes"]
    message_start = identity["message_start"]

    lines = [
        f"// {network} public launch profile generated from zkcoin_public_launch_profile_manifest.json",
        f"        consensus.ltc_snapshot.nHeight = {snapshot['height']};",
        f"        consensus.ltc_snapshot.hashBlock = uint256S(\"0x{snapshot['block_hash']}\");",
        f"        consensus.ltc_snapshot.hashUTXORoot = uint256S(\"0x{snapshot['import_hash']}\");",
        f"        consensus.auxpow.nStartHeight = {auxpow['start_height']};",
        f"        consensus.auxpow.nChainId = {auxpow['chain_id']};",
        "        consensus.auxpow.fStrictChainId = true;",
        "        consensus.shielded_pool.nStartHeight = -1;",
        "        consensus.shielded_pool.fAllowScaffoldProofs = false;",
        "        consensus.BIP16Height = 1;",
        "        consensus.BIP34Height = 1;",
        "        consensus.BIP34Hash = uint256{};",
        "        consensus.BIP65Height = 1;",
        "        consensus.BIP66Height = 1;",
        "        consensus.CSVHeight = 1;",
        "        consensus.SegwitHeight = 1;",
        "        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;",
        "        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;",
        "        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nStartHeight = 0;",
        "        consensus.vDeployments[Consensus::DEPLOYMENT_TAPROOT].nTimeoutHeight = 0;",
        "        consensus.nMinimumChainWork = uint256{};",
        "        consensus.defaultAssumeValid = uint256{};",
    ]
    for index, byte in enumerate(message_start):
        lines.append(f"        pchMessageStart[{index}] = {cpp_byte(byte)};")
    lines.extend(
        [
            f"        nDefaultPort = {identity['default_port']};",
            "        vSeeds.clear();",
        ]
    )
    for seed in identity["dns_seeds"]:
        lines.append(f"        vSeeds.emplace_back({cpp_string(seed)});")
    lines.extend(
        [
            "        vFixedSeeds.clear();",
            f"        base58Prefixes[PUBKEY_ADDRESS] = {cpp_base58(base58['pubkey_address'])};",
            f"        base58Prefixes[SCRIPT_ADDRESS] = {cpp_base58(base58['script_address'])};",
            f"        base58Prefixes[SCRIPT_ADDRESS2] = {cpp_base58(base58['script_address2'])};",
            f"        base58Prefixes[SECRET_KEY] = {cpp_base58(base58['secret_key'])};",
            f"        base58Prefixes[EXT_PUBLIC_KEY] = {cpp_base58(base58['ext_public_key'])};",
            f"        base58Prefixes[EXT_SECRET_KEY] = {cpp_base58(base58['ext_secret_key'])};",
            f"        bech32_hrp = {cpp_string(identity['bech32_hrp'])};",
            f"        mweb_hrp = {cpp_string(identity['mweb_hrp'])};",
            "        checkpointData = {",
            "            {",
            "                {0, consensus.hashGenesisBlock},",
            "            }",
            "        };",
            "        chainTxData = ChainTxData{",
            "            /* nTime    */ 0,",
            "            /* nTxCount */ 0,",
            "            /* dTxRate  */ 0,",
            "        };",
        ]
    )
    return "\n".join(lines)


def emit_chainparams(manifest):
    return "\n\n".join(
        emit_network_chainparams(network, manifest["networks"][network])
        for network in NETWORKS
    )


def chainparams_class_block(chainparams_text, class_name, next_class_name):
    start_marker = f"class {class_name} : public CChainParams"
    start = chainparams_text.find(start_marker)
    if start == -1:
        return None
    next_marker = f"class {next_class_name} : public CChainParams"
    end = chainparams_text.find(next_marker, start + len(start_marker))
    if end == -1:
        return None
    return chainparams_text[start:end]


def chainparams_sync_errors(manifest, chainparams_text):
    errors = []
    for network in NETWORKS:
        expected = emit_network_chainparams(network, manifest["networks"][network])
        class_name, next_class_name = CHAINPARAMS_CLASS_BOUNDS[network]
        block = chainparams_class_block(chainparams_text, class_name, next_class_name)
        if block is None:
            errors.append(f"{network}: cannot find {class_name} block before {next_class_name}")
            continue
        expected_count = block.count(expected)
        foreign_markers = [
            other_network
            for other_network in NETWORKS
            if other_network != network
            and f"// {other_network} public launch profile generated" in block
        ]
        if expected_count == 1 and not foreign_markers:
            continue
        if expected_count > 1:
            errors.append(f"{network}: generated snippet appears more than once in {class_name}")
        for other_network in foreign_markers:
            errors.append(f"{network}: foreign {other_network} generated snippet present in {class_name}")
        if expected_count >= 1:
            continue
        if expected_count == 0 and expected in chainparams_text:
            errors.append(f"{network}: generated snippet is present outside the {class_name} block")
        missing_lines = [
            line
            for line in expected.splitlines()
            if line not in block
        ]
        if missing_lines:
            errors.append(f"{network}: missing generated chainparams snippet lines in {class_name}")
            for line in missing_lines[:8]:
                errors.append(f"{network}: missing line: {line.strip()}")
            if len(missing_lines) > 8:
                errors.append(f"{network}: {len(missing_lines) - 8} more generated line(s) are missing")
        else:
            errors.append(f"{network}: generated chainparams lines are present in {class_name} but not as one contiguous snippet")
    return errors


def display_path(path):
    path = Path(path)
    try:
        resolved = path.resolve()
        return str(resolved.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def shell_quote(value):
    return shlex.quote(str(value))


def next_blocker_command(blocker_id, manifest_path):
    network, blocker = blocker_id.split(".", 1)
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    if blocker == "litecoin_snapshot":
        return (
            "select and verify the final Litecoin snapshot, generate the required audit JSON shape with "
            f"{tool_path} --snapshot-audit-template {network} {manifest_path}, "
            "fill it with final audited constants, run "
            f"{tool_path} --check-snapshot-audit {network} <snapshot_audit.json> "
            f"{manifest_path}, then run "
            f"{tool_path} --set-snapshot-audit {network} <snapshot_audit.json> "
            f"--in-place {manifest_path}"
        )
    if blocker == "auxpow_chain_id":
        return (
            "select a non-Litecoin AuxPoW child chain id, run "
            f"{tool_path} --check-auxpow {network} <chain_id> {manifest_path}, then run "
            f"{tool_path} --set-auxpow {network} <chain_id> --in-place {manifest_path}"
        )
    if blocker == "public_network_identity":
        return (
            "select non-Litecoin public identity values, run "
            f"{tool_path} --check-identity {network} <message_start> <port> <pubkey> <script> "
            f"<script2> <secret> <xpub> <xprv> <bech32_hrp> <mweb_hrp> {manifest_path}, then run "
            f"{tool_path} --set-identity {network} <message_start> <port> <pubkey> <script> "
            f"<script2> <secret> <xpub> <xprv> <bech32_hrp> <mweb_hrp> --in-place {manifest_path}"
        )
    if blocker == "dns_seeds":
        return (
            "provision zkCoin DNS seed infrastructure, run "
            f"{tool_path} --check-dns-seeds {network} <seed1.hostname>,<seed2.hostname> "
            f"{manifest_path}, then run "
            f"{tool_path} --set-dns-seeds {network} <seed1.hostname>,<seed2.hostname> --in-place {manifest_path}"
        )
    raise ValueError(f"unknown blocker id: {blocker_id}")


def next_action_text(manifest, manifest_path):
    manifest_path = shell_quote(display_path(manifest_path))
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    blockers = ordered_unresolved_blocker_ids(manifest)
    lines = ["zkCoin public launch profile next action:"]
    if blockers:
        lines.append(f"  - next blocker: {blockers[0]}")
        lines.append(f"  - action: {next_blocker_command(blockers[0], manifest_path)}")
        if len(blockers) > 1:
            lines.append("  - later blockers: " + ", ".join(blockers[1:]))
        return "\n".join(lines)

    if manifest.get("status") == "blocked":
        lines.append("  - next step: mark the complete manifest ready for chainparams")
        lines.append(f"  - command: {tool_path} --mark-ready --in-place {manifest_path}")
        return "\n".join(lines)

    lines.append("  - next step: apply the ready manifest to chainparams and verify sync")
    lines.append(f"  - emit: {tool_path} --emit-chainparams {manifest_path}")
    lines.append(f"  - verify: {tool_path} --check-chainparams src/chainparams.cpp {manifest_path}")
    return "\n".join(lines)


def action_plan_entries(manifest, manifest_path):
    manifest_path = shell_quote(display_path(manifest_path))
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    blockers = ordered_unresolved_blocker_ids(manifest)
    if blockers:
        return [
            {
                "step": index,
                "kind": "blocker",
                "id": blocker,
                "action": next_blocker_command(blocker, manifest_path),
            }
            for index, blocker in enumerate(blockers, 1)
        ]

    if manifest.get("status") == "blocked":
        return [
            {
                "step": 1,
                "kind": "mark-ready",
                "id": "mark-ready",
                "command": f"{tool_path} --mark-ready --in-place {manifest_path}",
            },
        ]

    return [
        {
            "step": 1,
            "kind": "emit-chainparams",
            "id": "emit-chainparams",
            "command": f"{tool_path} --emit-chainparams {manifest_path}",
        },
        {
            "step": 2,
            "kind": "check-chainparams",
            "id": "check-chainparams",
            "command": f"{tool_path} --check-chainparams src/chainparams.cpp {manifest_path}",
        },
    ]


def action_plan_text(manifest, manifest_path):
    entries = action_plan_entries(manifest, manifest_path)
    lines = ["zkCoin public launch profile action plan:"]
    if entries and entries[0]["kind"] == "blocker":
        for entry in entries:
            lines.append(f"  {entry['step']}. {entry['id']}")
            lines.append(f"     action: {entry['action']}")
        return "\n".join(lines)

    descriptions = {
        "mark-ready": "mark-ready",
        "emit-chainparams": "emit chainparams",
        "check-chainparams": "verify chainparams",
    }
    for entry in entries:
        description = descriptions.get(entry["id"], entry["id"])
        lines.append(f"  {entry['step']}. {description}")
        lines.append(f"     command: {entry['command']}")
    return "\n".join(lines)


def status_json_text(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    status = manifest.get("status")
    return json.dumps(
        {
            "schema_version": STATUS_JSON_SCHEMA_VERSION,
            "manifest": display_path(manifest_path),
            "status": status,
            "ready_for_chainparams": status == "ready-for-chainparams" and not blockers,
            "unresolved_blocker_count": len(blockers),
            "unresolved_blockers": blockers,
            "blocked_fields": check.blockers,
            "action_count": len(actions),
            "next": actions[0] if actions else None,
            "actions": actions,
        },
        indent=2,
        sort_keys=False,
    )


def selected_primary_actions(args):
    actions = []
    if args.set_snapshot is not None:
        actions.append("--set-snapshot")
    if args.set_snapshot_audit is not None:
        actions.append("--set-snapshot-audit")
    if args.check_snapshot_audit is not None:
        actions.append("--check-snapshot-audit")
    if args.set_auxpow is not None:
        actions.append("--set-auxpow")
    if args.check_auxpow is not None:
        actions.append("--check-auxpow")
    if args.set_dns_seeds is not None:
        actions.append("--set-dns-seeds")
    if args.check_dns_seeds is not None:
        actions.append("--check-dns-seeds")
    if args.set_identity is not None:
        actions.append("--set-identity")
    if args.check_identity is not None:
        actions.append("--check-identity")
    if args.mark_ready:
        actions.append("--mark-ready")
    if args.next_action:
        actions.append("--next-action")
    if args.action_plan:
        actions.append("--action-plan")
    if args.status_json:
        actions.append("--status-json")
    if args.emit_chainparams:
        actions.append("--emit-chainparams")
    if args.check_chainparams is not None:
        actions.append("--check-chainparams")
    if args.snapshot_audit_template is not None:
        actions.append("--snapshot-audit-template")
    return actions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-blocked", action="store_true", help="allow the checked-in blocked manifest while still validating schema and known constraints")
    parser.add_argument("--next-action", action="store_true", help="print the next unresolved public launch-profile action")
    parser.add_argument("--action-plan", action="store_true", help="print every unresolved public launch-profile action in blocker order")
    parser.add_argument("--status-json", action="store_true", help="print machine-readable public launch-profile status and action guidance")
    parser.add_argument("--emit-chainparams", action="store_true", help="emit chainparams.cpp assignment snippets from a ready manifest")
    parser.add_argument(
        "--snapshot-audit-template",
        metavar="NETWORK",
        help="print the required snapshot audit summary JSON shape for one public network",
    )
    parser.add_argument(
        "--check-chainparams",
        metavar="CHAINPARAMS",
        type=Path,
        help="verify a ready manifest's emitted snippets are present in chainparams.cpp",
    )
    parser.add_argument(
        "--set-snapshot",
        nargs=4,
        metavar=("NETWORK", "HEIGHT", "BLOCK_HASH", "IMPORT_HASH"),
        help="rejected for public manifests; use --set-snapshot-audit with verified snapshot output",
    )
    parser.add_argument(
        "--set-snapshot-audit",
        nargs=2,
        metavar=("NETWORK", "AUDIT_JSON"),
        help="update one network's Litecoin snapshot constants from a verified snapshot audit summary",
    )
    parser.add_argument(
        "--check-snapshot-audit",
        nargs=2,
        metavar=("NETWORK", "AUDIT_JSON"),
        help="verify a snapshot audit summary and artifact without updating the manifest",
    )
    parser.add_argument(
        "--set-auxpow",
        nargs=2,
        metavar=("NETWORK", "CHAIN_ID"),
        help="update one network's AuxPoW chain id and remove its AuxPoW blocker",
    )
    parser.add_argument(
        "--check-auxpow",
        nargs=2,
        metavar=("NETWORK", "CHAIN_ID"),
        help="verify one network's AuxPoW chain id candidate without updating the manifest",
    )
    parser.add_argument(
        "--set-dns-seeds",
        nargs=2,
        metavar=("NETWORK", "SEED1,SEED2"),
        help="update one network's DNS seed hostnames and remove its DNS seed blocker",
    )
    parser.add_argument(
        "--check-dns-seeds",
        nargs=2,
        metavar=("NETWORK", "SEED1,SEED2"),
        help="verify one network's DNS seed hostname candidates without updating the manifest",
    )
    parser.add_argument(
        "--set-identity",
        nargs=11,
        metavar=(
            "NETWORK",
            "MESSAGE_START",
            "DEFAULT_PORT",
            "PUBKEY",
            "SCRIPT",
            "SCRIPT2",
            "SECRET",
            "XPUB",
            "XPRV",
            "BECH32_HRP",
            "MWEB_HRP",
        ),
        help="update one network's public identity values and remove its public identity blocker",
    )
    parser.add_argument(
        "--check-identity",
        nargs=11,
        metavar=(
            "NETWORK",
            "MESSAGE_START",
            "DEFAULT_PORT",
            "PUBKEY",
            "SCRIPT",
            "SCRIPT2",
            "SECRET",
            "XPUB",
            "XPRV",
            "BECH32_HRP",
            "MWEB_HRP",
        ),
        help="verify one network's public identity candidate without updating the manifest",
    )
    parser.add_argument(
        "--mark-ready",
        action="store_true",
        help="set status to ready-for-chainparams and clear blockers only after strict validation passes",
    )
    parser.add_argument("--in-place", action="store_true", help="write update changes back to the manifest file")
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    primary_actions = selected_primary_actions(args)
    if len(primary_actions) > 1:
        print(
            "error: use only one primary action at a time: " + ", ".join(primary_actions),
            file=sys.stderr,
        )
        return 1

    try:
        manifest_text = read_launch_manifest_text(args.manifest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    try:
        manifest = json.loads(
            manifest_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        print(f"error: {args.manifest} contains duplicate field: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.manifest} is not valid JSON: {exc}", file=sys.stderr)
        return 1

    if args.snapshot_audit_template is not None:
        if args.in_place:
            print("error: --snapshot-audit-template does not write the manifest", file=sys.stderr)
            return 1
        try:
            print(snapshot_audit_template_text(args.snapshot_audit_template))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.set_snapshot is not None and args.set_snapshot_audit is not None:
        print("error: use either --set-snapshot or --set-snapshot-audit, not both", file=sys.stderr)
        return 1

    if args.set_snapshot is not None:
        print("error: manual snapshot constants are not accepted; use --set-snapshot-audit with a verified snapshot audit summary", file=sys.stderr)
        return 1

    if args.set_snapshot_audit is not None:
        try:
            set_snapshot_from_audit(manifest, *args.set_snapshot_audit)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.check_snapshot_audit is not None:
        if args.in_place:
            print("error: --check-snapshot-audit does not write the manifest", file=sys.stderr)
            return 1
        try:
            audit, candidate = checked_snapshot_audit_candidate(
                manifest,
                *args.check_snapshot_audit,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(
            snapshot_audit_check_text(
                args.check_snapshot_audit[0],
                audit,
                candidate,
            )
        )
        return 0

    if args.set_auxpow is not None:
        try:
            set_auxpow(manifest, *args.set_auxpow)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.check_auxpow is not None:
        if args.in_place:
            print("error: --check-auxpow does not write the manifest", file=sys.stderr)
            return 1
        try:
            auxpow, candidate = checked_auxpow_candidate(manifest, *args.check_auxpow)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(auxpow_check_text(args.check_auxpow[0], auxpow, candidate))
        return 0

    if args.set_dns_seeds is not None:
        try:
            set_dns_seeds(manifest, *args.set_dns_seeds)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.check_dns_seeds is not None:
        if args.in_place:
            print("error: --check-dns-seeds does not write the manifest", file=sys.stderr)
            return 1
        try:
            dns_seeds, candidate = checked_dns_seeds_candidate(manifest, *args.check_dns_seeds)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(dns_seeds_check_text(args.check_dns_seeds[0], dns_seeds, candidate))
        return 0

    if args.set_identity is not None:
        try:
            set_identity(manifest, *args.set_identity)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.check_identity is not None:
        if args.in_place:
            print("error: --check-identity does not write the manifest", file=sys.stderr)
            return 1
        try:
            identity, candidate = checked_identity_candidate(
                manifest,
                args.check_identity[0],
                *args.check_identity[1:],
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(identity_check_text(args.check_identity[0], identity, candidate))
        return 0

    updated_launch_fields = (
        args.set_snapshot is not None
        or args.set_snapshot_audit is not None
        or args.set_auxpow is not None
        or args.set_dns_seeds is not None
        or args.set_identity is not None
    )

    if updated_launch_fields and not args.mark_ready:
        demote_ready_for_review(manifest)

    if args.mark_ready:
        try:
            mark_ready(manifest)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    updated_manifest = (
        updated_launch_fields
        or args.mark_ready
    )
    allow_blocked = args.allow_blocked or updated_manifest
    if args.next_action:
        allow_blocked = True
    if args.action_plan:
        allow_blocked = True
    if args.status_json:
        allow_blocked = True
    check = validate_manifest(manifest, allow_blocked)
    if check.errors:
        print("zkCoin public launch profile manifest failed validation:", file=sys.stderr)
        for error in check.errors:
            print(f"  - {error}", file=sys.stderr)
        if check.blockers:
            print("Blocked launch-profile fields:", file=sys.stderr)
            for blocker in check.blockers:
                print(f"  - {blocker}", file=sys.stderr)
        return 1

    if updated_manifest:
        if args.in_place:
            try:
                write_manifest(args.manifest, manifest)
            except ValueError as exc:
                print(f"error: {exc}", file=sys.stderr)
                return 1
            print(f"Updated {args.manifest}")
        else:
            print(json.dumps(manifest, indent=2, sort_keys=False))
        return 0

    if args.next_action:
        if args.in_place:
            print("error: --next-action does not write the manifest", file=sys.stderr)
            return 1
        print(next_action_text(manifest, args.manifest))
        return 0

    if args.action_plan:
        if args.in_place:
            print("error: --action-plan does not write the manifest", file=sys.stderr)
            return 1
        print(action_plan_text(manifest, args.manifest))
        return 0

    if args.status_json:
        if args.in_place:
            print("error: --status-json does not write the manifest", file=sys.stderr)
            return 1
        print(status_json_text(manifest, args.manifest, check))
        return 0

    if args.in_place:
        print("error: --in-place requires --set-snapshot, --set-snapshot-audit, --set-auxpow, --set-dns-seeds, --set-identity, or --mark-ready", file=sys.stderr)
        return 1

    if args.emit_chainparams:
        if check.blockers:
            print("error: cannot emit chainparams while launch-profile fields are blocked", file=sys.stderr)
            for blocker in check.blockers:
                print(f"  - {blocker}", file=sys.stderr)
            return 1
        print(emit_chainparams(manifest))
        return 0

    if args.check_chainparams is not None:
        if check.blockers:
            print("error: cannot check chainparams while launch-profile fields are blocked", file=sys.stderr)
            for blocker in check.blockers:
                print(f"  - {blocker}", file=sys.stderr)
            return 1
        try:
            chainparams_text = read_chainparams_text(args.check_chainparams)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        errors = chainparams_sync_errors(manifest, chainparams_text)
        if errors:
            print("zkCoin public launch chainparams sync check failed:", file=sys.stderr)
            for error in errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        print("zkCoin public launch chainparams snippets match the ready manifest.")
        return 0

    if check.blockers:
        print("zkCoin public launch profile manifest is schema-valid but blocked.")
        print("Blocked launch-profile fields:")
        for blocker in check.blockers:
            print(f"  - {blocker}")
    else:
        print("zkCoin public launch profile manifest is ready for chainparams.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
