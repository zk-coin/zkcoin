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


def unresolved_blocker_ids(manifest):
    blockers = set()
    networks = manifest.get("networks", {})
    for network in NETWORKS:
        profile = networks.get(network, {})
        snapshot = profile.get("litecoin_snapshot", {})
        snapshot_audit = snapshot.get("audit", {})
        if (
            any(snapshot.get(field) is None for field in SNAPSHOT_FIELDS)
            or not isinstance(snapshot_audit, dict)
            or any(snapshot_audit.get(field) is None for field in SNAPSHOT_AUDIT_FIELDS)
        ):
            blockers.add(f"{network}.litecoin_snapshot")

        auxpow = profile.get("auxpow", {})
        if auxpow.get("chain_id") is None:
            blockers.add(f"{network}.auxpow_chain_id")

        identity = profile.get("public_network_identity", {})
        base58 = identity.get("base58_prefixes", {})
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
        if not isinstance(value, int) or value <= 0:
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
    if any(not isinstance(byte, int) or byte < 0 or byte > 255 for byte in value):
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
    check.require_positive_int(snapshot.get("height"), f"{network}.litecoin_snapshot.height", allow_null=allow_null)
    check.require_hex256(snapshot.get("block_hash"), f"{network}.litecoin_snapshot.block_hash", allow_null=allow_null)
    check.require_hex256(snapshot.get("import_hash"), f"{network}.litecoin_snapshot.import_hash", allow_null=allow_null)
    audit = check.require_object(snapshot.get("audit"), f"{network}.litecoin_snapshot.audit")
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
    if auxpow.get("start_height") != 1:
        check.error(f"{network}.auxpow.start_height", "must be 1 for first post-genesis launch block")
    chain_id = auxpow.get("chain_id")
    if chain_id is None and allow_null:
        check.blockers.append(f"{network}.auxpow.chain_id")
    elif not isinstance(chain_id, int) or not (0 < chain_id < 0x8000):
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
    check.require_bool(script_rules.get("active_at_launch"), f"{network}.script_rules.active_at_launch", True)
    rules = check.require_list(script_rules.get("required_rules"), f"{network}.script_rules.required_rules")
    if sorted(rules) != sorted(SCRIPT_RULES):
        check.error(f"{network}.script_rules.required_rules", "must list BIP16, BIP34, BIP65, BIP66, CSV, Segwit, Taproot")


def validate_shielded_pool(check, network, profile):
    shielded = check.require_object(profile.get("shielded_pool"), f"{network}.shielded_pool")
    check.require_bool(shielded.get("active_at_launch"), f"{network}.shielded_pool.active_at_launch", False)
    check.require_bool(shielded.get("scaffold_proofs"), f"{network}.shielded_pool.scaffold_proofs", False)
    if shielded.get("real_proof_backend") != "orchard-v1":
        check.error(f"{network}.shielded_pool.real_proof_backend", "must be orchard-v1")
    activation_policy = check.require_string(shielded.get("activation_policy"), f"{network}.shielded_pool.activation_policy")
    if activation_policy is not None and activation_policy != "post-launch-only":
        check.error(f"{network}.shielded_pool.activation_policy", "must be post-launch-only")


def validate_chain_history(check, network, profile):
    history = check.require_object(profile.get("chain_history"), f"{network}.chain_history")
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
            or any(not isinstance(byte, int) or byte < 0 or byte > 255 for byte in value)
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
    message_start = identity.get("message_start")
    if message_start is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.message_start")
    elif not message_start_valid(message_start):
        check.error(f"{network}.public_network_identity.message_start", "must be 4 non-Litecoin non-printable magic bytes")

    default_port = identity.get("default_port")
    if default_port is None and allow_null:
        check.blockers.append(f"{network}.public_network_identity.default_port")
    elif not isinstance(default_port, int) or default_port <= 1024 or default_port > 65535:
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
        or any(not isinstance(byte, int) or byte < 0 or byte > 255 for byte in value)
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
        if isinstance(auxpow, dict) and isinstance(auxpow.get("chain_id"), int):
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
        if isinstance(default_port, int):
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
    if manifest.get("version") != 1:
        check.error("version", "must be 1")
    status = manifest.get("status")
    if status not in ("blocked", "ready-for-chainparams"):
        check.error("status", "must be blocked or ready-for-chainparams")
    blockers = check.require_list(manifest.get("blockers"), "blockers")
    blocker_ids = set()
    for index, blocker in enumerate(blockers):
        blocker = check.require_object(blocker, f"blockers[{index}]")
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
    for network in NETWORKS:
        profile = check.require_object(networks.get(network), f"networks.{network}")
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
    value = value.lower()
    if re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{label} must be a 64-character hex string")
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
        raise ValueError(f"snapshot audit {field} must be a 64-character hex string")
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
        raise ValueError(f"snapshot audit {field} must be an absolute non-placeholder path")
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


def open_regular_file_no_symlink(path, *, symlink_error, missing_error, not_regular_error, open_error):
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if nofollow == 0 and path.is_symlink():
        raise ValueError(f"{symlink_error}: {path}")
    flags = os.O_RDONLY | nofollow
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(f"{symlink_error}: {path}")
        if exc.errno in (errno.ENOENT, errno.ENOTDIR):
            raise ValueError(f"{missing_error}: {path}")
        raise ValueError(f"{open_error}: {exc}")
    try:
        file_stat = os.fstat(fd)
    except OSError as exc:
        os.close(fd)
        raise ValueError(f"{open_error}: {exc}")
    if not stat.S_ISREG(file_stat.st_mode):
        os.close(fd)
        raise ValueError(f"{not_regular_error}: {path}")
    return fd, file_stat.st_size


def snapshot_file_sha256(snapshot_file):
    digest = hashlib.sha256()
    for chunk in iter(lambda: snapshot_file.read(1024 * 1024), b""):
        digest.update(chunk)
    return digest.hexdigest()


def verify_snapshot_audit_artifact(audit):
    snapshot_path = Path(audit["snapshot_file"])
    fd, actual_size = open_regular_file_no_symlink(
        snapshot_path,
        symlink_error="snapshot audit file artifact must not be a symlink",
        missing_error="snapshot audit file artifact does not exist",
        not_regular_error="snapshot audit file artifact must be a regular file",
        open_error="cannot read snapshot audit file artifact",
    )
    snapshot_file = None
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


def parse_snapshot_audit(audit_path):
    audit_summary_path = Path(audit_path)
    fd, _ = open_regular_file_no_symlink(
        audit_summary_path,
        symlink_error="snapshot audit summary must not be a symlink",
        missing_error="cannot read snapshot audit summary",
        not_regular_error="snapshot audit summary must be a regular file",
        open_error="cannot read snapshot audit summary",
    )
    audit_summary_file = None
    try:
        audit_summary_file = os.fdopen(fd, "r", encoding="utf8")
        fd = None
        audit = json.loads(audit_summary_file.read())
    except OSError as exc:
        raise ValueError(f"cannot read snapshot audit summary: {exc}")
    except json.JSONDecodeError as exc:
        raise ValueError(f"snapshot audit summary is not valid JSON: {exc}")
    finally:
        if audit_summary_file is not None:
            audit_summary_file.close()
        elif fd is not None:
            os.close(fd)

    if not isinstance(audit, dict):
        raise ValueError("snapshot audit summary must be a JSON object")

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
    blockers = manifest.get("blockers", [])
    manifest["blockers"] = [
        blocker
        for blocker in blockers
        if not (isinstance(blocker, dict) and blocker.get("id") == blocker_id)
    ]


def set_snapshot(manifest, network, height, block_hash, import_hash, audit=None):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    networks = manifest.setdefault("networks", {})
    profile = networks.setdefault(network, {})
    snapshot = {
        "height": parse_height(height),
        "block_hash": parse_hex256(block_hash, "block_hash"),
        "import_hash": parse_hex256(import_hash, "import_hash"),
    }
    if audit is not None:
        snapshot["audit"] = audit
    profile["litecoin_snapshot"] = snapshot
    remove_blocker(manifest, f"{network}.litecoin_snapshot")


def set_snapshot_from_audit(manifest, network, audit_path):
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
    set_snapshot(manifest, network, audit["height"], audit["block_hash"], audit["import_hash"], audit["audit"])


def set_auxpow(manifest, network, chain_id):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    networks = manifest.setdefault("networks", {})
    profile = networks.setdefault(network, {})
    profile["auxpow"] = {
        "start_height": 1,
        "chain_id": parse_chain_id(chain_id),
        "strict_chain_id": True,
        "forbidden_parent_version_chain_id_range": [
            8192,
            16383,
        ],
    }
    remove_blocker(manifest, f"{network}.auxpow_chain_id")


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
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    networks = manifest.setdefault("networks", {})
    profile = networks.setdefault(network, {})
    identity = profile.setdefault("public_network_identity", {})
    identity["dns_seeds"] = parse_dns_seeds(dns_seeds)
    remove_blocker(manifest, f"{network}.dns_seeds")


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

    networks = manifest.setdefault("networks", {})
    profile = networks.setdefault(network, {})
    identity = profile.setdefault("public_network_identity", {})
    identity.update(parsed_identity)
    identity.setdefault("dns_seeds", [])
    identity.setdefault("fixed_seeds", [])
    remove_blocker(manifest, f"{network}.public_network_identity")


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


def write_manifest(path, manifest):
    text = json.dumps(manifest, indent=2, sort_keys=False) + "\n"
    tmp_path = path.with_name(path.name + ".tmp")
    tmp_path.write_text(text, encoding="utf8")
    tmp_path.replace(path)


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


def next_blocker_command(blocker_id, manifest_path):
    network, blocker = blocker_id.split(".", 1)
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    if blocker == "litecoin_snapshot":
        return (
            "select and verify the final Litecoin snapshot, then run "
            f"{tool_path} --set-snapshot-audit {network} <snapshot_audit.json> "
            f"--in-place {manifest_path}"
        )
    if blocker == "auxpow_chain_id":
        return (
            "select a non-Litecoin AuxPoW child chain id and run "
            f"{tool_path} --set-auxpow {network} <chain_id> --in-place {manifest_path}"
        )
    if blocker == "public_network_identity":
        return (
            "select non-Litecoin public identity values and run "
            f"{tool_path} --set-identity {network} <message_start> <port> <pubkey> <script> "
            f"<script2> <secret> <xpub> <xprv> <bech32_hrp> <mweb_hrp> --in-place {manifest_path}"
        )
    if blocker == "dns_seeds":
        return (
            "provision zkCoin DNS seed infrastructure and run "
            f"{tool_path} --set-dns-seeds {network} <seed1.hostname>,<seed2.hostname> --in-place {manifest_path}"
        )
    raise ValueError(f"unknown blocker id: {blocker_id}")


def next_action_text(manifest, manifest_path):
    manifest_path = display_path(manifest_path)
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--allow-blocked", action="store_true", help="allow the checked-in blocked manifest while still validating schema and known constraints")
    parser.add_argument("--next-action", action="store_true", help="print the next unresolved public launch-profile action")
    parser.add_argument("--emit-chainparams", action="store_true", help="emit chainparams.cpp assignment snippets from a ready manifest")
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
        "--set-auxpow",
        nargs=2,
        metavar=("NETWORK", "CHAIN_ID"),
        help="update one network's AuxPoW chain id and remove its AuxPoW blocker",
    )
    parser.add_argument(
        "--set-dns-seeds",
        nargs=2,
        metavar=("NETWORK", "SEED1,SEED2"),
        help="update one network's DNS seed hostnames and remove its DNS seed blocker",
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
        "--mark-ready",
        action="store_true",
        help="set status to ready-for-chainparams and clear blockers only after strict validation passes",
    )
    parser.add_argument("--in-place", action="store_true", help="write update changes back to the manifest file")
    parser.add_argument("manifest", nargs="?", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    try:
        manifest = json.loads(args.manifest.read_text(encoding="utf8"))
    except OSError as exc:
        print(f"error: cannot read {args.manifest}: {exc}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as exc:
        print(f"error: {args.manifest} is not valid JSON: {exc}", file=sys.stderr)
        return 1

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

    if args.set_auxpow is not None:
        try:
            set_auxpow(manifest, *args.set_auxpow)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.set_dns_seeds is not None:
        try:
            set_dns_seeds(manifest, *args.set_dns_seeds)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

    if args.set_identity is not None:
        try:
            set_identity(manifest, *args.set_identity)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1

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
            write_manifest(args.manifest, manifest)
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
            chainparams_text = args.check_chainparams.read_text(encoding="utf8")
        except OSError as exc:
            print(f"error: cannot read {args.check_chainparams}: {exc}", file=sys.stderr)
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
