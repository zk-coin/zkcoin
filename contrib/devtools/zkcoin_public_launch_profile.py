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
LITECOIN_DNS_SEED_MARKERS = ("koin-project.com", "litecoin", "thrasher.io")
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
VALUE_SELECTION_CANDIDATE_MAX_BYTES = 64 * 1024
RELEASE_EVIDENCE_BUNDLE_MAX_BYTES = 512 * 1024
RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES = 64 * 1024
RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES = (
    RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES
)
RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES = (
    RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES
)
RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES = 64 * 1024
RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES = 256 * 1024
RELEASE_EVIDENCE_BUNDLE_MISMATCH_LIMIT = 50
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
BLOCKER_TYPES = (
    "litecoin_snapshot",
    "auxpow_chain_id",
    "public_network_identity",
    "dns_seeds",
)
READINESS_GATES = (
    "external_artifact",
    "value_selection",
)
REQUIRED_BLOCKERS = set(BLOCKER_ORDER)
STATUS_JSON_SCHEMA_VERSION = 2
RELEASE_EVIDENCE_ARCHIVE_RECORD_FIELDS = (
    "release_evidence_bundle_uri",
    "release_evidence_bundle_sha256",
    "release_evidence_bundle_schema_version",
    "manifest_path",
    "manifest_commit",
    "gate_command",
    "gate_verified",
    "gate_mismatch_count",
    "gate_checked_at",
)
RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_FIELDS = (
    "release_evidence_publication_index_uri",
    "release_evidence_publication_index_sha256",
    "release_evidence_publication_index_schema_version",
    "manifest_path",
    "manifest_commit",
    "gate_command",
    "gate_verified",
    "gate_mismatch_count",
    "gate_checked_at",
)
RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_FIELDS = (
    "release_evidence_publication_closeout_uri",
    "release_evidence_publication_closeout_sha256",
    "release_evidence_publication_closeout_schema_version",
    "manifest_path",
    "manifest_commit",
    "gate_command",
    "gate_verified",
    "gate_mismatch_count",
    "gate_checked_at",
)
RELEASE_EVIDENCE_PUBLICATION_INDEX_FIELDS = (
    "schema_version",
    "release_evidence_bundle_uri",
    "release_evidence_archive_record_uri",
    "release_evidence_handoff_summary_uri",
    "manifest_commit",
    "published_at",
    "publisher",
)
RELEASE_EVIDENCE_PUBLICATION_ARTIFACT_PATH_FLAGS = (
    (
        "release-evidence-bundle",
        "--release-evidence-bundle-path",
        "<release_evidence_bundle.json>",
    ),
    (
        "release-evidence-archive-record",
        "--release-evidence-archive-record-path",
        "<release_evidence_archive_record.json>",
    ),
    (
        "release-evidence-publication-index",
        "--release-evidence-publication-index-path",
        "<release_evidence_publication_index.json>",
    ),
    (
        "release-evidence-publication-index-archive-record",
        "--release-evidence-publication-index-archive-record-path",
        "<release_evidence_publication_index_archive_record.json>",
    ),
    (
        "release-evidence-publication-closeout",
        "--release-evidence-publication-closeout-path",
        "<release_evidence_publication_closeout.json>",
    ),
    (
        "release-evidence-publication-closeout-archive-record",
        "--release-evidence-publication-closeout-archive-record-path",
        "<release_evidence_publication_closeout_archive_record.json>",
    ),
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


def blocked_fields_for_blocker(blocker_id, blocked_fields):
    network, blocker = blocker_id.split(".", 1)
    if blocker == "litecoin_snapshot":
        prefix = f"{network}.litecoin_snapshot."
        return [field for field in blocked_fields if field.startswith(prefix)]
    if blocker == "auxpow_chain_id":
        path = f"{network}.auxpow.chain_id"
        return [field for field in blocked_fields if field == path]
    if blocker == "public_network_identity":
        prefix = f"{network}.public_network_identity."
        dns_seed_path = f"{network}.public_network_identity.dns_seeds"
        return [
            field
            for field in blocked_fields
            if field.startswith(prefix) and field != dns_seed_path
        ]
    if blocker == "dns_seeds":
        path = f"{network}.public_network_identity.dns_seeds"
        return [field for field in blocked_fields if field == path]
    raise ValueError(f"unknown blocker id: {blocker_id}")


def blocked_field_group_entries(blockers, blocked_fields, actions):
    actions_by_id = {entry["id"]: entry for entry in actions}
    blockers_by_network = items_by_network(blockers)
    blockers_by_type = blockers_by_blocker_type(blockers)
    entries = []
    for index, blocker in enumerate(blockers, 1):
        network, blocker_type = blocker.split(".", 1)
        network_blockers = blockers_by_network[network]
        blocker_type_blockers = blockers_by_type[blocker_type]
        fields = blocked_fields_for_blocker(blocker, blocked_fields)
        action = actions_by_id[blocker]
        entries.append(
            {
                "step": index,
                "network_step": network_blockers.index(blocker) + 1,
                "network_step_count": len(network_blockers),
                "blocker_type_step": blocker_type_blockers.index(blocker) + 1,
                "blocker_type_step_count": len(blocker_type_blockers),
                "kind": "blocker",
                "id": blocker,
                "network": network,
                "blocker_type": blocker_type,
                "action": action["action"],
                "template_command": action["template_command"],
                "check_command": action["check_command"],
                "preflight_command": action["preflight_command"],
                "apply_command": action["apply_command"],
                "snapshot_audit_handoff_command": action["snapshot_audit_handoff_command"],
                "readiness_summary_command": action["readiness_summary_command"],
                "network_readiness_summary_command": action["network_readiness_summary_command"],
                "blocker_type_readiness_summary_command": action["blocker_type_readiness_summary_command"],
                "readiness_gate_summary_command": action["readiness_gate_summary_command"],
                "blocker_readiness_summary_command": action["blocker_readiness_summary_command"],
                "template_fields": action.get("template_fields"),
                "template_field_count": action.get("template_field_count", 0),
                "candidate_constraints": action.get("candidate_constraints"),
                "candidate_constraint_count": action.get("candidate_constraint_count", 0),
                "field_count": len(fields),
                "fields": fields,
            }
        )
    return entries


def actions_with_blocked_fields(actions, blocked_field_groups):
    groups_by_id = {entry["id"]: entry for entry in blocked_field_groups}
    entries = []
    for action in actions:
        entry = dict(action)
        if entry.get("kind") == "blocker":
            group = groups_by_id[entry["id"]]
            entry["field_count"] = group["field_count"]
            entry["fields"] = group["fields"]
        entries.append(entry)
    return entries


def items_by_network(items):
    grouped = {network: [] for network in NETWORKS}
    for item in items:
        network = item.split(".", 1)[0]
        if network in grouped:
            grouped[network].append(item)
    return grouped


def item_counts_by_network(items):
    return {
        network: len(network_items)
        for network, network_items in items_by_network(items).items()
    }


def actions_by_network(actions):
    grouped = {network: [] for network in NETWORKS}
    for action in actions:
        network = action.get("network")
        if network in grouped:
            grouped[network].append(action)
    return grouped


def action_counts_by_network(actions):
    return {
        network: len(network_actions)
        for network, network_actions in actions_by_network(actions).items()
    }


def actions_by_blocker_type(actions):
    grouped = {blocker_type: [] for blocker_type in BLOCKER_TYPES}
    for action in actions:
        blocker_type = action.get("blocker_type")
        if blocker_type in grouped:
            grouped[blocker_type].append(action)
    return grouped


def action_counts_by_blocker_type(actions):
    return {
        blocker_type: len(blocker_actions)
        for blocker_type, blocker_actions in actions_by_blocker_type(actions).items()
    }


def actions_by_readiness_gate(actions):
    grouped = {gate: [] for gate in READINESS_GATES}
    for action in actions:
        blocker_type = action.get("blocker_type")
        if blocker_type in BLOCKER_TYPES:
            grouped[blocker_type_readiness_gate(blocker_type)].append(action)
    return grouped


def action_counts_by_readiness_gate(actions):
    return {
        gate: len(gate_actions)
        for gate, gate_actions in actions_by_readiness_gate(actions).items()
    }


def actions_by_network_and_blocker_type(actions):
    grouped = {
        network: {blocker_type: [] for blocker_type in BLOCKER_TYPES}
        for network in NETWORKS
    }
    for action in actions:
        network = action.get("network")
        blocker_type = action.get("blocker_type")
        if network in grouped and blocker_type in grouped[network]:
            grouped[network][blocker_type].append(action)
    return grouped


def action_counts_by_network_and_blocker_type(actions):
    return {
        network: {
            blocker_type: len(blocker_actions)
            for blocker_type, blocker_actions in actions_by_type.items()
        }
        for network, actions_by_type in actions_by_network_and_blocker_type(actions).items()
    }


def candidate_constraints_by_blocker_type():
    return {
        blocker_type: blocker_candidate_constraints(blocker_type)
        for blocker_type in BLOCKER_TYPES
    }


def candidate_constraint_counts_by_blocker_type():
    return {
        blocker_type: len(constraints) if constraints is not None else 0
        for blocker_type, constraints in candidate_constraints_by_blocker_type().items()
    }


def candidate_constraints_by_network_and_blocker_type():
    constraints_by_type = candidate_constraints_by_blocker_type()
    return {
        network: {
            blocker_type: constraints_by_type[blocker_type]
            for blocker_type in BLOCKER_TYPES
        }
        for network in NETWORKS
    }


def candidate_constraint_counts_by_network_and_blocker_type():
    counts_by_type = candidate_constraint_counts_by_blocker_type()
    return {
        network: {
            blocker_type: counts_by_type[blocker_type]
            for blocker_type in BLOCKER_TYPES
        }
        for network in NETWORKS
    }


def candidate_constraints_by_blocker():
    constraints_by_type = candidate_constraints_by_blocker_type()
    return {
        f"{network}.{blocker_type}": constraints_by_type[blocker_type]
        for network in NETWORKS
        for blocker_type in BLOCKER_TYPES
    }


def candidate_constraint_counts_by_blocker():
    counts_by_type = candidate_constraint_counts_by_blocker_type()
    return {
        f"{network}.{blocker_type}": counts_by_type[blocker_type]
        for network in NETWORKS
        for blocker_type in BLOCKER_TYPES
    }


def blocker_external_artifacts(blocker_type):
    if blocker_type == "litecoin_snapshot":
        return [
            {
                "id": "snapshot_audit_json",
                "argument": "<snapshot_audit.json>",
                "required_for_commands": ["check_command", "preflight_command", "apply_command"],
                "source": "operator-generated snapshot audit summary",
                "must_be_utf8_json_object": True,
                "must_match_template_fields": list(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
                "max_bytes": SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES,
            },
            {
                "id": "snapshot_file",
                "path_field": "snapshot_file",
                "source": "snapshot audit JSON field",
                "required_for_commands": ["check_command", "preflight_command", "apply_command"],
                "must_be_local_regular_file": True,
                "must_not_be_symlink": True,
                "parent_must_not_be_symlink": True,
                "size_field": "snapshot_file_size",
                "sha256_field": "snapshot_file_sha256",
                "must_remain_stable_during_verification": True,
            },
        ]
    return []


def external_artifacts_by_blocker_type():
    return {
        blocker_type: blocker_external_artifacts(blocker_type)
        for blocker_type in BLOCKER_TYPES
    }


def external_artifact_counts_by_blocker_type():
    return {
        blocker_type: len(artifacts)
        for blocker_type, artifacts in external_artifacts_by_blocker_type().items()
    }


def external_artifacts_by_network_and_blocker_type():
    artifacts_by_type = external_artifacts_by_blocker_type()
    return {
        network: {
            blocker_type: artifacts_by_type[blocker_type]
            for blocker_type in BLOCKER_TYPES
        }
        for network in NETWORKS
    }


def external_artifact_counts_by_network_and_blocker_type():
    counts_by_type = external_artifact_counts_by_blocker_type()
    return {
        network: {
            blocker_type: counts_by_type[blocker_type]
            for blocker_type in BLOCKER_TYPES
        }
        for network in NETWORKS
    }


def snapshot_audit_external_artifacts_by_network():
    artifacts_by_network = external_artifacts_by_network_and_blocker_type()
    return {
        network: artifacts_by_network[network]["litecoin_snapshot"]
        for network in NETWORKS
    }


def snapshot_audit_external_artifact_counts_by_network():
    return {
        network: len(artifacts)
        for network, artifacts in snapshot_audit_external_artifacts_by_network().items()
    }


def snapshot_audit_handoff_readiness_by_network(
    network_progress,
    blocked_field_groups,
    next_snapshot_audit_handoff_commands_by_network,
):
    artifacts_by_network = snapshot_audit_external_artifacts_by_network()
    artifact_counts_by_network = snapshot_audit_external_artifact_counts_by_network()
    blocked_field_counts = blocked_field_counts_by_network_and_blocker_type(blocked_field_groups)
    blocker_groups = blocked_field_groups_by_network_and_blocker_type(blocked_field_groups)
    return {
        network: {
            "blocker": f"{network}.litecoin_snapshot",
            "unresolved": bool(blocker_groups[network]["litecoin_snapshot"]),
            "is_next_blocker": (
                network_progress[network]["next_blocked_field_group"] is not None
                and network_progress[network]["next_blocked_field_group"]["id"] == f"{network}.litecoin_snapshot"
            ),
            "blocked_field_count": blocked_field_counts[network]["litecoin_snapshot"],
            "next_command": next_snapshot_audit_handoff_commands_by_network[network],
            "external_artifacts": artifacts_by_network[network],
            "external_artifact_count": artifact_counts_by_network[network],
        }
        for network in NETWORKS
    }


SNAPSHOT_AUDIT_HANDOFF_CHECKLIST_COMMAND_STEPS = (
    ("generate_template", "template_command"),
    ("verify_audit", "check_command"),
    ("preflight_audit", "preflight_command"),
    ("apply_audit", "apply_command"),
)


def snapshot_audit_handoff_checklist_by_network(manifest_path, blocked_field_groups):
    manifest_path = shell_quote(display_path(manifest_path))
    artifacts_by_network = snapshot_audit_external_artifacts_by_network()
    blocked_field_counts = blocked_field_counts_by_network_and_blocker_type(blocked_field_groups)
    blocker_groups = blocked_field_groups_by_network_and_blocker_type(blocked_field_groups)
    checklist_by_network = {}
    for network in NETWORKS:
        blocker = f"{network}.litecoin_snapshot"
        unresolved = bool(blocker_groups[network]["litecoin_snapshot"])
        commands = blocker_action_commands(blocker, manifest_path)
        artifact_ids = [artifact["id"] for artifact in artifacts_by_network[network]]
        artifact_ids_by_command = {
            command_key: [
                artifact["id"]
                for artifact in artifacts_by_network[network]
                if command_key in artifact.get("required_for_commands", [])
            ]
            for _, command_key in SNAPSHOT_AUDIT_HANDOFF_CHECKLIST_COMMAND_STEPS
        }
        command_steps = [
            {
                "id": step_id,
                "kind": "command",
                "command_key": command_key,
                "command": commands[command_key],
                "available": commands[command_key] is not None,
                "required_artifacts": artifact_ids_by_command[command_key],
                "requires_preflight": command_key == "apply_command",
            }
            for step_id, command_key in SNAPSHOT_AUDIT_HANDOFF_CHECKLIST_COMMAND_STEPS
        ]
        artifact_steps = [
            {
                "id": artifact["id"],
                "kind": "external_artifact",
                "required": unresolved,
                "required_for_commands": artifact["required_for_commands"],
            }
            for artifact in artifacts_by_network[network]
        ]
        steps = [command_steps[0]] + artifact_steps + command_steps[1:]
        checklist_by_network[network] = {
            "blocker": blocker,
            "state": "required" if unresolved else "complete",
            "unresolved": unresolved,
            "blocked_field_count": blocked_field_counts[network]["litecoin_snapshot"],
            "artifact_ids": artifact_ids,
            "required_artifact_count": len(artifact_ids),
            "command_keys": [
                command_key
                for _, command_key in SNAPSHOT_AUDIT_HANDOFF_CHECKLIST_COMMAND_STEPS
            ],
            "available_command_count": sum(
                1
                for _, command_key in SNAPSHOT_AUDIT_HANDOFF_CHECKLIST_COMMAND_STEPS
                if commands[command_key] is not None
            ),
            "steps": steps,
        }
    return checklist_by_network


def snapshot_audit_handoff_checklist_summary_by_network(checklists_by_network):
    summary_by_network = {}
    for network, checklist in checklists_by_network.items():
        steps = checklist["steps"]
        summary_by_network[network] = {
            "blocker": checklist["blocker"],
            "state": checklist["state"],
            "unresolved": checklist["unresolved"],
            "blocked_field_count": checklist["blocked_field_count"],
            "step_ids": [step["id"] for step in steps],
            "step_count": len(steps),
            "command_step_count": sum(1 for step in steps if step["kind"] == "command"),
            "external_artifact_step_count": sum(
                1
                for step in steps
                if step["kind"] == "external_artifact"
            ),
            "required_artifact_ids": checklist["artifact_ids"],
            "required_artifact_count": checklist["required_artifact_count"],
            "available_command_count": checklist["available_command_count"],
            "requires_preflight_step_ids": [
                step["id"]
                for step in steps
                if step.get("requires_preflight")
            ],
        }
    return summary_by_network


def external_artifacts_by_blocker():
    artifacts_by_type = external_artifacts_by_blocker_type()
    return {
        f"{network}.{blocker_type}": artifacts_by_type[blocker_type]
        for network in NETWORKS
        for blocker_type in BLOCKER_TYPES
    }


def external_artifact_counts_by_blocker():
    counts_by_type = external_artifact_counts_by_blocker_type()
    return {
        f"{network}.{blocker_type}": counts_by_type[blocker_type]
        for network in NETWORKS
        for blocker_type in BLOCKER_TYPES
    }


def blocker_type_readiness_gate(blocker_type):
    if blocker_external_artifacts(blocker_type):
        return "external_artifact"
    return "value_selection"


def readiness_gate_by_blocker_type():
    return {
        blocker_type: blocker_type_readiness_gate(blocker_type)
        for blocker_type in BLOCKER_TYPES
    }


def readiness_gate_by_network_and_blocker_type():
    gates_by_type = readiness_gate_by_blocker_type()
    return {
        network: {
            blocker_type: gates_by_type[blocker_type]
            for blocker_type in BLOCKER_TYPES
        }
        for network in NETWORKS
    }


def readiness_gate_by_blocker():
    gates_by_type = readiness_gate_by_blocker_type()
    return {
        f"{network}.{blocker_type}": gates_by_type[blocker_type]
        for network in NETWORKS
        for blocker_type in BLOCKER_TYPES
    }


def blocker_types_by_readiness_gate():
    grouped = {gate: [] for gate in READINESS_GATES}
    for blocker_type in BLOCKER_TYPES:
        grouped[blocker_type_readiness_gate(blocker_type)].append(blocker_type)
    return grouped


def blocker_type_counts_by_readiness_gate():
    return {
        gate: len(blocker_types)
        for gate, blocker_types in blocker_types_by_readiness_gate().items()
    }


def blockers_by_readiness_gate(blockers):
    gates_by_type = readiness_gate_by_blocker_type()
    grouped = {gate: [] for gate in READINESS_GATES}
    for blocker in blockers:
        _, blocker_type = blocker.split(".", 1)
        gate = gates_by_type.get(blocker_type)
        if gate in grouped:
            grouped[gate].append(blocker)
    return grouped


def blocker_counts_by_readiness_gate(blockers):
    return {
        gate: len(gate_blockers)
        for gate, gate_blockers in blockers_by_readiness_gate(blockers).items()
    }


def later_blockers_by_readiness_gate(blockers):
    return {
        gate: gate_blockers[1:]
        for gate, gate_blockers in blockers_by_readiness_gate(blockers).items()
    }


def later_blocker_counts_by_readiness_gate(blockers):
    return {
        gate: len(gate_blockers)
        for gate, gate_blockers in later_blockers_by_readiness_gate(blockers).items()
    }


def blocked_field_groups_by_readiness_gate(blocked_field_groups):
    grouped = {gate: [] for gate in READINESS_GATES}
    for group in blocked_field_groups:
        gate = blocker_type_readiness_gate(group["blocker_type"])
        grouped[gate].append(group)
    return grouped


def blocked_field_group_counts_by_readiness_gate(blocked_field_groups):
    return {
        gate: len(groups)
        for gate, groups in blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def blocked_fields_by_readiness_gate(blocked_field_groups):
    return {
        gate: [
            field
            for group in groups
            for field in group.get("fields", [])
        ]
        for gate, groups in blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def blocked_field_counts_by_readiness_gate(blocked_field_groups):
    return {
        gate: len(fields)
        for gate, fields in blocked_fields_by_readiness_gate(blocked_field_groups).items()
    }


def later_blocked_field_groups_by_readiness_gate(blocked_field_groups):
    return {
        gate: groups[1:]
        for gate, groups in blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def later_blocked_field_group_counts_by_readiness_gate(blocked_field_groups):
    return {
        gate: len(groups)
        for gate, groups in later_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def later_blocked_fields_by_readiness_gate(blocked_field_groups):
    return {
        gate: [
            field
            for group in groups
            for field in group.get("fields", [])
        ]
        for gate, groups in later_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def later_blocked_field_counts_by_readiness_gate(blocked_field_groups):
    return {
        gate: len(fields)
        for gate, fields in later_blocked_fields_by_readiness_gate(blocked_field_groups).items()
    }


def next_actions_by_readiness_gate(actions):
    return {
        gate: gate_actions[0] if gate_actions else None
        for gate, gate_actions in actions_by_readiness_gate(actions).items()
    }


def next_commands_by_readiness_gate(actions):
    return {
        gate: action_command_fields(action)
        for gate, action in next_actions_by_readiness_gate(actions).items()
    }


def command_field_values_by_group(commands_by_group, command_field):
    return {
        group: commands.get(command_field) if commands is not None else None
        for group, commands in commands_by_group.items()
    }


def command_field_counts_by_group(commands_by_group, command_field):
    return {
        group: 1 if commands is not None and commands.get(command_field) is not None else 0
        for group, commands in commands_by_group.items()
    }


def next_blocked_field_groups_by_readiness_gate(blocked_field_groups):
    return {
        gate: groups[0] if groups else None
        for gate, groups in blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_blocked_fields_by_readiness_gate(blocked_field_groups):
    return {
        gate: next_group["fields"] if next_group else []
        for gate, next_group in next_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_blocked_field_counts_by_readiness_gate(blocked_field_groups):
    return {
        gate: next_group["field_count"] if next_group else 0
        for gate, next_group in next_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_blockers_by_readiness_gate(blocked_field_groups):
    return {
        gate: next_group["id"] if next_group else None
        for gate, next_group in next_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_blocker_networks_by_readiness_gate(blocked_field_groups):
    return {
        gate: next_group["network"] if next_group else None
        for gate, next_group in next_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_blocker_types_by_readiness_gate(blocked_field_groups):
    return {
        gate: next_group["blocker_type"] if next_group else None
        for gate, next_group in next_blocked_field_groups_by_readiness_gate(blocked_field_groups).items()
    }


def next_actions_by_network_and_blocker_type(actions):
    return {
        network: {
            blocker_type: blocker_actions[0] if blocker_actions else None
            for blocker_type, blocker_actions in actions_by_type.items()
        }
        for network, actions_by_type in actions_by_network_and_blocker_type(actions).items()
    }


def next_commands_by_network_and_blocker_type(actions):
    return {
        network: {
            blocker_type: action_command_fields(action)
            for blocker_type, action in actions_by_type.items()
        }
        for network, actions_by_type in next_actions_by_network_and_blocker_type(actions).items()
    }


def blockers_by_blocker_type(blockers):
    grouped = {blocker_type: [] for blocker_type in BLOCKER_TYPES}
    for blocker in blockers:
        blocker_parts = blocker.split(".", 1)
        blocker_type = blocker_parts[1] if len(blocker_parts) == 2 else None
        if blocker_type in grouped:
            grouped[blocker_type].append(blocker)
    return grouped


def blockers_by_network_and_blocker_type(blockers):
    grouped = {
        network: {blocker_type: [] for blocker_type in BLOCKER_TYPES}
        for network in NETWORKS
    }
    for blocker in blockers:
        blocker_parts = blocker.split(".", 1)
        if len(blocker_parts) != 2:
            continue
        network, blocker_type = blocker_parts
        if network in grouped and blocker_type in grouped[network]:
            grouped[network][blocker_type].append(blocker)
    return grouped


def blocker_counts_by_blocker_type(blockers):
    return {
        blocker_type: len(blocker_ids)
        for blocker_type, blocker_ids in blockers_by_blocker_type(blockers).items()
    }


def blocker_counts_by_network_and_blocker_type(blockers):
    return {
        network: {
            blocker_type: len(blocker_ids)
            for blocker_type, blocker_ids in blockers_by_type.items()
        }
        for network, blockers_by_type in blockers_by_network_and_blocker_type(blockers).items()
    }


def blocked_fields_by_blocker_type(blocked_field_groups):
    grouped = {blocker_type: [] for blocker_type in BLOCKER_TYPES}
    for group in blocked_field_groups:
        blocker_type = group.get("blocker_type")
        if blocker_type in grouped:
            grouped[blocker_type].extend(group.get("fields", []))
    return grouped


def blocked_fields_by_network_and_blocker_type(blocked_field_groups):
    grouped = {
        network: {blocker_type: [] for blocker_type in BLOCKER_TYPES}
        for network in NETWORKS
    }
    for group in blocked_field_groups:
        network = group.get("network")
        blocker_type = group.get("blocker_type")
        if network in grouped and blocker_type in grouped[network]:
            grouped[network][blocker_type].extend(group.get("fields", []))
    return grouped


def blocked_field_counts_by_blocker_type(blocked_field_groups):
    return {
        blocker_type: len(fields)
        for blocker_type, fields in blocked_fields_by_blocker_type(blocked_field_groups).items()
    }


def blocked_field_counts_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: len(fields)
            for blocker_type, fields in fields_by_type.items()
        }
        for network, fields_by_type in blocked_fields_by_network_and_blocker_type(blocked_field_groups).items()
    }


def blocked_field_groups_by_network(blocked_field_groups):
    grouped = {network: [] for network in NETWORKS}
    for group in blocked_field_groups:
        network = group.get("network")
        if network in grouped:
            grouped[network].append(group)
    return grouped


def blocked_field_group_counts_by_network(blocked_field_groups):
    return {
        network: len(groups)
        for network, groups in blocked_field_groups_by_network(blocked_field_groups).items()
    }


def blocked_field_groups_by_blocker(blocked_field_groups):
    return {
        group["id"]: group
        for group in blocked_field_groups
    }


def blocked_field_group_counts_by_blocker(blocked_field_groups):
    return {
        blocker: 1
        for blocker in blocked_field_groups_by_blocker(blocked_field_groups)
    }


def blocked_field_groups_by_blocker_type(blocked_field_groups):
    grouped = {blocker_type: [] for blocker_type in BLOCKER_TYPES}
    for group in blocked_field_groups:
        blocker_type = group.get("blocker_type")
        if blocker_type in grouped:
            grouped[blocker_type].append(group)
    return grouped


def blocked_field_group_counts_by_blocker_type(blocked_field_groups):
    return {
        blocker_type: len(groups)
        for blocker_type, groups in blocked_field_groups_by_blocker_type(blocked_field_groups).items()
    }


def next_blocked_field_groups_by_blocker_type(blocked_field_groups):
    return {
        blocker_type: groups[0] if groups else None
        for blocker_type, groups in blocked_field_groups_by_blocker_type(blocked_field_groups).items()
    }


def blocked_field_groups_by_network_and_blocker_type(blocked_field_groups):
    grouped = {
        network: {blocker_type: [] for blocker_type in BLOCKER_TYPES}
        for network in NETWORKS
    }
    for group in blocked_field_groups:
        network = group.get("network")
        blocker_type = group.get("blocker_type")
        if network in grouped and blocker_type in grouped[network]:
            grouped[network][blocker_type].append(group)
    return grouped


def blocked_field_group_counts_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: len(groups)
            for blocker_type, groups in groups_by_type.items()
        }
        for network, groups_by_type in blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def blocked_blocker_types_by_network(blocked_field_groups):
    return {
        network: [
            blocker_type
            for blocker_type, groups in groups_by_type.items()
            if groups
        ]
        for network, groups_by_type in blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def ready_blocker_types_by_network(blocked_field_groups):
    return {
        network: [
            blocker_type
            for blocker_type, groups in groups_by_type.items()
            if not groups
        ]
        for network, groups_by_type in blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def blocked_networks_by_blocker_type(blocked_field_groups):
    grouped = blocked_field_groups_by_network_and_blocker_type(blocked_field_groups)
    return {
        blocker_type: [
            network
            for network in NETWORKS
            if grouped[network][blocker_type]
        ]
        for blocker_type in BLOCKER_TYPES
    }


def ready_networks_by_blocker_type(blocked_field_groups):
    grouped = blocked_field_groups_by_network_and_blocker_type(blocked_field_groups)
    return {
        blocker_type: [
            network
            for network in NETWORKS
            if not grouped[network][blocker_type]
        ]
        for blocker_type in BLOCKER_TYPES
    }


def blocked_blocker_type_counts_by_network(blocked_field_groups):
    return {
        network: len(blocker_types)
        for network, blocker_types in blocked_blocker_types_by_network(blocked_field_groups).items()
    }


def ready_blocker_type_counts_by_network(blocked_field_groups):
    return {
        network: len(blocker_types)
        for network, blocker_types in ready_blocker_types_by_network(blocked_field_groups).items()
    }


def blocked_network_counts_by_blocker_type(blocked_field_groups):
    return {
        blocker_type: len(networks)
        for blocker_type, networks in blocked_networks_by_blocker_type(blocked_field_groups).items()
    }


def ready_network_counts_by_blocker_type(blocked_field_groups):
    return {
        blocker_type: len(networks)
        for blocker_type, networks in ready_networks_by_blocker_type(blocked_field_groups).items()
    }


def next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: groups[0] if groups else None
            for blocker_type, groups in groups_by_type.items()
        }
        for network, groups_by_type in blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def next_blocked_fields_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: next_group["fields"] if next_group else []
            for blocker_type, next_group in groups_by_type.items()
        }
        for network, groups_by_type in next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def next_blocked_field_counts_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: next_group["field_count"] if next_group else 0
            for blocker_type, next_group in groups_by_type.items()
        }
        for network, groups_by_type in next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def next_blockers_by_network_and_blocker_type(blocked_field_groups):
    return {
        network: {
            blocker_type: next_group["id"] if next_group else None
            for blocker_type, next_group in groups_by_type.items()
        }
        for network, groups_by_type in next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups).items()
    }


def network_progress_entries(blockers, blocked_fields, blocked_field_groups):
    blockers_by_network = items_by_network(blockers)
    blocked_fields_by_network = items_by_network(blocked_fields)
    groups_by_network = {network: [] for network in NETWORKS}
    for group in blocked_field_groups:
        groups_by_network[group["network"]].append(group)
    return {
        network: {
            "ready_for_launch_profile": (
                len(blockers_by_network[network]) == 0
                and len(blocked_fields_by_network[network]) == 0
            ),
            "unresolved_blocker_count": len(blockers_by_network[network]),
            "unresolved_blockers": blockers_by_network[network],
            "blocked_field_count": len(blocked_fields_by_network[network]),
            "blocked_fields": blocked_fields_by_network[network],
            "next_blocked_field_group": (
                groups_by_network[network][0] if groups_by_network[network] else None
            ),
        }
        for network in NETWORKS
    }


def blocker_type_progress_entries(actions, blockers, blocked_field_groups):
    blockers_by_type = blockers_by_blocker_type(blockers)
    fields_by_type = blocked_fields_by_blocker_type(blocked_field_groups)
    next_actions_by_type = next_actions_by_blocker_type(actions)
    return {
        blocker_type: {
            "ready_for_launch_profile": (
                len(blockers_by_type[blocker_type]) == 0
                and len(fields_by_type[blocker_type]) == 0
            ),
            "unresolved_blocker_count": len(blockers_by_type[blocker_type]),
            "unresolved_blockers": blockers_by_type[blocker_type],
            "blocked_field_count": len(fields_by_type[blocker_type]),
            "blocked_fields": fields_by_type[blocker_type],
            "next_action": next_actions_by_type[blocker_type],
        }
        for blocker_type in BLOCKER_TYPES
    }


def readiness_gate_progress_entries(actions, blockers, blocked_field_groups):
    blocker_types_by_gate = blocker_types_by_readiness_gate()
    blockers_by_gate = blockers_by_readiness_gate(blockers)
    groups_by_gate = blocked_field_groups_by_readiness_gate(blocked_field_groups)
    fields_by_gate = blocked_fields_by_readiness_gate(blocked_field_groups)
    next_actions_by_gate = next_actions_by_readiness_gate(actions)
    return {
        gate: {
            "ready_for_launch_profile": (
                len(blockers_by_gate[gate]) == 0
                and len(fields_by_gate[gate]) == 0
            ),
            "blocker_type_count": len(blocker_types_by_gate[gate]),
            "blocker_types": blocker_types_by_gate[gate],
            "unresolved_blocker_count": len(blockers_by_gate[gate]),
            "unresolved_blockers": blockers_by_gate[gate],
            "blocked_field_group_count": len(groups_by_gate[gate]),
            "blocked_field_groups": groups_by_gate[gate],
            "blocked_field_count": len(fields_by_gate[gate]),
            "blocked_fields": fields_by_gate[gate],
            "next_action": next_actions_by_gate[gate],
            "next_blocked_field_group": (
                groups_by_gate[gate][0] if groups_by_gate[gate] else None
            ),
        }
        for gate in READINESS_GATES
    }


def blocked_networks(network_progress):
    return [
        network
        for network in NETWORKS
        if not network_progress[network]["ready_for_launch_profile"]
    ]


def ready_networks(network_progress):
    return [
        network
        for network in NETWORKS
        if network_progress[network]["ready_for_launch_profile"]
    ]


def blocked_blocker_types(blocker_type_progress):
    return [
        blocker_type
        for blocker_type in BLOCKER_TYPES
        if not blocker_type_progress[blocker_type]["ready_for_launch_profile"]
    ]


def ready_blocker_types(blocker_type_progress):
    return [
        blocker_type
        for blocker_type in BLOCKER_TYPES
        if blocker_type_progress[blocker_type]["ready_for_launch_profile"]
    ]


COMMAND_FIELDS = (
    "template_command",
    "check_command",
    "preflight_command",
    "apply_command",
    "snapshot_audit_handoff_command",
    "readiness_summary_command",
    "network_readiness_summary_command",
    "blocker_type_readiness_summary_command",
    "readiness_gate_summary_command",
    "blocker_readiness_summary_command",
    "command",
)


def action_command_fields(action):
    if action is None:
        return None
    return {
        command_field: action.get(command_field)
        for command_field in COMMAND_FIELDS
    }


def action_command_keys(action):
    command_fields = action_command_fields(action)
    if command_fields is None:
        return []
    return [
        command_field
        for command_field, command in command_fields.items()
        if command is not None
    ]


def action_command_values(action):
    command_fields = action_command_fields(action)
    if command_fields is None:
        return []
    return [
        command
        for command in command_fields.values()
        if command is not None
    ]


def action_command_pairs(action):
    command_fields = action_command_fields(action)
    if command_fields is None:
        return []
    return [
        {"key": command_field, "value": command}
        for command_field, command in command_fields.items()
        if command is not None
    ]


def next_actions_by_blocker_type(actions):
    grouped = actions_by_blocker_type(actions)
    return {
        blocker_type: blocker_actions[0] if blocker_actions else None
        for blocker_type, blocker_actions in grouped.items()
    }


def next_commands_by_blocker_type(actions):
    return {
        blocker_type: action_command_fields(action)
        for blocker_type, action in next_actions_by_blocker_type(actions).items()
    }


def network_next_command_fields(network_progress):
    return {
        network: action_command_fields(
            network_progress[network]["next_blocked_field_group"]
        )
        for network in NETWORKS
    }


def network_next_blocked_field_groups(network_progress):
    return {
        network: network_progress[network]["next_blocked_field_group"]
        for network in NETWORKS
    }


def network_next_blocked_fields(network_progress):
    return {
        network: (
            network_progress[network]["next_blocked_field_group"]["fields"]
            if network_progress[network]["next_blocked_field_group"]
            else []
        )
        for network in NETWORKS
    }


def network_next_blocked_field_counts(network_progress):
    return {
        network: (
            network_progress[network]["next_blocked_field_group"]["field_count"]
            if network_progress[network]["next_blocked_field_group"]
            else 0
        )
        for network in NETWORKS
    }


def network_next_blockers(network_progress):
    return {
        network: (
            network_progress[network]["next_blocked_field_group"]["id"]
            if network_progress[network]["next_blocked_field_group"]
            else None
        )
        for network in NETWORKS
    }


def network_next_blocker_types(network_progress):
    return {
        network: (
            network_progress[network]["next_blocked_field_group"]["blocker_type"]
            if network_progress[network]["next_blocked_field_group"]
            else None
        )
        for network in NETWORKS
    }


def blocker_type_next_blocked_fields(blocker_type_progress):
    return {
        blocker_type: (
            blocker_type_progress[blocker_type]["next_action"]["fields"]
            if blocker_type_progress[blocker_type]["next_action"]
            else []
        )
        for blocker_type in BLOCKER_TYPES
    }


def blocker_type_next_blocked_field_counts(blocker_type_progress):
    return {
        blocker_type: (
            blocker_type_progress[blocker_type]["next_action"]["field_count"]
            if blocker_type_progress[blocker_type]["next_action"]
            else 0
        )
        for blocker_type in BLOCKER_TYPES
    }


def blocker_type_next_blockers(blocker_type_progress):
    return {
        blocker_type: (
            blocker_type_progress[blocker_type]["next_action"]["id"]
            if blocker_type_progress[blocker_type]["next_action"]
            else None
        )
        for blocker_type in BLOCKER_TYPES
    }


def blocker_type_next_blocker_networks(blocker_type_progress):
    return {
        blocker_type: (
            blocker_type_progress[blocker_type]["next_action"]["network"]
            if blocker_type_progress[blocker_type]["next_action"]
            else None
        )
        for blocker_type in BLOCKER_TYPES
    }


def list_summary(items):
    return ", ".join(items) if items else "none"


def network_count_summary(counts):
    return ", ".join(f"{network}={counts[network]}" for network in NETWORKS)


def blocker_type_count_summary(counts):
    return ", ".join(
        f"{blocker_type}={counts[blocker_type]}"
        for blocker_type in BLOCKER_TYPES
    )


def readiness_gate_count_summary(counts):
    return ", ".join(f"{gate}={counts[gate]}" for gate in READINESS_GATES)


def blocker_type_list_summary(items_by_blocker_type):
    return "; ".join(
        f"{blocker_type}={list_summary(items_by_blocker_type[blocker_type])}"
        for blocker_type in BLOCKER_TYPES
    )


def readiness_gate_list_summary(items_by_gate):
    return "; ".join(
        f"{gate}={list_summary(items_by_gate[gate])}"
        for gate in READINESS_GATES
    )


def readiness_gate_value_summary(values_by_gate):
    return ", ".join(
        f"{gate}={values_by_gate[gate] or 'none'}"
        for gate in READINESS_GATES
    )


def readiness_gate_blocker_command_summary(manifest_path, blockers_by_gate):
    return "; ".join(
        f"{gate}={blocker_readiness_summary_command_summary(manifest_path, blockers_by_gate[gate])}"
        for gate in READINESS_GATES
    )


def network_blocker_type_count_summary(counts):
    return "; ".join(
        f"{network}: "
        + ", ".join(
            f"{blocker_type}={counts[network][blocker_type]}"
            for blocker_type in BLOCKER_TYPES
        )
        for network in NETWORKS
    )


def network_blocker_type_value_summary(values):
    return "; ".join(
        f"{network}: "
        + ", ".join(
            f"{blocker_type}={values[network][blocker_type] or 'none'}"
            for blocker_type in BLOCKER_TYPES
        )
        for network in NETWORKS
    )


def network_next_blocker_summary(network_progress):
    entries = []
    for network in NETWORKS:
        next_group = network_progress[network]["next_blocked_field_group"]
        next_blocker = next_group["id"] if next_group else "none"
        entries.append(f"{network}={next_blocker}")
    return ", ".join(entries)


def network_next_blocker_field_count_summary(network_progress):
    entries = []
    for network in NETWORKS:
        next_group = network_progress[network]["next_blocked_field_group"]
        field_count = next_group["field_count"] if next_group else 0
        entries.append(f"{network}={field_count}")
    return ", ".join(entries)


def network_next_blocker_command_summary(network_progress, command_key):
    entries = []
    for network in NETWORKS:
        next_group = network_progress[network]["next_blocked_field_group"]
        command = next_group.get(command_key) if next_group else None
        entries.append(f"{network}={command or 'none'}")
    return "; ".join(entries)


def blocker_type_next_blocker_summary(blocker_type_progress):
    entries = []
    for blocker_type in BLOCKER_TYPES:
        next_action = blocker_type_progress[blocker_type]["next_action"]
        next_blocker = next_action["id"] if next_action else "none"
        entries.append(f"{blocker_type}={next_blocker}")
    return ", ".join(entries)


def blocker_type_next_blocker_network_summary(blocker_type_progress):
    entries = []
    for blocker_type in BLOCKER_TYPES:
        next_action = blocker_type_progress[blocker_type]["next_action"]
        network = next_action["network"] if next_action else "none"
        entries.append(f"{blocker_type}={network}")
    return ", ".join(entries)


def blocker_type_next_blocker_field_count_summary(blocker_type_progress):
    entries = []
    for blocker_type in BLOCKER_TYPES:
        next_action = blocker_type_progress[blocker_type]["next_action"]
        field_count = next_action["field_count"] if next_action else 0
        entries.append(f"{blocker_type}={field_count}")
    return ", ".join(entries)


def blocker_type_next_action_command_summary(blocker_type_progress, command_key):
    entries = []
    for blocker_type in BLOCKER_TYPES:
        next_action = blocker_type_progress[blocker_type]["next_action"]
        command = next_action.get(command_key) if next_action else None
        entries.append(f"{blocker_type}={command or 'none'}")
    return "; ".join(entries)


def readiness_gate_next_action_command_summary(readiness_gate_progress, command_key):
    entries = []
    for gate in READINESS_GATES:
        next_action = readiness_gate_progress[gate]["next_action"]
        command = next_action.get(command_key) if next_action else None
        entries.append(f"{gate}={command or 'none'}")
    return "; ".join(entries)


def yes_no(value):
    return "yes" if value else "no"


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
            self.error(path, "must be an absolute non-placeholder path, normalized without control characters")

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
    if any(marker in seed for marker in LITECOIN_DNS_SEED_MARKERS):
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
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or value in ("", "TODO", "TBD", "CHANGE_ME")
        or value.startswith("<")
        or "\0" in value
        or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value)
    ):
        return False
    return value != "/" and not value.startswith("//") and os.path.normpath(value) == value


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
    blocker_ids_in_order = []
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
        blocker_ids_in_order.append(blocker_id)
        check.require_string(blocker.get("description"), f"blockers[{index}].description")
    expected_blockers = unresolved_blocker_ids(manifest)
    missing_blockers = sorted(expected_blockers - blocker_ids)
    if status == "blocked" and missing_blockers:
        check.error("blockers", "missing required blocker ids: " + ", ".join(missing_blockers))
    stale_blockers = sorted(blocker_ids - expected_blockers)
    if status == "blocked" and stale_blockers:
        check.error("blockers", "contains resolved or unknown blocker ids: " + ", ".join(stale_blockers))
    expected_blocker_order = [blocker for blocker in BLOCKER_ORDER if blocker in expected_blockers]
    if (
        status == "blocked"
        and not missing_blockers
        and not stale_blockers
        and len(blocker_ids_in_order) == len(blocker_ids)
        and blocker_ids_in_order != expected_blocker_order
    ):
        check.error(
            "blockers",
            "must match unresolved blocker order: " + ", ".join(expected_blocker_order),
        )
    if status == "ready-for-chainparams" and expected_blockers:
        check.error(
            "status",
            "must be blocked until required blocker ids are resolved: "
            + ", ".join(expected_blocker_order),
        )
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
            f"snapshot audit {field} must be an absolute non-placeholder path, normalized without control characters"
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


def snapshot_audit_template_json_payload(network, manifest_path):
    template = snapshot_audit_template(network)
    blocker_id = f"{network}.litecoin_snapshot"
    constraints = blocker_candidate_constraints("litecoin_snapshot")
    external_artifacts = blocker_external_artifacts("litecoin_snapshot")
    operator_fields = [
        field
        for field in SNAPSHOT_AUDIT_SUMMARY_FIELDS
        if template[field] is None
    ]
    prefilled_fields = {
        field: value
        for field, value in template.items()
        if value is not None
    }
    commands = blocker_action_commands(
        blocker_id,
        shell_quote(display_path(manifest_path)),
    )
    return {
        "schema_version": 1,
        "network": network,
        "blocker": blocker_id,
        "readiness_gate": blocker_type_readiness_gate("litecoin_snapshot"),
        "source_chain": SNAPSHOT_SOURCE_CHAINS[network],
        "source_chain_by_network": dict(SNAPSHOT_SOURCE_CHAINS),
        "template": template,
        "fields": list(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
        "field_count": len(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
        "operator_fields": operator_fields,
        "operator_field_count": len(operator_fields),
        "prefilled_fields": prefilled_fields,
        "prefilled_field_count": len(prefilled_fields),
        "requirements": {
            "must_be_utf8_json_object": True,
            "field_order_must_match_template": True,
            "rejects_duplicate_fields": True,
            "max_bytes": SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES,
        },
        "snapshot_artifact_requirements": {
            "must_be_absolute_normalized_regular_file": True,
            "must_not_be_symlink": True,
            "must_remain_stable_during_verification": True,
            "size_and_sha256_must_match_audit": True,
        },
        "candidate_constraints": constraints,
        "candidate_constraint_count": len(constraints),
        "external_artifacts": external_artifacts,
        "external_artifact_count": len(external_artifacts),
        "commands": {
            **commands,
            "network_handoff_bundle_command": network_handoff_bundle_command(
                manifest_path,
                network,
            ),
        },
    }


def snapshot_audit_template_json_text(network, manifest_path):
    return json.dumps(
        snapshot_audit_template_json_payload(network, manifest_path),
        indent=2,
        sort_keys=False,
    )


def read_snapshot_audit_summary_text_from_path(audit_path):
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
        return audit_summary_text
    finally:
        os.close(fd)


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


def value_selection_candidate_too_large_error(candidate_path):
    return (
        "value-selection candidate must not exceed "
        f"{VALUE_SELECTION_CANDIDATE_MAX_BYTES} bytes: {candidate_path}"
    )


def read_value_selection_candidate_bytes(candidate_path):
    fd, candidate_stat = open_regular_file_no_symlink(
        candidate_path,
        symlink_error="value-selection candidate path must not be a symlink",
        missing_error="cannot read value-selection candidate",
        not_regular_error="value-selection candidate path must be a regular file",
        open_error="cannot read value-selection candidate",
        parent_symlink_error=(
            "value-selection candidate parent directory must not be a symlink"
        ),
    )
    if candidate_stat.st_size > VALUE_SELECTION_CANDIDATE_MAX_BYTES:
        os.close(fd)
        raise ValueError(value_selection_candidate_too_large_error(candidate_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= VALUE_SELECTION_CANDIDATE_MAX_BYTES:
            chunk = os.read(
                fd,
                min(65536, VALUE_SELECTION_CANDIDATE_MAX_BYTES + 1 - total_bytes),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > VALUE_SELECTION_CANDIDATE_MAX_BYTES:
            raise ValueError(value_selection_candidate_too_large_error(candidate_path))
        require_regular_file_stable(
            candidate_path,
            candidate_stat,
            fd,
            "value-selection candidate changed during read",
            parent_symlink_error=(
                "value-selection candidate parent directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(f"cannot read value-selection candidate: {exc}") from None
    finally:
        os.close(fd)

    return b"".join(chunks)


def value_selection_candidate_artifact_metadata(candidate_path, candidate_bytes):
    return {
        "path": display_path(candidate_path),
        "size": len(candidate_bytes),
        "sha256": hashlib.sha256(candidate_bytes).hexdigest(),
        "max_bytes": VALUE_SELECTION_CANDIDATE_MAX_BYTES,
        "must_be_utf8_json_object": True,
        "rejects_duplicate_fields": True,
        "must_remain_stable_during_verification": True,
    }


def read_value_selection_candidate_text(candidate_path):
    candidate_bytes = read_value_selection_candidate_bytes(candidate_path)
    try:
        return candidate_bytes.decode("utf8")
    except UnicodeDecodeError:
        raise ValueError("value-selection candidate is not valid UTF-8") from None


def read_value_selection_candidate_json_with_metadata(candidate_path):
    candidate_bytes = read_value_selection_candidate_bytes(candidate_path)
    metadata = value_selection_candidate_artifact_metadata(
        candidate_path,
        candidate_bytes,
    )
    try:
        candidate_text = candidate_bytes.decode("utf8")
    except UnicodeDecodeError:
        raise ValueError("value-selection candidate is not valid UTF-8") from None
    try:
        candidate = json.loads(
            candidate_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"value-selection candidate contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"value-selection candidate is not valid JSON: {exc}"
        ) from None
    if not isinstance(candidate, dict):
        raise ValueError("value-selection candidate must be a JSON object")
    return candidate, metadata


def read_value_selection_candidate_json(candidate_path):
    candidate, _ = read_value_selection_candidate_json_with_metadata(candidate_path)
    return candidate


def release_evidence_bundle_too_large_error(bundle_path):
    return (
        "release evidence bundle must not exceed "
        f"{RELEASE_EVIDENCE_BUNDLE_MAX_BYTES} bytes: {bundle_path}"
    )


def read_release_evidence_bundle_text(bundle_path):
    fd, bundle_stat = open_regular_file_no_symlink(
        bundle_path,
        symlink_error="release evidence bundle path must not be a symlink",
        missing_error="cannot read release evidence bundle",
        not_regular_error="release evidence bundle path must be a regular file",
        open_error="cannot read release evidence bundle",
        parent_symlink_error=(
            "release evidence bundle parent directory must not be a symlink"
        ),
    )
    if bundle_stat.st_size > RELEASE_EVIDENCE_BUNDLE_MAX_BYTES:
        os.close(fd)
        raise ValueError(release_evidence_bundle_too_large_error(bundle_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= RELEASE_EVIDENCE_BUNDLE_MAX_BYTES:
            chunk = os.read(
                fd,
                min(65536, RELEASE_EVIDENCE_BUNDLE_MAX_BYTES + 1 - total_bytes),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > RELEASE_EVIDENCE_BUNDLE_MAX_BYTES:
            raise ValueError(release_evidence_bundle_too_large_error(bundle_path))
        require_regular_file_stable(
            bundle_path,
            bundle_stat,
            fd,
            "release evidence bundle changed during read",
            parent_symlink_error=(
                "release evidence bundle parent directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(f"cannot read release evidence bundle: {exc}") from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{bundle_path} is not valid UTF-8") from None


def release_evidence_archive_record_too_large_error(record_path):
    return (
        "release evidence archive record must not exceed "
        f"{RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES} bytes: {record_path}"
    )


def read_release_evidence_archive_record_text(record_path):
    fd, record_stat = open_regular_file_no_symlink(
        record_path,
        symlink_error="release evidence archive record path must not be a symlink",
        missing_error="cannot read release evidence archive record",
        not_regular_error=(
            "release evidence archive record path must be a regular file"
        ),
        open_error="cannot read release evidence archive record",
        parent_symlink_error=(
            "release evidence archive record parent directory must not be a symlink"
        ),
    )
    if record_stat.st_size > RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES:
        os.close(fd)
        raise ValueError(release_evidence_archive_record_too_large_error(record_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES:
            chunk = os.read(
                fd,
                min(
                    65536,
                    RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES + 1 - total_bytes,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > RELEASE_EVIDENCE_ARCHIVE_RECORD_MAX_BYTES:
            raise ValueError(release_evidence_archive_record_too_large_error(record_path))
        require_regular_file_stable(
            record_path,
            record_stat,
            fd,
            "release evidence archive record changed during read",
            parent_symlink_error=(
                "release evidence archive record parent directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(
            f"cannot read release evidence archive record: {exc}"
        ) from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{record_path} is not valid UTF-8") from None


def release_evidence_publication_index_archive_record_too_large_error(record_path):
    return (
        "release evidence publication index archive record must not exceed "
        f"{RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES} "
        f"bytes: {record_path}"
    )


def read_release_evidence_publication_index_archive_record_text(record_path):
    fd, record_stat = open_regular_file_no_symlink(
        record_path,
        symlink_error=(
            "release evidence publication index archive record path must not be "
            "a symlink"
        ),
        missing_error=(
            "cannot read release evidence publication index archive record"
        ),
        not_regular_error=(
            "release evidence publication index archive record path must be a "
            "regular file"
        ),
        open_error="cannot read release evidence publication index archive record",
        parent_symlink_error=(
            "release evidence publication index archive record parent directory "
            "must not be a symlink"
        ),
    )
    if (
        record_stat.st_size
        > RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES
    ):
        os.close(fd)
        raise ValueError(
            release_evidence_publication_index_archive_record_too_large_error(
                record_path
            )
        )

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES:
            chunk = os.read(
                fd,
                min(
                    65536,
                    RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES
                    + 1
                    - total_bytes,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if (
            total_bytes
            > RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_MAX_BYTES
        ):
            raise ValueError(
                release_evidence_publication_index_archive_record_too_large_error(
                    record_path
                )
            )
        require_regular_file_stable(
            record_path,
            record_stat,
            fd,
            "release evidence publication index archive record changed during read",
            parent_symlink_error=(
                "release evidence publication index archive record parent "
                "directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(
            "cannot read release evidence publication index archive record: "
            f"{exc}"
        ) from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{record_path} is not valid UTF-8") from None


def release_evidence_publication_closeout_archive_record_too_large_error(
    record_path,
):
    return (
        "release evidence publication closeout archive record must not exceed "
        f"{RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES} "
        f"bytes: {record_path}"
    )


def read_release_evidence_publication_closeout_archive_record_text(
    record_path,
):
    fd, record_stat = open_regular_file_no_symlink(
        record_path,
        symlink_error=(
            "release evidence publication closeout archive record path must not "
            "be a symlink"
        ),
        missing_error=(
            "cannot read release evidence publication closeout archive record"
        ),
        not_regular_error=(
            "release evidence publication closeout archive record path must be "
            "a regular file"
        ),
        open_error=(
            "cannot read release evidence publication closeout archive record"
        ),
        parent_symlink_error=(
            "release evidence publication closeout archive record parent "
            "directory must not be a symlink"
        ),
    )
    if (
        record_stat.st_size
        > RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES
    ):
        os.close(fd)
        raise ValueError(
            release_evidence_publication_closeout_archive_record_too_large_error(
                record_path
            )
        )

    chunks = []
    total_bytes = 0
    try:
        while (
            total_bytes
            <= RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES
        ):
            chunk = os.read(
                fd,
                min(
                    65536,
                    RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES
                    + 1
                    - total_bytes,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if (
            total_bytes
            > RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_MAX_BYTES
        ):
            raise ValueError(
                release_evidence_publication_closeout_archive_record_too_large_error(
                    record_path
                )
            )
        require_regular_file_stable(
            record_path,
            record_stat,
            fd,
            (
                "release evidence publication closeout archive record changed "
                "during read"
            ),
            parent_symlink_error=(
                "release evidence publication closeout archive record parent "
                "directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(
            "cannot read release evidence publication closeout archive record: "
            f"{exc}"
        ) from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{record_path} is not valid UTF-8") from None


def release_evidence_publication_index_too_large_error(index_path):
    return (
        "release evidence publication index must not exceed "
        f"{RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES} bytes: {index_path}"
    )


def read_release_evidence_publication_index_text(index_path):
    fd, index_stat = open_regular_file_no_symlink(
        index_path,
        symlink_error="release evidence publication index path must not be a symlink",
        missing_error="cannot read release evidence publication index",
        not_regular_error=(
            "release evidence publication index path must be a regular file"
        ),
        open_error="cannot read release evidence publication index",
        parent_symlink_error=(
            "release evidence publication index parent directory must not be a symlink"
        ),
    )
    if index_stat.st_size > RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES:
        os.close(fd)
        raise ValueError(release_evidence_publication_index_too_large_error(index_path))

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES:
            chunk = os.read(
                fd,
                min(
                    65536,
                    RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES + 1 - total_bytes,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > RELEASE_EVIDENCE_PUBLICATION_INDEX_MAX_BYTES:
            raise ValueError(
                release_evidence_publication_index_too_large_error(index_path)
            )
        require_regular_file_stable(
            index_path,
            index_stat,
            fd,
            "release evidence publication index changed during read",
            parent_symlink_error=(
                "release evidence publication index parent directory must not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(
            f"cannot read release evidence publication index: {exc}"
        ) from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{index_path} is not valid UTF-8") from None


def release_evidence_publication_closeout_too_large_error(closeout_path):
    return (
        "release evidence publication closeout must not exceed "
        f"{RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES} bytes: "
        f"{closeout_path}"
    )


def read_release_evidence_publication_closeout_text(closeout_path):
    fd, closeout_stat = open_regular_file_no_symlink(
        closeout_path,
        symlink_error=(
            "release evidence publication closeout path must not be a symlink"
        ),
        missing_error="cannot read release evidence publication closeout",
        not_regular_error=(
            "release evidence publication closeout path must be a regular file"
        ),
        open_error="cannot read release evidence publication closeout",
        parent_symlink_error=(
            "release evidence publication closeout parent directory must not "
            "be a symlink"
        ),
    )
    if closeout_stat.st_size > RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES:
        os.close(fd)
        raise ValueError(
            release_evidence_publication_closeout_too_large_error(closeout_path)
        )

    chunks = []
    total_bytes = 0
    try:
        while total_bytes <= RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES:
            chunk = os.read(
                fd,
                min(
                    65536,
                    RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES
                    + 1
                    - total_bytes,
                ),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total_bytes += len(chunk)
        if total_bytes > RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_MAX_BYTES:
            raise ValueError(
                release_evidence_publication_closeout_too_large_error(
                    closeout_path
                )
            )
        require_regular_file_stable(
            closeout_path,
            closeout_stat,
            fd,
            "release evidence publication closeout changed during read",
            parent_symlink_error=(
                "release evidence publication closeout parent directory must "
                "not be a symlink"
            ),
        )
    except OSError as exc:
        raise ValueError(
            f"cannot read release evidence publication closeout: {exc}"
        ) from None
    finally:
        os.close(fd)

    try:
        return b"".join(chunks).decode("utf8")
    except UnicodeDecodeError:
        raise ValueError(f"{closeout_path} is not valid UTF-8") from None


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


def candidate_next_step_text(candidate, applied_label, manifest_path, network, blocker_type):
    next_action = next_action_command(manifest_path)
    readiness_command = readiness_summary_command(manifest_path)
    network_readiness_command = network_readiness_summary_command(manifest_path, network)
    blocker_type_readiness_command = blocker_type_readiness_summary_command(manifest_path, blocker_type)
    manifest_path_arg = shell_quote(display_path(manifest_path))
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = validate_manifest(candidate, allow_blocked=True).blockers
    lines = [
        f"  remaining blockers after applying {applied_label}: {len(blockers)}",
        f"  remaining blockers on {network} after applying {applied_label}: "
        f"{item_counts_by_network(blockers)[network]}",
        f"  remaining blocked fields after applying {applied_label}: {len(blocked_fields)}",
        f"  remaining blocked fields on {network} after applying {applied_label}: "
        f"{item_counts_by_network(blocked_fields)[network]}",
        f"  next action command after applying {applied_label}: {next_action}",
        f"  readiness summary command after applying {applied_label}: {readiness_command}",
        f"  network readiness summary command after applying {applied_label}: {network_readiness_command}",
        f"  blocker type readiness summary command after applying {applied_label}: {blocker_type_readiness_command}",
    ]
    if blockers:
        next_blocker = blockers[0]
        commands = blocker_action_commands(next_blocker, manifest_path_arg)
        lines.append(f"  next blocker after applying {applied_label}: {next_blocker}")
        if commands["template_command"] is not None:
            lines.append(
                f"  next template command after applying {applied_label}: "
                f"{commands['template_command']}"
            )
        lines.append(
            f"  next check command after applying {applied_label}: "
            f"{commands['check_command']}"
        )
        lines.append(
            f"  next apply command after applying {applied_label}: "
            f"{commands['apply_command']}"
        )
        lines.append(
            f"  next network readiness summary command after applying {applied_label}: "
            f"{commands['network_readiness_summary_command']}"
        )
        lines.append(
            f"  next blocker type readiness summary command after applying {applied_label}: "
            f"{commands['blocker_type_readiness_summary_command']}"
        )
        lines.append(
            f"  next blocker readiness summary command after applying {applied_label}: "
            f"{blocker_readiness_summary_command(manifest_path, next_blocker)}"
        )
        return "\n".join(lines)
    if candidate.get("status") == "blocked":
        lines.append(
            f"  next step after applying {applied_label}: "
            "mark the complete manifest ready for chainparams"
        )
        lines.append(
            f"  next command after applying {applied_label}: "
            f"{tool_path} --mark-ready --in-place {manifest_path_arg}"
        )
        return "\n".join(lines)
    lines.append(f"  next step after applying {applied_label}: emit and check chainparams")
    lines.append(
        f"  next emit command after applying {applied_label}: "
        f"{tool_path} --emit-chainparams {manifest_path_arg}"
    )
    lines.append(
        f"  next check command after applying {applied_label}: "
        f"{tool_path} --check-chainparams src/chainparams.cpp {manifest_path_arg}"
    )
    return "\n".join(lines)


def snapshot_audit_apply_command(network, audit_path, manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    audit_path = shell_quote(display_path(audit_path))
    manifest_path = shell_quote(display_path(manifest_path))
    return (
        f"{tool_path} --set-snapshot-audit {network} "
        f"{audit_path} --in-place {manifest_path}"
    )


def snapshot_audit_check_command(network, audit_path, manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    audit_path = shell_quote(display_path(audit_path))
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --check-snapshot-audit {network} {audit_path} {manifest_path}"


def snapshot_audit_preflight_command(network, audit_path, manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    audit_path = shell_quote(display_path(audit_path))
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --snapshot-audit-preflight {network} {audit_path} {manifest_path}"


def snapshot_audit_template_command(network, manifest_path, *, json_output=False):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    json_arg = "--json " if json_output else ""
    return f"{tool_path} {json_arg}--snapshot-audit-template {network} {manifest_path}"


def snapshot_audit_template_diff_command(network, audit_path, manifest_path, *, json_output=False):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    audit_path = shell_quote(display_path(audit_path))
    manifest_path = shell_quote(display_path(manifest_path))
    json_arg = "--json " if json_output else ""
    return (
        f"{tool_path} {json_arg}--snapshot-audit-template-diff {network} "
        f"{audit_path} {manifest_path}"
    )


def snapshot_audit_template_diff_payload(network, audit_path, manifest_path):
    template = snapshot_audit_template(network)
    template_fields = list(SNAPSHOT_AUDIT_SUMMARY_FIELDS)
    expected_source_chain = SNAPSHOT_SOURCE_CHAINS[network]
    blocker_id = f"{network}.litecoin_snapshot"
    audit_summary_text = read_snapshot_audit_summary_text_from_path(audit_path)

    audit = None
    parse_error = None
    duplicate_field = None
    try:
        audit = json.loads(
            audit_summary_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        duplicate_field = str(exc)
        parse_error = f"snapshot audit summary contains duplicate field: {exc}"
    except json.JSONDecodeError as exc:
        parse_error = f"snapshot audit summary is not valid JSON: {exc}"

    json_parse_ok = parse_error is None
    json_object_ok = isinstance(audit, dict)
    audit_fields = list(audit) if json_object_ok else []
    known_fields = [field for field in audit_fields if field in SNAPSHOT_AUDIT_SUMMARY_FIELDS]
    present_template_fields = [
        field for field in template_fields
        if json_object_ok and field in audit
    ]
    missing_fields = [
        field for field in template_fields
        if json_object_ok and field not in audit
    ]
    unexpected_fields = [
        field for field in audit_fields
        if field not in SNAPSHOT_AUDIT_SUMMARY_FIELDS
    ]
    source_chain = audit.get("source_chain") if json_object_ok else None
    source_chain_matches_network = source_chain == expected_source_chain
    field_set_matches_template = (
        json_object_ok
        and not missing_fields
        and not unexpected_fields
    )
    known_field_order_matches_template = (
        json_object_ok
        and known_fields == present_template_fields
    )
    field_order_matches_template = (
        json_object_ok
        and audit_fields == template_fields
    )
    ready_for_full_audit_check = (
        json_parse_ok
        and json_object_ok
        and field_set_matches_template
        and field_order_matches_template
        and source_chain_matches_network
    )

    issues = []
    if parse_error is not None:
        issues.append({
            "kind": "json_parse",
            "message": parse_error,
        })
    elif not json_object_ok:
        issues.append({
            "kind": "json_object",
            "message": "snapshot audit summary must be a JSON object",
        })
    if missing_fields:
        issues.append({
            "kind": "missing_fields",
            "fields": missing_fields,
            "field_count": len(missing_fields),
        })
    if unexpected_fields:
        issues.append({
            "kind": "unexpected_fields",
            "fields": unexpected_fields,
            "field_count": len(unexpected_fields),
        })
    if json_object_ok and not known_field_order_matches_template:
        issues.append({
            "kind": "field_order",
            "message": "known snapshot audit fields are not in template order",
        })
    if (
        json_object_ok
        and field_set_matches_template
        and not field_order_matches_template
    ):
        issues.append({
            "kind": "exact_field_order",
            "message": "snapshot audit summary field order must match --snapshot-audit-template output",
        })
    if json_object_ok and not source_chain_matches_network:
        issues.append({
            "kind": "source_chain",
            "expected": expected_source_chain,
            "actual": source_chain,
        })

    return {
        "schema_version": 1,
        "network": network,
        "blocker": blocker_id,
        "readiness_gate": blocker_type_readiness_gate("litecoin_snapshot"),
        "audit_summary_path": display_path(audit_path),
        "artifact_verification_performed": False,
        "value_validation_performed": False,
        "expected_source_chain": expected_source_chain,
        "source_chain": source_chain,
        "source_chain_matches_network": source_chain_matches_network,
        "template": template,
        "template_fields": template_fields,
        "template_field_count": len(template_fields),
        "fields": audit_fields,
        "field_count": len(audit_fields),
        "known_fields": known_fields,
        "known_field_count": len(known_fields),
        "present_template_fields": present_template_fields,
        "present_template_field_count": len(present_template_fields),
        "missing_fields": missing_fields,
        "missing_field_count": len(missing_fields),
        "unexpected_fields": unexpected_fields,
        "unexpected_field_count": len(unexpected_fields),
        "field_set_matches_template": field_set_matches_template,
        "known_field_order_matches_template": known_field_order_matches_template,
        "field_order_matches_template": field_order_matches_template,
        "json_parse_ok": json_parse_ok,
        "json_object_ok": json_object_ok,
        "duplicate_field": duplicate_field,
        "parse_error": parse_error,
        "ready_for_full_audit_check": ready_for_full_audit_check,
        "issues": issues,
        "issue_count": len(issues),
        "commands": {
            "template_command": snapshot_audit_template_command(network, manifest_path),
            "template_json_command": snapshot_audit_template_command(
                network,
                manifest_path,
                json_output=True,
            ),
            "template_diff_command": snapshot_audit_template_diff_command(
                network,
                audit_path,
                manifest_path,
            ),
            "template_diff_json_command": snapshot_audit_template_diff_command(
                network,
                audit_path,
                manifest_path,
                json_output=True,
            ),
            "check_command": snapshot_audit_check_command(network, audit_path, manifest_path),
            "preflight_command": snapshot_audit_preflight_command(network, audit_path, manifest_path),
            "apply_command": snapshot_audit_apply_command(network, audit_path, manifest_path),
            "snapshot_audit_handoff_command": snapshot_audit_handoff_command(
                manifest_path,
                network,
            ),
            "network_handoff_bundle_command": network_handoff_bundle_command(
                manifest_path,
                network,
            ),
            "blocker_readiness_summary_command": blocker_readiness_summary_command(
                manifest_path,
                blocker_id,
            ),
        },
    }


def snapshot_audit_template_diff_text(network, audit_path, manifest_path):
    diff = snapshot_audit_template_diff_payload(network, audit_path, manifest_path)
    lines = [
        f"Snapshot audit template diff for {network}.",
        f"  - audit summary: {diff['audit_summary_path']}",
        f"  - JSON parse ok: {yes_no(diff['json_parse_ok'])}",
        f"  - JSON object ok: {yes_no(diff['json_object_ok'])}",
        f"  - template field count: {diff['template_field_count']}",
        f"  - present field count: {diff['field_count']}",
        f"  - missing fields: {list_summary(diff['missing_fields'])}",
        f"  - unexpected fields: {list_summary(diff['unexpected_fields'])}",
        f"  - known field order matches template: {yes_no(diff['known_field_order_matches_template'])}",
        f"  - exact field order matches template: {yes_no(diff['field_order_matches_template'])}",
        f"  - expected source chain: {diff['expected_source_chain']}",
        f"  - source chain: {diff['source_chain'] if diff['source_chain'] is not None else 'none'}",
        f"  - source chain matches network: {yes_no(diff['source_chain_matches_network'])}",
        f"  - artifact verification performed: {yes_no(diff['artifact_verification_performed'])}",
        f"  - ready for full audit check: {yes_no(diff['ready_for_full_audit_check'])}",
    ]
    if diff["parse_error"] is not None:
        lines.append(f"  - parse error: {diff['parse_error']}")
    lines.extend((
        f"  - template diff JSON command: {diff['commands']['template_diff_json_command']}",
        f"  - check command: {diff['commands']['check_command']}",
        f"  - preflight command: {diff['commands']['preflight_command']}",
        f"  - apply command: {diff['commands']['apply_command']}",
    ))
    return "\n".join(lines)


def snapshot_audit_template_diff_json_text(network, audit_path, manifest_path):
    return json.dumps(
        snapshot_audit_template_diff_payload(network, audit_path, manifest_path),
        indent=2,
        sort_keys=False,
    )


def snapshot_audit_check_text(network, audit, candidate, audit_path, manifest_path):
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
        f"  apply command: {snapshot_audit_apply_command(network, audit_path, manifest_path)}",
        candidate_next_step_text(candidate, "audit", manifest_path, network, "litecoin_snapshot"),
    ))


def snapshot_audit_json_payload(network, audit, candidate, audit_path, manifest_path):
    audit_detail = audit["audit"]
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    blocker_counts_by_network = item_counts_by_network(blockers)
    blocked_field_counts_by_network = item_counts_by_network(blocked_fields)
    next_blocker = blockers[0] if blockers else None
    if next_blocker is None:
        next_blocker_network = None
        next_blocker_type = None
        next_blocker_commands = None
    else:
        next_blocker_network, next_blocker_type = next_blocker.split(".", 1)
        next_blocker_commands = blocker_action_commands(
            next_blocker,
            shell_quote(display_path(manifest_path)),
        )

    return {
        "schema_version": 1,
        "network": network,
        "verified": True,
        "ready_to_apply": True,
        "audit_path": display_path(audit_path),
        "audit": {
            "height": audit["height"],
            "block_hash": audit["block_hash"],
            "import_hash": audit["import_hash"],
            "snapshot_hash": audit_detail["snapshot_hash"],
            "coins": audit_detail["coins"],
            "base_nchaintx": audit_detail["base_nchaintx"],
            "source_chain": audit_detail["source_chain"],
            "snapshot_file_size": audit_detail["snapshot_file_size"],
            "snapshot_file_sha256": audit_detail["snapshot_file_sha256"],
            "snapshot_file": audit_detail["snapshot_file"],
            "total_amount": audit_detail["total_amount"],
        },
        "commands": {
            "apply": snapshot_audit_apply_command(network, audit_path, manifest_path),
            "recheck": snapshot_audit_check_command(network, audit_path, manifest_path),
            "network_handoff_bundle": network_handoff_bundle_command(manifest_path, network),
            "current_blocker_readiness_summary": blocker_readiness_summary_command(
                manifest_path,
                f"{network}.litecoin_snapshot",
            ),
        },
        "post_apply": {
            "remaining_blocker_count": len(blockers),
            "remaining_blocker_count_for_network": blocker_counts_by_network[network],
            "remaining_blocker_counts_by_network": blocker_counts_by_network,
            "remaining_blockers": blockers,
            "remaining_blockers_by_network": items_by_network(blockers),
            "remaining_blocked_field_count": len(blocked_fields),
            "remaining_blocked_field_count_for_network": blocked_field_counts_by_network[network],
            "remaining_blocked_field_counts_by_network": blocked_field_counts_by_network,
            "remaining_blocked_fields": blocked_fields,
            "remaining_blocked_fields_by_network": items_by_network(blocked_fields),
            "next_action_command": next_action_command(manifest_path),
            "readiness_summary_command": readiness_summary_command(manifest_path),
            "network_readiness_summary_command": network_readiness_summary_command(
                manifest_path,
                network,
            ),
            "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
                manifest_path,
                "litecoin_snapshot",
            ),
            "next_blocker": next_blocker,
            "next_blocker_network": next_blocker_network,
            "next_blocker_type": next_blocker_type,
            "next_commands": next_blocker_commands,
        },
    }


def snapshot_audit_check_json_text(network, audit, candidate, audit_path, manifest_path):
    return json.dumps(
        snapshot_audit_json_payload(network, audit, candidate, audit_path, manifest_path),
        indent=2,
        sort_keys=False,
    )


def snapshot_audit_preflight_text(network, audit, candidate, audit_path, manifest_path):
    audit_detail = audit["audit"]
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    next_blocker = blockers[0] if blockers else "none"
    return "\n".join((
        f"Snapshot audit ready-to-apply preflight passed for {network}.",
        "  - ready to apply: yes",
        f"  - source chain: {audit_detail['source_chain']}",
        f"  - snapshot file: {audit_detail['snapshot_file']}",
        f"  - snapshot file size: {audit_detail['snapshot_file_size']}",
        f"  - snapshot file SHA-256: {audit_detail['snapshot_file_sha256']}",
        f"  - apply command: {snapshot_audit_apply_command(network, audit_path, manifest_path)}",
        f"  - recheck command: {snapshot_audit_check_command(network, audit_path, manifest_path)}",
        f"  - network handoff bundle command: {network_handoff_bundle_command(manifest_path, network)}",
        (
            "  - current blocker readiness summary command: "
            + blocker_readiness_summary_command(manifest_path, f"{network}.litecoin_snapshot")
        ),
        f"  - remaining blockers after applying audit: {len(blockers)}",
        (
            f"  - remaining blockers on {network} after applying audit: "
            f"{item_counts_by_network(blockers)[network]}"
        ),
        f"  - remaining blocked fields after applying audit: {len(blocked_fields)}",
        (
            f"  - remaining blocked fields on {network} after applying audit: "
            f"{item_counts_by_network(blocked_fields)[network]}"
        ),
        f"  - next blocker after applying audit: {next_blocker}",
    ))


def snapshot_audit_preflight_json_text(network, audit, candidate, audit_path, manifest_path):
    return json.dumps(
        snapshot_audit_json_payload(network, audit, candidate, audit_path, manifest_path),
        indent=2,
        sort_keys=False,
    )


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


def auxpow_apply_command(network, auxpow, manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return (
        f"{tool_path} --set-auxpow {network} "
        f"0x{auxpow['chain_id']:x} --in-place {manifest_path}"
    )


def auxpow_check_command(network, auxpow, manifest_path, json_output=False):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}--check-auxpow "
        f"{network} 0x{auxpow['chain_id']:x} {manifest_path}"
    )


def auxpow_json_payload(network, auxpow, candidate, manifest_path):
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    blocker_counts_by_network = item_counts_by_network(blockers)
    blocked_field_counts_by_network = item_counts_by_network(blocked_fields)
    next_blocker = blockers[0] if blockers else None
    if next_blocker is None:
        next_blocker_network = None
        next_blocker_type = None
        next_blocker_commands = None
    else:
        next_blocker_network, next_blocker_type = next_blocker.split(".", 1)
        next_blocker_commands = blocker_action_commands(
            next_blocker,
            shell_quote(display_path(manifest_path)),
        )
    constraints = blocker_candidate_constraints("auxpow_chain_id")

    return {
        "schema_version": 1,
        "network": network,
        "blocker": f"{network}.auxpow_chain_id",
        "readiness_gate": blocker_type_readiness_gate("auxpow_chain_id"),
        "verified": True,
        "ready_to_apply": True,
        "candidate": {
            "start_height": auxpow["start_height"],
            "chain_id": auxpow["chain_id"],
            "chain_id_hex": f"0x{auxpow['chain_id']:x}",
            "strict_chain_id": auxpow["strict_chain_id"],
            "forbidden_parent_version_chain_id_range": auxpow[
                "forbidden_parent_version_chain_id_range"
            ],
        },
        "candidate_constraints": constraints,
        "candidate_constraint_count": len(constraints),
        "commands": {
            "apply": auxpow_apply_command(network, auxpow, manifest_path),
            "recheck": auxpow_check_command(network, auxpow, manifest_path),
            "network_handoff_bundle": network_handoff_bundle_command(manifest_path, network),
            "current_blocker_readiness_summary": blocker_readiness_summary_command(
                manifest_path,
                f"{network}.auxpow_chain_id",
            ),
        },
        "post_apply": {
            "remaining_blocker_count": len(blockers),
            "remaining_blocker_count_for_network": blocker_counts_by_network[network],
            "remaining_blocker_counts_by_network": blocker_counts_by_network,
            "remaining_blockers": blockers,
            "remaining_blockers_by_network": items_by_network(blockers),
            "remaining_blocked_field_count": len(blocked_fields),
            "remaining_blocked_field_count_for_network": blocked_field_counts_by_network[network],
            "remaining_blocked_field_counts_by_network": blocked_field_counts_by_network,
            "remaining_blocked_fields": blocked_fields,
            "remaining_blocked_fields_by_network": items_by_network(blocked_fields),
            "next_action_command": next_action_command(manifest_path),
            "readiness_summary_command": readiness_summary_command(manifest_path),
            "network_readiness_summary_command": network_readiness_summary_command(
                manifest_path,
                network,
            ),
            "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
                manifest_path,
                "auxpow_chain_id",
            ),
            "next_blocker": next_blocker,
            "next_blocker_network": next_blocker_network,
            "next_blocker_type": next_blocker_type,
            "next_commands": next_blocker_commands,
        },
    }


def auxpow_check_json_text(network, auxpow, candidate, manifest_path):
    return json.dumps(
        auxpow_json_payload(network, auxpow, candidate, manifest_path),
        indent=2,
        sort_keys=False,
    )


def auxpow_check_text(network, auxpow, candidate, manifest_path):
    return "\n".join((
        f"AuxPoW chain id candidate verified for {network}.",
        f"  chain id: {auxpow['chain_id']}",
        f"  chain id hex: 0x{auxpow['chain_id']:x}",
        f"  start height: {auxpow['start_height']}",
        f"  strict chain id: {str(auxpow['strict_chain_id']).lower()}",
        "  forbidden parent-version chain-id range: 0x2000-0x3fff",
        f"  apply command: {auxpow_apply_command(network, auxpow, manifest_path)}",
        candidate_next_step_text(candidate, "candidate", manifest_path, network, "auxpow_chain_id"),
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


def dns_seeds_apply_command(network, dns_seeds, manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    dns_seed_arg = shell_quote(",".join(dns_seeds))
    return (
        f"{tool_path} --set-dns-seeds {network} "
        f"{dns_seed_arg} --in-place {manifest_path}"
    )


def dns_seeds_check_command(network, dns_seeds, manifest_path, json_output=False):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    dns_seed_arg = shell_quote(",".join(dns_seeds))
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}--check-dns-seeds "
        f"{network} {dns_seed_arg} {manifest_path}"
    )


def dns_seeds_json_payload(network, dns_seeds, candidate, manifest_path):
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    blocker_counts_by_network = item_counts_by_network(blockers)
    blocked_field_counts_by_network = item_counts_by_network(blocked_fields)
    next_blocker = blockers[0] if blockers else None
    if next_blocker is None:
        next_blocker_network = None
        next_blocker_type = None
        next_blocker_commands = None
    else:
        next_blocker_network, next_blocker_type = next_blocker.split(".", 1)
        next_blocker_commands = blocker_action_commands(
            next_blocker,
            shell_quote(display_path(manifest_path)),
        )
    constraints = blocker_candidate_constraints("dns_seeds")

    return {
        "schema_version": 1,
        "network": network,
        "blocker": f"{network}.dns_seeds",
        "readiness_gate": blocker_type_readiness_gate("dns_seeds"),
        "verified": True,
        "ready_to_apply": True,
        "candidate": {
            "seeds": list(dns_seeds),
            "seed_count": len(dns_seeds),
        },
        "candidate_constraints": constraints,
        "candidate_constraint_count": len(constraints),
        "commands": {
            "apply": dns_seeds_apply_command(network, dns_seeds, manifest_path),
            "recheck": dns_seeds_check_command(network, dns_seeds, manifest_path),
            "network_handoff_bundle": network_handoff_bundle_command(manifest_path, network),
            "current_blocker_readiness_summary": blocker_readiness_summary_command(
                manifest_path,
                f"{network}.dns_seeds",
            ),
        },
        "post_apply": {
            "remaining_blocker_count": len(blockers),
            "remaining_blocker_count_for_network": blocker_counts_by_network[network],
            "remaining_blocker_counts_by_network": blocker_counts_by_network,
            "remaining_blockers": blockers,
            "remaining_blockers_by_network": items_by_network(blockers),
            "remaining_blocked_field_count": len(blocked_fields),
            "remaining_blocked_field_count_for_network": blocked_field_counts_by_network[network],
            "remaining_blocked_field_counts_by_network": blocked_field_counts_by_network,
            "remaining_blocked_fields": blocked_fields,
            "remaining_blocked_fields_by_network": items_by_network(blocked_fields),
            "next_action_command": next_action_command(manifest_path),
            "readiness_summary_command": readiness_summary_command(manifest_path),
            "network_readiness_summary_command": network_readiness_summary_command(
                manifest_path,
                network,
            ),
            "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
                manifest_path,
                "dns_seeds",
            ),
            "next_blocker": next_blocker,
            "next_blocker_network": next_blocker_network,
            "next_blocker_type": next_blocker_type,
            "next_commands": next_blocker_commands,
        },
    }


def dns_seeds_check_json_text(network, dns_seeds, candidate, manifest_path):
    return json.dumps(
        dns_seeds_json_payload(network, dns_seeds, candidate, manifest_path),
        indent=2,
        sort_keys=False,
    )


def dns_seeds_check_text(network, dns_seeds, candidate, manifest_path):
    return "\n".join((
        f"DNS seed candidate verified for {network}.",
        f"  seed count: {len(dns_seeds)}",
        "  seeds: " + ", ".join(dns_seeds),
        f"  apply command: {dns_seeds_apply_command(network, dns_seeds, manifest_path)}",
        candidate_next_step_text(candidate, "candidate", manifest_path, network, "dns_seeds"),
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


def identity_byte_arg(bytes_):
    return ",".join(str(byte) for byte in bytes_)


def identity_hex_arg(bytes_):
    return "".join(f"{byte:02x}" for byte in bytes_)


def identity_apply_command(network, identity, manifest_path):
    base58 = identity["base58_prefixes"]
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    args = [
        network,
        identity_byte_arg(identity["message_start"]),
        str(identity["default_port"]),
        identity_byte_arg(base58["pubkey_address"]),
        identity_byte_arg(base58["script_address"]),
        identity_byte_arg(base58["script_address2"]),
        identity_byte_arg(base58["secret_key"]),
        identity_hex_arg(base58["ext_public_key"]),
        identity_hex_arg(base58["ext_secret_key"]),
        identity["bech32_hrp"],
        identity["mweb_hrp"],
    ]
    return (
        f"{tool_path} --set-identity "
        + " ".join(shell_quote(arg) for arg in args)
        + f" --in-place {manifest_path}"
    )


def identity_check_command(network, identity, manifest_path, json_output=False):
    base58 = identity["base58_prefixes"]
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    json_flag = "--json " if json_output else ""
    args = [
        network,
        identity_byte_arg(identity["message_start"]),
        str(identity["default_port"]),
        identity_byte_arg(base58["pubkey_address"]),
        identity_byte_arg(base58["script_address"]),
        identity_byte_arg(base58["script_address2"]),
        identity_byte_arg(base58["secret_key"]),
        identity_hex_arg(base58["ext_public_key"]),
        identity_hex_arg(base58["ext_secret_key"]),
        identity["bech32_hrp"],
        identity["mweb_hrp"],
    ]
    return (
        f"{tool_path} {json_flag}--check-identity "
        + " ".join(shell_quote(arg) for arg in args)
        + f" {manifest_path}"
    )


def identity_json_payload(network, identity, candidate, manifest_path):
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    blocker_counts_by_network = item_counts_by_network(blockers)
    blocked_field_counts_by_network = item_counts_by_network(blocked_fields)
    next_blocker = blockers[0] if blockers else None
    if next_blocker is None:
        next_blocker_network = None
        next_blocker_type = None
        next_blocker_commands = None
    else:
        next_blocker_network, next_blocker_type = next_blocker.split(".", 1)
        next_blocker_commands = blocker_action_commands(
            next_blocker,
            shell_quote(display_path(manifest_path)),
        )
    constraints = blocker_candidate_constraints("public_network_identity")

    return {
        "schema_version": 1,
        "network": network,
        "blocker": f"{network}.public_network_identity",
        "readiness_gate": blocker_type_readiness_gate("public_network_identity"),
        "verified": True,
        "ready_to_apply": True,
        "candidate": identity,
        "candidate_constraints": constraints,
        "candidate_constraint_count": len(constraints),
        "commands": {
            "apply": identity_apply_command(network, identity, manifest_path),
            "recheck": identity_check_command(network, identity, manifest_path),
            "network_handoff_bundle": network_handoff_bundle_command(manifest_path, network),
            "current_blocker_readiness_summary": blocker_readiness_summary_command(
                manifest_path,
                f"{network}.public_network_identity",
            ),
        },
        "post_apply": {
            "remaining_blocker_count": len(blockers),
            "remaining_blocker_count_for_network": blocker_counts_by_network[network],
            "remaining_blocker_counts_by_network": blocker_counts_by_network,
            "remaining_blockers": blockers,
            "remaining_blockers_by_network": items_by_network(blockers),
            "remaining_blocked_field_count": len(blocked_fields),
            "remaining_blocked_field_count_for_network": blocked_field_counts_by_network[network],
            "remaining_blocked_field_counts_by_network": blocked_field_counts_by_network,
            "remaining_blocked_fields": blocked_fields,
            "remaining_blocked_fields_by_network": items_by_network(blocked_fields),
            "next_action_command": next_action_command(manifest_path),
            "readiness_summary_command": readiness_summary_command(manifest_path),
            "network_readiness_summary_command": network_readiness_summary_command(
                manifest_path,
                network,
            ),
            "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
                manifest_path,
                "public_network_identity",
            ),
            "next_blocker": next_blocker,
            "next_blocker_network": next_blocker_network,
            "next_blocker_type": next_blocker_type,
            "next_commands": next_blocker_commands,
        },
    }


def identity_check_json_text(network, identity, candidate, manifest_path):
    return json.dumps(
        identity_json_payload(network, identity, candidate, manifest_path),
        indent=2,
        sort_keys=False,
    )


def identity_check_text(network, identity, candidate, manifest_path):
    base58 = identity["base58_prefixes"]
    return "\n".join((
        f"Public identity candidate verified for {network}.",
        f"  message start: {identity_byte_arg(identity['message_start'])}",
        f"  default port: {identity['default_port']}",
        f"  pubkey address prefix: {identity_byte_arg(base58['pubkey_address'])}",
        f"  script address prefix: {identity_byte_arg(base58['script_address'])}",
        f"  script address 2 prefix: {identity_byte_arg(base58['script_address2'])}",
        f"  secret key prefix: {identity_byte_arg(base58['secret_key'])}",
        f"  extended public key prefix: {','.join(f'{byte:02x}' for byte in base58['ext_public_key'])}",
        f"  extended secret key prefix: {','.join(f'{byte:02x}' for byte in base58['ext_secret_key'])}",
        f"  bech32 HRP: {identity['bech32_hrp']}",
        f"  MWEB HRP: {identity['mweb_hrp']}",
        f"  apply command: {identity_apply_command(network, identity, manifest_path)}",
        candidate_next_step_text(candidate, "candidate", manifest_path, network, "public_network_identity"),
    ))


def require_value_selection_candidate_fields(candidate, network):
    expected = value_selection_candidate_template(network)
    expected_fields = list(expected)
    if list(candidate) != expected_fields:
        raise ValueError(
            "value-selection candidate fields must match template order: "
            + ", ".join(expected_fields)
        )
    if candidate.get("schema_version") != expected["schema_version"]:
        raise ValueError("value-selection candidate schema_version must be 1")
    if candidate.get("network") != network:
        raise ValueError(
            f"value-selection candidate network must match requested network: {network}"
        )

    identity = candidate.get("public_network_identity")
    if not isinstance(identity, dict):
        raise ValueError(
            "value-selection candidate public_network_identity must be a JSON object"
        )
    expected_identity_fields = list(expected["public_network_identity"])
    if list(identity) != expected_identity_fields:
        raise ValueError(
            "value-selection candidate public_network_identity fields must match "
            "template order: " + ", ".join(expected_identity_fields)
        )

    base58 = identity.get("base58_prefixes")
    if not isinstance(base58, dict):
        raise ValueError(
            "value-selection candidate public_network_identity.base58_prefixes "
            "must be a JSON object"
        )
    expected_base58_fields = list(expected["public_network_identity"]["base58_prefixes"])
    if list(base58) != expected_base58_fields:
        raise ValueError(
            "value-selection candidate base58_prefixes fields must match template "
            "order: " + ", ".join(expected_base58_fields)
        )


def value_selection_candidate_scalar_arg(candidate, field_path):
    current = candidate
    for field in field_path.split("."):
        if not isinstance(current, dict) or field not in current:
            raise ValueError(f"value-selection candidate missing field: {field_path}")
        current = current[field]
    if isinstance(current, bool) or current is None:
        raise ValueError(
            f"value-selection candidate {field_path} must be a string or integer"
        )
    if isinstance(current, int):
        return str(current)
    if not isinstance(current, str):
        raise ValueError(
            f"value-selection candidate {field_path} must be a string or integer"
        )
    value = current.strip()
    if not value:
        raise ValueError(f"value-selection candidate {field_path} must not be empty")
    if value.startswith("<") and value.endswith(">"):
        raise ValueError(
            f"value-selection candidate {field_path} still contains placeholder {value}"
        )
    return value


def value_selection_candidate_dns_seed_arg(candidate):
    dns_seeds = candidate.get("dns_seeds")
    if not isinstance(dns_seeds, list) or not dns_seeds:
        raise ValueError(
            "value-selection candidate dns_seeds must be a non-empty JSON array"
        )
    values = []
    for index, seed in enumerate(dns_seeds, 1):
        if not isinstance(seed, str):
            raise ValueError(
                f"value-selection candidate dns_seeds[{index}] must be a string"
            )
        value = seed.strip()
        if not value:
            raise ValueError(
                f"value-selection candidate dns_seeds[{index}] must not be empty"
            )
        if value.startswith("<") and value.endswith(">"):
            raise ValueError(
                "value-selection candidate "
                f"dns_seeds[{index}] still contains placeholder {value}"
            )
        values.append(value)
    return ",".join(values)


def value_selection_candidate_args(candidate, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    require_value_selection_candidate_fields(candidate, network)
    identity_prefix = "public_network_identity"
    base58_prefix = f"{identity_prefix}.base58_prefixes"
    return {
        "auxpow_chain_id": value_selection_candidate_scalar_arg(
            candidate,
            "auxpow_chain_id",
        ),
        "identity_args": [
            value_selection_candidate_scalar_arg(candidate, f"{identity_prefix}.message_start"),
            value_selection_candidate_scalar_arg(candidate, f"{identity_prefix}.default_port"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.pubkey_address"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.script_address"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.script_address2"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.secret_key"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.ext_public_key"),
            value_selection_candidate_scalar_arg(candidate, f"{base58_prefix}.ext_secret_key"),
            value_selection_candidate_scalar_arg(candidate, f"{identity_prefix}.bech32_hrp"),
            value_selection_candidate_scalar_arg(candidate, f"{identity_prefix}.mweb_hrp"),
        ],
        "dns_seeds": value_selection_candidate_dns_seed_arg(candidate),
    }


def checked_network_value_selection_candidate(manifest, network, candidate_path):
    candidate_json, candidate_metadata = read_value_selection_candidate_json_with_metadata(
        Path(candidate_path)
    )
    args = value_selection_candidate_args(candidate_json, network)
    auxpow, _ = checked_auxpow_candidate(
        manifest,
        network,
        args["auxpow_chain_id"],
    )
    identity, _ = checked_identity_candidate(
        manifest,
        network,
        *args["identity_args"],
    )
    dns_seeds, _ = checked_dns_seeds_candidate(
        manifest,
        network,
        args["dns_seeds"],
    )

    candidate = json.loads(json.dumps(manifest))
    set_auxpow(candidate, network, args["auxpow_chain_id"])
    set_identity(candidate, network, *args["identity_args"])
    set_dns_seeds(candidate, network, args["dns_seeds"])
    check = validate_manifest(candidate, allow_blocked=True)
    if check.errors:
        raise ValueError(
            validation_failure_message(
                "value-selection candidate failed validation:",
                check,
            )
        )
    return candidate_json, candidate_metadata, auxpow, identity, dns_seeds, candidate


def value_selection_candidate_post_apply_payload(candidate, manifest_path, network):
    candidate_check = validate_manifest(candidate, allow_blocked=True)
    blockers = ordered_unresolved_blocker_ids(candidate)
    blocked_fields = candidate_check.blockers
    blocker_counts_by_network = item_counts_by_network(blockers)
    blocked_field_counts_by_network = item_counts_by_network(blocked_fields)
    next_blocker = blockers[0] if blockers else None
    if next_blocker is None:
        next_blocker_network = None
        next_blocker_type = None
        next_blocker_commands = None
    else:
        next_blocker_network, next_blocker_type = next_blocker.split(".", 1)
        next_blocker_commands = blocker_action_commands(
            next_blocker,
            shell_quote(display_path(manifest_path)),
        )

    return {
        "remaining_blocker_count": len(blockers),
        "remaining_blocker_count_for_network": blocker_counts_by_network[network],
        "remaining_blocker_counts_by_network": blocker_counts_by_network,
        "remaining_blockers": blockers,
        "remaining_blockers_by_network": items_by_network(blockers),
        "remaining_blocked_field_count": len(blocked_fields),
        "remaining_blocked_field_count_for_network": blocked_field_counts_by_network[
            network
        ],
        "remaining_blocked_field_counts_by_network": blocked_field_counts_by_network,
        "remaining_blocked_fields": blocked_fields,
        "remaining_blocked_fields_by_network": items_by_network(blocked_fields),
        "next_action_command": next_action_command(manifest_path),
        "readiness_summary_command": readiness_summary_command(manifest_path),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
        "next_blocker": next_blocker,
        "next_blocker_network": next_blocker_network,
        "next_blocker_type": next_blocker_type,
        "next_commands": next_blocker_commands,
    }


def value_selection_candidate_section_payloads(
    network,
    auxpow,
    identity,
    dns_seeds,
    manifest_path,
):
    return [
        {
            "id": "auxpow_chain_id",
            "blocker": f"{network}.auxpow_chain_id",
            "readiness_gate": blocker_type_readiness_gate("auxpow_chain_id"),
            "verified": True,
            "ready_to_apply": True,
            "candidate": {
                "chain_id": auxpow["chain_id"],
                "chain_id_hex": f"0x{auxpow['chain_id']:x}",
            },
            "candidate_constraints": blocker_candidate_constraints(
                "auxpow_chain_id"
            ),
            "check_command": auxpow_check_command(network, auxpow, manifest_path),
            "json_check_command": auxpow_check_command(
                network,
                auxpow,
                manifest_path,
                json_output=True,
            ),
            "apply_command": auxpow_apply_command(network, auxpow, manifest_path),
        },
        {
            "id": "public_network_identity",
            "blocker": f"{network}.public_network_identity",
            "readiness_gate": blocker_type_readiness_gate("public_network_identity"),
            "verified": True,
            "ready_to_apply": True,
            "candidate": identity,
            "candidate_constraints": blocker_candidate_constraints(
                "public_network_identity"
            ),
            "check_command": identity_check_command(network, identity, manifest_path),
            "json_check_command": identity_check_command(
                network,
                identity,
                manifest_path,
                json_output=True,
            ),
            "apply_command": identity_apply_command(network, identity, manifest_path),
        },
        {
            "id": "dns_seeds",
            "blocker": f"{network}.dns_seeds",
            "readiness_gate": blocker_type_readiness_gate("dns_seeds"),
            "verified": True,
            "ready_to_apply": True,
            "candidate": {
                "seeds": list(dns_seeds),
                "seed_count": len(dns_seeds),
            },
            "candidate_constraints": blocker_candidate_constraints("dns_seeds"),
            "check_command": dns_seeds_check_command(
                network,
                dns_seeds,
                manifest_path,
            ),
            "json_check_command": dns_seeds_check_command(
                network,
                dns_seeds,
                manifest_path,
                json_output=True,
            ),
            "apply_command": dns_seeds_apply_command(
                network,
                dns_seeds,
                manifest_path,
            ),
        },
    ]


def network_value_selection_candidate_check_json_payload(
    manifest,
    manifest_path,
    network,
    candidate_path,
    candidate_json,
    candidate_metadata,
    auxpow,
    identity,
    dns_seeds,
    candidate,
):
    sections = value_selection_candidate_section_payloads(
        network,
        auxpow,
        identity,
        dns_seeds,
        manifest_path,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "network": network,
        "candidate_path": display_path(candidate_path),
        "candidate_artifact": candidate_metadata,
        "candidate_size": candidate_metadata["size"],
        "candidate_sha256": candidate_metadata["sha256"],
        "candidate_max_bytes": candidate_metadata["max_bytes"],
        "candidate_schema_version": candidate_json.get("schema_version"),
        "candidate_network": candidate_json.get("network"),
        "candidate_template_schema_version": value_selection_candidate_template(
            network
        )["schema_version"],
        "verified": True,
        "ready_to_apply": True,
        "section_count": len(sections),
        "verified_section_count": sum(1 for section in sections if section["verified"]),
        "sections": sections,
        "section_ids": [section["id"] for section in sections],
        "section_blockers": [section["blocker"] for section in sections],
        "candidate_constraints_by_blocker": {
            section["blocker"]: section["candidate_constraints"]
            for section in sections
        },
        "commands": {
            "candidate_check": network_value_selection_candidate_check_command(
                manifest_path,
                network,
                candidate_path,
            ),
            "candidate_check_json": network_value_selection_candidate_check_command(
                manifest_path,
                network,
                candidate_path,
                json_output=True,
            ),
            "candidate_template": network_value_selection_candidate_template_command(
                manifest_path,
                network,
            ),
            "candidate_template_json": network_value_selection_candidate_template_command(
                manifest_path,
                network,
                json_output=True,
            ),
            "network_readiness_summary": network_readiness_summary_command(
                manifest_path,
                network,
            ),
            "network_handoff_bundle": network_handoff_bundle_command(
                manifest_path,
                network,
            ),
        },
        "post_apply": value_selection_candidate_post_apply_payload(
            candidate,
            manifest_path,
            network,
        ),
    }


def network_value_selection_candidate_check_json_text(
    manifest,
    manifest_path,
    network,
    candidate_path,
    candidate_json,
    candidate_metadata,
    auxpow,
    identity,
    dns_seeds,
    candidate,
):
    return json.dumps(
        network_value_selection_candidate_check_json_payload(
            manifest,
            manifest_path,
            network,
            candidate_path,
            candidate_json,
            candidate_metadata,
            auxpow,
            identity,
            dns_seeds,
            candidate,
        ),
        indent=2,
        sort_keys=False,
    )


def network_value_selection_candidate_check_text(
    manifest,
    manifest_path,
    network,
    candidate_path,
    candidate_json,
    candidate_metadata,
    auxpow,
    identity,
    dns_seeds,
    candidate,
):
    payload = network_value_selection_candidate_check_json_payload(
        manifest,
        manifest_path,
        network,
        candidate_path,
        candidate_json,
        candidate_metadata,
        auxpow,
        identity,
        dns_seeds,
        candidate,
    )
    post_apply = payload["post_apply"]
    lines = [
        "zkCoin public launch profile network value-selection candidate check:",
        f"  - manifest: {payload['manifest']}",
        f"  - status: {payload['status']}",
        f"  - network: {network}",
        f"  - candidate: {payload['candidate_path']}",
        f"  - candidate size: {payload['candidate_size']}",
        f"  - candidate sha256: {payload['candidate_sha256']}",
        f"  - candidate network: {payload['candidate_network']}",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - ready to apply: {yes_no(payload['ready_to_apply'])}",
        (
            "  - verified sections: "
            f"{payload['verified_section_count']}/{payload['section_count']}"
        ),
        f"  - candidate check command: {payload['commands']['candidate_check']}",
        (
            "  - candidate check JSON command: "
            + payload["commands"]["candidate_check_json"]
        ),
        (
            "  - candidate template command: "
            + payload["commands"]["candidate_template"]
        ),
        (
            "  - network readiness summary command: "
            + payload["commands"]["network_readiness_summary"]
        ),
        (
            "  - post-apply remaining blockers: "
            f"{post_apply['remaining_blocker_count']}"
        ),
        (
            "  - post-apply remaining blockers for network: "
            f"{post_apply['remaining_blocker_count_for_network']}"
        ),
        (
            "  - post-apply next blocker: "
            + (post_apply["next_blocker"] or "none")
        ),
    ]
    for section in payload["sections"]:
        lines.extend([
            f"  - {section['blocker']} section: {section['id']}",
            f"    - verified: {yes_no(section['verified'])}",
            f"    - JSON check command: {section['json_check_command']}",
            f"    - apply command: {section['apply_command']}",
        ])
    return "\n".join(lines)


def value_selection_candidate_artifact_status_entry(
    manifest,
    manifest_path,
    step,
    network,
    candidate_path,
):
    template_command = network_value_selection_candidate_template_command(
        manifest_path,
        network,
    )
    template_json_command = network_value_selection_candidate_template_command(
        manifest_path,
        network,
        json_output=True,
    )
    if candidate_path is None:
        check_command = network_value_selection_candidate_check_command(
            manifest_path,
            network,
        )
        check_json_command = network_value_selection_candidate_check_command(
            manifest_path,
            network,
            json_output=True,
        )
        return {
            "step": step,
            "network": network,
            "candidate_path": None,
            "provided": False,
            "status": "missing-artifact",
            "verified": False,
            "ready_to_apply": False,
            "error": None,
            "candidate_artifact": None,
            "candidate_size": None,
            "candidate_sha256": None,
            "candidate_max_bytes": None,
            "candidate_schema_version": None,
            "candidate_network": None,
            "section_count": 0,
            "verified_section_count": 0,
            "section_ids": [],
            "section_blockers": [],
            "post_apply": None,
            "candidate_template_command": template_command,
            "candidate_template_json_command": template_json_command,
            "candidate_check_command": check_command,
            "candidate_check_json_command": check_json_command,
            "commands": {
                "candidate_template": template_command,
                "candidate_template_json": template_json_command,
                "candidate_check": check_command,
                "candidate_check_json": check_json_command,
            },
        }

    check_command = network_value_selection_candidate_check_command(
        manifest_path,
        network,
        candidate_path,
    )
    check_json_command = network_value_selection_candidate_check_command(
        manifest_path,
        network,
        candidate_path,
        json_output=True,
    )
    try:
        (
            candidate_json,
            candidate_metadata,
            auxpow,
            identity,
            dns_seeds,
            candidate,
        ) = checked_network_value_selection_candidate(
            manifest,
            network,
            candidate_path,
        )
    except ValueError as exc:
        return {
            "step": step,
            "network": network,
            "candidate_path": display_path(candidate_path),
            "provided": True,
            "status": "error",
            "verified": False,
            "ready_to_apply": False,
            "error": str(exc),
            "candidate_artifact": None,
            "candidate_size": None,
            "candidate_sha256": None,
            "candidate_max_bytes": None,
            "candidate_schema_version": None,
            "candidate_network": None,
            "section_count": 0,
            "verified_section_count": 0,
            "section_ids": [],
            "section_blockers": [],
            "post_apply": None,
            "candidate_template_command": template_command,
            "candidate_template_json_command": template_json_command,
            "candidate_check_command": check_command,
            "candidate_check_json_command": check_json_command,
            "commands": {
                "candidate_template": template_command,
                "candidate_template_json": template_json_command,
                "candidate_check": check_command,
                "candidate_check_json": check_json_command,
            },
        }

    check_payload = network_value_selection_candidate_check_json_payload(
        manifest,
        manifest_path,
        network,
        candidate_path,
        candidate_json,
        candidate_metadata,
        auxpow,
        identity,
        dns_seeds,
        candidate,
    )
    return {
        "step": step,
        "network": network,
        "candidate_path": display_path(candidate_path),
        "provided": True,
        "status": "verified",
        "verified": True,
        "ready_to_apply": check_payload["ready_to_apply"],
        "error": None,
        "candidate_artifact": check_payload["candidate_artifact"],
        "candidate_size": check_payload["candidate_size"],
        "candidate_sha256": check_payload["candidate_sha256"],
        "candidate_max_bytes": check_payload["candidate_max_bytes"],
        "candidate_schema_version": check_payload["candidate_schema_version"],
        "candidate_network": check_payload["candidate_network"],
        "section_count": check_payload["section_count"],
        "verified_section_count": check_payload["verified_section_count"],
        "section_ids": check_payload["section_ids"],
        "section_blockers": check_payload["section_blockers"],
        "sections": check_payload["sections"],
        "post_apply": check_payload["post_apply"],
        "candidate_template_command": template_command,
        "candidate_template_json_command": template_json_command,
        "candidate_check_command": check_command,
        "candidate_check_json_command": check_json_command,
        "commands": {
            "candidate_template": template_command,
            "candidate_template_json": template_json_command,
            "candidate_check": check_command,
            "candidate_check_json": check_json_command,
        },
    }


def value_selection_candidate_artifact_status_payload(
    manifest,
    manifest_path,
    main_candidate_path=None,
    testnet_candidate_path=None,
):
    candidate_paths = {
        "main": main_candidate_path,
        "testnet": testnet_candidate_path,
    }
    entries = [
        value_selection_candidate_artifact_status_entry(
            manifest,
            manifest_path,
            step,
            network,
            candidate_paths.get(network),
        )
        for step, network in enumerate(NETWORKS, 1)
    ]
    provided_candidate_count = sum(1 for entry in entries if entry["provided"])
    verified_candidate_count = sum(1 for entry in entries if entry["verified"])
    error_candidate_count = sum(1 for entry in entries if entry["status"] == "error")
    missing_candidate_count = sum(
        1 for entry in entries if entry["status"] == "missing-artifact"
    )
    status_command = value_selection_candidate_artifact_status_command(
        manifest_path,
        main_candidate_path,
        testnet_candidate_path,
    )
    status_json_command = value_selection_candidate_artifact_status_command(
        manifest_path,
        main_candidate_path,
        testnet_candidate_path,
        json_output=True,
    )
    next_missing_candidate = next(
        (entry["network"] for entry in entries if not entry["provided"]),
        None,
    )
    next_unverified_candidate = next(
        (entry["network"] for entry in entries if not entry["verified"]),
        None,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "network_count": len(NETWORKS),
        "candidate_count": len(entries),
        "provided_candidate_count": provided_candidate_count,
        "missing_candidate_count": missing_candidate_count,
        "verified_candidate_count": verified_candidate_count,
        "error_candidate_count": error_candidate_count,
        "all_required_candidates_verified": verified_candidate_count == len(entries),
        "next_missing_candidate": next_missing_candidate,
        "next_unverified_candidate": next_unverified_candidate,
        "candidate_statuses": entries,
        "candidate_statuses_by_network": {
            entry["network"]: entry
            for entry in entries
        },
        "network_value_selection_candidate_template_commands_by_network": (
            network_value_selection_candidate_template_commands(manifest_path)
        ),
        "network_value_selection_candidate_template_json_commands_by_network": (
            network_value_selection_candidate_template_commands(
                manifest_path,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_commands_by_network": (
            network_value_selection_candidate_check_commands(manifest_path)
        ),
        "network_value_selection_candidate_check_json_commands_by_network": (
            network_value_selection_candidate_check_commands(
                manifest_path,
                json_output=True,
            )
        ),
        "value_selection_candidate_artifact_status_command": status_command,
        "value_selection_candidate_artifact_status_json_command": (
            status_json_command
        ),
        "commands": {
            "value_selection_candidate_artifact_status": status_command,
            "value_selection_candidate_artifact_status_json": (
                status_json_command
            ),
        },
    }


def value_selection_candidate_artifact_status_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile value-selection candidate artifact status:",
        f"  - manifest: {payload['manifest']}",
        f"  - status: {payload['status']}",
        (
            "  - supplied candidates: "
            f"{payload['provided_candidate_count']}/{payload['candidate_count']}"
        ),
        (
            "  - verified candidates: "
            f"{payload['verified_candidate_count']}/{payload['candidate_count']}"
        ),
        (
            "  - candidate errors: "
            f"{payload['error_candidate_count']}"
        ),
        (
            "  - all required candidates verified: "
            f"{yes_no(payload['all_required_candidates_verified'])}"
        ),
        (
            "  - next missing candidate: "
            f"{payload['next_missing_candidate'] or 'none'}"
        ),
        (
            "  - next unverified candidate: "
            f"{payload['next_unverified_candidate'] or 'none'}"
        ),
        (
            "  - value-selection candidate artifact status command: "
            + payload["value_selection_candidate_artifact_status_command"]
        ),
        (
            "  - value-selection candidate artifact status JSON command: "
            + payload["value_selection_candidate_artifact_status_json_command"]
        ),
    ]
    for entry in payload["candidate_statuses"]:
        lines.extend([
            f"  - {entry['network']} candidate status: {entry['status']}",
            f"    - supplied: {yes_no(entry['provided'])}",
            (
                "    - path: "
                + (entry["candidate_path"] or "<value_selection_candidate.json>")
            ),
            f"    - verified: {yes_no(entry['verified'])}",
            (
                "    - candidate check command: "
                + entry["candidate_check_command"]
            ),
            (
                "    - candidate check JSON command: "
                + entry["candidate_check_json_command"]
            ),
            (
                "    - candidate template command: "
                + entry["candidate_template_command"]
            ),
        ])
        if entry["candidate_size"] is not None:
            lines.extend([
                f"    - candidate size: {entry['candidate_size']}",
                f"    - candidate sha256: {entry['candidate_sha256']}",
                f"    - candidate network: {entry['candidate_network']}",
                (
                    "    - verified sections: "
                    f"{entry['verified_section_count']}/{entry['section_count']}"
                ),
            ])
        if entry["post_apply"] is not None:
            lines.extend([
                (
                    "    - post-apply remaining blockers: "
                    f"{entry['post_apply']['remaining_blocker_count']}"
                ),
                (
                    "    - post-apply next blocker: "
                    + (entry["post_apply"]["next_blocker"] or "none")
                ),
            ])
        if entry["error"]:
            lines.append(f"    - error: {entry['error']}")
    return "\n".join(lines)


def value_selection_candidate_artifact_status_text(
    manifest,
    manifest_path,
    main_candidate_path=None,
    testnet_candidate_path=None,
):
    return value_selection_candidate_artifact_status_text_from_payload(
        value_selection_candidate_artifact_status_payload(
            manifest,
            manifest_path,
            main_candidate_path,
            testnet_candidate_path,
        )
    )


def value_selection_candidate_artifact_status_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def value_selection_candidate_artifact_status_json_text(
    manifest,
    manifest_path,
    main_candidate_path=None,
    testnet_candidate_path=None,
):
    return value_selection_candidate_artifact_status_json_text_from_payload(
        value_selection_candidate_artifact_status_payload(
            manifest,
            manifest_path,
            main_candidate_path,
            testnet_candidate_path,
        )
    )


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


def command_path_arg(path):
    path = str(path)
    if path.startswith("<") and path.endswith(">"):
        return path
    return shell_quote(display_path(path))


def action_plan_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --action-plan {manifest_path}"


def readiness_summary_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --readiness-summary {manifest_path}"


def status_json_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --status-json {manifest_path}"


def value_selection_checklists_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --value-selection-checklists {manifest_path}"


def launch_gate_preflight_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --launch-gate-preflight {manifest_path}"


def operator_runbook_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --operator-runbook {manifest_path}"


def release_evidence_bundle_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --release-evidence-bundle {manifest_path}"


def release_evidence_bundle_json_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --json --release-evidence-bundle {manifest_path}"


def check_release_evidence_bundle_command(
    manifest_path,
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = "--require-release-evidence-bundle-match " if require_match else ""
    return (
        f"{tool_path} {json_flag}{require_match_flag}--check-release-evidence-bundle "
        f"{bundle_path} {manifest_path}"
    )


def release_evidence_bundle_gate_command(
    manifest_path,
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_bundle_command(
        manifest_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def release_evidence_archive_checklist_command(
    manifest_path,
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}--release-evidence-archive-checklist "
        f"{bundle_path} {manifest_path}"
    )


def check_release_evidence_archive_command(
    manifest_path,
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = "--require-release-evidence-archive-match " if require_match else ""
    return (
        f"{tool_path} {json_flag}{require_match_flag}--check-release-evidence-archive "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_archive_gate_command(
    manifest_path,
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_archive_command(
        manifest_path,
        archive_record_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def release_evidence_handoff_summary_command(
    manifest_path,
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}--release-evidence-handoff-summary "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_publication_index_template_command(
    manifest_path,
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}--release-evidence-publication-index-template "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def check_release_evidence_publication_index_command(
    manifest_path,
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = (
        "--require-release-evidence-publication-index-match "
        if require_match
        else ""
    )
    return (
        f"{tool_path} {json_flag}{require_match_flag}"
        "--check-release-evidence-publication-index "
        f"{publication_index_path} {archive_record_path} "
        f"{bundle_path} {manifest_path}"
    )


def release_evidence_publication_index_gate_command(
    manifest_path,
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_publication_index_command(
        manifest_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def release_evidence_publication_index_archive_checklist_command(
    manifest_path,
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        "--release-evidence-publication-index-archive-checklist "
        f"{publication_index_path} {archive_record_path} "
        f"{bundle_path} {manifest_path}"
    )


def check_release_evidence_publication_index_archive_command(
    manifest_path,
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = (
        "--require-release-evidence-publication-index-archive-match "
        if require_match
        else ""
    )
    return (
        f"{tool_path} {json_flag}{require_match_flag}"
        "--check-release-evidence-publication-index-archive "
        f"{publication_index_archive_record_path} {publication_index_path} "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_publication_index_archive_gate_command(
    manifest_path,
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_publication_index_archive_command(
        manifest_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def release_evidence_publication_index_archive_handoff_summary_command(
    manifest_path,
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        "--release-evidence-publication-index-archive-handoff-summary "
        f"{publication_index_archive_record_path} {publication_index_path} "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_publication_closeout_checklist_command(
    manifest_path,
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        "--release-evidence-publication-closeout-checklist "
        f"{publication_index_archive_record_path} {publication_index_path} "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def check_release_evidence_publication_closeout_command(
    manifest_path,
    closeout_path="<release_evidence_publication_closeout.json>",
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    closeout_path = command_path_arg(closeout_path)
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = (
        "--require-release-evidence-publication-closeout-match "
        if require_match
        else ""
    )
    return (
        f"{tool_path} {json_flag}{require_match_flag}"
        "--check-release-evidence-publication-closeout "
        f"{closeout_path} {publication_index_archive_record_path} "
        f"{publication_index_path} {archive_record_path} "
        f"{bundle_path} {manifest_path}"
    )


def release_evidence_publication_closeout_gate_command(
    manifest_path,
    closeout_path="<release_evidence_publication_closeout.json>",
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_publication_closeout_command(
        manifest_path,
        closeout_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def check_release_evidence_publication_closeout_archive_command(
    manifest_path,
    closeout_archive_record_path=(
        "<release_evidence_publication_closeout_archive_record.json>"
    ),
    closeout_path="<release_evidence_publication_closeout.json>",
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
    require_match=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    closeout_archive_record_path = command_path_arg(closeout_archive_record_path)
    closeout_path = command_path_arg(closeout_path)
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    require_match_flag = (
        "--require-release-evidence-publication-closeout-archive-match "
        if require_match
        else ""
    )
    return (
        f"{tool_path} {json_flag}{require_match_flag}"
        "--check-release-evidence-publication-closeout-archive "
        f"{closeout_archive_record_path} {closeout_path} "
        f"{publication_index_archive_record_path} {publication_index_path} "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_publication_closeout_archive_gate_command(
    manifest_path,
    closeout_archive_record_path=(
        "<release_evidence_publication_closeout_archive_record.json>"
    ),
    closeout_path="<release_evidence_publication_closeout.json>",
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    return check_release_evidence_publication_closeout_archive_command(
        manifest_path,
        closeout_archive_record_path,
        closeout_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        json_output=json_output,
        require_match=True,
    )


def release_evidence_publication_closeout_archive_handoff_summary_command(
    manifest_path,
    closeout_archive_record_path=(
        "<release_evidence_publication_closeout_archive_record.json>"
    ),
    closeout_path="<release_evidence_publication_closeout.json>",
    publication_index_archive_record_path=(
        "<release_evidence_publication_index_archive_record.json>"
    ),
    publication_index_path="<release_evidence_publication_index.json>",
    archive_record_path="<release_evidence_archive_record.json>",
    bundle_path="<release_evidence_bundle.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    closeout_archive_record_path = command_path_arg(closeout_archive_record_path)
    closeout_path = command_path_arg(closeout_path)
    publication_index_archive_record_path = command_path_arg(
        publication_index_archive_record_path
    )
    publication_index_path = command_path_arg(publication_index_path)
    archive_record_path = command_path_arg(archive_record_path)
    bundle_path = command_path_arg(bundle_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        "--release-evidence-publication-closeout-archive-handoff-summary "
        f"{closeout_archive_record_path} {closeout_path} "
        f"{publication_index_archive_record_path} {publication_index_path} "
        f"{archive_record_path} {bundle_path} {manifest_path}"
    )


def release_evidence_publication_status_command(
    manifest_path,
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        f"--release-evidence-publication-status {manifest_path}"
    )


def release_evidence_publication_artifact_status_command(
    manifest_path,
    bundle_path=None,
    archive_record_path=None,
    publication_index_path=None,
    publication_index_archive_record_path=None,
    closeout_path=None,
    closeout_archive_record_path=None,
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    args = [str(tool_path)]
    if json_output:
        args.append("--json")
    args.append("--release-evidence-publication-artifact-status")
    artifact_paths = (
        bundle_path,
        archive_record_path,
        publication_index_path,
        publication_index_archive_record_path,
        closeout_path,
        closeout_archive_record_path,
    )
    for (_, flag, _), artifact_path in zip(
        RELEASE_EVIDENCE_PUBLICATION_ARTIFACT_PATH_FLAGS,
        artifact_paths,
    ):
        if artifact_path is None:
            continue
        args.extend([flag, command_path_arg(artifact_path)])
    args.append(manifest_path)
    return " ".join(args)


def next_action_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --next-action {manifest_path}"


def snapshot_audit_handoff_command(manifest_path, network):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --snapshot-audit-handoff {network} {manifest_path}"


def snapshot_audit_handoffs_command(manifest_path):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --snapshot-audit-handoffs {manifest_path}"


def status_command_fields(manifest_path):
    return {
        "action_plan": action_plan_command(manifest_path),
        "next_action": next_action_command(manifest_path),
        "readiness_summary": readiness_summary_command(manifest_path),
        "status_json": status_json_command(manifest_path),
    }


def network_readiness_summary_command(manifest_path, network):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --network-readiness-summary {network} {manifest_path}"


def network_handoff_bundle_command(manifest_path, network):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --network-handoff-bundle {network} {manifest_path}"


def network_later_blockers_command(manifest_path, network):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --network-later-blockers {network} {manifest_path}"


def network_value_selection_later_blockers_command(manifest_path, network):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --network-value-selection-later-blockers {network} {manifest_path}"


def network_value_selection_candidate_template_command(manifest_path, network, json_output=False):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        f"--network-value-selection-candidate-template {network} {manifest_path}"
    )


def network_value_selection_candidate_check_command(
    manifest_path,
    network,
    candidate_path="<value_selection_candidate.json>",
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    candidate_path = command_path_arg(candidate_path)
    json_flag = "--json " if json_output else ""
    return (
        f"{tool_path} {json_flag}"
        f"--check-network-value-selection-candidate "
        f"{network} {candidate_path} {manifest_path}"
    )


def value_selection_candidate_artifact_status_command(
    manifest_path,
    main_candidate_path=None,
    testnet_candidate_path=None,
    json_output=False,
):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    args = [str(tool_path)]
    if json_output:
        args.append("--json")
    args.append("--value-selection-candidate-artifact-status")
    if main_candidate_path is not None:
        args.extend([
            "--main-value-selection-candidate",
            command_path_arg(main_candidate_path),
        ])
    if testnet_candidate_path is not None:
        args.extend([
            "--testnet-value-selection-candidate",
            command_path_arg(testnet_candidate_path),
        ])
    args.append(manifest_path)
    return " ".join(args)


def blocker_type_readiness_summary_command(manifest_path, blocker_type):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --blocker-type-readiness-summary {blocker_type} {manifest_path}"


def blocker_type_later_blockers_command(manifest_path, blocker_type):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --blocker-type-later-blockers {blocker_type} {manifest_path}"


def readiness_gate_summary_command(manifest_path, readiness_gate):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --readiness-gate-summary {readiness_gate} {manifest_path}"


def readiness_gate_later_blockers_command(manifest_path, readiness_gate):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --readiness-gate-later-blockers {readiness_gate} {manifest_path}"


def blocker_readiness_summary_command(manifest_path, blocker_id):
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    manifest_path = shell_quote(display_path(manifest_path))
    return f"{tool_path} --blocker-readiness-summary {blocker_id} {manifest_path}"


def network_readiness_summary_commands(manifest_path):
    return {
        network: network_readiness_summary_command(manifest_path, network)
        for network in NETWORKS
    }


def snapshot_audit_handoff_commands(manifest_path):
    return {
        network: snapshot_audit_handoff_command(manifest_path, network)
        for network in NETWORKS
    }


def network_handoff_bundle_commands(manifest_path):
    return {
        network: network_handoff_bundle_command(manifest_path, network)
        for network in NETWORKS
    }


def network_later_blockers_commands(manifest_path):
    return {
        network: network_later_blockers_command(manifest_path, network)
        for network in NETWORKS
    }


def network_value_selection_later_blockers_commands(manifest_path):
    return {
        network: network_value_selection_later_blockers_command(manifest_path, network)
        for network in NETWORKS
    }


def network_value_selection_candidate_template_commands(manifest_path, json_output=False):
    return {
        network: network_value_selection_candidate_template_command(
            manifest_path,
            network,
            json_output=json_output,
        )
        for network in NETWORKS
    }


def network_value_selection_candidate_check_commands(manifest_path, json_output=False):
    return {
        network: network_value_selection_candidate_check_command(
            manifest_path,
            network,
            json_output=json_output,
        )
        for network in NETWORKS
    }


def blocker_type_readiness_summary_commands(manifest_path):
    return {
        blocker_type: blocker_type_readiness_summary_command(manifest_path, blocker_type)
        for blocker_type in BLOCKER_TYPES
    }


def blocker_type_later_blockers_commands(manifest_path):
    return {
        blocker_type: blocker_type_later_blockers_command(manifest_path, blocker_type)
        for blocker_type in BLOCKER_TYPES
    }


def readiness_gate_summary_commands(manifest_path):
    return {
        gate: readiness_gate_summary_command(manifest_path, gate)
        for gate in READINESS_GATES
    }


def readiness_gate_later_blockers_commands(manifest_path):
    return {
        gate: readiness_gate_later_blockers_command(manifest_path, gate)
        for gate in READINESS_GATES
    }


def blocker_readiness_summary_commands(manifest_path, blockers):
    return {
        blocker: blocker_readiness_summary_command(manifest_path, blocker)
        for blocker in blockers
    }


def later_blocker_readiness_summary_commands_by_readiness_gate(manifest_path, blockers):
    return {
        gate: blocker_readiness_summary_commands(manifest_path, gate_blockers)
        for gate, gate_blockers in later_blockers_by_readiness_gate(blockers).items()
    }


def later_blocker_readiness_summary_command_counts_by_readiness_gate(manifest_path, blockers):
    return {
        gate: len(commands)
        for gate, commands in later_blocker_readiness_summary_commands_by_readiness_gate(
            manifest_path,
            blockers,
        ).items()
    }


def blocker_readiness_summary_command_summary(manifest_path, blockers):
    if not blockers:
        return "none"
    return "; ".join(
        f"{blocker}={blocker_readiness_summary_command(manifest_path, blocker)}"
        for blocker in blockers
    )


def network_readiness_summary_command_summary(manifest_path):
    commands = network_readiness_summary_commands(manifest_path)
    return "; ".join(f"{network}={commands[network]}" for network in NETWORKS)


def snapshot_audit_handoff_command_summary(manifest_path):
    commands = snapshot_audit_handoff_commands(manifest_path)
    return "; ".join(f"{network}={commands[network]}" for network in NETWORKS)


def network_handoff_bundle_command_summary(manifest_path):
    commands = network_handoff_bundle_commands(manifest_path)
    return "; ".join(f"{network}={commands[network]}" for network in NETWORKS)


def network_later_blockers_command_summary(manifest_path):
    commands = network_later_blockers_commands(manifest_path)
    return "; ".join(f"{network}={commands[network]}" for network in NETWORKS)


def network_value_selection_later_blockers_command_summary(manifest_path):
    commands = network_value_selection_later_blockers_commands(manifest_path)
    return "; ".join(f"{network}={commands[network]}" for network in NETWORKS)


def blocker_type_readiness_summary_command_summary(manifest_path):
    commands = blocker_type_readiness_summary_commands(manifest_path)
    return "; ".join(
        f"{blocker_type}={commands[blocker_type]}"
        for blocker_type in BLOCKER_TYPES
    )


def blocker_type_later_blockers_command_summary(manifest_path):
    commands = blocker_type_later_blockers_commands(manifest_path)
    return "; ".join(
        f"{blocker_type}={commands[blocker_type]}"
        for blocker_type in BLOCKER_TYPES
    )


def readiness_gate_summary_command_summary(manifest_path):
    commands = readiness_gate_summary_commands(manifest_path)
    return "; ".join(f"{gate}={commands[gate]}" for gate in READINESS_GATES)


def readiness_gate_later_blockers_command_summary(manifest_path):
    commands = readiness_gate_later_blockers_commands(manifest_path)
    return "; ".join(f"{gate}={commands[gate]}" for gate in READINESS_GATES)


def blocker_action_commands(blocker_id, manifest_path):
    network, blocker = blocker_id.split(".", 1)
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    readiness_command = f"{tool_path} --readiness-summary {manifest_path}"
    network_summary_command = (
        f"{tool_path} --network-readiness-summary {network} {manifest_path}"
    )
    blocker_type_summary_command = (
        f"{tool_path} --blocker-type-readiness-summary {blocker} {manifest_path}"
    )
    gate_summary_command = (
        f"{tool_path} --readiness-gate-summary "
        f"{blocker_type_readiness_gate(blocker)} {manifest_path}"
    )
    blocker_summary_command = (
        f"{tool_path} --blocker-readiness-summary {blocker_id} {manifest_path}"
    )
    if blocker == "litecoin_snapshot":
        return {
            "template_command": (
                f"{tool_path} --snapshot-audit-template {network} {manifest_path}"
            ),
            "check_command": (
                f"{tool_path} --check-snapshot-audit {network} "
                f"<snapshot_audit.json> {manifest_path}"
            ),
            "preflight_command": (
                f"{tool_path} --snapshot-audit-preflight {network} "
                f"<snapshot_audit.json> {manifest_path}"
            ),
            "apply_command": (
                f"{tool_path} --set-snapshot-audit {network} "
                f"<snapshot_audit.json> --in-place {manifest_path}"
            ),
            "snapshot_audit_handoff_command": (
                f"{tool_path} --snapshot-audit-handoff {network} {manifest_path}"
            ),
            "readiness_summary_command": readiness_command,
            "network_readiness_summary_command": network_summary_command,
            "blocker_type_readiness_summary_command": blocker_type_summary_command,
            "readiness_gate_summary_command": gate_summary_command,
            "blocker_readiness_summary_command": blocker_summary_command,
        }
    if blocker == "auxpow_chain_id":
        return {
            "template_command": None,
            "check_command": (
                f"{tool_path} --check-auxpow {network} <chain_id> {manifest_path}"
            ),
            "preflight_command": None,
            "apply_command": (
                f"{tool_path} --set-auxpow {network} <chain_id> --in-place {manifest_path}"
            ),
            "snapshot_audit_handoff_command": None,
            "readiness_summary_command": readiness_command,
            "network_readiness_summary_command": network_summary_command,
            "blocker_type_readiness_summary_command": blocker_type_summary_command,
            "readiness_gate_summary_command": gate_summary_command,
            "blocker_readiness_summary_command": blocker_summary_command,
        }
    if blocker == "public_network_identity":
        return {
            "template_command": None,
            "check_command": (
                f"{tool_path} --check-identity {network} <message_start> <port> "
                f"<pubkey> <script> <script2> <secret> <xpub> <xprv> "
                f"<bech32_hrp> <mweb_hrp> {manifest_path}"
            ),
            "preflight_command": None,
            "apply_command": (
                f"{tool_path} --set-identity {network} <message_start> <port> "
                f"<pubkey> <script> <script2> <secret> <xpub> <xprv> "
                f"<bech32_hrp> <mweb_hrp> --in-place {manifest_path}"
            ),
            "snapshot_audit_handoff_command": None,
            "readiness_summary_command": readiness_command,
            "network_readiness_summary_command": network_summary_command,
            "blocker_type_readiness_summary_command": blocker_type_summary_command,
            "readiness_gate_summary_command": gate_summary_command,
            "blocker_readiness_summary_command": blocker_summary_command,
        }
    if blocker == "dns_seeds":
        return {
            "template_command": None,
            "check_command": (
                f"{tool_path} --check-dns-seeds {network} "
                f"<seed1.hostname>,<seed2.hostname> {manifest_path}"
            ),
            "preflight_command": None,
            "apply_command": (
                f"{tool_path} --set-dns-seeds {network} "
                f"<seed1.hostname>,<seed2.hostname> --in-place {manifest_path}"
            ),
            "snapshot_audit_handoff_command": None,
            "readiness_summary_command": readiness_command,
            "network_readiness_summary_command": network_summary_command,
            "blocker_type_readiness_summary_command": blocker_type_summary_command,
            "readiness_gate_summary_command": gate_summary_command,
            "blocker_readiness_summary_command": blocker_summary_command,
        }
    raise ValueError(f"unknown blocker id: {blocker_id}")


def blocker_json_check_command(blocker_id, manifest_path):
    network, blocker = blocker_id.split(".", 1)
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    if blocker == "auxpow_chain_id":
        return (
            f"{tool_path} --json --check-auxpow {network} "
            f"<chain_id> {manifest_path}"
        )
    if blocker == "public_network_identity":
        return (
            f"{tool_path} --json --check-identity {network} "
            f"<message_start> <port> <pubkey> <script> <script2> <secret> "
            f"<xpub> <xprv> <bech32_hrp> <mweb_hrp> {manifest_path}"
        )
    if blocker == "dns_seeds":
        return (
            f"{tool_path} --json --check-dns-seeds {network} "
            f"<seed1.hostname>,<seed2.hostname> {manifest_path}"
        )
    return None


def blocker_json_check_commands(blockers, manifest_path):
    return {
        blocker: blocker_json_check_command(blocker, manifest_path)
        for blocker in blockers
    }


def blocker_template_fields(blocker_type):
    if blocker_type == "litecoin_snapshot":
        return list(SNAPSHOT_AUDIT_SUMMARY_FIELDS)
    return None


def blocker_candidate_constraints(blocker_type):
    if blocker_type == "litecoin_snapshot":
        return {
            "audit_summary_fields": list(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
            "audit_summary_max_bytes": SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES,
            "audit_summary_must_be_utf8_json_object": True,
            "audit_summary_rejects_duplicate_fields": True,
            "audit_summary_field_order_must_match_template": True,
            "positive_integer_fields": [
                "height",
                "coins",
                "base_nchaintx",
                "snapshot_file_size",
            ],
            "hex256_fields": [
                "block_hash",
                "import_hash",
                "snapshot_hash",
                "snapshot_file_sha256",
            ],
            "hex256_length": 64,
            "hex256_must_be_lowercase": True,
            "hex256_must_not_be_null_uint256": True,
            "source_chain_by_network": dict(SNAPSHOT_SOURCE_CHAINS),
            "snapshot_file_must_be_absolute_normalized_path": True,
            "snapshot_file_must_not_be_placeholder": True,
            "snapshot_file_must_not_contain_control_characters": True,
            "snapshot_file_must_be_regular_file": True,
            "snapshot_file_must_not_be_symlink": True,
            "snapshot_file_parent_must_not_be_symlink": True,
            "snapshot_file_must_differ_from_audit_summary": True,
            "snapshot_file_must_remain_stable_during_verification": True,
            "snapshot_file_size_must_match_artifact": True,
            "snapshot_file_sha256_must_match_artifact": True,
            "total_amount_must_be_positive_decimal_8_places": True,
            "total_amount_max": SNAPSHOT_MAX_MONEY_TEXT,
        }
    if blocker_type == "auxpow_chain_id":
        return {
            "chain_id_min": 1,
            "chain_id_max": 0x7fff,
            "placeholder_chain_id": PLACEHOLDER_AUXPOW_CHAIN_ID,
            "placeholder_chain_id_hex": f"0x{PLACEHOLDER_AUXPOW_CHAIN_ID:x}",
            "forbidden_parent_version_chain_id_range": [
                FORBIDDEN_PARENT_VERSION_CHAIN_IDS.start,
                FORBIDDEN_PARENT_VERSION_CHAIN_IDS.stop - 1,
            ],
            "start_height": 1,
            "strict_chain_id": True,
        }
    if blocker_type == "public_network_identity":
        return {
            "message_start_bytes": 4,
            "message_start_must_be_non_printable": True,
            "message_start_must_not_be_all_zero": True,
            "message_start_must_not_be_all_ff": True,
            "forbidden_litecoin_message_starts": [
                list(message_start)
                for message_start in sorted(LITECOIN_MESSAGE_STARTS)
            ],
            "default_port_min": 1025,
            "default_port_max": 65535,
            "forbidden_litecoin_default_ports": sorted(LITECOIN_DEFAULT_PORTS),
            "base58_prefix_lengths": {
                field: expected_len
                for field, expected_len in BASE58_FIELDS
            },
            "forbidden_litecoin_base58_prefixes": [
                list(prefix)
                for prefix in sorted(LITECOIN_BASE58_PREFIXES)
            ],
            "bech32_hrp_max_length": MAX_BECH32_HRP_LENGTH,
            "hrp_must_be_lowercase_printable_ascii": True,
            "forbidden_litecoin_hrps": sorted(LITECOIN_HRPS),
            "mweb_hrp_must_differ_from_bech32_hrp": True,
            "fixed_seeds_must_remain_empty": True,
        }
    if blocker_type == "dns_seeds":
        return {
            "dns_seed_count_min": 1,
            "dns_seed_host_max_length": 253,
            "dns_seed_label_max_length": 63,
            "dns_seed_min_labels": 2,
            "dns_seed_must_be_lowercase": True,
            "dns_seed_allowed_label_pattern": "[a-z0-9-]+",
            "dns_seed_must_not_start_or_end_with_hyphen_or_dot": True,
            "dns_seed_final_label_must_contain_letter": True,
            "reserved_dns_seed_suffixes": sorted(RESERVED_DNS_SEED_SUFFIXES),
            "forbidden_litecoin_dns_seed_markers": sorted(LITECOIN_DNS_SEED_MARKERS),
            "dns_seed_hostnames_must_be_unique": True,
            "dns_seed_hostnames_must_differ_across_networks": True,
        }
    return None


def next_blocker_command(blocker_id, manifest_path):
    network, blocker = blocker_id.split(".", 1)
    commands = blocker_action_commands(blocker_id, manifest_path)
    if blocker == "litecoin_snapshot":
        return (
            "select and verify the final Litecoin snapshot, generate the required audit JSON shape with "
            f"{commands['template_command']}, "
            "fill it with final audited constants, run "
            f"{commands['check_command']}, run {commands['preflight_command']}, "
            f"then run {commands['apply_command']}"
        )
    if blocker == "auxpow_chain_id":
        return (
            "select a non-Litecoin AuxPoW child chain id, run "
            f"{commands['check_command']}, then run {commands['apply_command']}"
        )
    if blocker == "public_network_identity":
        return (
            "select non-Litecoin public identity values, run "
            f"{commands['check_command']}, then run {commands['apply_command']}"
        )
    if blocker == "dns_seeds":
        return (
            "provision zkCoin DNS seed infrastructure, run "
            f"{commands['check_command']}, then run {commands['apply_command']}"
        )
    raise ValueError(f"unknown blocker id: {blocker_id}")


def append_blocker_handoff_command_lines(lines, commands, prefix):
    if commands["template_command"] is not None:
        lines.append(f"{prefix}template command: {commands['template_command']}")
    lines.append(f"{prefix}check command: {commands['check_command']}")
    if commands["preflight_command"] is not None:
        lines.append(f"{prefix}preflight command: {commands['preflight_command']}")
    lines.append(f"{prefix}apply command: {commands['apply_command']}")
    if commands.get("snapshot_audit_handoff_command") is not None:
        lines.append(
            f"{prefix}snapshot audit handoff command: "
            f"{commands['snapshot_audit_handoff_command']}"
        )


def append_blocker_command_lines(lines, commands, prefix):
    append_blocker_handoff_command_lines(lines, commands, prefix)
    lines.append(
        f"{prefix}readiness summary command: {commands['readiness_summary_command']}"
    )
    lines.append(
        f"{prefix}network readiness summary command: "
        f"{commands['network_readiness_summary_command']}"
    )
    lines.append(
        f"{prefix}blocker type readiness summary command: "
        f"{commands['blocker_type_readiness_summary_command']}"
    )
    lines.append(
        f"{prefix}readiness gate summary command: "
        f"{commands['readiness_gate_summary_command']}"
    )
    lines.append(
        f"{prefix}blocker readiness summary command: "
        f"{commands['blocker_readiness_summary_command']}"
    )


def append_blocker_field_lines(lines, entry, prefix, item_prefix):
    lines.append(f"{prefix}blocked field paths:")
    for field in entry["fields"]:
        lines.append(f"{item_prefix}{field}")


def next_action_text(manifest, manifest_path):
    manifest_path = shell_quote(display_path(manifest_path))
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    blockers = ordered_unresolved_blocker_ids(manifest)
    lines = ["zkCoin public launch profile next action:"]
    if blockers:
        next_blocker = blockers[0]
        lines.append(f"  - next blocker: {next_blocker}")
        lines.append(f"  - action: {next_blocker_command(next_blocker, manifest_path)}")
        append_blocker_command_lines(
            lines,
            blocker_action_commands(next_blocker, manifest_path),
            "  - ",
        )
        if len(blockers) > 1:
            lines.append("  - later blockers: " + ", ".join(blockers[1:]))
            lines.append(
                "  - later blocker readiness summary commands: "
                + "; ".join(
                    "{}={}".format(
                        blocker,
                        blocker_action_commands(blocker, manifest_path)[
                            "blocker_readiness_summary_command"
                        ],
                    )
                    for blocker in blockers[1:]
                )
            )
        return "\n".join(lines)

    if manifest.get("status") == "blocked":
        lines.append("  - next step: mark the complete manifest ready for chainparams")
        lines.append(f"  - command: {tool_path} --mark-ready --in-place {manifest_path}")
        return "\n".join(lines)

    lines.append("  - next step: apply the ready manifest to chainparams and verify sync")
    lines.append(f"  - emit: {tool_path} --emit-chainparams {manifest_path}")
    lines.append(f"  - verify: {tool_path} --check-chainparams src/chainparams.cpp {manifest_path}")
    return "\n".join(lines)


def blocker_action_entry(index, blocker, blockers, manifest_path):
    network, blocker_type = blocker.split(".", 1)
    network_blockers = items_by_network(blockers)[network]
    blocker_type_blockers = blockers_by_blocker_type(blockers)[blocker_type]
    template_fields = blocker_template_fields(blocker_type)
    candidate_constraints = blocker_candidate_constraints(blocker_type)
    return {
        "step": index,
        "network_step": network_blockers.index(blocker) + 1,
        "network_step_count": len(network_blockers),
        "blocker_type_step": blocker_type_blockers.index(blocker) + 1,
        "blocker_type_step_count": len(blocker_type_blockers),
        "kind": "blocker",
        "id": blocker,
        "network": network,
        "blocker_type": blocker_type,
        "action": next_blocker_command(blocker, manifest_path),
        "template_fields": template_fields,
        "template_field_count": len(template_fields) if template_fields is not None else 0,
        "candidate_constraints": candidate_constraints,
        "candidate_constraint_count": len(candidate_constraints) if candidate_constraints is not None else 0,
        **blocker_action_commands(blocker, manifest_path),
    }


def action_plan_entries(manifest, manifest_path):
    manifest_path = shell_quote(display_path(manifest_path))
    tool_path = Path("contrib/devtools/zkcoin_public_launch_profile.py")
    blockers = ordered_unresolved_blocker_ids(manifest)
    if blockers:
        return [
            blocker_action_entry(index, blocker, blockers, manifest_path)
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
            append_blocker_command_lines(lines, entry, "     ")
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


def readiness_summary_text(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    blocker_type_progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    readiness_gate_progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    ready_for_chainparams = manifest.get("status") == "ready-for-chainparams" and not blockers
    next_action = actions[0] if actions else None
    lines = [
        "zkCoin public launch profile readiness summary:",
        f"  - status: {manifest.get('status')}",
        f"  - ready for chainparams: {yes_no(ready_for_chainparams)}",
        f"  - action plan command: {action_plan_command(manifest_path)}",
        f"  - next action command: {next_action_command(manifest_path)}",
        f"  - readiness summary command: {readiness_summary_command(manifest_path)}",
        f"  - status JSON command: {status_json_command(manifest_path)}",
        f"  - value-selection checklists command: {value_selection_checklists_command(manifest_path)}",
        f"  - snapshot audit handoffs command: {snapshot_audit_handoffs_command(manifest_path)}",
        f"  - launch-gate preflight command: {launch_gate_preflight_command(manifest_path)}",
        f"  - operator runbook command: {operator_runbook_command(manifest_path)}",
        f"  - release evidence bundle command: {release_evidence_bundle_command(manifest_path)}",
        f"  - release evidence bundle JSON command: {release_evidence_bundle_json_command(manifest_path)}",
        f"  - check release evidence bundle command: {check_release_evidence_bundle_command(manifest_path)}",
        f"  - check release evidence bundle JSON command: {check_release_evidence_bundle_command(manifest_path, json_output=True)}",
        f"  - release evidence bundle gate command: {release_evidence_bundle_gate_command(manifest_path)}",
        f"  - release evidence bundle gate JSON command: {release_evidence_bundle_gate_command(manifest_path, json_output=True)}",
        f"  - release evidence archive checklist command: {release_evidence_archive_checklist_command(manifest_path)}",
        f"  - release evidence archive checklist JSON command: {release_evidence_archive_checklist_command(manifest_path, json_output=True)}",
        f"  - check release evidence archive command: {check_release_evidence_archive_command(manifest_path)}",
        f"  - check release evidence archive JSON command: {check_release_evidence_archive_command(manifest_path, json_output=True)}",
        f"  - release evidence archive gate command: {release_evidence_archive_gate_command(manifest_path)}",
        f"  - release evidence archive gate JSON command: {release_evidence_archive_gate_command(manifest_path, json_output=True)}",
        f"  - release evidence handoff summary command: {release_evidence_handoff_summary_command(manifest_path)}",
        f"  - release evidence handoff summary JSON command: {release_evidence_handoff_summary_command(manifest_path, json_output=True)}",
        f"  - release evidence publication index template command: {release_evidence_publication_index_template_command(manifest_path)}",
        f"  - release evidence publication index template JSON command: {release_evidence_publication_index_template_command(manifest_path, json_output=True)}",
        f"  - check release evidence publication index command: {check_release_evidence_publication_index_command(manifest_path)}",
        f"  - check release evidence publication index JSON command: {check_release_evidence_publication_index_command(manifest_path, json_output=True)}",
        f"  - release evidence publication index gate command: {release_evidence_publication_index_gate_command(manifest_path)}",
        f"  - release evidence publication index gate JSON command: {release_evidence_publication_index_gate_command(manifest_path, json_output=True)}",
        f"  - blocked networks: {list_summary(blocked_networks(network_progress))}",
        f"  - ready networks: {list_summary(ready_networks(network_progress))}",
        f"  - blocked networks by blocker type: {blocker_type_list_summary(blocked_networks_by_blocker_type(blocked_field_groups))}",
        f"  - ready networks by blocker type: {blocker_type_list_summary(ready_networks_by_blocker_type(blocked_field_groups))}",
        f"  - blocker types by readiness gate: {readiness_gate_list_summary(blocker_types_by_readiness_gate())}",
        f"  - unresolved blockers: {len(blockers)}",
        f"  - unresolved blockers by network: {network_count_summary(item_counts_by_network(blockers))}",
        f"  - unresolved blockers by blocker type: {blocker_type_count_summary(blocker_counts_by_blocker_type(blockers))}",
        f"  - unresolved blockers by readiness gate: {readiness_gate_count_summary(blocker_counts_by_readiness_gate(blockers))}",
        f"  - unresolved blockers by network and blocker type: {network_blocker_type_count_summary(blocker_counts_by_network_and_blocker_type(blockers))}",
        f"  - blocked fields: {len(check.blockers)}",
        f"  - blocked fields by network: {network_count_summary(item_counts_by_network(check.blockers))}",
        f"  - blocked fields by blocker type: {blocker_type_count_summary(blocked_field_counts_by_blocker_type(blocked_field_groups))}",
        f"  - blocked field groups by readiness gate: {readiness_gate_count_summary(blocked_field_group_counts_by_readiness_gate(blocked_field_groups))}",
        f"  - blocked fields by readiness gate: {readiness_gate_count_summary(blocked_field_counts_by_readiness_gate(blocked_field_groups))}",
        f"  - blocked fields by network and blocker type: {network_blocker_type_count_summary(blocked_field_counts_by_network_and_blocker_type(blocked_field_groups))}",
        f"  - next blockers by network: {network_next_blocker_summary(network_progress)}",
        f"  - next blockers by readiness gate: {readiness_gate_value_summary(next_blockers_by_readiness_gate(blocked_field_groups))}",
        f"  - next blocker fields by readiness gate: {readiness_gate_count_summary(next_blocked_field_counts_by_readiness_gate(blocked_field_groups))}",
        f"  - later blockers by readiness gate: {readiness_gate_list_summary(later_blockers_by_readiness_gate(blockers))}",
        f"  - later blocker fields by readiness gate: {readiness_gate_count_summary(later_blocked_field_counts_by_readiness_gate(blocked_field_groups))}",
        f"  - next blockers by network and blocker type: {network_blocker_type_value_summary(next_blockers_by_network_and_blocker_type(blocked_field_groups))}",
        f"  - next blocker fields by network: {network_next_blocker_field_count_summary(network_progress)}",
        f"  - next blocker fields by network and blocker type: {network_blocker_type_count_summary(next_blocked_field_counts_by_network_and_blocker_type(blocked_field_groups))}",
        f"  - next blockers by blocker type: {blocker_type_next_blocker_summary(blocker_type_progress)}",
        f"  - next blocker networks by blocker type: {blocker_type_next_blocker_network_summary(blocker_type_progress)}",
        f"  - next blocker fields by blocker type: {blocker_type_next_blocker_field_count_summary(blocker_type_progress)}",
        f"  - next template commands by network: {network_next_blocker_command_summary(network_progress, 'template_command')}",
        f"  - next check commands by network: {network_next_blocker_command_summary(network_progress, 'check_command')}",
        f"  - next preflight commands by network: {network_next_blocker_command_summary(network_progress, 'preflight_command')}",
        f"  - next apply commands by network: {network_next_blocker_command_summary(network_progress, 'apply_command')}",
        f"  - next snapshot audit handoff commands by network: {network_next_blocker_command_summary(network_progress, 'snapshot_audit_handoff_command')}",
        f"  - next template commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'template_command')}",
        f"  - next check commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'check_command')}",
        f"  - next preflight commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'preflight_command')}",
        f"  - next apply commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'apply_command')}",
        f"  - next snapshot audit handoff commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'snapshot_audit_handoff_command')}",
        f"  - next network readiness summary commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'network_readiness_summary_command')}",
        f"  - next blocker type readiness summary commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'blocker_type_readiness_summary_command')}",
        f"  - next preflight commands by readiness gate: {readiness_gate_next_action_command_summary(readiness_gate_progress, 'preflight_command')}",
        f"  - next snapshot audit handoff commands by readiness gate: {readiness_gate_next_action_command_summary(readiness_gate_progress, 'snapshot_audit_handoff_command')}",
        f"  - next readiness gate summary commands by readiness gate: {readiness_gate_next_action_command_summary(readiness_gate_progress, 'readiness_gate_summary_command')}",
        f"  - next blocker readiness summary commands by blocker type: {blocker_type_next_action_command_summary(blocker_type_progress, 'blocker_readiness_summary_command')}",
        f"  - later blocker readiness summary commands by readiness gate: {readiness_gate_blocker_command_summary(manifest_path, later_blockers_by_readiness_gate(blockers))}",
        f"  - next blocker type readiness summary commands by network: {network_next_blocker_command_summary(network_progress, 'blocker_type_readiness_summary_command')}",
        f"  - next blocker readiness summary commands by network: {network_next_blocker_command_summary(network_progress, 'blocker_readiness_summary_command')}",
        f"  - snapshot audit handoff commands by network: {snapshot_audit_handoff_command_summary(manifest_path)}",
        f"  - network readiness summary commands by network: {network_readiness_summary_command_summary(manifest_path)}",
        f"  - network handoff bundle commands by network: {network_handoff_bundle_command_summary(manifest_path)}",
        f"  - network later blocker commands by network: {network_later_blockers_command_summary(manifest_path)}",
        f"  - network value-selection later blocker commands by network: {network_value_selection_later_blockers_command_summary(manifest_path)}",
        f"  - blocker type readiness summary commands by blocker type: {blocker_type_readiness_summary_command_summary(manifest_path)}",
        f"  - blocker type later blocker commands by blocker type: {blocker_type_later_blockers_command_summary(manifest_path)}",
        f"  - readiness gate summary commands by readiness gate: {readiness_gate_summary_command_summary(manifest_path)}",
        f"  - readiness gate later blocker commands by readiness gate: {readiness_gate_later_blockers_command_summary(manifest_path)}",
    ]

    if blockers:
        lines.append(f"  - next blocker: {next_action['id']}")
        lines.append(f"  - next blocker fields: {next_action['field_count']}")
        append_blocker_field_lines(lines, next_action, "  - ", "    - ")
        append_blocker_command_lines(lines, next_action, "  - ")
        if len(blockers) > 1:
            lines.append("  - later blockers: " + ", ".join(blockers[1:]))
            lines.append(
                "  - later blocker readiness summary commands: "
                + blocker_readiness_summary_command_summary(manifest_path, blockers[1:])
            )
        return "\n".join(lines)

    if manifest.get("status") == "blocked":
        lines.append("  - next step: mark-ready")
        lines.append(f"  - command: {next_action['command']}")
        return "\n".join(lines)

    lines.append("  - next step: apply ready manifest to chainparams and verify sync")
    for action in actions:
        lines.append(f"  - {action['id']}: {action['command']}")
    return "\n".join(lines)


def readiness_summary_json_payload(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    blocker_type_progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    readiness_gate_progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    status = manifest.get("status")
    ready_for_chainparams = status == "ready-for-chainparams" and not blockers
    next_action = actions[0] if actions else None
    current_blocker = blocked_field_groups[0] if blocked_field_groups else None
    later_blockers = blockers[1:] if blockers else []
    commands = status_command_fields(manifest_path)
    value_selection_states = network_value_selection_json_states(
        blocked_field_groups,
        network_progress,
        manifest_path,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": status,
        "ready_for_chainparams": ready_for_chainparams,
        "commands": commands,
        "action_plan_command": commands["action_plan"],
        "next_action_command": commands["next_action"],
        "readiness_summary_command": commands["readiness_summary"],
        "status_json_command": commands["status_json"],
        "value_selection_checklists_command": value_selection_checklists_command(
            manifest_path,
        ),
        "value_selection_candidate_artifact_status_command": (
            value_selection_candidate_artifact_status_command(manifest_path)
        ),
        "value_selection_candidate_artifact_status_json_command": (
            value_selection_candidate_artifact_status_command(
                manifest_path,
                json_output=True,
            )
        ),
        "snapshot_audit_handoffs_command": snapshot_audit_handoffs_command(
            manifest_path,
        ),
        "launch_gate_preflight_command": launch_gate_preflight_command(
            manifest_path,
        ),
        "operator_runbook_command": operator_runbook_command(
            manifest_path,
        ),
        "release_evidence_bundle_command": release_evidence_bundle_command(
            manifest_path,
        ),
        "release_evidence_bundle_json_command": release_evidence_bundle_json_command(
            manifest_path,
        ),
        "check_release_evidence_bundle_command": (
            check_release_evidence_bundle_command(manifest_path)
        ),
        "check_release_evidence_bundle_json_command": (
            check_release_evidence_bundle_command(manifest_path, json_output=True)
        ),
        "release_evidence_bundle_gate_command": (
            release_evidence_bundle_gate_command(manifest_path)
        ),
        "release_evidence_bundle_gate_json_command": (
            release_evidence_bundle_gate_command(manifest_path, json_output=True)
        ),
        "release_evidence_archive_checklist_command": (
            release_evidence_archive_checklist_command(manifest_path)
        ),
        "release_evidence_archive_checklist_json_command": (
            release_evidence_archive_checklist_command(manifest_path, json_output=True)
        ),
        "check_release_evidence_archive_command": (
            check_release_evidence_archive_command(manifest_path)
        ),
        "check_release_evidence_archive_json_command": (
            check_release_evidence_archive_command(manifest_path, json_output=True)
        ),
        "release_evidence_archive_gate_command": (
            release_evidence_archive_gate_command(manifest_path)
        ),
        "release_evidence_archive_gate_json_command": (
            release_evidence_archive_gate_command(manifest_path, json_output=True)
        ),
        "release_evidence_handoff_summary_command": (
            release_evidence_handoff_summary_command(manifest_path)
        ),
        "release_evidence_handoff_summary_json_command": (
            release_evidence_handoff_summary_command(manifest_path, json_output=True)
        ),
        "release_evidence_publication_index_template_command": (
            release_evidence_publication_index_template_command(manifest_path)
        ),
        "release_evidence_publication_index_template_json_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_command": (
            check_release_evidence_publication_index_command(manifest_path)
        ),
        "check_release_evidence_publication_index_json_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_command": (
            release_evidence_publication_index_gate_command(manifest_path)
        ),
        "release_evidence_publication_index_gate_json_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                json_output=True,
            )
        ),
        "blocked_networks": blocked_networks(network_progress),
        "blocked_network_count": len(blocked_networks(network_progress)),
        "ready_networks": ready_networks(network_progress),
        "ready_network_count": len(ready_networks(network_progress)),
        "blocked_networks_by_blocker_type": blocked_networks_by_blocker_type(
            blocked_field_groups,
        ),
        "ready_networks_by_blocker_type": ready_networks_by_blocker_type(
            blocked_field_groups,
        ),
        "blocker_types_by_readiness_gate": blocker_types_by_readiness_gate(),
        "blocker_type_counts_by_readiness_gate": (
            blocker_type_counts_by_readiness_gate()
        ),
        "unresolved_blockers": blockers,
        "unresolved_blocker_count": len(blockers),
        "unresolved_blockers_by_network": items_by_network(blockers),
        "unresolved_blocker_counts_by_network": item_counts_by_network(blockers),
        "unresolved_blockers_by_blocker_type": blockers_by_blocker_type(blockers),
        "unresolved_blocker_counts_by_blocker_type": (
            blocker_counts_by_blocker_type(blockers)
        ),
        "unresolved_blockers_by_readiness_gate": (
            blockers_by_readiness_gate(blockers)
        ),
        "unresolved_blocker_counts_by_readiness_gate": (
            blocker_counts_by_readiness_gate(blockers)
        ),
        "unresolved_blockers_by_network_and_blocker_type": (
            blockers_by_network_and_blocker_type(blockers)
        ),
        "unresolved_blocker_counts_by_network_and_blocker_type": (
            blocker_counts_by_network_and_blocker_type(blockers)
        ),
        "blocked_fields": check.blockers,
        "blocked_field_count": len(check.blockers),
        "blocked_fields_by_network": items_by_network(check.blockers),
        "blocked_field_counts_by_network": item_counts_by_network(check.blockers),
        "blocked_fields_by_blocker_type": blocked_fields_by_blocker_type(
            blocked_field_groups,
        ),
        "blocked_field_counts_by_blocker_type": (
            blocked_field_counts_by_blocker_type(blocked_field_groups)
        ),
        "blocked_fields_by_readiness_gate": blocked_fields_by_readiness_gate(
            blocked_field_groups,
        ),
        "blocked_field_counts_by_readiness_gate": (
            blocked_field_counts_by_readiness_gate(blocked_field_groups)
        ),
        "blocked_fields_by_network_and_blocker_type": (
            blocked_fields_by_network_and_blocker_type(blocked_field_groups)
        ),
        "blocked_field_counts_by_network_and_blocker_type": (
            blocked_field_counts_by_network_and_blocker_type(blocked_field_groups)
        ),
        "blocked_field_groups": blocked_field_groups,
        "blocked_field_group_count": len(blocked_field_groups),
        "blocked_field_groups_by_readiness_gate": (
            blocked_field_groups_by_readiness_gate(blocked_field_groups)
        ),
        "blocked_field_group_counts_by_readiness_gate": (
            blocked_field_group_counts_by_readiness_gate(blocked_field_groups)
        ),
        "network_progress": network_progress,
        "blocker_type_progress": blocker_type_progress,
        "readiness_gate_progress": readiness_gate_progress,
        "next_action": next_action,
        "next_action_id": next_action["id"] if next_action is not None else None,
        "next_action_kind": next_action["kind"] if next_action is not None else None,
        "next_action_commands": action_command_fields(next_action),
        "current_blocker": current_blocker,
        "current_blocker_id": (
            current_blocker["id"] if current_blocker is not None else None
        ),
        "current_blocker_field_count": (
            current_blocker["field_count"] if current_blocker is not None else 0
        ),
        "current_commands": action_command_fields(current_blocker),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "later_blockers_by_readiness_gate": later_blockers_by_readiness_gate(
            blockers,
        ),
        "later_blocker_counts_by_readiness_gate": (
            later_blocker_counts_by_readiness_gate(blockers)
        ),
        "later_blocker_readiness_summary_commands_by_readiness_gate": (
            later_blocker_readiness_summary_commands_by_readiness_gate(
                manifest_path,
                blockers,
            )
        ),
        "next_commands_by_network": network_next_command_fields(network_progress),
        "next_commands_by_blocker_type": next_commands_by_blocker_type(actions),
        "next_commands_by_readiness_gate": next_commands_by_readiness_gate(
            actions,
        ),
        "snapshot_audit_handoff_commands_by_network": (
            snapshot_audit_handoff_commands(manifest_path)
        ),
        "network_readiness_summary_commands_by_network": (
            network_readiness_summary_commands(manifest_path)
        ),
        "network_handoff_bundle_commands_by_network": (
            network_handoff_bundle_commands(manifest_path)
        ),
        "network_later_blockers_commands_by_network": (
            network_later_blockers_commands(manifest_path)
        ),
        "network_value_selection_later_blockers_commands_by_network": (
            network_value_selection_later_blockers_commands(manifest_path)
        ),
        "queued_value_selection_json_check_commands_by_network": {
            network: state["json_check_commands"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_json_check_command_counts_by_network": {
            network: state["json_check_command_count"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_candidate_checklists_by_network": {
            network: state["candidate_checklist"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_candidate_checklist_summaries_by_network": {
            network: state["candidate_checklist_summary"]
            for network, state in value_selection_states.items()
        },
        "blocker_type_readiness_summary_commands_by_blocker_type": (
            blocker_type_readiness_summary_commands(manifest_path)
        ),
        "blocker_type_later_blockers_commands_by_blocker_type": (
            blocker_type_later_blockers_commands(manifest_path)
        ),
        "readiness_gate_summary_commands_by_readiness_gate": (
            readiness_gate_summary_commands(manifest_path)
        ),
        "readiness_gate_later_blockers_commands_by_readiness_gate": (
            readiness_gate_later_blockers_commands(manifest_path)
        ),
    }


def readiness_summary_json_text(manifest, manifest_path, check):
    return json.dumps(
        readiness_summary_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def snapshot_audit_handoffs_state(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    network_next_commands = network_next_command_fields(network_progress)
    next_snapshot_audit_handoff_commands_by_network = command_field_values_by_group(
        network_next_commands,
        "snapshot_audit_handoff_command",
    )
    readiness_by_network = snapshot_audit_handoff_readiness_by_network(
        network_progress,
        blocked_field_groups,
        next_snapshot_audit_handoff_commands_by_network,
    )
    checklist_by_network = snapshot_audit_handoff_checklist_by_network(
        manifest_path,
        blocked_field_groups,
    )
    checklist_summary_by_network = snapshot_audit_handoff_checklist_summary_by_network(
        checklist_by_network,
    )
    return {
        "readiness_by_network": readiness_by_network,
        "checklist_by_network": checklist_by_network,
        "checklist_summary_by_network": checklist_summary_by_network,
        "next_snapshot_audit_handoff_commands_by_network": (
            next_snapshot_audit_handoff_commands_by_network
        ),
    }


def snapshot_audit_handoffs_summary(handoffs_state):
    readiness_by_network = handoffs_state["readiness_by_network"]
    checklist_summary_by_network = handoffs_state["checklist_summary_by_network"]
    return {
        "network_count": len(readiness_by_network),
        "unresolved_network_count": sum(
            1
            for readiness in readiness_by_network.values()
            if readiness["unresolved"]
        ),
        "next_blocker_network_count": sum(
            1
            for readiness in readiness_by_network.values()
            if readiness["is_next_blocker"]
        ),
        "blocked_field_count": sum(
            readiness["blocked_field_count"]
            for readiness in readiness_by_network.values()
        ),
        "required_artifact_count": sum(
            summary["required_artifact_count"]
            for summary in checklist_summary_by_network.values()
        ),
        "step_count": sum(
            summary["step_count"]
            for summary in checklist_summary_by_network.values()
        ),
        "available_command_count": sum(
            summary["available_command_count"]
            for summary in checklist_summary_by_network.values()
        ),
        "blockers_by_network": {
            network: readiness["blocker"]
            for network, readiness in readiness_by_network.items()
        },
    }


def snapshot_audit_handoffs_text(manifest, manifest_path, check):
    handoffs_state = snapshot_audit_handoffs_state(
        manifest,
        manifest_path,
        check,
    )
    summary = snapshot_audit_handoffs_summary(handoffs_state)
    commands_by_network = snapshot_audit_handoff_commands(manifest_path)
    readiness_by_network = handoffs_state["readiness_by_network"]
    checklist_summary_by_network = handoffs_state["checklist_summary_by_network"]
    lines = [
        "zkCoin public launch profile snapshot audit handoffs:",
        f"  - status: {manifest.get('status')}",
        f"  - snapshot audit handoffs command: {snapshot_audit_handoffs_command(manifest_path)}",
        f"  - networks: {list_summary(NETWORKS)}",
        f"  - unresolved snapshot blockers: {summary['unresolved_network_count']}",
        f"  - blocked snapshot fields: {summary['blocked_field_count']}",
        f"  - required external artifacts: {summary['required_artifact_count']}",
        f"  - available handoff commands: {summary['available_command_count']}",
    ]
    for network in NETWORKS:
        readiness = readiness_by_network[network]
        checklist_summary = checklist_summary_by_network[network]
        lines.extend([
            f"  - {network} blocker: {readiness['blocker']}",
            f"  - {network} state: {checklist_summary['state']}",
            f"  - {network} blocked fields: {readiness['blocked_field_count']}",
            f"  - {network} required artifacts: {list_summary(checklist_summary['required_artifact_ids'])}",
            f"  - {network} step count: {checklist_summary['step_count']}",
            f"  - {network} snapshot audit handoff command: {commands_by_network[network]}",
        ])
    return "\n".join(lines)


def snapshot_audit_handoffs_json_payload(manifest, manifest_path, check):
    handoffs_state = snapshot_audit_handoffs_state(
        manifest,
        manifest_path,
        check,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "snapshot_audit_handoffs_command": snapshot_audit_handoffs_command(
            manifest_path,
        ),
        "networks": list(NETWORKS),
        "network_count": len(NETWORKS),
        "snapshot_audit_handoff_commands_by_network": (
            snapshot_audit_handoff_commands(manifest_path)
        ),
        "snapshot_audit_handoff_command_count": len(NETWORKS),
        "next_snapshot_audit_handoff_commands_by_network": (
            handoffs_state["next_snapshot_audit_handoff_commands_by_network"]
        ),
        "snapshot_audit_handoff_readiness_by_network": (
            handoffs_state["readiness_by_network"]
        ),
        "snapshot_audit_handoff_checklist_by_network": (
            handoffs_state["checklist_by_network"]
        ),
        "snapshot_audit_handoff_checklist_summary_by_network": (
            handoffs_state["checklist_summary_by_network"]
        ),
        "snapshot_audit_external_artifacts_by_network": (
            snapshot_audit_external_artifacts_by_network()
        ),
        "snapshot_audit_external_artifact_counts_by_network": (
            snapshot_audit_external_artifact_counts_by_network()
        ),
        "summary": snapshot_audit_handoffs_summary(handoffs_state),
    }


def snapshot_audit_handoffs_json_text(manifest, manifest_path, check):
    return json.dumps(
        snapshot_audit_handoffs_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def snapshot_audit_handoff_text(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blocker_id = f"{network}.litecoin_snapshot"
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    blocked_group = groups_by_blocker.get(blocker_id)
    commands = blocker_action_commands(
        blocker_id,
        shell_quote(display_path(manifest_path)),
    )
    constraints = blocker_candidate_constraints("litecoin_snapshot")
    external_artifacts = blocker_external_artifacts("litecoin_snapshot")
    lines = [
        "zkCoin public launch profile snapshot audit handoff:",
        f"  - network: {network}",
        f"  - blocker: {blocker_id}",
        f"  - unresolved: {yes_no(blocker_id in blockers)}",
        f"  - source chain: {SNAPSHOT_SOURCE_CHAINS[network]}",
        f"  - audit summary fields: {list_summary(SNAPSHOT_AUDIT_SUMMARY_FIELDS)}",
        f"  - audit summary field count: {len(SNAPSHOT_AUDIT_SUMMARY_FIELDS)}",
        (
            "  - audit summary requirements: UTF-8 JSON object, exact template "
            f"field order, no duplicate fields, max {SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES} bytes"
        ),
        (
            "  - snapshot artifact requirements: absolute normalized regular file, "
            "not a symlink, stable during verification, size and SHA-256 must match audit"
        ),
        f"  - candidate constraint count: {len(constraints)}",
        f"  - external artifacts: {list_summary(artifact['id'] for artifact in external_artifacts)}",
        f"  - external artifact count: {len(external_artifacts)}",
        f"  - blocked fields: {blocked_group['field_count'] if blocked_group is not None else 0}",
    ]
    if blocked_group is not None:
        append_blocker_field_lines(lines, blocked_group, "  - ", "    - ")
    append_blocker_handoff_command_lines(lines, commands, "  - ")
    lines.extend([
        f"  - network handoff bundle command: {network_handoff_bundle_command(manifest_path, network)}",
        f"  - blocker readiness summary command: {blocker_readiness_summary_command(manifest_path, blocker_id)}",
    ])
    return "\n".join(lines)


def snapshot_audit_handoff_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blocker_id = f"{network}.litecoin_snapshot"
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    blocked_group = groups_by_blocker.get(blocker_id)
    blocked_fields = blocked_group["fields"] if blocked_group is not None else []
    commands = blocker_action_commands(
        blocker_id,
        shell_quote(display_path(manifest_path)),
    )
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    network_next_commands = network_next_command_fields(network_progress)
    next_snapshot_audit_handoff_commands_by_network = command_field_values_by_group(
        network_next_commands,
        "snapshot_audit_handoff_command",
    )
    readiness = snapshot_audit_handoff_readiness_by_network(
        network_progress,
        blocked_field_groups,
        next_snapshot_audit_handoff_commands_by_network,
    )[network]
    checklists = snapshot_audit_handoff_checklist_by_network(
        manifest_path,
        blocked_field_groups,
    )
    checklist = checklists[network]
    checklist_summary = snapshot_audit_handoff_checklist_summary_by_network(
        checklists,
    )[network]
    constraints = blocker_candidate_constraints("litecoin_snapshot")
    external_artifacts = blocker_external_artifacts("litecoin_snapshot")
    return {
        "schema_version": 1,
        "network": network,
        "blocker": blocker_id,
        "unresolved": blocker_id in blockers,
        "is_next_blocker": readiness["is_next_blocker"],
        "source_chain": SNAPSHOT_SOURCE_CHAINS[network],
        "audit_summary": {
            "fields": list(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
            "field_count": len(SNAPSHOT_AUDIT_SUMMARY_FIELDS),
            "requirements": {
                "must_be_utf8_json_object": True,
                "field_order_must_match_template": True,
                "rejects_duplicate_fields": True,
                "max_bytes": SNAPSHOT_AUDIT_SUMMARY_MAX_BYTES,
            },
        },
        "snapshot_artifact_requirements": {
            "must_be_absolute_normalized_regular_file": True,
            "must_not_be_symlink": True,
            "must_remain_stable_during_verification": True,
            "size_and_sha256_must_match_audit": True,
        },
        "candidate_constraints": constraints,
        "candidate_constraint_count": len(constraints),
        "external_artifacts": external_artifacts,
        "external_artifact_count": len(external_artifacts),
        "blocked_fields": blocked_fields,
        "blocked_field_count": len(blocked_fields),
        "commands": {
            **commands,
            "network_handoff_bundle_command": network_handoff_bundle_command(
                manifest_path,
                network,
            ),
        },
        "readiness": readiness,
        "checklist": checklist,
        "checklist_summary": checklist_summary,
    }


def snapshot_audit_handoff_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        snapshot_audit_handoff_json_payload(manifest, manifest_path, check, network),
        indent=2,
        sort_keys=False,
    )


def network_readiness_summary_text(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    progress = network_progress[network]
    next_group = progress["next_blocked_field_group"]
    lines = [
        "zkCoin public launch profile network readiness summary:",
        f"  - network: {network}",
        f"  - ready for launch profile: {yes_no(progress['ready_for_launch_profile'])}",
        f"  - unresolved blockers: {progress['unresolved_blocker_count']}",
        f"  - blocked fields: {progress['blocked_field_count']}",
        f"  - blocked blocker types: {list_summary(blocked_blocker_types_by_network(blocked_field_groups)[network])}",
        f"  - ready blocker types: {list_summary(ready_blocker_types_by_network(blocked_field_groups)[network])}",
    ]
    if next_group is None:
        lines.append("  - next blocker: none")
        return "\n".join(lines)

    lines.append(f"  - next blocker: {next_group['id']}")
    lines.append(f"  - next blocker fields: {next_group['field_count']}")
    append_blocker_field_lines(lines, next_group, "  - ", "    - ")
    append_blocker_command_lines(lines, next_group, "  - ")
    remaining_blockers = progress["unresolved_blockers"][1:]
    if remaining_blockers:
        lines.append("  - later blockers: " + ", ".join(remaining_blockers))
        lines.append(
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, remaining_blockers)
        )
    return "\n".join(lines)


def network_readiness_summary_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    progress = network_progress[network]
    current_group = progress["next_blocked_field_group"]
    current_blocker_id = current_group["id"] if current_group is not None else None
    later_blockers = progress["unresolved_blockers"][1:]
    blocked_blocker_types = blocked_blocker_types_by_network(blocked_field_groups)[network]
    ready_blocker_types = ready_blocker_types_by_network(blocked_field_groups)[network]
    return {
        "schema_version": 1,
        "network": network,
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "unresolved_blockers": progress["unresolved_blockers"],
        "unresolved_blocker_count": progress["unresolved_blocker_count"],
        "blocked_fields": progress["blocked_fields"],
        "blocked_field_count": progress["blocked_field_count"],
        "blocked_blocker_types": blocked_blocker_types,
        "blocked_blocker_type_count": len(blocked_blocker_types),
        "ready_blocker_types": ready_blocker_types,
        "ready_blocker_type_count": len(ready_blocker_types),
        "current_blocker": current_group,
        "current_blocker_id": current_blocker_id,
        "current_blocker_field_count": (
            current_group["field_count"] if current_group is not None else 0
        ),
        "current_commands": action_command_fields(current_group),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
        "network_later_blockers_command": network_later_blockers_command(
            manifest_path,
            network,
        ),
        "network_value_selection_later_blockers_command": (
            network_value_selection_later_blockers_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_command": (
            network_value_selection_candidate_template_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_json_command": (
            network_value_selection_candidate_template_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_command": (
            network_value_selection_candidate_check_command(manifest_path, network)
        ),
        "network_value_selection_candidate_check_json_command": (
            network_value_selection_candidate_check_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
    }


def network_readiness_summary_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        network_readiness_summary_json_payload(
            manifest,
            manifest_path,
            check,
            network,
        ),
        indent=2,
        sort_keys=False,
    )


def network_later_blockers_text(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    later_blockers = network_progress["unresolved_blockers"][1:]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_fields = [
        field
        for blocker in later_blockers
        for field in groups_by_blocker.get(blocker, {}).get("fields", [])
    ]
    next_group = network_progress["next_blocked_field_group"]
    lines = [
        "zkCoin public launch profile network later blockers:",
        f"  - network: {network}",
        f"  - current blocker: {next_group['id'] if next_group is not None else 'none'}",
        f"  - later blockers: {list_summary(later_blockers)}",
        f"  - later blocker count: {len(later_blockers)}",
        f"  - later blocker fields: {len(later_fields)}",
        (
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        ),
    ]
    return "\n".join(lines)


def network_later_blockers_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    later_blockers = network_progress["unresolved_blockers"][1:]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_groups = [
        groups_by_blocker[blocker]
        for blocker in later_blockers
    ]
    later_fields = [
        field
        for group in later_groups
        for field in group.get("fields", [])
    ]
    next_group = network_progress["next_blocked_field_group"]
    current_blocker_id = next_group["id"] if next_group is not None else None
    return {
        "schema_version": 1,
        "network": network,
        "ready_for_launch_profile": network_progress["ready_for_launch_profile"],
        "current_blocker": current_blocker_id,
        "current_blocker_field_count": (
            next_group["field_count"] if next_group is not None else 0
        ),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_fields": later_fields,
        "later_blocker_field_count": len(later_fields),
        "later_blocker_field_groups": later_groups,
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
        "network_later_blockers_command": network_later_blockers_command(
            manifest_path,
            network,
        ),
    }


def network_later_blockers_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        network_later_blockers_json_payload(
            manifest,
            manifest_path,
            check,
            network,
        ),
        indent=2,
        sort_keys=False,
    )


def blocker_type_readiness_summary_text(manifest, manifest_path, check, blocker_type):
    if blocker_type not in BLOCKER_TYPES:
        raise ValueError("blocker type must be one of: " + ", ".join(BLOCKER_TYPES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    blocker_type_progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    progress = blocker_type_progress[blocker_type]
    next_action = progress["next_action"]
    lines = [
        "zkCoin public launch profile blocker-type readiness summary:",
        f"  - blocker type: {blocker_type}",
        f"  - ready for launch profile: {yes_no(progress['ready_for_launch_profile'])}",
        f"  - unresolved blockers: {progress['unresolved_blocker_count']}",
        f"  - blocked fields: {progress['blocked_field_count']}",
        f"  - blocked networks: {list_summary(blocked_networks_by_blocker_type(blocked_field_groups)[blocker_type])}",
        f"  - ready networks: {list_summary(ready_networks_by_blocker_type(blocked_field_groups)[blocker_type])}",
    ]
    if next_action is None:
        lines.append("  - next blocker: none")
        return "\n".join(lines)

    lines.append(f"  - next blocker: {next_action['id']}")
    lines.append(f"  - next blocker fields: {next_action['field_count']}")
    append_blocker_field_lines(lines, next_action, "  - ", "    - ")
    append_blocker_command_lines(lines, next_action, "  - ")
    remaining_blockers = progress["unresolved_blockers"][1:]
    if remaining_blockers:
        lines.append("  - later blockers: " + ", ".join(remaining_blockers))
        lines.append(
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, remaining_blockers)
        )
    return "\n".join(lines)


def blocker_type_readiness_summary_json_payload(manifest, manifest_path, check, blocker_type):
    if blocker_type not in BLOCKER_TYPES:
        raise ValueError("blocker type must be one of: " + ", ".join(BLOCKER_TYPES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[blocker_type]
    current_action = progress["next_action"]
    current_blocker_id = current_action["id"] if current_action is not None else None
    later_blockers = progress["unresolved_blockers"][1:]
    readiness_gate = blocker_type_readiness_gate(blocker_type)
    return {
        "schema_version": 1,
        "blocker_type": blocker_type,
        "readiness_gate": readiness_gate,
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "unresolved_blockers": progress["unresolved_blockers"],
        "unresolved_blocker_count": progress["unresolved_blocker_count"],
        "blocked_fields": progress["blocked_fields"],
        "blocked_field_count": progress["blocked_field_count"],
        "blocked_networks": blocked_networks_by_blocker_type(blocked_field_groups)[blocker_type],
        "ready_networks": ready_networks_by_blocker_type(blocked_field_groups)[blocker_type],
        "current_blocker": current_action,
        "current_blocker_id": current_blocker_id,
        "current_blocker_field_count": (
            current_action["field_count"] if current_action is not None else 0
        ),
        "current_commands": action_command_fields(current_action),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
            manifest_path,
            blocker_type,
        ),
        "blocker_type_later_blockers_command": blocker_type_later_blockers_command(
            manifest_path,
            blocker_type,
        ),
        "readiness_gate_summary_command": readiness_gate_summary_command(
            manifest_path,
            readiness_gate,
        ),
        "readiness_gate_later_blockers_command": readiness_gate_later_blockers_command(
            manifest_path,
            readiness_gate,
        ),
    }


def blocker_type_readiness_summary_json_text(manifest, manifest_path, check, blocker_type):
    return json.dumps(
        blocker_type_readiness_summary_json_payload(
            manifest,
            manifest_path,
            check,
            blocker_type,
        ),
        indent=2,
        sort_keys=False,
    )


def blocker_type_later_blockers_text(manifest, manifest_path, check, blocker_type):
    if blocker_type not in BLOCKER_TYPES:
        raise ValueError("blocker type must be one of: " + ", ".join(BLOCKER_TYPES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[blocker_type]
    later_blockers = progress["unresolved_blockers"][1:]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_fields = [
        field
        for blocker in later_blockers
        for field in groups_by_blocker.get(blocker, {}).get("fields", [])
    ]
    next_action = progress["next_action"]
    lines = [
        "zkCoin public launch profile blocker-type later blockers:",
        f"  - blocker type: {blocker_type}",
        f"  - current blocker: {next_action['id'] if next_action is not None else 'none'}",
        f"  - later blockers: {list_summary(later_blockers)}",
        f"  - later blocker count: {len(later_blockers)}",
        f"  - later blocker fields: {len(later_fields)}",
        (
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        ),
    ]
    return "\n".join(lines)


def blocker_type_later_blockers_json_payload(manifest, manifest_path, check, blocker_type):
    if blocker_type not in BLOCKER_TYPES:
        raise ValueError("blocker type must be one of: " + ", ".join(BLOCKER_TYPES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[blocker_type]
    later_blockers = progress["unresolved_blockers"][1:]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_groups = [
        groups_by_blocker[blocker]
        for blocker in later_blockers
    ]
    later_fields = [
        field
        for group in later_groups
        for field in group.get("fields", [])
    ]
    current_action = progress["next_action"]
    current_blocker_id = current_action["id"] if current_action is not None else None
    readiness_gate = blocker_type_readiness_gate(blocker_type)
    return {
        "schema_version": 1,
        "blocker_type": blocker_type,
        "readiness_gate": readiness_gate,
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "blocked_networks": blocked_networks_by_blocker_type(blocked_field_groups)[blocker_type],
        "ready_networks": ready_networks_by_blocker_type(blocked_field_groups)[blocker_type],
        "current_blocker": current_blocker_id,
        "current_blocker_field_count": (
            current_action["field_count"] if current_action is not None else 0
        ),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_fields": later_fields,
        "later_blocker_field_count": len(later_fields),
        "later_blocker_field_groups": later_groups,
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "blocker_type_readiness_summary_command": blocker_type_readiness_summary_command(
            manifest_path,
            blocker_type,
        ),
        "blocker_type_later_blockers_command": blocker_type_later_blockers_command(
            manifest_path,
            blocker_type,
        ),
        "readiness_gate_summary_command": readiness_gate_summary_command(
            manifest_path,
            readiness_gate,
        ),
        "readiness_gate_later_blockers_command": readiness_gate_later_blockers_command(
            manifest_path,
            readiness_gate,
        ),
    }


def blocker_type_later_blockers_json_text(manifest, manifest_path, check, blocker_type):
    return json.dumps(
        blocker_type_later_blockers_json_payload(
            manifest,
            manifest_path,
            check,
            blocker_type,
        ),
        indent=2,
        sort_keys=False,
    )


def readiness_gate_summary_text(manifest, manifest_path, check, readiness_gate):
    if readiness_gate not in READINESS_GATES:
        raise ValueError("readiness gate must be one of: " + ", ".join(READINESS_GATES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[readiness_gate]
    next_action = progress["next_action"]
    lines = [
        "zkCoin public launch profile readiness-gate summary:",
        f"  - readiness gate: {readiness_gate}",
        f"  - ready for launch profile: {yes_no(progress['ready_for_launch_profile'])}",
        f"  - blocker types: {list_summary(progress['blocker_types'])}",
        f"  - unresolved blockers: {progress['unresolved_blocker_count']}",
        f"  - blocked field groups: {progress['blocked_field_group_count']}",
        f"  - blocked fields: {progress['blocked_field_count']}",
    ]
    if next_action is None:
        lines.append("  - next blocker: none")
        return "\n".join(lines)

    lines.append(f"  - next blocker: {next_action['id']}")
    lines.append(f"  - next blocker fields: {next_action['field_count']}")
    append_blocker_field_lines(lines, next_action, "  - ", "    - ")
    append_blocker_command_lines(lines, next_action, "  - ")
    remaining_blockers = progress["unresolved_blockers"][1:]
    if remaining_blockers:
        lines.append("  - later blockers: " + ", ".join(remaining_blockers))
        lines.append(
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, remaining_blockers)
        )
    return "\n".join(lines)


def readiness_gate_summary_json_payload(manifest, manifest_path, check, readiness_gate):
    if readiness_gate not in READINESS_GATES:
        raise ValueError("readiness gate must be one of: " + ", ".join(READINESS_GATES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[readiness_gate]
    current_action = progress["next_action"]
    current_blocker_id = current_action["id"] if current_action is not None else None
    later_blockers = progress["unresolved_blockers"][1:]
    blocker_types = progress["blocker_types"]
    return {
        "schema_version": 1,
        "readiness_gate": readiness_gate,
        "blocker_types": blocker_types,
        "blocker_type_count": progress["blocker_type_count"],
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "unresolved_blockers": progress["unresolved_blockers"],
        "unresolved_blocker_count": progress["unresolved_blocker_count"],
        "blocked_field_groups": progress["blocked_field_groups"],
        "blocked_field_group_count": progress["blocked_field_group_count"],
        "blocked_fields": progress["blocked_fields"],
        "blocked_field_count": progress["blocked_field_count"],
        "current_blocker": current_action,
        "current_blocker_id": current_blocker_id,
        "current_blocker_field_count": (
            current_action["field_count"] if current_action is not None else 0
        ),
        "current_commands": action_command_fields(current_action),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "blocker_type_readiness_summary_commands": {
            blocker_type: blocker_type_readiness_summary_command(
                manifest_path,
                blocker_type,
            )
            for blocker_type in blocker_types
        },
        "blocker_type_later_blockers_commands": {
            blocker_type: blocker_type_later_blockers_command(
                manifest_path,
                blocker_type,
            )
            for blocker_type in blocker_types
        },
        "readiness_gate_summary_command": readiness_gate_summary_command(
            manifest_path,
            readiness_gate,
        ),
        "readiness_gate_later_blockers_command": readiness_gate_later_blockers_command(
            manifest_path,
            readiness_gate,
        ),
    }


def readiness_gate_summary_json_text(manifest, manifest_path, check, readiness_gate):
    return json.dumps(
        readiness_gate_summary_json_payload(
            manifest,
            manifest_path,
            check,
            readiness_gate,
        ),
        indent=2,
        sort_keys=False,
    )


def readiness_gate_later_blockers_text(manifest, manifest_path, check, readiness_gate):
    if readiness_gate not in READINESS_GATES:
        raise ValueError("readiness gate must be one of: " + ", ".join(READINESS_GATES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[readiness_gate]
    later_blockers = progress["unresolved_blockers"][1:]
    later_groups = later_blocked_field_groups_by_readiness_gate(blocked_field_groups)[readiness_gate]
    later_fields = [
        field
        for group in later_groups
        for field in group.get("fields", [])
    ]
    next_action = progress["next_action"]
    lines = [
        "zkCoin public launch profile readiness-gate later blockers:",
        f"  - readiness gate: {readiness_gate}",
        f"  - current blocker: {next_action['id'] if next_action is not None else 'none'}",
        f"  - later blockers: {list_summary(later_blockers)}",
        f"  - later blocker count: {len(later_blockers)}",
        f"  - later blocker fields: {len(later_fields)}",
        (
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        ),
    ]
    return "\n".join(lines)


def readiness_gate_later_blockers_json_payload(manifest, manifest_path, check, readiness_gate):
    if readiness_gate not in READINESS_GATES:
        raise ValueError("readiness gate must be one of: " + ", ".join(READINESS_GATES))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )[readiness_gate]
    later_blockers = progress["unresolved_blockers"][1:]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_groups = [
        groups_by_blocker[blocker]
        for blocker in later_blockers
    ]
    later_fields = [
        field
        for group in later_groups
        for field in group.get("fields", [])
    ]
    current_action = progress["next_action"]
    current_blocker_id = current_action["id"] if current_action is not None else None
    blocker_types = progress["blocker_types"]
    return {
        "schema_version": 1,
        "readiness_gate": readiness_gate,
        "blocker_types": blocker_types,
        "blocker_type_count": progress["blocker_type_count"],
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "current_blocker": current_blocker_id,
        "current_blocker_field_count": (
            current_action["field_count"] if current_action is not None else 0
        ),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_fields": later_fields,
        "later_blocker_field_count": len(later_fields),
        "later_blocker_field_groups": later_groups,
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "blocker_type_readiness_summary_commands": {
            blocker_type: blocker_type_readiness_summary_command(
                manifest_path,
                blocker_type,
            )
            for blocker_type in blocker_types
        },
        "blocker_type_later_blockers_commands": {
            blocker_type: blocker_type_later_blockers_command(
                manifest_path,
                blocker_type,
            )
            for blocker_type in blocker_types
        },
        "readiness_gate_summary_command": readiness_gate_summary_command(
            manifest_path,
            readiness_gate,
        ),
        "readiness_gate_later_blockers_command": readiness_gate_later_blockers_command(
            manifest_path,
            readiness_gate,
        ),
    }


def readiness_gate_later_blockers_json_text(manifest, manifest_path, check, readiness_gate):
    return json.dumps(
        readiness_gate_later_blockers_json_payload(
            manifest,
            manifest_path,
            check,
            readiness_gate,
        ),
        indent=2,
        sort_keys=False,
    )


def network_value_selection_later_blocker_state(blocked_field_groups, network_progress):
    value_selection_types = set(blocker_types_by_readiness_gate()["value_selection"])
    later_blockers = [
        blocker
        for blocker in network_progress["unresolved_blockers"][1:]
        if blocker.split(".", 1)[1] in value_selection_types
    ]
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    later_fields = [
        field
        for blocker in later_blockers
        for field in groups_by_blocker[blocker].get("fields", [])
    ]
    return later_blockers, later_fields


def network_value_selection_later_blockers_text(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    later_blockers, later_fields = network_value_selection_later_blocker_state(
        blocked_field_groups,
        network_progress,
    )
    next_group = network_progress["next_blocked_field_group"]
    lines = [
        "zkCoin public launch profile network value-selection later blockers:",
        f"  - network: {network}",
        f"  - current blocker: {next_group['id'] if next_group is not None else 'none'}",
        f"  - value-selection blocker types: {list_summary(blocker_types_by_readiness_gate()['value_selection'])}",
        f"  - later value-selection blockers: {list_summary(later_blockers)}",
        f"  - later value-selection blocker count: {len(later_blockers)}",
        f"  - later value-selection blocker fields: {len(later_fields)}",
        (
            "  - later value-selection blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        ),
        (
            "  - value-selection candidate template command: "
            + network_value_selection_candidate_template_command(manifest_path, network)
        ),
        (
            "  - value-selection candidate check command: "
            + network_value_selection_candidate_check_command(manifest_path, network)
        ),
    ]
    return "\n".join(lines)


def value_selection_candidate_checklist(later_groups):
    steps = []
    for index, group in enumerate(later_groups, 1):
        steps.append({
            "step": index,
            "id": f"{group['id']}.candidate_json_check",
            "blocker": group["id"],
            "network": group["network"],
            "blocker_type": group["blocker_type"],
            "field_count": group["field_count"],
            "fields": group["fields"],
            "json_check_command": group["json_check_command"],
            "apply_command": group["apply_command"],
            "blocker_readiness_summary_command": group[
                "blocker_readiness_summary_command"
            ],
            "requires_operator_selected_values": True,
            "required_before_apply": True,
        })
    return steps


def value_selection_candidate_checklist_summary(checklist):
    return {
        "step_count": len(checklist),
        "required_json_check_count": len(checklist),
        "apply_command_count": sum(
            1
            for step in checklist
            if step["apply_command"] is not None
        ),
        "all_steps_have_json_check_commands": all(
            step["json_check_command"] is not None
            for step in checklist
        ),
        "all_steps_require_operator_selected_values": all(
            step["requires_operator_selected_values"]
            for step in checklist
        ),
        "blockers": [
            step["blocker"]
            for step in checklist
        ],
    }


def network_value_selection_json_state(blocked_field_groups, network_progress, manifest_path, network):
    later_blockers, later_fields = network_value_selection_later_blocker_state(
        blocked_field_groups,
        network_progress[network],
    )
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    manifest_arg = shell_quote(display_path(manifest_path))
    json_check_commands = blocker_json_check_commands(later_blockers, manifest_arg)
    later_groups = [
        {
            **groups_by_blocker[blocker],
            "json_check_command": json_check_commands[blocker],
        }
        for blocker in later_blockers
    ]
    checklist = value_selection_candidate_checklist(later_groups)
    return {
        "blockers": later_blockers,
        "fields": later_fields,
        "field_groups": later_groups,
        "json_check_commands": json_check_commands,
        "json_check_command_count": len(json_check_commands),
        "candidate_checklist": checklist,
        "candidate_checklist_summary": (
            value_selection_candidate_checklist_summary(checklist)
        ),
    }


def network_value_selection_json_states(blocked_field_groups, network_progress, manifest_path):
    return {
        network: network_value_selection_json_state(
            blocked_field_groups,
            network_progress,
            manifest_path,
            network,
        )
        for network in NETWORKS
    }


def value_selection_checklists_state(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    return network_value_selection_json_states(
        blocked_field_groups,
        network_progress,
        manifest_path,
    )


def value_selection_checklists_summary(value_selection_states):
    checklist_summaries = {
        network: state["candidate_checklist_summary"]
        for network, state in value_selection_states.items()
    }
    blockers_by_network = {
        network: state["blockers"]
        for network, state in value_selection_states.items()
    }
    return {
        "network_count": len(value_selection_states),
        "step_count": sum(
            summary["step_count"]
            for summary in checklist_summaries.values()
        ),
        "required_json_check_count": sum(
            summary["required_json_check_count"]
            for summary in checklist_summaries.values()
        ),
        "apply_command_count": sum(
            summary["apply_command_count"]
            for summary in checklist_summaries.values()
        ),
        "all_steps_have_json_check_commands": all(
            summary["all_steps_have_json_check_commands"]
            for summary in checklist_summaries.values()
        ),
        "all_steps_require_operator_selected_values": all(
            summary["all_steps_require_operator_selected_values"]
            for summary in checklist_summaries.values()
        ),
        "blockers_by_network": blockers_by_network,
    }


def value_selection_checklists_text(manifest, manifest_path, check):
    value_selection_states = value_selection_checklists_state(
        manifest,
        manifest_path,
        check,
    )
    summary = value_selection_checklists_summary(value_selection_states)
    lines = [
        "zkCoin public launch profile value-selection checklists:",
        f"  - status: {manifest.get('status')}",
        f"  - value-selection checklists command: {value_selection_checklists_command(manifest_path)}",
        f"  - value-selection blocker types: {list_summary(blocker_types_by_readiness_gate()['value_selection'])}",
        f"  - networks: {list_summary(NETWORKS)}",
        f"  - required JSON checks: {summary['required_json_check_count']}",
        f"  - apply commands: {summary['apply_command_count']}",
        f"  - all steps have JSON check commands: {yes_no(summary['all_steps_have_json_check_commands'])}",
        f"  - all steps require operator-selected values: {yes_no(summary['all_steps_require_operator_selected_values'])}",
    ]
    for network in NETWORKS:
        state = value_selection_states[network]
        lines.extend([
            f"  - {network} queued value-selection blockers: {list_summary(state['blockers'])}",
            f"  - {network} queued value-selection blocker fields: {len(state['fields'])}",
            f"  - {network} required JSON checks: {state['json_check_command_count']}",
        (
            f"  - {network} candidate template command: "
            + network_value_selection_candidate_template_command(
                manifest_path,
                network,
            )
        ),
        (
            f"  - {network} candidate check command: "
            + network_value_selection_candidate_check_command(
                manifest_path,
                network,
            )
        ),
    ])
        for blocker, command in state["json_check_commands"].items():
            lines.append(f"    - {blocker}: {command}")
    return "\n".join(lines)


def value_selection_checklists_json_payload(manifest, manifest_path, check):
    value_selection_states = value_selection_checklists_state(
        manifest,
        manifest_path,
        check,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "value_selection_checklists_command": value_selection_checklists_command(
            manifest_path,
        ),
        "value_selection_blocker_types": list(
            blocker_types_by_readiness_gate()["value_selection"]
        ),
        "networks": list(NETWORKS),
        "network_count": len(NETWORKS),
        "queued_value_selection_blockers_by_network": {
            network: state["blockers"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_blocker_counts_by_network": {
            network: len(state["blockers"])
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_fields_by_network": {
            network: state["fields"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_field_counts_by_network": {
            network: len(state["fields"])
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_json_check_commands_by_network": {
            network: state["json_check_commands"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_json_check_command_counts_by_network": {
            network: state["json_check_command_count"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_candidate_checklists_by_network": {
            network: state["candidate_checklist"]
            for network, state in value_selection_states.items()
        },
        "queued_value_selection_candidate_checklist_summaries_by_network": {
            network: state["candidate_checklist_summary"]
            for network, state in value_selection_states.items()
        },
        "summary": value_selection_checklists_summary(value_selection_states),
        "network_value_selection_later_blockers_commands_by_network": (
            network_value_selection_later_blockers_commands(manifest_path)
        ),
        "network_value_selection_candidate_template_commands_by_network": (
            network_value_selection_candidate_template_commands(manifest_path)
        ),
        "network_value_selection_candidate_template_json_commands_by_network": (
            network_value_selection_candidate_template_commands(
                manifest_path,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_commands_by_network": (
            network_value_selection_candidate_check_commands(manifest_path)
        ),
        "network_value_selection_candidate_check_json_commands_by_network": (
            network_value_selection_candidate_check_commands(
                manifest_path,
                json_output=True,
            )
        ),
    }


def value_selection_checklists_json_text(manifest, manifest_path, check):
    return json.dumps(
        value_selection_checklists_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def value_selection_candidate_template(network):
    return {
        "schema_version": 1,
        "network": network,
        "auxpow_chain_id": "<chain_id>",
        "public_network_identity": {
            "message_start": "<message_start>",
            "default_port": "<port>",
            "base58_prefixes": {
                "pubkey_address": "<pubkey>",
                "script_address": "<script>",
                "script_address2": "<script2>",
                "secret_key": "<secret>",
                "ext_public_key": "<xpub>",
                "ext_secret_key": "<xprv>",
            },
            "bech32_hrp": "<bech32_hrp>",
            "mweb_hrp": "<mweb_hrp>",
        },
        "dns_seeds": [
            "<seed1.hostname>",
            "<seed2.hostname>",
        ],
    }


def network_value_selection_candidate_template_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    value_selection_states = value_selection_checklists_state(
        manifest,
        manifest_path,
        check,
    )
    state = value_selection_states[network]
    template = value_selection_candidate_template(network)
    required_sections_by_blocker = {
        f"{network}.auxpow_chain_id": ["auxpow_chain_id"],
        f"{network}.public_network_identity": ["public_network_identity"],
        f"{network}.dns_seeds": ["dns_seeds"],
    }
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "network": network,
        "value_selection_blocker_types": list(
            blocker_types_by_readiness_gate()["value_selection"]
        ),
        "queued_value_selection_blockers": state["blockers"],
        "queued_value_selection_blocker_count": len(state["blockers"]),
        "queued_value_selection_fields": state["fields"],
        "queued_value_selection_field_count": len(state["fields"]),
        "queued_value_selection_field_groups": state["field_groups"],
        "queued_value_selection_json_check_commands": state["json_check_commands"],
        "queued_value_selection_json_check_command_count": state[
            "json_check_command_count"
        ],
        "queued_value_selection_candidate_checklist": state["candidate_checklist"],
        "queued_value_selection_candidate_checklist_summary": (
            state["candidate_checklist_summary"]
        ),
        "candidate_template_schema_version": template["schema_version"],
        "candidate_template": template,
        "candidate_template_field_order": list(template.keys()),
        "candidate_template_required_sections_by_blocker": {
            blocker: required_sections_by_blocker[blocker]
            for blocker in state["blockers"]
        },
        "candidate_constraints_by_blocker": {
            group["id"]: group["candidate_constraints"]
            for group in state["field_groups"]
        },
        "network_value_selection_candidate_template_command": (
            network_value_selection_candidate_template_command(
                manifest_path,
                network,
            )
        ),
        "network_value_selection_candidate_template_json_command": (
            network_value_selection_candidate_template_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_command": (
            network_value_selection_candidate_check_command(manifest_path, network)
        ),
        "network_value_selection_candidate_check_json_command": (
            network_value_selection_candidate_check_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "network_value_selection_later_blockers_command": (
            network_value_selection_later_blockers_command(manifest_path, network)
        ),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
    }


def network_value_selection_candidate_template_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        network_value_selection_candidate_template_json_payload(
            manifest,
            manifest_path,
            check,
            network,
        ),
        indent=2,
        sort_keys=False,
    )


def network_value_selection_candidate_template_text(manifest, manifest_path, check, network):
    payload = network_value_selection_candidate_template_json_payload(
        manifest,
        manifest_path,
        check,
        network,
    )
    lines = [
        "zkCoin public launch profile network value-selection candidate template:",
        f"  - manifest: {payload['manifest']}",
        f"  - status: {payload['status']}",
        f"  - network: {network}",
        (
            "  - queued value-selection blockers: "
            + list_summary(payload["queued_value_selection_blockers"])
        ),
        f"  - queued value-selection blocker count: {payload['queued_value_selection_blocker_count']}",
        f"  - queued value-selection fields: {payload['queued_value_selection_field_count']}",
        f"  - required JSON checks: {payload['queued_value_selection_json_check_command_count']}",
        (
            "  - candidate template command: "
            + payload["network_value_selection_candidate_template_command"]
        ),
        (
            "  - candidate template JSON command: "
            + payload["network_value_selection_candidate_template_json_command"]
        ),
        (
            "  - candidate check command: "
            + payload["network_value_selection_candidate_check_command"]
        ),
        (
            "  - candidate check JSON command: "
            + payload["network_value_selection_candidate_check_json_command"]
        ),
        (
            "  - value-selection later blockers command: "
            + payload["network_value_selection_later_blockers_command"]
        ),
        (
            "  - network readiness summary command: "
            + payload["network_readiness_summary_command"]
        ),
        "  - candidate template JSON:",
    ]
    template_lines = json.dumps(
        payload["candidate_template"],
        indent=2,
        sort_keys=False,
    ).splitlines()
    lines.extend(f"    {line}" for line in template_lines)
    for blocker, command in payload["queued_value_selection_json_check_commands"].items():
        lines.append(f"  - {blocker} JSON check command: {command}")
    return "\n".join(lines)


def launch_gate_preflight_state(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    readiness_gate_progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    snapshot_state = snapshot_audit_handoffs_state(manifest, manifest_path, check)
    snapshot_summary = snapshot_audit_handoffs_summary(snapshot_state)
    value_selection_states = value_selection_checklists_state(
        manifest,
        manifest_path,
        check,
    )
    value_selection_summary = value_selection_checklists_summary(
        value_selection_states,
    )
    gate_commands = {
        "external_artifact": snapshot_audit_handoffs_command(manifest_path),
        "value_selection": value_selection_checklists_command(manifest_path),
    }
    gates = {}
    for gate in READINESS_GATES:
        progress = readiness_gate_progress[gate]
        next_group = progress["next_blocked_field_group"]
        gates[gate] = {
            "ready_for_launch_profile": progress["ready_for_launch_profile"],
            "blocker_types": progress["blocker_types"],
            "blocker_type_count": progress["blocker_type_count"],
            "unresolved_blockers": progress["unresolved_blockers"],
            "unresolved_blocker_count": progress["unresolved_blocker_count"],
            "blocked_field_count": progress["blocked_field_count"],
            "blocked_field_group_count": progress["blocked_field_group_count"],
            "next_blocker": next_group["id"] if next_group is not None else None,
            "next_blocker_network": (
                next_group["network"] if next_group is not None else None
            ),
            "next_blocker_type": (
                next_group["blocker_type"] if next_group is not None else None
            ),
            "handoff_command": gate_commands[gate],
        }
    gates["external_artifact"].update({
        "required_external_artifact_count": (
            snapshot_summary["required_artifact_count"]
        ),
        "checklist_step_count": snapshot_summary["step_count"],
        "available_command_count": snapshot_summary["available_command_count"],
    })
    gates["value_selection"].update({
        "required_json_check_count": (
            value_selection_summary["required_json_check_count"]
        ),
        "checklist_step_count": value_selection_summary["step_count"],
        "apply_command_count": value_selection_summary["apply_command_count"],
        "all_steps_have_json_check_commands": (
            value_selection_summary["all_steps_have_json_check_commands"]
        ),
        "all_steps_require_operator_selected_values": (
            value_selection_summary[
                "all_steps_require_operator_selected_values"
            ]
        ),
    })
    return {
        "gates": gates,
        "gate_commands": gate_commands,
        "snapshot_audit": {
            "summary": snapshot_summary,
            "checklist_summary_by_network": (
                snapshot_state["checklist_summary_by_network"]
            ),
        },
        "value_selection": {
            "summary": value_selection_summary,
            "checklist_summaries_by_network": {
                network: state["candidate_checklist_summary"]
                for network, state in value_selection_states.items()
            },
            "json_check_command_counts_by_network": {
                network: state["json_check_command_count"]
                for network, state in value_selection_states.items()
            },
        },
    }


def launch_gate_preflight_summary(preflight_state):
    gates = preflight_state["gates"]
    blocked_gates = [
        gate
        for gate in READINESS_GATES
        if not gates[gate]["ready_for_launch_profile"]
    ]
    ready_gates = [
        gate
        for gate in READINESS_GATES
        if gates[gate]["ready_for_launch_profile"]
    ]
    return {
        "readiness_gate_count": len(READINESS_GATES),
        "blocked_gate_count": len(blocked_gates),
        "blocked_gates": blocked_gates,
        "ready_gate_count": len(ready_gates),
        "ready_gates": ready_gates,
        "unresolved_blocker_count": sum(
            gate["unresolved_blocker_count"]
            for gate in gates.values()
        ),
        "blocked_field_count": sum(
            gate["blocked_field_count"]
            for gate in gates.values()
        ),
        "required_external_artifact_count": (
            gates["external_artifact"]["required_external_artifact_count"]
        ),
        "required_json_check_count": (
            gates["value_selection"]["required_json_check_count"]
        ),
        "checklist_step_count": sum(
            gate["checklist_step_count"]
            for gate in gates.values()
        ),
        "gate_commands": preflight_state["gate_commands"],
    }


def launch_gate_preflight_text(manifest, manifest_path, check):
    preflight_state = launch_gate_preflight_state(
        manifest,
        manifest_path,
        check,
    )
    summary = launch_gate_preflight_summary(preflight_state)
    gates = preflight_state["gates"]
    lines = [
        "zkCoin public launch profile launch-gate preflight:",
        f"  - status: {manifest.get('status')}",
        f"  - launch-gate preflight command: {launch_gate_preflight_command(manifest_path)}",
        f"  - readiness gates: {list_summary(READINESS_GATES)}",
        f"  - blocked gates: {list_summary(summary['blocked_gates'])}",
        f"  - ready gates: {list_summary(summary['ready_gates'])}",
        f"  - unresolved blockers: {summary['unresolved_blocker_count']}",
        f"  - blocked fields: {summary['blocked_field_count']}",
        f"  - external_artifact blockers: {gates['external_artifact']['unresolved_blocker_count']}",
        f"  - external_artifact blocked fields: {gates['external_artifact']['blocked_field_count']}",
        f"  - external_artifact required external artifacts: {gates['external_artifact']['required_external_artifact_count']}",
        f"  - external_artifact checklist steps: {gates['external_artifact']['checklist_step_count']}",
        f"  - external_artifact handoff command: {gates['external_artifact']['handoff_command']}",
        f"  - value_selection blockers: {gates['value_selection']['unresolved_blocker_count']}",
        f"  - value_selection blocked fields: {gates['value_selection']['blocked_field_count']}",
        f"  - value_selection required JSON checks: {gates['value_selection']['required_json_check_count']}",
        f"  - value_selection checklist steps: {gates['value_selection']['checklist_step_count']}",
        f"  - value_selection handoff command: {gates['value_selection']['handoff_command']}",
    ]
    return "\n".join(lines)


def launch_gate_preflight_json_payload(manifest, manifest_path, check):
    preflight_state = launch_gate_preflight_state(
        manifest,
        manifest_path,
        check,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "launch_gate_preflight_command": launch_gate_preflight_command(
            manifest_path,
        ),
        "readiness_gates": list(READINESS_GATES),
        "readiness_gate_count": len(READINESS_GATES),
        "gate_preflight_by_readiness_gate": preflight_state["gates"],
        "gate_commands_by_readiness_gate": preflight_state["gate_commands"],
        "snapshot_audit_handoffs_command": (
            preflight_state["gate_commands"]["external_artifact"]
        ),
        "value_selection_checklists_command": (
            preflight_state["gate_commands"]["value_selection"]
        ),
        "snapshot_audit_handoffs_summary": (
            preflight_state["snapshot_audit"]["summary"]
        ),
        "snapshot_audit_handoff_checklist_summary_by_network": (
            preflight_state["snapshot_audit"]["checklist_summary_by_network"]
        ),
        "value_selection_checklists_summary": (
            preflight_state["value_selection"]["summary"]
        ),
        "queued_value_selection_candidate_checklist_summaries_by_network": (
            preflight_state["value_selection"]["checklist_summaries_by_network"]
        ),
        "queued_value_selection_json_check_command_counts_by_network": (
            preflight_state["value_selection"][
                "json_check_command_counts_by_network"
            ]
        ),
        "summary": launch_gate_preflight_summary(preflight_state),
    }


def launch_gate_preflight_json_text(manifest, manifest_path, check):
    return json.dumps(
        launch_gate_preflight_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def operator_runbook_steps(manifest_path):
    return [
        {
            "step": 1,
            "id": "launch-gate-preflight",
            "readiness_gate": "all",
            "command": launch_gate_preflight_command(manifest_path),
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "snapshot-audit-handoffs",
            "readiness_gate": "external_artifact",
            "command": snapshot_audit_handoffs_command(manifest_path),
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": "value-selection-checklists",
            "readiness_gate": "value_selection",
            "command": value_selection_checklists_command(manifest_path),
            "required_before_launch": True,
        },
    ]


def operator_runbook_state(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    next_blocker = blockers[0] if blockers else None
    manifest_arg = shell_quote(display_path(manifest_path))
    next_blocker_commands = (
        blocker_action_commands(next_blocker, manifest_arg)
        if next_blocker is not None
        else {}
    )
    next_handoff_command = (
        next_blocker_commands.get("snapshot_audit_handoff_command")
        or next_blocker_commands.get("blocker_readiness_summary_command")
    )
    preflight_state = launch_gate_preflight_state(manifest, manifest_path, check)
    return {
        "runbook_steps": operator_runbook_steps(manifest_path),
        "preflight_state": preflight_state,
        "preflight_summary": launch_gate_preflight_summary(preflight_state),
        "next_blocker": next_blocker,
        "next_blocker_commands": next_blocker_commands,
        "next_blocker_handoff_command": next_handoff_command,
    }


def operator_runbook_summary(runbook_state):
    preflight_summary = runbook_state["preflight_summary"]
    return {
        "step_count": len(runbook_state["runbook_steps"]),
        "readiness_gate_count": preflight_summary["readiness_gate_count"],
        "blocked_gate_count": preflight_summary["blocked_gate_count"],
        "blocked_gates": preflight_summary["blocked_gates"],
        "ready_gate_count": preflight_summary["ready_gate_count"],
        "ready_gates": preflight_summary["ready_gates"],
        "unresolved_blocker_count": preflight_summary["unresolved_blocker_count"],
        "blocked_field_count": preflight_summary["blocked_field_count"],
        "required_external_artifact_count": (
            preflight_summary["required_external_artifact_count"]
        ),
        "required_json_check_count": (
            preflight_summary["required_json_check_count"]
        ),
        "checklist_step_count": preflight_summary["checklist_step_count"],
    }


def operator_runbook_text(manifest, manifest_path, check):
    runbook_state = operator_runbook_state(manifest, manifest_path, check)
    summary = operator_runbook_summary(runbook_state)
    lines = [
        "zkCoin public launch profile operator runbook:",
        f"  - status: {manifest.get('status')}",
        f"  - operator runbook command: {operator_runbook_command(manifest_path)}",
        f"  - release evidence bundle command: {release_evidence_bundle_command(manifest_path)}",
        f"  - launch-gate preflight command: {launch_gate_preflight_command(manifest_path)}",
        f"  - snapshot audit handoffs command: {snapshot_audit_handoffs_command(manifest_path)}",
        f"  - value-selection checklists command: {value_selection_checklists_command(manifest_path)}",
        f"  - readiness gates: {list_summary(READINESS_GATES)}",
        f"  - blocked gates: {list_summary(summary['blocked_gates'])}",
        f"  - ready gates: {list_summary(summary['ready_gates'])}",
        f"  - unresolved blockers: {summary['unresolved_blocker_count']}",
        f"  - blocked fields: {summary['blocked_field_count']}",
        f"  - required external artifacts: {summary['required_external_artifact_count']}",
        f"  - required JSON checks: {summary['required_json_check_count']}",
        f"  - checklist steps: {summary['checklist_step_count']}",
        f"  - runbook steps: {summary['step_count']}",
    ]
    for step in runbook_state["runbook_steps"]:
        lines.extend([
            f"  - step {step['step']}: {step['id']}",
            f"  - step {step['step']} command: {step['command']}",
        ])
    if runbook_state["next_blocker"] is not None:
        lines.extend([
            f"  - next blocker: {runbook_state['next_blocker']}",
            (
                "  - next recommended handoff command: "
                f"{runbook_state['next_blocker_handoff_command']}"
            ),
        ])
    return "\n".join(lines)


def operator_runbook_json_payload(manifest, manifest_path, check):
    runbook_state = operator_runbook_state(manifest, manifest_path, check)
    preflight_state = runbook_state["preflight_state"]
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "operator_runbook_command": operator_runbook_command(manifest_path),
        "release_evidence_bundle_command": release_evidence_bundle_command(
            manifest_path,
        ),
        "launch_gate_preflight_command": launch_gate_preflight_command(
            manifest_path,
        ),
        "snapshot_audit_handoffs_command": snapshot_audit_handoffs_command(
            manifest_path,
        ),
        "value_selection_checklists_command": value_selection_checklists_command(
            manifest_path,
        ),
        "readiness_gates": list(READINESS_GATES),
        "runbook_steps": runbook_state["runbook_steps"],
        "runbook_step_count": len(runbook_state["runbook_steps"]),
        "next_blocker": runbook_state["next_blocker"],
        "next_blocker_handoff_command": (
            runbook_state["next_blocker_handoff_command"]
        ),
        "next_blocker_commands": runbook_state["next_blocker_commands"],
        "gate_preflight_by_readiness_gate": preflight_state["gates"],
        "launch_gate_preflight_summary": runbook_state["preflight_summary"],
        "snapshot_audit_handoffs_summary": (
            preflight_state["snapshot_audit"]["summary"]
        ),
        "value_selection_checklists_summary": (
            preflight_state["value_selection"]["summary"]
        ),
        "summary": operator_runbook_summary(runbook_state),
    }


def operator_runbook_json_text(manifest, manifest_path, check):
    return json.dumps(
        operator_runbook_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def release_evidence_payload_entries(manifest_path):
    return [
        {
            "step": 1,
            "id": "operator-runbook",
            "payload_key": "operator_runbook",
            "command": operator_runbook_command(manifest_path),
            "schema_version": 1,
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "launch-gate-preflight",
            "payload_key": "launch_gate_preflight",
            "command": launch_gate_preflight_command(manifest_path),
            "schema_version": 1,
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": "snapshot-audit-handoffs",
            "payload_key": "snapshot_audit_handoffs",
            "command": snapshot_audit_handoffs_command(manifest_path),
            "schema_version": 1,
            "required_before_launch": True,
        },
        {
            "step": 4,
            "id": "value-selection-checklists",
            "payload_key": "value_selection_checklists",
            "command": value_selection_checklists_command(manifest_path),
            "schema_version": 1,
            "required_before_launch": True,
        },
    ]


def release_evidence_bundle_state(manifest, manifest_path, check):
    operator_payload = operator_runbook_json_payload(manifest, manifest_path, check)
    return {
        "payload_entries": release_evidence_payload_entries(manifest_path),
        "operator_runbook": operator_payload,
        "launch_gate_preflight": launch_gate_preflight_json_payload(
            manifest,
            manifest_path,
            check,
        ),
        "snapshot_audit_handoffs": snapshot_audit_handoffs_json_payload(
            manifest,
            manifest_path,
            check,
        ),
        "value_selection_checklists": value_selection_checklists_json_payload(
            manifest,
            manifest_path,
            check,
        ),
        "operator_summary": operator_payload["summary"],
    }


def release_evidence_bundle_summary(bundle_state):
    operator_summary = bundle_state["operator_summary"]
    return {
        "evidence_payload_count": len(bundle_state["payload_entries"]),
        "readiness_gate_count": operator_summary["readiness_gate_count"],
        "blocked_gate_count": operator_summary["blocked_gate_count"],
        "blocked_gates": operator_summary["blocked_gates"],
        "ready_gate_count": operator_summary["ready_gate_count"],
        "ready_gates": operator_summary["ready_gates"],
        "unresolved_blocker_count": operator_summary["unresolved_blocker_count"],
        "blocked_field_count": operator_summary["blocked_field_count"],
        "required_external_artifact_count": (
            operator_summary["required_external_artifact_count"]
        ),
        "required_json_check_count": operator_summary["required_json_check_count"],
        "checklist_step_count": operator_summary["checklist_step_count"],
        "runbook_step_count": operator_summary["step_count"],
        "embedded_payload_schema_versions": {
            entry["payload_key"]: entry["schema_version"]
            for entry in bundle_state["payload_entries"]
        },
    }


def release_evidence_bundle_text(manifest, manifest_path, check):
    bundle_state = release_evidence_bundle_state(manifest, manifest_path, check)
    summary = release_evidence_bundle_summary(bundle_state)
    operator_payload = bundle_state["operator_runbook"]
    lines = [
        "zkCoin public launch profile release evidence bundle:",
        f"  - status: {manifest.get('status')}",
        f"  - release evidence bundle command: {release_evidence_bundle_command(manifest_path)}",
        f"  - release evidence bundle JSON command: {release_evidence_bundle_json_command(manifest_path)}",
        f"  - check release evidence bundle command: {check_release_evidence_bundle_command(manifest_path)}",
        f"  - check release evidence bundle JSON command: {check_release_evidence_bundle_command(manifest_path, json_output=True)}",
        f"  - release evidence bundle gate command: {release_evidence_bundle_gate_command(manifest_path)}",
        f"  - release evidence bundle gate JSON command: {release_evidence_bundle_gate_command(manifest_path, json_output=True)}",
        f"  - release evidence archive checklist command: {release_evidence_archive_checklist_command(manifest_path)}",
        f"  - release evidence archive checklist JSON command: {release_evidence_archive_checklist_command(manifest_path, json_output=True)}",
        f"  - check release evidence archive command: {check_release_evidence_archive_command(manifest_path)}",
        f"  - check release evidence archive JSON command: {check_release_evidence_archive_command(manifest_path, json_output=True)}",
        f"  - release evidence archive gate command: {release_evidence_archive_gate_command(manifest_path)}",
        f"  - release evidence archive gate JSON command: {release_evidence_archive_gate_command(manifest_path, json_output=True)}",
        f"  - release evidence handoff summary command: {release_evidence_handoff_summary_command(manifest_path)}",
        f"  - release evidence handoff summary JSON command: {release_evidence_handoff_summary_command(manifest_path, json_output=True)}",
        f"  - release evidence publication index template command: {release_evidence_publication_index_template_command(manifest_path)}",
        f"  - release evidence publication index template JSON command: {release_evidence_publication_index_template_command(manifest_path, json_output=True)}",
        f"  - check release evidence publication index command: {check_release_evidence_publication_index_command(manifest_path)}",
        f"  - check release evidence publication index JSON command: {check_release_evidence_publication_index_command(manifest_path, json_output=True)}",
        f"  - release evidence publication index gate command: {release_evidence_publication_index_gate_command(manifest_path)}",
        f"  - release evidence publication index gate JSON command: {release_evidence_publication_index_gate_command(manifest_path, json_output=True)}",
        f"  - operator runbook command: {operator_runbook_command(manifest_path)}",
        f"  - launch-gate preflight command: {launch_gate_preflight_command(manifest_path)}",
        f"  - snapshot audit handoffs command: {snapshot_audit_handoffs_command(manifest_path)}",
        f"  - value-selection checklists command: {value_selection_checklists_command(manifest_path)}",
        f"  - evidence payloads: {summary['evidence_payload_count']}",
        f"  - readiness gates: {list_summary(READINESS_GATES)}",
        f"  - blocked gates: {list_summary(summary['blocked_gates'])}",
        f"  - ready gates: {list_summary(summary['ready_gates'])}",
        f"  - unresolved blockers: {summary['unresolved_blocker_count']}",
        f"  - blocked fields: {summary['blocked_field_count']}",
        f"  - required external artifacts: {summary['required_external_artifact_count']}",
        f"  - required JSON checks: {summary['required_json_check_count']}",
        f"  - checklist steps: {summary['checklist_step_count']}",
        f"  - runbook steps: {summary['runbook_step_count']}",
    ]
    for entry in bundle_state["payload_entries"]:
        lines.extend([
            f"  - evidence {entry['step']}: {entry['id']}",
            f"  - evidence {entry['step']} command: {entry['command']}",
        ])
    if operator_payload["next_blocker"] is not None:
        lines.extend([
            f"  - next blocker: {operator_payload['next_blocker']}",
            (
                "  - next recommended handoff command: "
                f"{operator_payload['next_blocker_handoff_command']}"
            ),
        ])
    return "\n".join(lines)


def release_evidence_bundle_json_payload(manifest, manifest_path, check):
    bundle_state = release_evidence_bundle_state(manifest, manifest_path, check)
    operator_payload = bundle_state["operator_runbook"]
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "release_evidence_bundle_command": release_evidence_bundle_command(
            manifest_path,
        ),
        "release_evidence_bundle_json_command": release_evidence_bundle_json_command(
            manifest_path,
        ),
        "check_release_evidence_bundle_command": (
            check_release_evidence_bundle_command(manifest_path)
        ),
        "check_release_evidence_bundle_json_command": (
            check_release_evidence_bundle_command(manifest_path, json_output=True)
        ),
        "release_evidence_bundle_gate_command": (
            release_evidence_bundle_gate_command(manifest_path)
        ),
        "release_evidence_bundle_gate_json_command": (
            release_evidence_bundle_gate_command(manifest_path, json_output=True)
        ),
        "release_evidence_archive_checklist_command": (
            release_evidence_archive_checklist_command(manifest_path)
        ),
        "release_evidence_archive_checklist_json_command": (
            release_evidence_archive_checklist_command(manifest_path, json_output=True)
        ),
        "check_release_evidence_archive_command": (
            check_release_evidence_archive_command(manifest_path)
        ),
        "check_release_evidence_archive_json_command": (
            check_release_evidence_archive_command(manifest_path, json_output=True)
        ),
        "release_evidence_archive_gate_command": (
            release_evidence_archive_gate_command(manifest_path)
        ),
        "release_evidence_archive_gate_json_command": (
            release_evidence_archive_gate_command(manifest_path, json_output=True)
        ),
        "release_evidence_handoff_summary_command": (
            release_evidence_handoff_summary_command(manifest_path)
        ),
        "release_evidence_handoff_summary_json_command": (
            release_evidence_handoff_summary_command(manifest_path, json_output=True)
        ),
        "release_evidence_publication_index_template_command": (
            release_evidence_publication_index_template_command(manifest_path)
        ),
        "release_evidence_publication_index_template_json_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_command": (
            check_release_evidence_publication_index_command(manifest_path)
        ),
        "check_release_evidence_publication_index_json_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_command": (
            release_evidence_publication_index_gate_command(manifest_path)
        ),
        "release_evidence_publication_index_gate_json_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                json_output=True,
            )
        ),
        "operator_runbook_command": operator_runbook_command(manifest_path),
        "launch_gate_preflight_command": launch_gate_preflight_command(
            manifest_path,
        ),
        "snapshot_audit_handoffs_command": snapshot_audit_handoffs_command(
            manifest_path,
        ),
        "value_selection_checklists_command": value_selection_checklists_command(
            manifest_path,
        ),
        "evidence_payloads": bundle_state["payload_entries"],
        "evidence_payload_count": len(bundle_state["payload_entries"]),
        "next_blocker": operator_payload["next_blocker"],
        "next_blocker_handoff_command": (
            operator_payload["next_blocker_handoff_command"]
        ),
        "evidence": {
            "operator_runbook": operator_payload,
            "launch_gate_preflight": bundle_state["launch_gate_preflight"],
            "snapshot_audit_handoffs": bundle_state["snapshot_audit_handoffs"],
            "value_selection_checklists": (
                bundle_state["value_selection_checklists"]
            ),
        },
        "summary": release_evidence_bundle_summary(bundle_state),
    }


def release_evidence_bundle_json_text(manifest, manifest_path, check):
    return json.dumps(
        release_evidence_bundle_json_payload(manifest, manifest_path, check),
        indent=2,
        sort_keys=False,
    )


def release_evidence_bundle_mismatch_value(value):
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, list):
        return f"<list:{len(value)}>"
    if isinstance(value, dict):
        return f"<object:{len(value)}>"
    return f"<{type(value).__name__}>"


def release_evidence_bundle_mismatch_entries(actual, expected):
    mismatches = []

    def append_mismatch(path, kind, actual_value, expected_value):
        if len(mismatches) >= RELEASE_EVIDENCE_BUNDLE_MISMATCH_LIMIT:
            return
        mismatches.append({
            "path": path or "$",
            "kind": kind,
            "expected": release_evidence_bundle_mismatch_value(expected_value),
            "actual": release_evidence_bundle_mismatch_value(actual_value),
        })

    def compare(actual_value, expected_value, path):
        if len(mismatches) >= RELEASE_EVIDENCE_BUNDLE_MISMATCH_LIMIT:
            return
        if isinstance(expected_value, dict):
            if not isinstance(actual_value, dict):
                append_mismatch(path, "type", actual_value, expected_value)
                return
            for key, expected_child in expected_value.items():
                child_path = f"{path}.{key}" if path else key
                if key not in actual_value:
                    append_mismatch(child_path, "missing", "<missing>", expected_child)
                    continue
                compare(actual_value[key], expected_child, child_path)
            for key in sorted(set(actual_value) - set(expected_value)):
                child_path = f"{path}.{key}" if path else key
                append_mismatch(child_path, "unexpected", actual_value[key], "<absent>")
            return
        if isinstance(expected_value, list):
            if not isinstance(actual_value, list):
                append_mismatch(path, "type", actual_value, expected_value)
                return
            if len(actual_value) != len(expected_value):
                append_mismatch(path, "length", actual_value, expected_value)
            for index, expected_child in enumerate(expected_value):
                if index >= len(actual_value):
                    append_mismatch(
                        f"{path}[{index}]",
                        "missing",
                        "<missing>",
                        expected_child,
                    )
                    continue
                compare(actual_value[index], expected_child, f"{path}[{index}]")
            return
        if actual_value != expected_value:
            append_mismatch(path, "value", actual_value, expected_value)

    compare(actual, expected, "")
    return mismatches


def release_evidence_bundle_check_payload(
    manifest,
    manifest_path,
    check,
    bundle_path,
    require_match=False,
):
    bundle_text = read_release_evidence_bundle_text(bundle_path)
    try:
        actual = json.loads(
            bundle_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{bundle_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{bundle_path} is not valid JSON: {exc}") from None

    if not isinstance(actual, dict):
        raise ValueError("release evidence bundle must be a JSON object")

    expected = release_evidence_bundle_json_payload(manifest, manifest_path, check)
    mismatches = release_evidence_bundle_mismatch_entries(actual, expected)
    verified = not mismatches
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "require_match": require_match,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "mismatch_limit": RELEASE_EVIDENCE_BUNDLE_MISMATCH_LIMIT,
        "mismatch_limit_reached": (
            len(mismatches) >= RELEASE_EVIDENCE_BUNDLE_MISMATCH_LIMIT
        ),
        "release_evidence_bundle_command": release_evidence_bundle_command(
            manifest_path,
        ),
        "release_evidence_bundle_json_command": release_evidence_bundle_json_command(
            manifest_path,
        ),
        "check_release_evidence_bundle_command": (
            check_release_evidence_bundle_command(manifest_path, bundle_path)
        ),
        "check_release_evidence_bundle_json_command": (
            check_release_evidence_bundle_command(
                manifest_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_bundle_gate_command": (
            release_evidence_bundle_gate_command(manifest_path, bundle_path)
        ),
        "release_evidence_bundle_gate_json_command": (
            release_evidence_bundle_gate_command(
                manifest_path,
                bundle_path,
                json_output=True,
            )
        ),
        "expected_schema_version": expected.get("schema_version"),
        "actual_schema_version": actual.get("schema_version"),
        "expected_status": expected.get("status"),
        "actual_status": actual.get("status"),
        "expected_evidence_payload_count": expected.get("evidence_payload_count"),
        "actual_evidence_payload_count": actual.get("evidence_payload_count"),
        "expected_next_blocker": expected.get("next_blocker"),
        "actual_next_blocker": actual.get("next_blocker"),
        "expected_summary": expected.get("summary"),
        "actual_summary": actual.get("summary"),
    }


def release_evidence_bundle_check_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence bundle check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - release evidence bundle command: {payload['release_evidence_bundle_command']}",
        f"  - release evidence bundle JSON command: {payload['release_evidence_bundle_json_command']}",
        f"  - check release evidence bundle command: {payload['check_release_evidence_bundle_command']}",
        f"  - check release evidence bundle JSON command: {payload['check_release_evidence_bundle_json_command']}",
        f"  - release evidence bundle gate command: {payload['release_evidence_bundle_gate_command']}",
        f"  - release evidence bundle gate JSON command: {payload['release_evidence_bundle_gate_json_command']}",
        f"  - expected schema version: {payload['expected_schema_version']}",
        f"  - actual schema version: {payload['actual_schema_version']}",
        f"  - expected evidence payloads: {payload['expected_evidence_payload_count']}",
        f"  - actual evidence payloads: {payload['actual_evidence_payload_count']}",
        f"  - expected next blocker: {payload['expected_next_blocker']}",
        f"  - actual next blocker: {payload['actual_next_blocker']}",
    ]
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_bundle_check_text(
    manifest,
    manifest_path,
    check,
    bundle_path,
    require_match=False,
):
    return release_evidence_bundle_check_text_from_payload(
        release_evidence_bundle_check_payload(
            manifest,
            manifest_path,
            check,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_bundle_check_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_bundle_check_json_text(
    manifest,
    manifest_path,
    check,
    bundle_path,
    require_match=False,
):
    return json.dumps(
        release_evidence_bundle_check_payload(
            manifest,
            manifest_path,
            check,
            bundle_path,
            require_match=require_match,
        ),
        indent=2,
        sort_keys=False,
    )


def release_evidence_archive_checklist_steps(manifest_path, bundle_path):
    archive_fields = list(RELEASE_EVIDENCE_ARCHIVE_RECORD_FIELDS)
    return [
        {
            "step": 1,
            "id": "generate-release-evidence-bundle",
            "description": "Generate the compact release evidence bundle JSON.",
            "command": release_evidence_bundle_json_command(manifest_path),
            "output_artifact": display_path(bundle_path),
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "verify-release-evidence-bundle-gate",
            "description": (
                "Verify the archived bundle matches the current launch manifest."
            ),
            "command": release_evidence_bundle_gate_command(
                manifest_path,
                bundle_path,
                json_output=True,
            ),
            "required_verified": True,
            "required_mismatch_count": 0,
            "required_exit_code": 0,
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": "archive-release-evidence-record",
            "description": (
                "Archive the bundle and record the bundle location plus gate output."
            ),
            "required_archive_record_fields": archive_fields,
            "required_archive_record_field_count": len(archive_fields),
            "required_before_launch": True,
        },
        {
            "step": 4,
            "id": "publish-release-evidence-handoff",
            "description": (
                "Attach the archive record to the release handoff without adding "
                "production constants."
            ),
            "required_before_launch": True,
        },
    ]


def release_evidence_archive_checklist_payload(
    manifest,
    manifest_path,
    check,
    bundle_path,
):
    bundle_state = release_evidence_bundle_state(manifest, manifest_path, check)
    steps = release_evidence_archive_checklist_steps(manifest_path, bundle_path)
    archive_fields = list(RELEASE_EVIDENCE_ARCHIVE_RECORD_FIELDS)
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "status": manifest.get("status"),
        "release_evidence_bundle": display_path(bundle_path),
        "release_evidence_archive_checklist_command": (
            release_evidence_archive_checklist_command(manifest_path, bundle_path)
        ),
        "release_evidence_archive_checklist_json_command": (
            release_evidence_archive_checklist_command(
                manifest_path,
                bundle_path,
                json_output=True,
            )
        ),
        "check_release_evidence_archive_command": (
            check_release_evidence_archive_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "check_release_evidence_archive_json_command": (
            check_release_evidence_archive_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_archive_gate_command": (
            release_evidence_archive_gate_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_archive_gate_json_command": (
            release_evidence_archive_gate_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_handoff_summary_command": (
            release_evidence_handoff_summary_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_handoff_summary_json_command": (
            release_evidence_handoff_summary_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_template_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_publication_index_template_json_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "check_release_evidence_publication_index_json_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_publication_index_gate_json_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_bundle_json_command": release_evidence_bundle_json_command(
            manifest_path,
        ),
        "release_evidence_bundle_gate_json_command": (
            release_evidence_bundle_gate_command(
                manifest_path,
                bundle_path,
                json_output=True,
            )
        ),
        "archive_record_schema_version": 1,
        "required_archive_record_fields": archive_fields,
        "required_archive_record_field_count": len(archive_fields),
        "required_gate_result": {
            "verified": True,
            "mismatch_count": 0,
            "required_match_exit_code": 0,
        },
        "evidence_payloads": bundle_state["payload_entries"],
        "evidence_payload_count": len(bundle_state["payload_entries"]),
        "summary": release_evidence_bundle_summary(bundle_state),
        "checklist_steps": steps,
        "checklist_step_count": len(steps),
    }


def release_evidence_archive_checklist_text(manifest, manifest_path, check, bundle_path):
    payload = release_evidence_archive_checklist_payload(
        manifest,
        manifest_path,
        check,
        bundle_path,
    )
    lines = [
        "zkCoin public launch profile release evidence archive checklist:",
        f"  - status: {payload['status']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - release evidence archive checklist command: {payload['release_evidence_archive_checklist_command']}",
        f"  - release evidence archive checklist JSON command: {payload['release_evidence_archive_checklist_json_command']}",
        f"  - check release evidence archive command: {payload['check_release_evidence_archive_command']}",
        f"  - check release evidence archive JSON command: {payload['check_release_evidence_archive_json_command']}",
        f"  - release evidence archive gate command: {payload['release_evidence_archive_gate_command']}",
        f"  - release evidence archive gate JSON command: {payload['release_evidence_archive_gate_json_command']}",
        f"  - release evidence handoff summary command: {payload['release_evidence_handoff_summary_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
        f"  - release evidence publication index template command: {payload['release_evidence_publication_index_template_command']}",
        f"  - release evidence publication index template JSON command: {payload['release_evidence_publication_index_template_json_command']}",
        f"  - check release evidence publication index command: {payload['check_release_evidence_publication_index_command']}",
        f"  - check release evidence publication index JSON command: {payload['check_release_evidence_publication_index_json_command']}",
        f"  - release evidence publication index gate command: {payload['release_evidence_publication_index_gate_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - release evidence bundle JSON command: {payload['release_evidence_bundle_json_command']}",
        f"  - release evidence bundle gate JSON command: {payload['release_evidence_bundle_gate_json_command']}",
        f"  - archive record schema version: {payload['archive_record_schema_version']}",
        f"  - archive record fields: {list_summary(payload['required_archive_record_fields'])}",
        "  - required gate verified: yes",
        "  - required gate mismatches: 0",
        "  - required gate exit code: 0",
        f"  - evidence payloads: {payload['evidence_payload_count']}",
        f"  - checklist steps: {payload['checklist_step_count']}",
    ]
    for step in payload["checklist_steps"]:
        lines.append(f"  - step {step['step']}: {step['id']}")
        if step.get("command") is not None:
            lines.append(f"  - step {step['step']} command: {step['command']}")
        if step.get("output_artifact") is not None:
            lines.append(f"  - step {step['step']} artifact: {step['output_artifact']}")
        if step.get("required_archive_record_fields") is not None:
            lines.append(
                f"  - step {step['step']} required fields: "
                f"{list_summary(step['required_archive_record_fields'])}"
            )
    return "\n".join(lines)


def release_evidence_archive_checklist_json_text(
    manifest,
    manifest_path,
    check,
    bundle_path,
):
    return json.dumps(
        release_evidence_archive_checklist_payload(
            manifest,
            manifest_path,
            check,
            bundle_path,
        ),
        indent=2,
        sort_keys=False,
    )


def release_evidence_bundle_sha256(bundle_path):
    bundle_text = read_release_evidence_bundle_text(bundle_path)
    return hashlib.sha256(bundle_text.encode("utf8")).hexdigest()


def read_release_evidence_archive_record(record_path):
    record_text = read_release_evidence_archive_record_text(record_path)
    try:
        record = json.loads(
            record_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{record_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{record_path} is not valid JSON: {exc}") from None

    if not isinstance(record, dict):
        raise ValueError("release evidence archive record must be a JSON object")
    return record


def read_release_evidence_publication_index_archive_record(record_path):
    record_text = read_release_evidence_publication_index_archive_record_text(
        record_path
    )
    try:
        record = json.loads(
            record_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{record_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{record_path} is not valid JSON: {exc}") from None

    if not isinstance(record, dict):
        raise ValueError(
            "release evidence publication index archive record must be a JSON "
            "object"
        )
    return record


def read_release_evidence_publication_closeout_archive_record(record_path):
    record_text = read_release_evidence_publication_closeout_archive_record_text(
        record_path
    )
    try:
        record = json.loads(
            record_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{record_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{record_path} is not valid JSON: {exc}") from None

    if not isinstance(record, dict):
        raise ValueError(
            "release evidence publication closeout archive record must be a "
            "JSON object"
        )
    return record


def read_release_evidence_publication_closeout(closeout_path):
    closeout_text = read_release_evidence_publication_closeout_text(
        closeout_path
    )
    try:
        closeout = json.loads(
            closeout_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{closeout_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{closeout_path} is not valid JSON: {exc}") from None

    if not isinstance(closeout, dict):
        raise ValueError(
            "release evidence publication closeout must be a JSON object"
        )
    return closeout


def release_evidence_archive_mismatch_entry(path, kind, actual_value, expected_value):
    return {
        "path": path or "$",
        "kind": kind,
        "expected": release_evidence_bundle_mismatch_value(expected_value),
        "actual": release_evidence_bundle_mismatch_value(actual_value),
    }


def append_release_evidence_archive_mismatch(
    mismatches,
    path,
    kind,
    actual_value,
    expected_value,
):
    mismatches.append(
        release_evidence_archive_mismatch_entry(
            path,
            kind,
            actual_value,
            expected_value,
        )
    )


def release_evidence_archive_check_payload(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    record = read_release_evidence_archive_record(archive_record_path)
    bundle_check = release_evidence_bundle_check_payload(
        manifest,
        manifest_path,
        check,
        bundle_path,
        require_match=True,
    )
    bundle_sha256 = release_evidence_bundle_sha256(bundle_path)
    archive_fields = list(RELEASE_EVIDENCE_ARCHIVE_RECORD_FIELDS)
    missing_required_fields = [
        field for field in archive_fields if field not in record
    ]
    unexpected_fields = sorted(set(record) - set(archive_fields))
    mismatches = []

    for field in missing_required_fields:
        append_release_evidence_archive_mismatch(
            mismatches,
            field,
            "missing",
            "<missing>",
            "required archive record field",
        )

    expected_archive_values = {
        "release_evidence_bundle_sha256": bundle_sha256,
        "release_evidence_bundle_schema_version": (
            bundle_check["expected_schema_version"]
        ),
        "manifest_path": display_path(manifest_path),
        "gate_command": bundle_check["release_evidence_bundle_gate_json_command"],
        "gate_verified": True,
        "gate_mismatch_count": 0,
    }
    for field, expected_value in expected_archive_values.items():
        if field not in record:
            continue
        actual_value = record[field]
        if type(actual_value) is not type(expected_value):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                expected_value,
            )
            continue
        if actual_value != expected_value:
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "value",
                actual_value,
                expected_value,
            )

    nonempty_string_fields = (
        "release_evidence_bundle_uri",
        "manifest_commit",
        "gate_checked_at",
    )
    for field in nonempty_string_fields:
        if field not in record:
            continue
        actual_value = record[field]
        if not isinstance(actual_value, str):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                "non-empty string",
            )
        elif not actual_value.strip():
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "empty",
                actual_value,
                "non-empty string",
            )

    if not bundle_check["verified"]:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_bundle_gate.verified",
            "value",
            bundle_check["verified"],
            True,
        )
    if bundle_check["mismatch_count"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_bundle_gate.mismatch_count",
            "value",
            bundle_check["mismatch_count"],
            0,
        )
    if bundle_check["required_match_exit_code"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_bundle_gate.required_match_exit_code",
            "value",
            bundle_check["required_match_exit_code"],
            0,
        )

    actual_archive_values = {
        field: record.get(field)
        for field in archive_fields
    }
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": not mismatches,
        "require_match": require_match,
        "required_match_exit_code": 0 if not mismatches else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "missing_required_fields": missing_required_fields,
        "missing_required_field_count": len(missing_required_fields),
        "unexpected_fields": unexpected_fields,
        "unexpected_field_count": len(unexpected_fields),
        "archive_record_schema_version": 1,
        "required_archive_record_fields": archive_fields,
        "required_archive_record_field_count": len(archive_fields),
        "release_evidence_bundle_sha256": bundle_sha256,
        "expected_archive_record_values": expected_archive_values,
        "actual_archive_record_values": actual_archive_values,
        "required_nonempty_string_fields": list(nonempty_string_fields),
        "bundle_gate_verified": bundle_check["verified"],
        "bundle_gate_mismatch_count": bundle_check["mismatch_count"],
        "bundle_gate_required_match_exit_code": (
            bundle_check["required_match_exit_code"]
        ),
        "bundle_gate_mismatches": bundle_check["mismatches"],
        "bundle_gate_mismatch_limit": bundle_check["mismatch_limit"],
        "bundle_gate_mismatch_limit_reached": (
            bundle_check["mismatch_limit_reached"]
        ),
        "check_release_evidence_archive_command": (
            check_release_evidence_archive_command(
                manifest_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "check_release_evidence_archive_json_command": (
            check_release_evidence_archive_command(
                manifest_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_archive_gate_command": (
            release_evidence_archive_gate_command(
                manifest_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_archive_gate_json_command": (
            release_evidence_archive_gate_command(
                manifest_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_archive_checklist_command": (
            release_evidence_archive_checklist_command(manifest_path, bundle_path)
        ),
        "release_evidence_archive_checklist_json_command": (
            release_evidence_archive_checklist_command(
                manifest_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_handoff_summary_command": (
            release_evidence_handoff_summary_command(
                manifest_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_handoff_summary_json_command": (
            release_evidence_handoff_summary_command(
                manifest_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_template_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_template_json_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "check_release_evidence_publication_index_json_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_publication_index_gate_json_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_bundle_gate_json_command": (
            bundle_check["release_evidence_bundle_gate_json_command"]
        ),
    }


def release_evidence_archive_check_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence archive check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - release evidence bundle sha256: {payload['release_evidence_bundle_sha256']}",
        f"  - required archive record fields: {list_summary(payload['required_archive_record_fields'])}",
        f"  - missing required fields: {list_summary(payload['missing_required_fields'])}",
        f"  - unexpected fields: {list_summary(payload['unexpected_fields'])}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - bundle gate verified: {yes_no(payload['bundle_gate_verified'])}",
        f"  - bundle gate mismatches: {payload['bundle_gate_mismatch_count']}",
        f"  - bundle gate required-match exit code: {payload['bundle_gate_required_match_exit_code']}",
        f"  - check release evidence archive command: {payload['check_release_evidence_archive_command']}",
        f"  - check release evidence archive JSON command: {payload['check_release_evidence_archive_json_command']}",
        f"  - release evidence archive gate command: {payload['release_evidence_archive_gate_command']}",
        f"  - release evidence archive gate JSON command: {payload['release_evidence_archive_gate_json_command']}",
        f"  - release evidence archive checklist command: {payload['release_evidence_archive_checklist_command']}",
        f"  - release evidence archive checklist JSON command: {payload['release_evidence_archive_checklist_json_command']}",
        f"  - release evidence handoff summary command: {payload['release_evidence_handoff_summary_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
        f"  - release evidence publication index template command: {payload['release_evidence_publication_index_template_command']}",
        f"  - release evidence publication index template JSON command: {payload['release_evidence_publication_index_template_json_command']}",
        f"  - check release evidence publication index command: {payload['check_release_evidence_publication_index_command']}",
        f"  - check release evidence publication index JSON command: {payload['check_release_evidence_publication_index_json_command']}",
        f"  - release evidence publication index gate command: {payload['release_evidence_publication_index_gate_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - release evidence bundle gate JSON command: {payload['release_evidence_bundle_gate_json_command']}",
    ]
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_archive_check_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_archive_check_text_from_payload(
        release_evidence_archive_check_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_archive_check_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_archive_check_json_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return json.dumps(
        release_evidence_archive_check_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        ),
        indent=2,
        sort_keys=False,
    )


def release_evidence_handoff_first_mismatch(bundle_gate, archive_gate):
    if archive_gate["mismatches"]:
        mismatch = dict(archive_gate["mismatches"][0])
        mismatch["source"] = "archive_gate"
        return mismatch
    if bundle_gate["mismatches"]:
        mismatch = dict(bundle_gate["mismatches"][0])
        mismatch["source"] = "bundle_gate"
        return mismatch
    return None


def release_evidence_handoff_artifacts(
    bundle_gate,
    archive_gate,
    summary_json_command,
    verified,
):
    return [
        {
            "step": 1,
            "id": "release-evidence-bundle",
            "description": "Retain the release evidence bundle JSON artifact.",
            "path": bundle_gate["release_evidence_bundle"],
            "verified": bundle_gate["verified"],
            "command": bundle_gate["release_evidence_bundle_gate_json_command"],
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "release-evidence-archive-record",
            "description": "Retain the filled release evidence archive record JSON.",
            "path": archive_gate["release_evidence_archive_record"],
            "verified": archive_gate["verified"],
            "command": archive_gate["release_evidence_archive_gate_json_command"],
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": "release-evidence-handoff-summary-json",
            "description": "Publish the handoff summary JSON after both gates pass.",
            "path": "<release_evidence_handoff_summary.json>",
            "verified": verified,
            "command": summary_json_command,
            "required_before_launch": True,
        },
    ]


def release_evidence_publication_blockers(handoff_artifacts):
    return [
        {
            "id": artifact["id"],
            "step": artifact["step"],
            "path": artifact["path"],
            "reason": "handoff artifact is not verified",
            "command": artifact["command"],
        }
        for artifact in handoff_artifacts
        if not artifact["verified"]
    ]


def release_evidence_handoff_summary_payload(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    bundle_gate = release_evidence_bundle_check_payload(
        manifest,
        manifest_path,
        check,
        bundle_path,
        require_match=True,
    )
    archive_gate = release_evidence_archive_check_payload(
        manifest,
        manifest_path,
        check,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    verified = bundle_gate["verified"] and archive_gate["verified"]
    summary_command = release_evidence_handoff_summary_command(
        manifest_path,
        archive_record_path,
        bundle_path,
    )
    summary_json_command = release_evidence_handoff_summary_command(
        manifest_path,
        archive_record_path,
        bundle_path,
        json_output=True,
    )
    publication_index_template_command = (
        release_evidence_publication_index_template_command(
            manifest_path,
            archive_record_path,
            bundle_path,
        )
    )
    publication_index_template_json_command = (
        release_evidence_publication_index_template_command(
            manifest_path,
            archive_record_path,
            bundle_path,
            json_output=True,
        )
    )
    publication_index_check_command = (
        check_release_evidence_publication_index_command(
            manifest_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
        )
    )
    publication_index_check_json_command = (
        check_release_evidence_publication_index_command(
            manifest_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
            json_output=True,
        )
    )
    publication_index_gate_command = (
        release_evidence_publication_index_gate_command(
            manifest_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
        )
    )
    publication_index_gate_json_command = (
        release_evidence_publication_index_gate_command(
            manifest_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
            json_output=True,
        )
    )
    handoff_artifacts = release_evidence_handoff_artifacts(
        bundle_gate,
        archive_gate,
        summary_json_command,
        verified,
    )
    publication_blockers = release_evidence_publication_blockers(handoff_artifacts)
    next_publication_blocker = (
        publication_blockers[0] if publication_blockers else None
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": (
            bundle_gate["mismatch_count"] + archive_gate["mismatch_count"]
        ),
        "handoff_artifact_count": len(handoff_artifacts),
        "verified_handoff_artifact_count": len([
            artifact
            for artifact in handoff_artifacts
            if artifact["verified"]
        ]),
        "handoff_artifacts": handoff_artifacts,
        "ready_for_publication": not publication_blockers,
        "publication_blocker_count": len(publication_blockers),
        "publication_blockers": publication_blockers,
        "next_publication_blocker": next_publication_blocker,
        "next_publication_blocker_id": (
            next_publication_blocker["id"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_path": (
            next_publication_blocker["path"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_command": (
            next_publication_blocker["command"]
            if next_publication_blocker is not None
            else None
        ),
        "first_mismatch": release_evidence_handoff_first_mismatch(
            bundle_gate,
            archive_gate,
        ),
        "bundle_gate": {
            "verified": bundle_gate["verified"],
            "require_match": bundle_gate["require_match"],
            "required_match_exit_code": bundle_gate["required_match_exit_code"],
            "mismatch_count": bundle_gate["mismatch_count"],
            "mismatch_limit_reached": bundle_gate["mismatch_limit_reached"],
        },
        "archive_gate": {
            "verified": archive_gate["verified"],
            "require_match": archive_gate["require_match"],
            "required_match_exit_code": archive_gate["required_match_exit_code"],
            "mismatch_count": archive_gate["mismatch_count"],
            "missing_required_field_count": (
                archive_gate["missing_required_field_count"]
            ),
            "unexpected_field_count": archive_gate["unexpected_field_count"],
            "bundle_gate_verified": archive_gate["bundle_gate_verified"],
            "bundle_gate_mismatch_count": (
                archive_gate["bundle_gate_mismatch_count"]
            ),
            "bundle_gate_required_match_exit_code": (
                archive_gate["bundle_gate_required_match_exit_code"]
            ),
        },
        "release_evidence_handoff_summary_command": summary_command,
        "release_evidence_handoff_summary_json_command": summary_json_command,
        "release_evidence_bundle_gate_json_command": (
            bundle_gate["release_evidence_bundle_gate_json_command"]
        ),
        "release_evidence_archive_gate_json_command": (
            archive_gate["release_evidence_archive_gate_json_command"]
        ),
        "release_evidence_publication_index_template_command": (
            publication_index_template_command
        ),
        "release_evidence_publication_index_template_json_command": (
            publication_index_template_json_command
        ),
        "check_release_evidence_publication_index_command": (
            publication_index_check_command
        ),
        "check_release_evidence_publication_index_json_command": (
            publication_index_check_json_command
        ),
        "release_evidence_publication_index_gate_command": (
            publication_index_gate_command
        ),
        "release_evidence_publication_index_gate_json_command": (
            publication_index_gate_json_command
        ),
        "commands": {
            "release_evidence_handoff_summary": summary_command,
            "release_evidence_handoff_summary_json": summary_json_command,
            "release_evidence_bundle_gate_json": (
                bundle_gate["release_evidence_bundle_gate_json_command"]
            ),
            "release_evidence_archive_gate_json": (
                archive_gate["release_evidence_archive_gate_json_command"]
            ),
            "release_evidence_publication_index_template": (
                publication_index_template_command
            ),
            "release_evidence_publication_index_template_json": (
                publication_index_template_json_command
            ),
            "check_release_evidence_publication_index": (
                publication_index_check_command
            ),
            "check_release_evidence_publication_index_json": (
                publication_index_check_json_command
            ),
            "release_evidence_publication_index_gate": (
                publication_index_gate_command
            ),
            "release_evidence_publication_index_gate_json": (
                publication_index_gate_json_command
            ),
        },
    }


def release_evidence_handoff_summary_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence handoff summary:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - handoff artifacts: {payload['handoff_artifact_count']}",
        f"  - verified handoff artifacts: {payload['verified_handoff_artifact_count']}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - bundle gate verified: {yes_no(payload['bundle_gate']['verified'])}",
        f"  - bundle gate required-match exit code: {payload['bundle_gate']['required_match_exit_code']}",
        f"  - bundle gate mismatches: {payload['bundle_gate']['mismatch_count']}",
        f"  - bundle gate mismatch limit reached: {yes_no(payload['bundle_gate']['mismatch_limit_reached'])}",
        f"  - archive gate verified: {yes_no(payload['archive_gate']['verified'])}",
        f"  - archive gate required-match exit code: {payload['archive_gate']['required_match_exit_code']}",
        f"  - archive gate mismatches: {payload['archive_gate']['mismatch_count']}",
        f"  - archive missing required fields: {payload['archive_gate']['missing_required_field_count']}",
        f"  - archive unexpected fields: {payload['archive_gate']['unexpected_field_count']}",
        f"  - release evidence handoff summary command: {payload['release_evidence_handoff_summary_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
        f"  - release evidence bundle gate JSON command: {payload['release_evidence_bundle_gate_json_command']}",
        f"  - release evidence archive gate JSON command: {payload['release_evidence_archive_gate_json_command']}",
        f"  - release evidence publication index template command: {payload['release_evidence_publication_index_template_command']}",
        f"  - release evidence publication index template JSON command: {payload['release_evidence_publication_index_template_json_command']}",
        f"  - check release evidence publication index command: {payload['check_release_evidence_publication_index_command']}",
        f"  - check release evidence publication index JSON command: {payload['check_release_evidence_publication_index_json_command']}",
        f"  - release evidence publication index gate command: {payload['release_evidence_publication_index_gate_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
    ]
    for artifact in payload["handoff_artifacts"]:
        lines.extend([
            f"  - handoff artifact {artifact['step']}: {artifact['id']}",
            f"  - handoff artifact {artifact['step']} path: {artifact['path']}",
            (
                f"  - handoff artifact {artifact['step']} verified: "
                f"{yes_no(artifact['verified'])}"
            ),
            f"  - handoff artifact {artifact['step']} command: {artifact['command']}",
        ])
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    if payload["first_mismatch"] is not None:
        mismatch = payload["first_mismatch"]
        lines.extend([
            f"  - first mismatch source: {mismatch['source']}",
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_handoff_summary_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    return release_evidence_handoff_summary_text_from_payload(
        release_evidence_handoff_summary_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_handoff_summary_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_handoff_summary_json_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    return release_evidence_handoff_summary_json_text_from_payload(
        release_evidence_handoff_summary_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_publication_index_template_values():
    return {
        "schema_version": 1,
        "release_evidence_bundle_uri": "<release_evidence_bundle_uri>",
        "release_evidence_archive_record_uri": (
            "<release_evidence_archive_record_uri>"
        ),
        "release_evidence_handoff_summary_uri": (
            "<release_evidence_handoff_summary_uri>"
        ),
        "manifest_commit": "<manifest_commit>",
        "published_at": "<published_at_rfc3339>",
        "publisher": "<publisher>",
    }


def release_evidence_publication_index_template_payload(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    handoff_summary = release_evidence_handoff_summary_payload(
        manifest,
        manifest_path,
        check,
        archive_record_path,
        bundle_path,
    )
    template_command = release_evidence_publication_index_template_command(
        manifest_path,
        archive_record_path,
        bundle_path,
    )
    template_json_command = release_evidence_publication_index_template_command(
        manifest_path,
        archive_record_path,
        bundle_path,
        json_output=True,
    )
    check_command = check_release_evidence_publication_index_command(
        manifest_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
    )
    check_json_command = check_release_evidence_publication_index_command(
        manifest_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
        json_output=True,
    )
    gate_command = release_evidence_publication_index_gate_command(
        manifest_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
    )
    gate_json_command = release_evidence_publication_index_gate_command(
        manifest_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
        json_output=True,
    )
    required_fields = list(RELEASE_EVIDENCE_PUBLICATION_INDEX_FIELDS)
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "publication_index_schema_version": 1,
        "required_publication_index_fields": required_fields,
        "required_publication_index_field_count": len(required_fields),
        "publication_index_template": (
            release_evidence_publication_index_template_values()
        ),
        "verified": handoff_summary["verified"],
        "ready_for_publication": handoff_summary["ready_for_publication"],
        "publication_blocker_count": handoff_summary["publication_blocker_count"],
        "publication_blockers": handoff_summary["publication_blockers"],
        "next_publication_blocker": handoff_summary["next_publication_blocker"],
        "next_publication_blocker_id": (
            handoff_summary["next_publication_blocker_id"]
        ),
        "next_publication_blocker_path": (
            handoff_summary["next_publication_blocker_path"]
        ),
        "next_publication_blocker_command": (
            handoff_summary["next_publication_blocker_command"]
        ),
        "handoff_artifact_count": handoff_summary["handoff_artifact_count"],
        "verified_handoff_artifact_count": (
            handoff_summary["verified_handoff_artifact_count"]
        ),
        "handoff_artifacts": handoff_summary["handoff_artifacts"],
        "release_evidence_publication_index_template_command": template_command,
        "release_evidence_publication_index_template_json_command": (
            template_json_command
        ),
        "check_release_evidence_publication_index_command": check_command,
        "check_release_evidence_publication_index_json_command": check_json_command,
        "release_evidence_publication_index_gate_command": gate_command,
        "release_evidence_publication_index_gate_json_command": gate_json_command,
        "release_evidence_handoff_summary_json_command": (
            handoff_summary["release_evidence_handoff_summary_json_command"]
        ),
        "commands": {
            "release_evidence_publication_index_template": template_command,
            "release_evidence_publication_index_template_json": (
                template_json_command
            ),
            "check_release_evidence_publication_index": check_command,
            "check_release_evidence_publication_index_json": check_json_command,
            "release_evidence_publication_index_gate": gate_command,
            "release_evidence_publication_index_gate_json": gate_json_command,
            "release_evidence_handoff_summary_json": (
                handoff_summary["release_evidence_handoff_summary_json_command"]
            ),
        },
    }


def release_evidence_publication_index_template_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication index template:",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - handoff artifacts: {payload['handoff_artifact_count']}",
        f"  - verified handoff artifacts: {payload['verified_handoff_artifact_count']}",
        f"  - publication index schema version: {payload['publication_index_schema_version']}",
        f"  - required publication index fields: {list_summary(payload['required_publication_index_fields'])}",
        f"  - release evidence publication index template command: {payload['release_evidence_publication_index_template_command']}",
        f"  - release evidence publication index template JSON command: {payload['release_evidence_publication_index_template_json_command']}",
        f"  - check release evidence publication index command: {payload['check_release_evidence_publication_index_command']}",
        f"  - check release evidence publication index JSON command: {payload['check_release_evidence_publication_index_json_command']}",
        f"  - release evidence publication index gate command: {payload['release_evidence_publication_index_gate_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
    ]
    for field in payload["required_publication_index_fields"]:
        lines.append(
            f"  - publication index {field}: "
            f"{payload['publication_index_template'][field]}"
        )
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_index_template_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_index_template_text_from_payload(
        release_evidence_publication_index_template_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_publication_index_template_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_index_template_json_text(
    manifest,
    manifest_path,
    check,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_index_template_json_text_from_payload(
        release_evidence_publication_index_template_payload(
            manifest,
            manifest_path,
            check,
            archive_record_path,
            bundle_path,
        )
    )


def parse_release_evidence_publication_index(index_path, index_text):
    try:
        publication_index = json.loads(
            index_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{index_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{index_path} is not valid JSON: {exc}") from None

    if not isinstance(publication_index, dict):
        raise ValueError("release evidence publication index must be a JSON object")
    return publication_index


def read_release_evidence_publication_index(index_path):
    return parse_release_evidence_publication_index(
        index_path,
        read_release_evidence_publication_index_text(index_path),
    )


def release_evidence_publication_index_placeholder_fields(publication_index):
    template = release_evidence_publication_index_template_values()
    return [
        field
        for field in RELEASE_EVIDENCE_PUBLICATION_INDEX_FIELDS
        if field != "schema_version"
        and publication_index.get(field) == template[field]
    ]


def release_evidence_publication_index_check_payload(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    publication_index_text = read_release_evidence_publication_index_text(
        publication_index_path
    )
    publication_index = parse_release_evidence_publication_index(
        publication_index_path,
        publication_index_text,
    )
    publication_index_sha256 = hashlib.sha256(
        publication_index_text.encode("utf8")
    ).hexdigest()
    handoff_summary = release_evidence_handoff_summary_payload(
        manifest,
        manifest_path,
        check,
        archive_record_path,
        bundle_path,
    )
    archive_gate = release_evidence_archive_check_payload(
        manifest,
        manifest_path,
        check,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    archive_values = archive_gate["actual_archive_record_values"]
    required_fields = list(RELEASE_EVIDENCE_PUBLICATION_INDEX_FIELDS)
    missing_required_fields = [
        field for field in required_fields if field not in publication_index
    ]
    unexpected_fields = sorted(set(publication_index) - set(required_fields))
    placeholder_fields = release_evidence_publication_index_placeholder_fields(
        publication_index,
    )
    mismatches = []

    for field in missing_required_fields:
        append_release_evidence_archive_mismatch(
            mismatches,
            field,
            "missing",
            "<missing>",
            "required publication index field",
        )

    expected_values = {
        "schema_version": 1,
        "release_evidence_bundle_uri": archive_values.get(
            "release_evidence_bundle_uri",
        ),
        "manifest_commit": archive_values.get("manifest_commit"),
    }
    for field, expected_value in expected_values.items():
        if field not in publication_index or expected_value is None:
            continue
        actual_value = publication_index[field]
        if type(actual_value) is not type(expected_value):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                expected_value,
            )
            continue
        if actual_value != expected_value:
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "value",
                actual_value,
                expected_value,
            )

    nonempty_string_fields = [
        field
        for field in required_fields
        if field != "schema_version"
    ]
    for field in nonempty_string_fields:
        if field not in publication_index:
            continue
        actual_value = publication_index[field]
        if not isinstance(actual_value, str):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                "non-empty non-placeholder string",
            )
        elif not actual_value.strip():
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "empty",
                actual_value,
                "non-empty non-placeholder string",
            )
        elif field in placeholder_fields:
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "placeholder",
                actual_value,
                "operator-supplied non-placeholder string",
            )

    if not handoff_summary["ready_for_publication"]:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_handoff.ready_for_publication",
            "value",
            handoff_summary["ready_for_publication"],
            True,
        )

    verified = not mismatches
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_index": display_path(
            publication_index_path,
        ),
        "release_evidence_publication_index_sha256": publication_index_sha256,
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "require_match": require_match,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "missing_required_fields": missing_required_fields,
        "missing_required_field_count": len(missing_required_fields),
        "unexpected_fields": unexpected_fields,
        "unexpected_field_count": len(unexpected_fields),
        "placeholder_fields": placeholder_fields,
        "placeholder_field_count": len(placeholder_fields),
        "publication_index_schema_version": 1,
        "required_publication_index_fields": required_fields,
        "required_publication_index_field_count": len(required_fields),
        "required_nonplaceholder_string_fields": nonempty_string_fields,
        "publication_index_template": (
            release_evidence_publication_index_template_values()
        ),
        "actual_publication_index_values": {
            field: publication_index.get(field)
            for field in required_fields
        },
        "expected_publication_index_values": expected_values,
        "ready_for_publication": handoff_summary["ready_for_publication"],
        "publication_blocker_count": handoff_summary["publication_blocker_count"],
        "publication_blockers": handoff_summary["publication_blockers"],
        "next_publication_blocker": handoff_summary["next_publication_blocker"],
        "next_publication_blocker_id": (
            handoff_summary["next_publication_blocker_id"]
        ),
        "next_publication_blocker_path": (
            handoff_summary["next_publication_blocker_path"]
        ),
        "next_publication_blocker_command": (
            handoff_summary["next_publication_blocker_command"]
        ),
        "handoff_verified": handoff_summary["verified"],
        "handoff_artifact_count": handoff_summary["handoff_artifact_count"],
        "verified_handoff_artifact_count": (
            handoff_summary["verified_handoff_artifact_count"]
        ),
        "archive_gate_verified": archive_gate["verified"],
        "archive_gate_mismatch_count": archive_gate["mismatch_count"],
        "check_release_evidence_publication_index_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "check_release_evidence_publication_index_json_command": (
            check_release_evidence_publication_index_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_gate_json_command": (
            release_evidence_publication_index_gate_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_template_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_template_json_command": (
            release_evidence_publication_index_template_command(
                manifest_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_handoff_summary_json_command": (
            handoff_summary["release_evidence_handoff_summary_json_command"]
        ),
        "release_evidence_publication_index_archive_checklist_command": (
            release_evidence_publication_index_archive_checklist_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_checklist_json_command": (
            release_evidence_publication_index_archive_checklist_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_archive_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "check_release_evidence_publication_index_archive_json_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_archive_gate_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_gate_json_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
    }


def release_evidence_publication_index_check_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication index check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence publication index sha256: {payload['release_evidence_publication_index_sha256']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - handoff verified: {yes_no(payload['handoff_verified'])}",
        f"  - handoff artifacts: {payload['handoff_artifact_count']}",
        f"  - verified handoff artifacts: {payload['verified_handoff_artifact_count']}",
        f"  - archive gate verified: {yes_no(payload['archive_gate_verified'])}",
        f"  - archive gate mismatches: {payload['archive_gate_mismatch_count']}",
        f"  - required publication index fields: {list_summary(payload['required_publication_index_fields'])}",
        f"  - missing required fields: {list_summary(payload['missing_required_fields'])}",
        f"  - unexpected fields: {list_summary(payload['unexpected_fields'])}",
        f"  - placeholder fields: {list_summary(payload['placeholder_fields'])}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - check release evidence publication index command: {payload['check_release_evidence_publication_index_command']}",
        f"  - check release evidence publication index JSON command: {payload['check_release_evidence_publication_index_json_command']}",
        f"  - release evidence publication index gate command: {payload['release_evidence_publication_index_gate_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - release evidence publication index template command: {payload['release_evidence_publication_index_template_command']}",
        f"  - release evidence publication index template JSON command: {payload['release_evidence_publication_index_template_json_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
        f"  - release evidence publication index archive checklist command: {payload['release_evidence_publication_index_archive_checklist_command']}",
        f"  - release evidence publication index archive checklist JSON command: {payload['release_evidence_publication_index_archive_checklist_json_command']}",
        f"  - check release evidence publication index archive command: {payload['check_release_evidence_publication_index_archive_command']}",
        f"  - check release evidence publication index archive JSON command: {payload['check_release_evidence_publication_index_archive_json_command']}",
        f"  - release evidence publication index archive gate command: {payload['release_evidence_publication_index_archive_gate_command']}",
        f"  - release evidence publication index archive gate JSON command: {payload['release_evidence_publication_index_archive_gate_json_command']}",
    ]
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_index_check_text(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_index_check_text_from_payload(
        release_evidence_publication_index_check_payload(
            manifest,
            manifest_path,
            check,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_index_check_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_index_check_json_text(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_index_check_json_text_from_payload(
        release_evidence_publication_index_check_payload(
            manifest,
            manifest_path,
            check,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_index_archive_checklist_steps(
    manifest_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    archive_fields = list(RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_FIELDS)
    return [
        {
            "step": 1,
            "id": "verify-release-evidence-publication-index-gate",
            "description": (
                "Verify the filled publication index matches the current "
                "release evidence handoff."
            ),
            "command": release_evidence_publication_index_gate_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            ),
            "required_verified": True,
            "required_mismatch_count": 0,
            "required_exit_code": 0,
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "archive-release-evidence-publication-index-record",
            "description": (
                "Archive the filled publication index and record its immutable "
                "location plus gate output."
            ),
            "required_archive_record_fields": archive_fields,
            "required_archive_record_field_count": len(archive_fields),
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": "publish-release-evidence-publication-index-archive-record",
            "description": (
                "Attach the publication index archive record to the release "
                "handoff without adding production constants."
            ),
            "required_before_launch": True,
        },
    ]


def release_evidence_publication_index_archive_checklist_payload(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    publication_index_gate = release_evidence_publication_index_check_payload(
        manifest,
        manifest_path,
        check,
        publication_index_path,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    archive_fields = list(RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_FIELDS)
    steps = release_evidence_publication_index_archive_checklist_steps(
        manifest_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
    )
    expected_archive_record_values = {
        "release_evidence_publication_index_sha256": (
            publication_index_gate["release_evidence_publication_index_sha256"]
        ),
        "release_evidence_publication_index_schema_version": (
            publication_index_gate["publication_index_schema_version"]
        ),
        "manifest_path": display_path(manifest_path),
        "manifest_commit": publication_index_gate[
            "expected_publication_index_values"
        ].get("manifest_commit"),
        "gate_command": (
            publication_index_gate[
                "release_evidence_publication_index_gate_json_command"
            ]
        ),
        "gate_verified": True,
        "gate_mismatch_count": 0,
    }
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_index": (
            publication_index_gate["release_evidence_publication_index"]
        ),
        "release_evidence_publication_index_sha256": (
            publication_index_gate["release_evidence_publication_index_sha256"]
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "release_evidence_publication_index_archive_checklist_command": (
            release_evidence_publication_index_archive_checklist_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_checklist_json_command": (
            release_evidence_publication_index_archive_checklist_command(
                manifest_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "check_release_evidence_publication_index_archive_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "check_release_evidence_publication_index_archive_json_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_archive_gate_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_gate_json_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_path=publication_index_path,
                archive_record_path=archive_record_path,
                bundle_path=bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_gate_json_command": (
            publication_index_gate[
                "release_evidence_publication_index_gate_json_command"
            ]
        ),
        "publication_index_gate_verified": publication_index_gate["verified"],
        "publication_index_gate_mismatch_count": (
            publication_index_gate["mismatch_count"]
        ),
        "publication_index_gate_required_match_exit_code": (
            publication_index_gate["required_match_exit_code"]
        ),
        "publication_index_gate_mismatches": publication_index_gate["mismatches"],
        "ready_for_archive": publication_index_gate["verified"],
        "archive_record_schema_version": 1,
        "required_archive_record_fields": archive_fields,
        "required_archive_record_field_count": len(archive_fields),
        "required_operator_supplied_archive_record_fields": [
            "release_evidence_publication_index_uri",
            "gate_checked_at",
        ],
        "expected_archive_record_values": expected_archive_record_values,
        "required_gate_result": {
            "verified": True,
            "mismatch_count": 0,
            "required_match_exit_code": 0,
        },
        "checklist_steps": steps,
        "checklist_step_count": len(steps),
    }


def release_evidence_publication_index_archive_checklist_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication index archive checklist:",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence publication index sha256: {payload['release_evidence_publication_index_sha256']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - ready for archive: {yes_no(payload['ready_for_archive'])}",
        f"  - publication index gate verified: {yes_no(payload['publication_index_gate_verified'])}",
        f"  - publication index gate mismatches: {payload['publication_index_gate_mismatch_count']}",
        f"  - publication index gate required-match exit code: {payload['publication_index_gate_required_match_exit_code']}",
        f"  - release evidence publication index archive checklist command: {payload['release_evidence_publication_index_archive_checklist_command']}",
        f"  - release evidence publication index archive checklist JSON command: {payload['release_evidence_publication_index_archive_checklist_json_command']}",
        f"  - check release evidence publication index archive command: {payload['check_release_evidence_publication_index_archive_command']}",
        f"  - check release evidence publication index archive JSON command: {payload['check_release_evidence_publication_index_archive_json_command']}",
        f"  - release evidence publication index archive gate command: {payload['release_evidence_publication_index_archive_gate_command']}",
        f"  - release evidence publication index archive gate JSON command: {payload['release_evidence_publication_index_archive_gate_json_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - archive record schema version: {payload['archive_record_schema_version']}",
        f"  - archive record fields: {list_summary(payload['required_archive_record_fields'])}",
        f"  - operator-supplied archive record fields: {list_summary(payload['required_operator_supplied_archive_record_fields'])}",
        "  - required gate verified: yes",
        "  - required gate mismatches: 0",
        "  - required gate exit code: 0",
        f"  - expected archive record release_evidence_publication_index_sha256: {payload['expected_archive_record_values']['release_evidence_publication_index_sha256']}",
        f"  - expected archive record manifest_commit: {payload['expected_archive_record_values']['manifest_commit']}",
        f"  - expected archive record gate_command: {payload['expected_archive_record_values']['gate_command']}",
        f"  - checklist steps: {payload['checklist_step_count']}",
    ]
    for step in payload["checklist_steps"]:
        lines.append(f"  - step {step['step']}: {step['id']}")
        if step.get("command") is not None:
            lines.append(f"  - step {step['step']} command: {step['command']}")
        if step.get("required_archive_record_fields") is not None:
            lines.append(
                f"  - step {step['step']} required fields: "
                f"{list_summary(step['required_archive_record_fields'])}"
            )
    if payload["publication_index_gate_mismatches"]:
        mismatch = payload["publication_index_gate_mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_index_archive_checklist_text(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_index_archive_checklist_text_from_payload(
        release_evidence_publication_index_archive_checklist_payload(
            manifest,
            manifest_path,
            check,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_publication_index_archive_checklist_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_index_archive_checklist_json_text(
    manifest,
    manifest_path,
    check,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_index_archive_checklist_json_text_from_payload(
        release_evidence_publication_index_archive_checklist_payload(
            manifest,
            manifest_path,
            check,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_publication_index_archive_check_payload(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    record = read_release_evidence_publication_index_archive_record(
        publication_index_archive_record_path
    )
    checklist = release_evidence_publication_index_archive_checklist_payload(
        manifest,
        manifest_path,
        check,
        publication_index_path,
        archive_record_path,
        bundle_path,
    )
    archive_fields = list(RELEASE_EVIDENCE_PUBLICATION_INDEX_ARCHIVE_RECORD_FIELDS)
    missing_required_fields = [
        field for field in archive_fields if field not in record
    ]
    unexpected_fields = sorted(set(record) - set(archive_fields))
    mismatches = []

    for field in missing_required_fields:
        append_release_evidence_archive_mismatch(
            mismatches,
            field,
            "missing",
            "<missing>",
            "required publication index archive record field",
        )

    expected_archive_values = checklist["expected_archive_record_values"]
    for field, expected_value in expected_archive_values.items():
        if field not in record:
            continue
        actual_value = record[field]
        if type(actual_value) is not type(expected_value):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                expected_value,
            )
            continue
        if actual_value != expected_value:
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "value",
                actual_value,
                expected_value,
            )

    nonempty_string_fields = (
        "release_evidence_publication_index_uri",
        "manifest_commit",
        "gate_checked_at",
    )
    for field in nonempty_string_fields:
        if field not in record:
            continue
        actual_value = record[field]
        if not isinstance(actual_value, str):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                "non-empty string",
            )
        elif not actual_value.strip():
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "empty",
                actual_value,
                "non-empty string",
            )

    if not checklist["publication_index_gate_verified"]:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_index_gate.verified",
            "value",
            checklist["publication_index_gate_verified"],
            True,
        )
    if checklist["publication_index_gate_mismatch_count"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_index_gate.mismatch_count",
            "value",
            checklist["publication_index_gate_mismatch_count"],
            0,
        )
    if checklist["publication_index_gate_required_match_exit_code"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_index_gate.required_match_exit_code",
            "value",
            checklist["publication_index_gate_required_match_exit_code"],
            0,
        )

    actual_archive_values = {
        field: record.get(field)
        for field in archive_fields
    }
    verified = not mismatches
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": (
            checklist["release_evidence_publication_index"]
        ),
        "release_evidence_publication_index_sha256": (
            checklist["release_evidence_publication_index_sha256"]
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "require_match": require_match,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "missing_required_fields": missing_required_fields,
        "missing_required_field_count": len(missing_required_fields),
        "unexpected_fields": unexpected_fields,
        "unexpected_field_count": len(unexpected_fields),
        "archive_record_schema_version": 1,
        "required_archive_record_fields": archive_fields,
        "required_archive_record_field_count": len(archive_fields),
        "expected_archive_record_values": expected_archive_values,
        "actual_archive_record_values": actual_archive_values,
        "required_nonempty_string_fields": list(nonempty_string_fields),
        "publication_index_gate_verified": (
            checklist["publication_index_gate_verified"]
        ),
        "publication_index_gate_mismatch_count": (
            checklist["publication_index_gate_mismatch_count"]
        ),
        "publication_index_gate_required_match_exit_code": (
            checklist["publication_index_gate_required_match_exit_code"]
        ),
        "publication_index_gate_mismatches": (
            checklist["publication_index_gate_mismatches"]
        ),
        "check_release_evidence_publication_index_archive_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "check_release_evidence_publication_index_archive_json_command": (
            check_release_evidence_publication_index_archive_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_archive_gate_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_gate_json_command": (
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_archive_handoff_summary_command": (
            release_evidence_publication_index_archive_handoff_summary_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_index_archive_handoff_summary_json_command": (
            release_evidence_publication_index_archive_handoff_summary_command(
                manifest_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_index_archive_checklist_command": (
            checklist["release_evidence_publication_index_archive_checklist_command"]
        ),
        "release_evidence_publication_index_archive_checklist_json_command": (
            checklist[
                "release_evidence_publication_index_archive_checklist_json_command"
            ]
        ),
        "release_evidence_publication_index_gate_json_command": (
            checklist["release_evidence_publication_index_gate_json_command"]
        ),
    }


def release_evidence_publication_index_archive_check_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication index archive check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence publication index sha256: {payload['release_evidence_publication_index_sha256']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - required archive record fields: {list_summary(payload['required_archive_record_fields'])}",
        f"  - missing required fields: {list_summary(payload['missing_required_fields'])}",
        f"  - unexpected fields: {list_summary(payload['unexpected_fields'])}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - publication index gate verified: {yes_no(payload['publication_index_gate_verified'])}",
        f"  - publication index gate mismatches: {payload['publication_index_gate_mismatch_count']}",
        f"  - publication index gate required-match exit code: {payload['publication_index_gate_required_match_exit_code']}",
        f"  - check release evidence publication index archive command: {payload['check_release_evidence_publication_index_archive_command']}",
        f"  - check release evidence publication index archive JSON command: {payload['check_release_evidence_publication_index_archive_json_command']}",
        f"  - release evidence publication index archive gate command: {payload['release_evidence_publication_index_archive_gate_command']}",
        f"  - release evidence publication index archive gate JSON command: {payload['release_evidence_publication_index_archive_gate_json_command']}",
        f"  - release evidence publication index archive handoff summary command: {payload['release_evidence_publication_index_archive_handoff_summary_command']}",
        f"  - release evidence publication index archive handoff summary JSON command: {payload['release_evidence_publication_index_archive_handoff_summary_json_command']}",
        f"  - release evidence publication index archive checklist command: {payload['release_evidence_publication_index_archive_checklist_command']}",
        f"  - release evidence publication index archive checklist JSON command: {payload['release_evidence_publication_index_archive_checklist_json_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
    ]
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_index_archive_check_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_index_archive_check_text_from_payload(
        release_evidence_publication_index_archive_check_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_index_archive_check_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_index_archive_check_json_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_index_archive_check_json_text_from_payload(
        release_evidence_publication_index_archive_check_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_index_archive_handoff_first_mismatch(
    publication_index_gate,
    publication_index_archive_gate,
):
    if publication_index_archive_gate["mismatches"]:
        mismatch = dict(publication_index_archive_gate["mismatches"][0])
        mismatch["source"] = "publication_index_archive_gate"
        return mismatch
    if publication_index_gate["mismatches"]:
        mismatch = dict(publication_index_gate["mismatches"][0])
        mismatch["source"] = "publication_index_gate"
        return mismatch
    return None


def release_evidence_publication_index_archive_handoff_artifacts(
    publication_index_gate,
    publication_index_archive_gate,
    summary_json_command,
    verified,
):
    return [
        {
            "step": 1,
            "id": "release-evidence-publication-index",
            "description": "Retain the filled release evidence publication index JSON.",
            "path": (
                publication_index_gate["release_evidence_publication_index"]
            ),
            "verified": publication_index_gate["verified"],
            "command": (
                publication_index_gate[
                    "release_evidence_publication_index_gate_json_command"
                ]
            ),
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "release-evidence-publication-index-archive-record",
            "description": (
                "Retain the filled publication index archive record JSON."
            ),
            "path": (
                publication_index_archive_gate[
                    "release_evidence_publication_index_archive_record"
                ]
            ),
            "verified": publication_index_archive_gate["verified"],
            "command": (
                publication_index_archive_gate[
                    "release_evidence_publication_index_archive_gate_json_command"
                ]
            ),
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": (
                "release-evidence-publication-index-archive-handoff-summary-json"
            ),
            "description": (
                "Publish the publication index archive handoff summary JSON "
                "after both gates pass."
            ),
            "path": (
                "<release_evidence_publication_index_archive_handoff_summary.json>"
            ),
            "verified": verified,
            "command": summary_json_command,
            "required_before_launch": True,
        },
    ]


def release_evidence_publication_index_archive_handoff_summary_payload(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    publication_index_gate = release_evidence_publication_index_check_payload(
        manifest,
        manifest_path,
        check,
        publication_index_path,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    publication_index_archive_gate = (
        release_evidence_publication_index_archive_check_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=True,
        )
    )
    verified = (
        publication_index_gate["verified"]
        and publication_index_archive_gate["verified"]
    )
    summary_command = (
        release_evidence_publication_index_archive_handoff_summary_command(
            manifest_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )
    summary_json_command = (
        release_evidence_publication_index_archive_handoff_summary_command(
            manifest_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            json_output=True,
        )
    )
    handoff_artifacts = (
        release_evidence_publication_index_archive_handoff_artifacts(
            publication_index_gate,
            publication_index_archive_gate,
            summary_json_command,
            verified,
        )
    )
    publication_blockers = release_evidence_publication_blockers(
        handoff_artifacts
    )
    next_publication_blocker = (
        publication_blockers[0] if publication_blockers else None
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": display_path(
            publication_index_path
        ),
        "release_evidence_publication_index_sha256": (
            publication_index_gate["release_evidence_publication_index_sha256"]
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": (
            publication_index_gate["mismatch_count"]
            + publication_index_archive_gate["mismatch_count"]
        ),
        "handoff_artifact_count": len(handoff_artifacts),
        "verified_handoff_artifact_count": len([
            artifact
            for artifact in handoff_artifacts
            if artifact["verified"]
        ]),
        "handoff_artifacts": handoff_artifacts,
        "ready_for_publication": not publication_blockers,
        "publication_blocker_count": len(publication_blockers),
        "publication_blockers": publication_blockers,
        "next_publication_blocker": next_publication_blocker,
        "next_publication_blocker_id": (
            next_publication_blocker["id"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_path": (
            next_publication_blocker["path"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_command": (
            next_publication_blocker["command"]
            if next_publication_blocker is not None
            else None
        ),
        "first_mismatch": (
            release_evidence_publication_index_archive_handoff_first_mismatch(
                publication_index_gate,
                publication_index_archive_gate,
            )
        ),
        "publication_index_gate": {
            "verified": publication_index_gate["verified"],
            "require_match": publication_index_gate["require_match"],
            "required_match_exit_code": (
                publication_index_gate["required_match_exit_code"]
            ),
            "mismatch_count": publication_index_gate["mismatch_count"],
            "missing_required_field_count": (
                publication_index_gate["missing_required_field_count"]
            ),
            "unexpected_field_count": publication_index_gate["unexpected_field_count"],
            "placeholder_field_count": (
                publication_index_gate["placeholder_field_count"]
            ),
            "handoff_verified": publication_index_gate["handoff_verified"],
            "archive_gate_verified": publication_index_gate[
                "archive_gate_verified"
            ],
            "archive_gate_mismatch_count": (
                publication_index_gate["archive_gate_mismatch_count"]
            ),
        },
        "publication_index_archive_gate": {
            "verified": publication_index_archive_gate["verified"],
            "require_match": publication_index_archive_gate["require_match"],
            "required_match_exit_code": (
                publication_index_archive_gate["required_match_exit_code"]
            ),
            "mismatch_count": publication_index_archive_gate["mismatch_count"],
            "missing_required_field_count": (
                publication_index_archive_gate["missing_required_field_count"]
            ),
            "unexpected_field_count": (
                publication_index_archive_gate["unexpected_field_count"]
            ),
            "publication_index_gate_verified": (
                publication_index_archive_gate[
                    "publication_index_gate_verified"
                ]
            ),
            "publication_index_gate_mismatch_count": (
                publication_index_archive_gate[
                    "publication_index_gate_mismatch_count"
                ]
            ),
            "publication_index_gate_required_match_exit_code": (
                publication_index_archive_gate[
                    "publication_index_gate_required_match_exit_code"
                ]
            ),
        },
        "release_evidence_publication_index_archive_handoff_summary_command": (
            summary_command
        ),
        "release_evidence_publication_index_archive_handoff_summary_json_command": (
            summary_json_command
        ),
        "release_evidence_publication_index_gate_json_command": (
            publication_index_gate[
                "release_evidence_publication_index_gate_json_command"
            ]
        ),
        "release_evidence_publication_index_archive_gate_json_command": (
            publication_index_archive_gate[
                "release_evidence_publication_index_archive_gate_json_command"
            ]
        ),
        "release_evidence_publication_index_archive_checklist_json_command": (
            publication_index_archive_gate[
                "release_evidence_publication_index_archive_checklist_json_command"
            ]
        ),
        "commands": {
            "release_evidence_publication_index_archive_handoff_summary": (
                summary_command
            ),
            "release_evidence_publication_index_archive_handoff_summary_json": (
                summary_json_command
            ),
            "release_evidence_publication_index_gate_json": (
                publication_index_gate[
                    "release_evidence_publication_index_gate_json_command"
                ]
            ),
            "release_evidence_publication_index_archive_gate_json": (
                publication_index_archive_gate[
                    "release_evidence_publication_index_archive_gate_json_command"
                ]
            ),
            "release_evidence_publication_index_archive_checklist_json": (
                publication_index_archive_gate[
                    "release_evidence_publication_index_archive_checklist_json_command"
                ]
            ),
        },
    }


def release_evidence_publication_index_archive_handoff_summary_text_from_payload(
    payload,
):
    lines = [
        "zkCoin public launch profile release evidence publication index archive handoff summary:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence publication index sha256: {payload['release_evidence_publication_index_sha256']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - handoff artifacts: {payload['handoff_artifact_count']}",
        f"  - verified handoff artifacts: {payload['verified_handoff_artifact_count']}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - publication index gate verified: {yes_no(payload['publication_index_gate']['verified'])}",
        f"  - publication index gate required-match exit code: {payload['publication_index_gate']['required_match_exit_code']}",
        f"  - publication index gate mismatches: {payload['publication_index_gate']['mismatch_count']}",
        f"  - publication index archive gate verified: {yes_no(payload['publication_index_archive_gate']['verified'])}",
        f"  - publication index archive gate required-match exit code: {payload['publication_index_archive_gate']['required_match_exit_code']}",
        f"  - publication index archive gate mismatches: {payload['publication_index_archive_gate']['mismatch_count']}",
        f"  - publication index archive missing required fields: {payload['publication_index_archive_gate']['missing_required_field_count']}",
        f"  - publication index archive unexpected fields: {payload['publication_index_archive_gate']['unexpected_field_count']}",
        f"  - release evidence publication index archive handoff summary command: {payload['release_evidence_publication_index_archive_handoff_summary_command']}",
        f"  - release evidence publication index archive handoff summary JSON command: {payload['release_evidence_publication_index_archive_handoff_summary_json_command']}",
        f"  - release evidence publication index gate JSON command: {payload['release_evidence_publication_index_gate_json_command']}",
        f"  - release evidence publication index archive gate JSON command: {payload['release_evidence_publication_index_archive_gate_json_command']}",
        f"  - release evidence publication index archive checklist JSON command: {payload['release_evidence_publication_index_archive_checklist_json_command']}",
    ]
    for artifact in payload["handoff_artifacts"]:
        lines.extend([
            f"  - handoff artifact {artifact['step']}: {artifact['id']}",
            f"  - handoff artifact {artifact['step']} path: {artifact['path']}",
            (
                f"  - handoff artifact {artifact['step']} verified: "
                f"{yes_no(artifact['verified'])}"
            ),
            f"  - handoff artifact {artifact['step']} command: {artifact['command']}",
        ])
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    if payload["first_mismatch"] is not None:
        mismatch = payload["first_mismatch"]
        lines.extend([
            f"  - first mismatch source: {mismatch['source']}",
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_index_archive_handoff_summary_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return (
        release_evidence_publication_index_archive_handoff_summary_text_from_payload(
            release_evidence_publication_index_archive_handoff_summary_payload(
                manifest,
                manifest_path,
                check,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        )
    )


def release_evidence_publication_index_archive_handoff_summary_json_text_from_payload(
    payload,
):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_index_archive_handoff_summary_json_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return (
        release_evidence_publication_index_archive_handoff_summary_json_text_from_payload(
            release_evidence_publication_index_archive_handoff_summary_payload(
                manifest,
                manifest_path,
                check,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        )
    )


def release_evidence_publication_closeout_artifacts(
    handoff_summary,
    publication_index_archive_handoff_summary,
):
    artifacts = []
    for source_artifact in (
        handoff_summary["handoff_artifacts"]
        + publication_index_archive_handoff_summary["handoff_artifacts"]
    ):
        artifact = dict(source_artifact)
        artifact["step"] = len(artifacts) + 1
        artifacts.append(artifact)
    return artifacts


def release_evidence_publication_closeout_summary(payload):
    return {
        "verified": payload["verified"],
        "required_match_exit_code": payload["required_match_exit_code"],
        "mismatch_count": payload["mismatch_count"],
        "handoff_artifact_count": payload["handoff_artifact_count"],
        "verified_handoff_artifact_count": (
            payload["verified_handoff_artifact_count"]
        ),
        "ready_for_publication": payload["ready_for_publication"],
        "publication_blocker_count": payload["publication_blocker_count"],
        "next_publication_blocker_id": payload["next_publication_blocker_id"],
    }


def release_evidence_publication_closeout_checklist_payload(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    handoff_summary = release_evidence_handoff_summary_payload(
        manifest,
        manifest_path,
        check,
        archive_record_path,
        bundle_path,
    )
    publication_index_archive_handoff_summary = (
        release_evidence_publication_index_archive_handoff_summary_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )
    verified = (
        handoff_summary["verified"]
        and publication_index_archive_handoff_summary["verified"]
    )
    closeout_command = release_evidence_publication_closeout_checklist_command(
        manifest_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
    )
    closeout_json_command = (
        release_evidence_publication_closeout_checklist_command(
            manifest_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            json_output=True,
        )
    )
    closeout_check_command = check_release_evidence_publication_closeout_command(
        manifest_path,
        publication_index_archive_record_path=(
            publication_index_archive_record_path
        ),
        publication_index_path=publication_index_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
    )
    closeout_check_json_command = (
        check_release_evidence_publication_closeout_command(
            manifest_path,
            publication_index_archive_record_path=(
                publication_index_archive_record_path
            ),
            publication_index_path=publication_index_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
            json_output=True,
        )
    )
    closeout_gate_command = release_evidence_publication_closeout_gate_command(
        manifest_path,
        publication_index_archive_record_path=(
            publication_index_archive_record_path
        ),
        publication_index_path=publication_index_path,
        archive_record_path=archive_record_path,
        bundle_path=bundle_path,
    )
    closeout_gate_json_command = (
        release_evidence_publication_closeout_gate_command(
            manifest_path,
            publication_index_archive_record_path=(
                publication_index_archive_record_path
            ),
            publication_index_path=publication_index_path,
            archive_record_path=archive_record_path,
            bundle_path=bundle_path,
            json_output=True,
        )
    )
    closeout_artifacts = release_evidence_publication_closeout_artifacts(
        handoff_summary,
        publication_index_archive_handoff_summary,
    )
    publication_blockers = release_evidence_publication_blockers(
        closeout_artifacts
    )
    next_publication_blocker = (
        publication_blockers[0] if publication_blockers else None
    )
    first_mismatch = (
        handoff_summary["first_mismatch"]
        or publication_index_archive_handoff_summary["first_mismatch"]
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": display_path(
            publication_index_path
        ),
        "release_evidence_publication_index_sha256": (
            publication_index_archive_handoff_summary[
                "release_evidence_publication_index_sha256"
            ]
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": (
            handoff_summary["mismatch_count"]
            + publication_index_archive_handoff_summary["mismatch_count"]
        ),
        "closeout_artifact_count": len(closeout_artifacts),
        "verified_closeout_artifact_count": len([
            artifact
            for artifact in closeout_artifacts
            if artifact["verified"]
        ]),
        "closeout_artifacts": closeout_artifacts,
        "ready_for_publication": not publication_blockers,
        "publication_blocker_count": len(publication_blockers),
        "publication_blockers": publication_blockers,
        "next_publication_blocker": next_publication_blocker,
        "next_publication_blocker_id": (
            next_publication_blocker["id"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_path": (
            next_publication_blocker["path"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_command": (
            next_publication_blocker["command"]
            if next_publication_blocker is not None
            else None
        ),
        "first_mismatch": first_mismatch,
        "release_evidence_handoff_summary": (
            release_evidence_publication_closeout_summary(handoff_summary)
        ),
        "release_evidence_publication_index_archive_handoff_summary": (
            release_evidence_publication_closeout_summary(
                publication_index_archive_handoff_summary
            )
        ),
        "release_evidence_publication_closeout_checklist_command": (
            closeout_command
        ),
        "release_evidence_publication_closeout_checklist_json_command": (
            closeout_json_command
        ),
        "check_release_evidence_publication_closeout_command": (
            closeout_check_command
        ),
        "check_release_evidence_publication_closeout_json_command": (
            closeout_check_json_command
        ),
        "release_evidence_publication_closeout_gate_command": (
            closeout_gate_command
        ),
        "release_evidence_publication_closeout_gate_json_command": (
            closeout_gate_json_command
        ),
        "release_evidence_handoff_summary_json_command": (
            handoff_summary["release_evidence_handoff_summary_json_command"]
        ),
        "release_evidence_publication_index_archive_handoff_summary_json_command": (
            publication_index_archive_handoff_summary[
                "release_evidence_publication_index_archive_handoff_summary_json_command"
            ]
        ),
        "commands": {
            "release_evidence_publication_closeout_checklist": (
                closeout_command
            ),
            "release_evidence_publication_closeout_checklist_json": (
                closeout_json_command
            ),
            "check_release_evidence_publication_closeout": (
                closeout_check_command
            ),
            "check_release_evidence_publication_closeout_json": (
                closeout_check_json_command
            ),
            "release_evidence_publication_closeout_gate": (
                closeout_gate_command
            ),
            "release_evidence_publication_closeout_gate_json": (
                closeout_gate_json_command
            ),
            "release_evidence_handoff_summary_json": (
                handoff_summary["release_evidence_handoff_summary_json_command"]
            ),
            "release_evidence_publication_index_archive_handoff_summary_json": (
                publication_index_archive_handoff_summary[
                    "release_evidence_publication_index_archive_handoff_summary_json_command"
                ]
            ),
        },
    }


def release_evidence_publication_closeout_checklist_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication closeout checklist:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence publication index sha256: {payload['release_evidence_publication_index_sha256']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - closeout artifacts: {payload['closeout_artifact_count']}",
        f"  - verified closeout artifacts: {payload['verified_closeout_artifact_count']}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - release evidence handoff summary verified: {yes_no(payload['release_evidence_handoff_summary']['verified'])}",
        f"  - release evidence handoff summary required-match exit code: {payload['release_evidence_handoff_summary']['required_match_exit_code']}",
        f"  - publication index archive handoff summary verified: {yes_no(payload['release_evidence_publication_index_archive_handoff_summary']['verified'])}",
        f"  - publication index archive handoff summary required-match exit code: {payload['release_evidence_publication_index_archive_handoff_summary']['required_match_exit_code']}",
        f"  - release evidence publication closeout checklist command: {payload['release_evidence_publication_closeout_checklist_command']}",
        f"  - release evidence publication closeout checklist JSON command: {payload['release_evidence_publication_closeout_checklist_json_command']}",
        f"  - check release evidence publication closeout command: {payload['check_release_evidence_publication_closeout_command']}",
        f"  - check release evidence publication closeout JSON command: {payload['check_release_evidence_publication_closeout_json_command']}",
        f"  - release evidence publication closeout gate command: {payload['release_evidence_publication_closeout_gate_command']}",
        f"  - release evidence publication closeout gate JSON command: {payload['release_evidence_publication_closeout_gate_json_command']}",
        f"  - release evidence handoff summary JSON command: {payload['release_evidence_handoff_summary_json_command']}",
        f"  - release evidence publication index archive handoff summary JSON command: {payload['release_evidence_publication_index_archive_handoff_summary_json_command']}",
    ]
    for artifact in payload["closeout_artifacts"]:
        lines.extend([
            f"  - closeout artifact {artifact['step']}: {artifact['id']}",
            f"  - closeout artifact {artifact['step']} path: {artifact['path']}",
            (
                f"  - closeout artifact {artifact['step']} verified: "
                f"{yes_no(artifact['verified'])}"
            ),
            f"  - closeout artifact {artifact['step']} command: {artifact['command']}",
        ])
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    if payload["first_mismatch"] is not None:
        mismatch = payload["first_mismatch"]
        lines.extend([
            f"  - first mismatch source: {mismatch['source']}",
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_closeout_checklist_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_closeout_checklist_text_from_payload(
        release_evidence_publication_closeout_checklist_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )


def release_evidence_publication_closeout_checklist_json_text_from_payload(
    payload,
):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_closeout_checklist_json_text(
    manifest,
    manifest_path,
    check,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return release_evidence_publication_closeout_checklist_json_text_from_payload(
        release_evidence_publication_closeout_checklist_payload(
            manifest,
            manifest_path,
            check,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )


def append_release_evidence_publication_closeout_mismatches(
    mismatches,
    actual_value,
    expected_value,
    path="$",
):
    if type(actual_value) is not type(expected_value):
        append_release_evidence_archive_mismatch(
            mismatches,
            path,
            "type",
            actual_value,
            expected_value,
        )
        return

    if isinstance(expected_value, dict):
        actual_keys = set(actual_value)
        expected_keys = set(expected_value)
        for key in sorted(expected_keys - actual_keys):
            append_release_evidence_archive_mismatch(
                mismatches,
                f"{path}.{key}",
                "missing",
                "<missing>",
                expected_value[key],
            )
        for key in sorted(actual_keys - expected_keys):
            append_release_evidence_archive_mismatch(
                mismatches,
                f"{path}.{key}",
                "unexpected",
                actual_value[key],
                "<absent>",
            )
        for key in sorted(actual_keys & expected_keys):
            append_release_evidence_publication_closeout_mismatches(
                mismatches,
                actual_value[key],
                expected_value[key],
                f"{path}.{key}",
            )
        return

    if isinstance(expected_value, list):
        if len(actual_value) != len(expected_value):
            append_release_evidence_archive_mismatch(
                mismatches,
                path,
                "length",
                len(actual_value),
                len(expected_value),
            )
        for index, (actual_item, expected_item) in enumerate(
            zip(actual_value, expected_value)
        ):
            append_release_evidence_publication_closeout_mismatches(
                mismatches,
                actual_item,
                expected_item,
                f"{path}[{index}]",
            )
        return

    if actual_value != expected_value:
        append_release_evidence_archive_mismatch(
            mismatches,
            path,
            "value",
            actual_value,
            expected_value,
        )


def release_evidence_publication_closeout_check_payload(
    manifest,
    manifest_path,
    check,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    closeout = read_release_evidence_publication_closeout(closeout_path)
    expected_closeout = release_evidence_publication_closeout_checklist_payload(
        manifest,
        manifest_path,
        check,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
    )
    mismatches = []
    append_release_evidence_publication_closeout_mismatches(
        mismatches,
        closeout,
        expected_closeout,
    )
    verified = not mismatches
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_closeout": display_path(closeout_path),
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": display_path(
            publication_index_path
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "require_match": require_match,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "expected_schema_version": expected_closeout["schema_version"],
        "actual_schema_version": closeout.get("schema_version"),
        "expected_closeout_values": expected_closeout,
        "actual_closeout_values": closeout,
        "expected_closeout_artifact_count": (
            expected_closeout["closeout_artifact_count"]
        ),
        "actual_closeout_artifact_count": closeout.get(
            "closeout_artifact_count"
        ),
        "expected_verified_closeout_artifact_count": (
            expected_closeout["verified_closeout_artifact_count"]
        ),
        "actual_verified_closeout_artifact_count": closeout.get(
            "verified_closeout_artifact_count"
        ),
        "expected_ready_for_publication": (
            expected_closeout["ready_for_publication"]
        ),
        "actual_ready_for_publication": closeout.get("ready_for_publication"),
        "check_release_evidence_publication_closeout_command": (
            check_release_evidence_publication_closeout_command(
                manifest_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "check_release_evidence_publication_closeout_json_command": (
            check_release_evidence_publication_closeout_command(
                manifest_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_closeout_gate_command": (
            release_evidence_publication_closeout_gate_command(
                manifest_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_closeout_gate_json_command": (
            release_evidence_publication_closeout_gate_command(
                manifest_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_closeout_checklist_json_command": (
            expected_closeout[
                "release_evidence_publication_closeout_checklist_json_command"
            ]
        ),
    }


def release_evidence_publication_closeout_check_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication closeout check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication closeout: {payload['release_evidence_publication_closeout']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - expected closeout artifacts: {payload['expected_closeout_artifact_count']}",
        f"  - actual closeout artifacts: {payload['actual_closeout_artifact_count']}",
        f"  - expected verified closeout artifacts: {payload['expected_verified_closeout_artifact_count']}",
        f"  - actual verified closeout artifacts: {payload['actual_verified_closeout_artifact_count']}",
        f"  - expected ready for publication: {yes_no(payload['expected_ready_for_publication'])}",
        f"  - actual ready for publication: {yes_no(payload['actual_ready_for_publication'])}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - check release evidence publication closeout command: {payload['check_release_evidence_publication_closeout_command']}",
        f"  - check release evidence publication closeout JSON command: {payload['check_release_evidence_publication_closeout_json_command']}",
        f"  - release evidence publication closeout gate command: {payload['release_evidence_publication_closeout_gate_command']}",
        f"  - release evidence publication closeout gate JSON command: {payload['release_evidence_publication_closeout_gate_json_command']}",
        f"  - release evidence publication closeout checklist JSON command: {payload['release_evidence_publication_closeout_checklist_json_command']}",
    ]
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_closeout_check_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_closeout_archive_check_payload(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    record = read_release_evidence_publication_closeout_archive_record(
        closeout_archive_record_path
    )
    closeout_text = read_release_evidence_publication_closeout_text(
        closeout_path
    )
    try:
        closeout = json.loads(
            closeout_text,
            object_pairs_hook=reject_duplicate_json_fields,
        )
    except DuplicateJSONFieldError as exc:
        raise ValueError(
            f"{closeout_path} contains duplicate field: {exc}"
        ) from None
    except json.JSONDecodeError as exc:
        raise ValueError(f"{closeout_path} is not valid JSON: {exc}") from None
    if not isinstance(closeout, dict):
        raise ValueError(
            "release evidence publication closeout must be a JSON object"
        )
    closeout_sha256 = hashlib.sha256(closeout_text.encode("utf8")).hexdigest()
    closeout_gate = release_evidence_publication_closeout_check_payload(
        manifest,
        manifest_path,
        check,
        closeout_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    archive_fields = list(
        RELEASE_EVIDENCE_PUBLICATION_CLOSEOUT_ARCHIVE_RECORD_FIELDS
    )
    missing_required_fields = [
        field for field in archive_fields if field not in record
    ]
    unexpected_fields = sorted(set(record) - set(archive_fields))
    mismatches = []

    for field in missing_required_fields:
        append_release_evidence_archive_mismatch(
            mismatches,
            field,
            "missing",
            "<missing>",
            "required publication closeout archive record field",
        )

    expected_archive_values = {
        "release_evidence_publication_closeout_sha256": closeout_sha256,
        "release_evidence_publication_closeout_schema_version": (
            closeout.get("schema_version")
        ),
        "manifest_path": display_path(manifest_path),
        "gate_command": (
            closeout_gate[
                "release_evidence_publication_closeout_gate_json_command"
            ]
        ),
        "gate_verified": True,
        "gate_mismatch_count": 0,
    }
    for field, expected_value in expected_archive_values.items():
        if field not in record:
            continue
        actual_value = record[field]
        if type(actual_value) is not type(expected_value):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                expected_value,
            )
            continue
        if actual_value != expected_value:
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "value",
                actual_value,
                expected_value,
            )

    nonempty_string_fields = (
        "release_evidence_publication_closeout_uri",
        "manifest_commit",
        "gate_checked_at",
    )
    for field in nonempty_string_fields:
        if field not in record:
            continue
        actual_value = record[field]
        if not isinstance(actual_value, str):
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "type",
                actual_value,
                "non-empty string",
            )
        elif not actual_value.strip():
            append_release_evidence_archive_mismatch(
                mismatches,
                field,
                "empty",
                actual_value,
                "non-empty string",
            )

    if not closeout_gate["verified"]:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_closeout_gate.verified",
            "value",
            closeout_gate["verified"],
            True,
        )
    if closeout_gate["mismatch_count"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_closeout_gate.mismatch_count",
            "value",
            closeout_gate["mismatch_count"],
            0,
        )
    if closeout_gate["required_match_exit_code"] != 0:
        append_release_evidence_archive_mismatch(
            mismatches,
            "release_evidence_publication_closeout_gate.required_match_exit_code",
            "value",
            closeout_gate["required_match_exit_code"],
            0,
        )

    actual_archive_values = {
        field: record.get(field)
        for field in archive_fields
    }
    verified = not mismatches
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_closeout_archive_record": display_path(
            closeout_archive_record_path
        ),
        "release_evidence_publication_closeout": display_path(closeout_path),
        "release_evidence_publication_closeout_sha256": closeout_sha256,
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": display_path(
            publication_index_path
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "require_match": require_match,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
        "missing_required_fields": missing_required_fields,
        "missing_required_field_count": len(missing_required_fields),
        "unexpected_fields": unexpected_fields,
        "unexpected_field_count": len(unexpected_fields),
        "archive_record_schema_version": 1,
        "required_archive_record_fields": archive_fields,
        "required_archive_record_field_count": len(archive_fields),
        "expected_archive_record_values": expected_archive_values,
        "actual_archive_record_values": actual_archive_values,
        "required_nonempty_string_fields": list(nonempty_string_fields),
        "closeout_schema_version": closeout.get("schema_version"),
        "closeout_gate_verified": closeout_gate["verified"],
        "closeout_gate_mismatch_count": closeout_gate["mismatch_count"],
        "closeout_gate_required_match_exit_code": (
            closeout_gate["required_match_exit_code"]
        ),
        "closeout_gate_mismatches": closeout_gate["mismatches"],
        "check_release_evidence_publication_closeout_archive_command": (
            check_release_evidence_publication_closeout_archive_command(
                manifest_path,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "check_release_evidence_publication_closeout_archive_json_command": (
            check_release_evidence_publication_closeout_archive_command(
                manifest_path,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_closeout_archive_gate_command": (
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        ),
        "release_evidence_publication_closeout_archive_gate_json_command": (
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                json_output=True,
            )
        ),
        "release_evidence_publication_closeout_gate_json_command": (
            closeout_gate[
                "release_evidence_publication_closeout_gate_json_command"
            ]
        ),
        "release_evidence_publication_closeout_checklist_json_command": (
            closeout_gate[
                "release_evidence_publication_closeout_checklist_json_command"
            ]
        ),
    }


def release_evidence_publication_closeout_archive_check_text_from_payload(
    payload,
):
    lines = [
        "zkCoin public launch profile release evidence publication closeout archive check:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - require match: {yes_no(payload['require_match'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication closeout archive record: {payload['release_evidence_publication_closeout_archive_record']}",
        f"  - release evidence publication closeout: {payload['release_evidence_publication_closeout']}",
        f"  - release evidence publication closeout sha256: {payload['release_evidence_publication_closeout_sha256']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - required archive record fields: {list_summary(payload['required_archive_record_fields'])}",
        f"  - missing required fields: {list_summary(payload['missing_required_fields'])}",
        f"  - unexpected fields: {list_summary(payload['unexpected_fields'])}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - closeout gate verified: {yes_no(payload['closeout_gate_verified'])}",
        f"  - closeout gate mismatches: {payload['closeout_gate_mismatch_count']}",
        f"  - closeout gate required-match exit code: {payload['closeout_gate_required_match_exit_code']}",
        f"  - check release evidence publication closeout archive command: {payload['check_release_evidence_publication_closeout_archive_command']}",
        f"  - check release evidence publication closeout archive JSON command: {payload['check_release_evidence_publication_closeout_archive_json_command']}",
        f"  - release evidence publication closeout archive gate command: {payload['release_evidence_publication_closeout_archive_gate_command']}",
        f"  - release evidence publication closeout archive gate JSON command: {payload['release_evidence_publication_closeout_archive_gate_json_command']}",
        f"  - release evidence publication closeout gate JSON command: {payload['release_evidence_publication_closeout_gate_json_command']}",
        f"  - release evidence publication closeout checklist JSON command: {payload['release_evidence_publication_closeout_checklist_json_command']}",
    ]
    if payload["mismatches"]:
        mismatch = payload["mismatches"][0]
        lines.extend([
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_closeout_archive_check_text(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_closeout_archive_check_text_from_payload(
        release_evidence_publication_closeout_archive_check_payload(
            manifest,
            manifest_path,
            check,
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_closeout_archive_check_json_text_from_payload(
    payload,
):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_closeout_archive_check_json_text(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
    require_match=False,
):
    return release_evidence_publication_closeout_archive_check_json_text_from_payload(
        release_evidence_publication_closeout_archive_check_payload(
            manifest,
            manifest_path,
            check,
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=require_match,
        )
    )


def release_evidence_publication_closeout_archive_handoff_first_mismatch(
    closeout_gate,
    closeout_archive_gate,
):
    if closeout_archive_gate["mismatches"]:
        mismatch = dict(closeout_archive_gate["mismatches"][0])
        mismatch["source"] = "closeout_archive_gate"
        return mismatch
    if closeout_gate["mismatches"]:
        mismatch = dict(closeout_gate["mismatches"][0])
        mismatch["source"] = "closeout_gate"
        return mismatch
    return None


def release_evidence_publication_closeout_archive_handoff_artifacts(
    closeout_gate,
    closeout_archive_gate,
    summary_json_command,
    verified,
):
    return [
        {
            "step": 1,
            "id": "release-evidence-publication-closeout",
            "description": "Retain the filled release evidence publication closeout JSON.",
            "path": closeout_gate["release_evidence_publication_closeout"],
            "verified": closeout_gate["verified"],
            "command": (
                closeout_gate[
                    "release_evidence_publication_closeout_gate_json_command"
                ]
            ),
            "required_before_launch": True,
        },
        {
            "step": 2,
            "id": "release-evidence-publication-closeout-archive-record",
            "description": (
                "Retain the filled publication closeout archive record JSON."
            ),
            "path": (
                closeout_archive_gate[
                    "release_evidence_publication_closeout_archive_record"
                ]
            ),
            "verified": closeout_archive_gate["verified"],
            "command": (
                closeout_archive_gate[
                    "release_evidence_publication_closeout_archive_gate_json_command"
                ]
            ),
            "required_before_launch": True,
        },
        {
            "step": 3,
            "id": (
                "release-evidence-publication-closeout-archive-handoff-summary-json"
            ),
            "description": (
                "Publish the closeout archive handoff summary JSON after both "
                "gates pass."
            ),
            "path": (
                "<release_evidence_publication_closeout_archive_handoff_summary.json>"
            ),
            "verified": verified,
            "command": summary_json_command,
            "required_before_launch": True,
        },
    ]


def release_evidence_publication_closeout_archive_handoff_summary_payload(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    closeout_gate = release_evidence_publication_closeout_check_payload(
        manifest,
        manifest_path,
        check,
        closeout_path,
        publication_index_archive_record_path,
        publication_index_path,
        archive_record_path,
        bundle_path,
        require_match=True,
    )
    closeout_archive_gate = (
        release_evidence_publication_closeout_archive_check_payload(
            manifest,
            manifest_path,
            check,
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            require_match=True,
        )
    )
    verified = closeout_gate["verified"] and closeout_archive_gate["verified"]
    summary_command = (
        release_evidence_publication_closeout_archive_handoff_summary_command(
            manifest_path,
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        )
    )
    summary_json_command = (
        release_evidence_publication_closeout_archive_handoff_summary_command(
            manifest_path,
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
            json_output=True,
        )
    )
    handoff_artifacts = (
        release_evidence_publication_closeout_archive_handoff_artifacts(
            closeout_gate,
            closeout_archive_gate,
            summary_json_command,
            verified,
        )
    )
    publication_blockers = release_evidence_publication_blockers(
        handoff_artifacts
    )
    next_publication_blocker = (
        publication_blockers[0] if publication_blockers else None
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "release_evidence_publication_closeout_archive_record": display_path(
            closeout_archive_record_path
        ),
        "release_evidence_publication_closeout": display_path(closeout_path),
        "release_evidence_publication_closeout_sha256": (
            closeout_archive_gate[
                "release_evidence_publication_closeout_sha256"
            ]
        ),
        "release_evidence_publication_index_archive_record": display_path(
            publication_index_archive_record_path
        ),
        "release_evidence_publication_index": display_path(
            publication_index_path
        ),
        "release_evidence_archive_record": display_path(archive_record_path),
        "release_evidence_bundle": display_path(bundle_path),
        "verified": verified,
        "required_match_exit_code": 0 if verified else 1,
        "mismatch_count": (
            closeout_gate["mismatch_count"]
            + closeout_archive_gate["mismatch_count"]
        ),
        "handoff_artifact_count": len(handoff_artifacts),
        "verified_handoff_artifact_count": len([
            artifact
            for artifact in handoff_artifacts
            if artifact["verified"]
        ]),
        "handoff_artifacts": handoff_artifacts,
        "ready_for_publication": not publication_blockers,
        "publication_blocker_count": len(publication_blockers),
        "publication_blockers": publication_blockers,
        "next_publication_blocker": next_publication_blocker,
        "next_publication_blocker_id": (
            next_publication_blocker["id"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_path": (
            next_publication_blocker["path"]
            if next_publication_blocker is not None
            else None
        ),
        "next_publication_blocker_command": (
            next_publication_blocker["command"]
            if next_publication_blocker is not None
            else None
        ),
        "first_mismatch": (
            release_evidence_publication_closeout_archive_handoff_first_mismatch(
                closeout_gate,
                closeout_archive_gate,
            )
        ),
        "closeout_gate": {
            "verified": closeout_gate["verified"],
            "require_match": closeout_gate["require_match"],
            "required_match_exit_code": (
                closeout_gate["required_match_exit_code"]
            ),
            "mismatch_count": closeout_gate["mismatch_count"],
            "expected_closeout_artifact_count": (
                closeout_gate["expected_closeout_artifact_count"]
            ),
            "actual_closeout_artifact_count": (
                closeout_gate["actual_closeout_artifact_count"]
            ),
            "expected_ready_for_publication": (
                closeout_gate["expected_ready_for_publication"]
            ),
            "actual_ready_for_publication": (
                closeout_gate["actual_ready_for_publication"]
            ),
        },
        "closeout_archive_gate": {
            "verified": closeout_archive_gate["verified"],
            "require_match": closeout_archive_gate["require_match"],
            "required_match_exit_code": (
                closeout_archive_gate["required_match_exit_code"]
            ),
            "mismatch_count": closeout_archive_gate["mismatch_count"],
            "missing_required_field_count": (
                closeout_archive_gate["missing_required_field_count"]
            ),
            "unexpected_field_count": (
                closeout_archive_gate["unexpected_field_count"]
            ),
            "closeout_gate_verified": (
                closeout_archive_gate["closeout_gate_verified"]
            ),
            "closeout_gate_mismatch_count": (
                closeout_archive_gate["closeout_gate_mismatch_count"]
            ),
            "closeout_gate_required_match_exit_code": (
                closeout_archive_gate[
                    "closeout_gate_required_match_exit_code"
                ]
            ),
        },
        "release_evidence_publication_closeout_archive_handoff_summary_command": (
            summary_command
        ),
        "release_evidence_publication_closeout_archive_handoff_summary_json_command": (
            summary_json_command
        ),
        "release_evidence_publication_closeout_gate_json_command": (
            closeout_gate[
                "release_evidence_publication_closeout_gate_json_command"
            ]
        ),
        "release_evidence_publication_closeout_archive_gate_json_command": (
            closeout_archive_gate[
                "release_evidence_publication_closeout_archive_gate_json_command"
            ]
        ),
        "release_evidence_publication_closeout_checklist_json_command": (
            closeout_gate[
                "release_evidence_publication_closeout_checklist_json_command"
            ]
        ),
        "commands": {
            "release_evidence_publication_closeout_archive_handoff_summary": (
                summary_command
            ),
            "release_evidence_publication_closeout_archive_handoff_summary_json": (
                summary_json_command
            ),
            "release_evidence_publication_closeout_gate_json": (
                closeout_gate[
                    "release_evidence_publication_closeout_gate_json_command"
                ]
            ),
            "release_evidence_publication_closeout_archive_gate_json": (
                closeout_archive_gate[
                    "release_evidence_publication_closeout_archive_gate_json_command"
                ]
            ),
            "release_evidence_publication_closeout_checklist_json": (
                closeout_gate[
                    "release_evidence_publication_closeout_checklist_json_command"
                ]
            ),
        },
    }


def release_evidence_publication_closeout_archive_handoff_summary_text_from_payload(
    payload,
):
    lines = [
        "zkCoin public launch profile release evidence publication closeout archive handoff summary:",
        f"  - verified: {yes_no(payload['verified'])}",
        f"  - required-match exit code: {payload['required_match_exit_code']}",
        f"  - manifest: {payload['manifest']}",
        f"  - release evidence publication closeout archive record: {payload['release_evidence_publication_closeout_archive_record']}",
        f"  - release evidence publication closeout: {payload['release_evidence_publication_closeout']}",
        f"  - release evidence publication closeout sha256: {payload['release_evidence_publication_closeout_sha256']}",
        f"  - release evidence publication index archive record: {payload['release_evidence_publication_index_archive_record']}",
        f"  - release evidence publication index: {payload['release_evidence_publication_index']}",
        f"  - release evidence archive record: {payload['release_evidence_archive_record']}",
        f"  - release evidence bundle: {payload['release_evidence_bundle']}",
        f"  - mismatches: {payload['mismatch_count']}",
        f"  - handoff artifacts: {payload['handoff_artifact_count']}",
        f"  - verified handoff artifacts: {payload['verified_handoff_artifact_count']}",
        f"  - ready for publication: {yes_no(payload['ready_for_publication'])}",
        f"  - publication blockers: {payload['publication_blocker_count']}",
        f"  - closeout gate verified: {yes_no(payload['closeout_gate']['verified'])}",
        f"  - closeout gate required-match exit code: {payload['closeout_gate']['required_match_exit_code']}",
        f"  - closeout gate mismatches: {payload['closeout_gate']['mismatch_count']}",
        f"  - closeout archive gate verified: {yes_no(payload['closeout_archive_gate']['verified'])}",
        f"  - closeout archive gate required-match exit code: {payload['closeout_archive_gate']['required_match_exit_code']}",
        f"  - closeout archive gate mismatches: {payload['closeout_archive_gate']['mismatch_count']}",
        f"  - closeout archive missing required fields: {payload['closeout_archive_gate']['missing_required_field_count']}",
        f"  - closeout archive unexpected fields: {payload['closeout_archive_gate']['unexpected_field_count']}",
        f"  - release evidence publication closeout archive handoff summary command: {payload['release_evidence_publication_closeout_archive_handoff_summary_command']}",
        f"  - release evidence publication closeout archive handoff summary JSON command: {payload['release_evidence_publication_closeout_archive_handoff_summary_json_command']}",
        f"  - release evidence publication closeout gate JSON command: {payload['release_evidence_publication_closeout_gate_json_command']}",
        f"  - release evidence publication closeout archive gate JSON command: {payload['release_evidence_publication_closeout_archive_gate_json_command']}",
        f"  - release evidence publication closeout checklist JSON command: {payload['release_evidence_publication_closeout_checklist_json_command']}",
    ]
    for artifact in payload["handoff_artifacts"]:
        lines.extend([
            f"  - handoff artifact {artifact['step']}: {artifact['id']}",
            f"  - handoff artifact {artifact['step']} path: {artifact['path']}",
            (
                f"  - handoff artifact {artifact['step']} verified: "
                f"{yes_no(artifact['verified'])}"
            ),
            f"  - handoff artifact {artifact['step']} command: {artifact['command']}",
        ])
    if payload["publication_blockers"]:
        lines.extend([
            f"  - next publication blocker: {payload['next_publication_blocker_id']}",
            f"  - next publication blocker path: {payload['next_publication_blocker_path']}",
            f"  - next publication blocker command: {payload['next_publication_blocker_command']}",
        ])
    if payload["first_mismatch"] is not None:
        mismatch = payload["first_mismatch"]
        lines.extend([
            f"  - first mismatch source: {mismatch['source']}",
            f"  - first mismatch path: {mismatch['path']}",
            f"  - first mismatch kind: {mismatch['kind']}",
        ])
    return "\n".join(lines)


def release_evidence_publication_closeout_archive_handoff_summary_text(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return (
        release_evidence_publication_closeout_archive_handoff_summary_text_from_payload(
            release_evidence_publication_closeout_archive_handoff_summary_payload(
                manifest,
                manifest_path,
                check,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        )
    )


def release_evidence_publication_closeout_archive_handoff_summary_json_text_from_payload(
    payload,
):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_closeout_archive_handoff_summary_json_text(
    manifest,
    manifest_path,
    check,
    closeout_archive_record_path,
    closeout_path,
    publication_index_archive_record_path,
    publication_index_path,
    archive_record_path,
    bundle_path,
):
    return (
        release_evidence_publication_closeout_archive_handoff_summary_json_text_from_payload(
            release_evidence_publication_closeout_archive_handoff_summary_payload(
                manifest,
                manifest_path,
                check,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
            )
        )
    )


def release_evidence_publication_status_step(
    step,
    step_id,
    kind,
    description,
    command,
    json_command,
    input_artifacts=None,
    output_artifact=None,
    requires_operator_values=False,
    operator_fields=None,
):
    return {
        "step": step,
        "id": step_id,
        "kind": kind,
        "description": description,
        "input_artifacts": list(input_artifacts or []),
        "input_artifact_count": len(input_artifacts or []),
        "output_artifact": output_artifact,
        "requires_operator_values": requires_operator_values,
        "operator_fields": list(operator_fields or []),
        "operator_field_count": len(operator_fields or []),
        "command": command,
        "json_command": json_command,
    }


def release_evidence_publication_status_steps(manifest_path):
    bundle = "<release_evidence_bundle.json>"
    archive = "<release_evidence_archive_record.json>"
    handoff = "<release_evidence_handoff_summary.json>"
    index = "<release_evidence_publication_index.json>"
    index_archive = (
        "<release_evidence_publication_index_archive_record.json>"
    )
    index_archive_handoff = (
        "<release_evidence_publication_index_archive_handoff_summary.json>"
    )
    closeout = "<release_evidence_publication_closeout.json>"
    closeout_archive = (
        "<release_evidence_publication_closeout_archive_record.json>"
    )
    closeout_archive_handoff = (
        "<release_evidence_publication_closeout_archive_handoff_summary.json>"
    )
    return [
        release_evidence_publication_status_step(
            1,
            "release-evidence-bundle",
            "generate",
            "Generate the deterministic launch-profile release evidence bundle.",
            release_evidence_bundle_command(manifest_path),
            release_evidence_bundle_json_command(manifest_path),
            output_artifact=bundle,
        ),
        release_evidence_publication_status_step(
            2,
            "release-evidence-archive-checklist",
            "operator-record",
            "Prepare the archive record fields for the retained bundle.",
            release_evidence_archive_checklist_command(manifest_path),
            release_evidence_archive_checklist_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[bundle],
            output_artifact=archive,
            requires_operator_values=True,
            operator_fields=[
                "release_evidence_bundle_uri",
                "manifest_commit",
                "gate_checked_at",
            ],
        ),
        release_evidence_publication_status_step(
            3,
            "release-evidence-archive-gate",
            "gate",
            "Verify the filled release evidence archive record.",
            release_evidence_archive_gate_command(manifest_path),
            release_evidence_archive_gate_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[archive, bundle],
        ),
        release_evidence_publication_status_step(
            4,
            "release-evidence-handoff-summary",
            "handoff",
            "Summarize the bundle and archive gates for publication.",
            release_evidence_handoff_summary_command(manifest_path),
            release_evidence_handoff_summary_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[archive, bundle],
            output_artifact=handoff,
        ),
        release_evidence_publication_status_step(
            5,
            "release-evidence-publication-index-template",
            "operator-record",
            "Prepare the publication index after the first handoff verifies.",
            release_evidence_publication_index_template_command(manifest_path),
            release_evidence_publication_index_template_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[archive, bundle],
            output_artifact=index,
            requires_operator_values=True,
            operator_fields=[
                "release_evidence_bundle_uri",
                "release_evidence_archive_record_uri",
                "release_evidence_handoff_summary_uri",
                "manifest_commit",
                "published_at",
                "publisher",
            ],
        ),
        release_evidence_publication_status_step(
            6,
            "release-evidence-publication-index-gate",
            "gate",
            "Verify the filled release evidence publication index.",
            release_evidence_publication_index_gate_command(manifest_path),
            release_evidence_publication_index_gate_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[index, archive, bundle],
        ),
        release_evidence_publication_status_step(
            7,
            "release-evidence-publication-index-archive-checklist",
            "operator-record",
            "Prepare the archive record for the retained publication index.",
            release_evidence_publication_index_archive_checklist_command(
                manifest_path
            ),
            release_evidence_publication_index_archive_checklist_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[index, archive, bundle],
            output_artifact=index_archive,
            requires_operator_values=True,
            operator_fields=[
                "release_evidence_publication_index_uri",
                "manifest_commit",
                "gate_checked_at",
            ],
        ),
        release_evidence_publication_status_step(
            8,
            "release-evidence-publication-index-archive-gate",
            "gate",
            "Verify the filled publication index archive record.",
            release_evidence_publication_index_archive_gate_command(
                manifest_path
            ),
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[index_archive, index, archive, bundle],
        ),
        release_evidence_publication_status_step(
            9,
            "release-evidence-publication-index-archive-handoff-summary",
            "handoff",
            "Summarize the publication index and archive gates.",
            release_evidence_publication_index_archive_handoff_summary_command(
                manifest_path
            ),
            release_evidence_publication_index_archive_handoff_summary_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[index_archive, index, archive, bundle],
            output_artifact=index_archive_handoff,
        ),
        release_evidence_publication_status_step(
            10,
            "release-evidence-publication-closeout-checklist",
            "handoff",
            "Build the final closeout checklist for retained publication evidence.",
            release_evidence_publication_closeout_checklist_command(
                manifest_path
            ),
            release_evidence_publication_closeout_checklist_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[index_archive, index, archive, bundle],
            output_artifact=closeout,
        ),
        release_evidence_publication_status_step(
            11,
            "release-evidence-publication-closeout-gate",
            "gate",
            "Verify the retained release evidence publication closeout JSON.",
            release_evidence_publication_closeout_gate_command(manifest_path),
            release_evidence_publication_closeout_gate_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[closeout, index_archive, index, archive, bundle],
        ),
        release_evidence_publication_status_step(
            12,
            "release-evidence-publication-closeout-archive-gate",
            "gate",
            "Verify the filled publication closeout archive record.",
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path
            ),
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[
                closeout_archive,
                closeout,
                index_archive,
                index,
                archive,
                bundle,
            ],
        ),
        release_evidence_publication_status_step(
            13,
            "release-evidence-publication-closeout-archive-handoff-summary",
            "handoff",
            "Summarize the retained closeout and closeout archive gates.",
            release_evidence_publication_closeout_archive_handoff_summary_command(
                manifest_path
            ),
            release_evidence_publication_closeout_archive_handoff_summary_command(
                manifest_path,
                json_output=True,
            ),
            input_artifacts=[
                closeout_archive,
                closeout,
                index_archive,
                index,
                archive,
                bundle,
            ],
            output_artifact=closeout_archive_handoff,
        ),
    ]


def release_evidence_publication_status_payload(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    steps = release_evidence_publication_status_steps(manifest_path)
    operator_value_steps = [
        step["id"]
        for step in steps
        if step["requires_operator_values"]
    ]
    gate_steps = [
        step["id"]
        for step in steps
        if step["kind"] == "gate"
    ]
    handoff_steps = [
        step["id"]
        for step in steps
        if step["kind"] == "handoff"
    ]
    status_command = release_evidence_publication_status_command(
        manifest_path
    )
    status_json_command = release_evidence_publication_status_command(
        manifest_path,
        json_output=True,
    )
    command_by_step = {
        step["id"]: step["command"]
        for step in steps
    }
    json_command_by_step = {
        step["id"]: step["json_command"]
        for step in steps
    }
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "launch_profile_blocked": bool(blockers),
        "unresolved_blocker_count": len(blockers),
        "unresolved_blockers": blockers,
        "ready_for_chainparams": (
            manifest.get("status") == "ready-for-chainparams"
            and not blockers
        ),
        "publication_step_count": len(steps),
        "gate_step_count": len(gate_steps),
        "gate_steps": gate_steps,
        "handoff_step_count": len(handoff_steps),
        "handoff_steps": handoff_steps,
        "operator_value_step_count": len(operator_value_steps),
        "operator_value_steps": operator_value_steps,
        "final_handoff_step_id": (
            "release-evidence-publication-closeout-archive-handoff-summary"
        ),
        "publication_steps": steps,
        "release_evidence_publication_status_command": status_command,
        "release_evidence_publication_status_json_command": (
            status_json_command
        ),
        "command_by_step": command_by_step,
        "json_command_by_step": json_command_by_step,
        "commands": {
            "release_evidence_publication_status": status_command,
            "release_evidence_publication_status_json": status_json_command,
            "by_step": command_by_step,
            "json_by_step": json_command_by_step,
        },
    }


def release_evidence_publication_status_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication status:",
        f"  - manifest: {payload['manifest']}",
        f"  - launch profile blocked: {yes_no(payload['launch_profile_blocked'])}",
        f"  - unresolved blockers: {payload['unresolved_blocker_count']}",
        f"  - ready for chainparams: {yes_no(payload['ready_for_chainparams'])}",
        f"  - publication steps: {payload['publication_step_count']}",
        f"  - gate steps: {payload['gate_step_count']}",
        f"  - handoff steps: {payload['handoff_step_count']}",
        f"  - operator-value steps: {payload['operator_value_step_count']}",
        f"  - final handoff step: {payload['final_handoff_step_id']}",
        f"  - release evidence publication status command: {payload['release_evidence_publication_status_command']}",
        f"  - release evidence publication status JSON command: {payload['release_evidence_publication_status_json_command']}",
    ]
    if payload["unresolved_blockers"]:
        lines.append(
            "  - unresolved blocker ids: "
            + list_summary(payload["unresolved_blockers"])
        )
    for step in payload["publication_steps"]:
        lines.extend([
            f"  - publication step {step['step']}: {step['id']}",
            f"  - publication step {step['step']} kind: {step['kind']}",
            (
                f"  - publication step {step['step']} input artifacts: "
                f"{list_summary(step['input_artifacts'])}"
            ),
            (
                f"  - publication step {step['step']} output artifact: "
                f"{step['output_artifact'] or 'none'}"
            ),
            (
                f"  - publication step {step['step']} requires operator values: "
                f"{yes_no(step['requires_operator_values'])}"
            ),
            (
                f"  - publication step {step['step']} operator fields: "
                f"{list_summary(step['operator_fields'])}"
            ),
            f"  - publication step {step['step']} command: {step['command']}",
            (
                f"  - publication step {step['step']} JSON command: "
                f"{step['json_command']}"
            ),
        ])
    return "\n".join(lines)


def release_evidence_publication_status_text(manifest, manifest_path, check):
    return release_evidence_publication_status_text_from_payload(
        release_evidence_publication_status_payload(
            manifest,
            manifest_path,
            check,
        )
    )


def release_evidence_publication_status_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_status_json_text(manifest, manifest_path, check):
    return release_evidence_publication_status_json_text_from_payload(
        release_evidence_publication_status_payload(
            manifest,
            manifest_path,
            check,
        )
    )


def release_evidence_publication_artifact_arg(
    artifact_paths,
    artifact_placeholders,
    artifact_id,
):
    artifact_path = artifact_paths[artifact_id]
    return artifact_path if artifact_path is not None else artifact_placeholders[artifact_id]


def release_evidence_publication_artifact_entry(
    step,
    artifact_id,
    flag,
    placeholder,
    artifact_path,
    verification_id,
):
    return {
        "step": step,
        "id": artifact_id,
        "flag": flag,
        "placeholder": placeholder,
        "path": display_path(artifact_path) if artifact_path is not None else None,
        "provided": artifact_path is not None,
        "verification_id": verification_id,
        "verified": False,
        "status": "missing-artifact" if artifact_path is None else "pending",
    }


def release_evidence_publication_artifact_verification_entry(
    step,
    verification_id,
    artifact_id,
    description,
    required_artifact_ids,
    command,
    json_command,
    payload_builder,
):
    missing_artifacts = [
        required_artifact_id
        for required_artifact_id, required_path in required_artifact_ids
        if required_path is None
    ]
    if missing_artifacts:
        return {
            "step": step,
            "id": verification_id,
            "artifact_id": artifact_id,
            "description": description,
            "required_artifacts": [
                required_artifact_id
                for required_artifact_id, _ in required_artifact_ids
            ],
            "missing_artifacts": missing_artifacts,
            "status": "missing-artifact",
            "verified": False,
            "mismatch_count": None,
            "required_match_exit_code": None,
            "error": None,
            "first_mismatch": None,
            "command": command,
            "json_command": json_command,
        }

    try:
        payload = payload_builder()
    except ValueError as exc:
        return {
            "step": step,
            "id": verification_id,
            "artifact_id": artifact_id,
            "description": description,
            "required_artifacts": [
                required_artifact_id
                for required_artifact_id, _ in required_artifact_ids
            ],
            "missing_artifacts": [],
            "status": "error",
            "verified": False,
            "mismatch_count": None,
            "required_match_exit_code": None,
            "error": str(exc),
            "first_mismatch": None,
            "command": command,
            "json_command": json_command,
        }

    mismatches = payload.get("mismatches", [])
    verified = bool(payload.get("verified"))
    return {
        "step": step,
        "id": verification_id,
        "artifact_id": artifact_id,
        "description": description,
        "required_artifacts": [
            required_artifact_id
            for required_artifact_id, _ in required_artifact_ids
        ],
        "missing_artifacts": [],
        "status": "verified" if verified else "mismatch",
        "verified": verified,
        "mismatch_count": payload.get("mismatch_count"),
        "required_match_exit_code": payload.get("required_match_exit_code"),
        "error": None,
        "first_mismatch": mismatches[0] if mismatches else None,
        "command": command,
        "json_command": json_command,
    }


def release_evidence_publication_artifact_status_payload(
    manifest,
    manifest_path,
    check,
    bundle_path=None,
    archive_record_path=None,
    publication_index_path=None,
    publication_index_archive_record_path=None,
    closeout_path=None,
    closeout_archive_record_path=None,
):
    blockers = ordered_unresolved_blocker_ids(manifest)
    artifact_paths = {
        "release-evidence-bundle": bundle_path,
        "release-evidence-archive-record": archive_record_path,
        "release-evidence-publication-index": publication_index_path,
        "release-evidence-publication-index-archive-record": (
            publication_index_archive_record_path
        ),
        "release-evidence-publication-closeout": closeout_path,
        "release-evidence-publication-closeout-archive-record": (
            closeout_archive_record_path
        ),
    }
    artifact_placeholders = {
        artifact_id: placeholder
        for artifact_id, _, placeholder in RELEASE_EVIDENCE_PUBLICATION_ARTIFACT_PATH_FLAGS
    }
    artifact_entries = [
        release_evidence_publication_artifact_entry(
            step,
            artifact_id,
            flag,
            placeholder,
            artifact_paths[artifact_id],
            verification_id,
        )
        for step, ((artifact_id, flag, placeholder), verification_id) in enumerate(
            zip(
                RELEASE_EVIDENCE_PUBLICATION_ARTIFACT_PATH_FLAGS,
                (
                    "release-evidence-bundle-gate",
                    "release-evidence-archive-gate",
                    "release-evidence-publication-index-gate",
                    "release-evidence-publication-index-archive-gate",
                    "release-evidence-publication-closeout-gate",
                    "release-evidence-publication-closeout-archive-gate",
                ),
            ),
            1,
        )
    ]

    artifact_arg = lambda artifact_id: release_evidence_publication_artifact_arg(
        artifact_paths,
        artifact_placeholders,
        artifact_id,
    )
    bundle_arg = artifact_arg("release-evidence-bundle")
    archive_arg = artifact_arg("release-evidence-archive-record")
    publication_index_arg = artifact_arg("release-evidence-publication-index")
    publication_index_archive_arg = artifact_arg(
        "release-evidence-publication-index-archive-record"
    )
    closeout_arg = artifact_arg("release-evidence-publication-closeout")
    closeout_archive_arg = artifact_arg(
        "release-evidence-publication-closeout-archive-record"
    )

    verification_entries = [
        release_evidence_publication_artifact_verification_entry(
            1,
            "release-evidence-bundle-gate",
            "release-evidence-bundle",
            "Verify the retained release evidence bundle.",
            [("release-evidence-bundle", bundle_path)],
            release_evidence_bundle_gate_command(manifest_path, bundle_arg),
            release_evidence_bundle_gate_command(
                manifest_path,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_bundle_check_payload(
                manifest,
                manifest_path,
                check,
                bundle_path,
                require_match=True,
            ),
        ),
        release_evidence_publication_artifact_verification_entry(
            2,
            "release-evidence-archive-gate",
            "release-evidence-archive-record",
            "Verify the retained release evidence archive record.",
            [
                ("release-evidence-archive-record", archive_record_path),
                ("release-evidence-bundle", bundle_path),
            ],
            release_evidence_archive_gate_command(
                manifest_path,
                archive_arg,
                bundle_arg,
            ),
            release_evidence_archive_gate_command(
                manifest_path,
                archive_arg,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_archive_check_payload(
                manifest,
                manifest_path,
                check,
                archive_record_path,
                bundle_path,
                require_match=True,
            ),
        ),
        release_evidence_publication_artifact_verification_entry(
            3,
            "release-evidence-publication-index-gate",
            "release-evidence-publication-index",
            "Verify the retained release evidence publication index.",
            [
                (
                    "release-evidence-publication-index",
                    publication_index_path,
                ),
                ("release-evidence-archive-record", archive_record_path),
                ("release-evidence-bundle", bundle_path),
            ],
            release_evidence_publication_index_gate_command(
                manifest_path,
                publication_index_arg,
                archive_arg,
                bundle_arg,
            ),
            release_evidence_publication_index_gate_command(
                manifest_path,
                publication_index_arg,
                archive_arg,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_publication_index_check_payload(
                manifest,
                manifest_path,
                check,
                publication_index_path,
                archive_record_path,
                bundle_path,
                require_match=True,
            ),
        ),
        release_evidence_publication_artifact_verification_entry(
            4,
            "release-evidence-publication-index-archive-gate",
            "release-evidence-publication-index-archive-record",
            "Verify the retained publication index archive record.",
            [
                (
                    "release-evidence-publication-index-archive-record",
                    publication_index_archive_record_path,
                ),
                (
                    "release-evidence-publication-index",
                    publication_index_path,
                ),
                ("release-evidence-archive-record", archive_record_path),
                ("release-evidence-bundle", bundle_path),
            ],
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
            ),
            release_evidence_publication_index_archive_gate_command(
                manifest_path,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_publication_index_archive_check_payload(
                manifest,
                manifest_path,
                check,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                require_match=True,
            ),
        ),
        release_evidence_publication_artifact_verification_entry(
            5,
            "release-evidence-publication-closeout-gate",
            "release-evidence-publication-closeout",
            "Verify the retained release evidence publication closeout.",
            [
                ("release-evidence-publication-closeout", closeout_path),
                (
                    "release-evidence-publication-index-archive-record",
                    publication_index_archive_record_path,
                ),
                (
                    "release-evidence-publication-index",
                    publication_index_path,
                ),
                ("release-evidence-archive-record", archive_record_path),
                ("release-evidence-bundle", bundle_path),
            ],
            release_evidence_publication_closeout_gate_command(
                manifest_path,
                closeout_arg,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
            ),
            release_evidence_publication_closeout_gate_command(
                manifest_path,
                closeout_arg,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_publication_closeout_check_payload(
                manifest,
                manifest_path,
                check,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                require_match=True,
            ),
        ),
        release_evidence_publication_artifact_verification_entry(
            6,
            "release-evidence-publication-closeout-archive-gate",
            "release-evidence-publication-closeout-archive-record",
            "Verify the retained publication closeout archive record.",
            [
                (
                    "release-evidence-publication-closeout-archive-record",
                    closeout_archive_record_path,
                ),
                ("release-evidence-publication-closeout", closeout_path),
                (
                    "release-evidence-publication-index-archive-record",
                    publication_index_archive_record_path,
                ),
                (
                    "release-evidence-publication-index",
                    publication_index_path,
                ),
                ("release-evidence-archive-record", archive_record_path),
                ("release-evidence-bundle", bundle_path),
            ],
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path,
                closeout_archive_arg,
                closeout_arg,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
            ),
            release_evidence_publication_closeout_archive_gate_command(
                manifest_path,
                closeout_archive_arg,
                closeout_arg,
                publication_index_archive_arg,
                publication_index_arg,
                archive_arg,
                bundle_arg,
                json_output=True,
            ),
            lambda: release_evidence_publication_closeout_archive_check_payload(
                manifest,
                manifest_path,
                check,
                closeout_archive_record_path,
                closeout_path,
                publication_index_archive_record_path,
                publication_index_path,
                archive_record_path,
                bundle_path,
                require_match=True,
            ),
        ),
    ]
    verifications_by_artifact = {
        verification["artifact_id"]: verification
        for verification in verification_entries
    }
    for artifact_entry in artifact_entries:
        verification = verifications_by_artifact[artifact_entry["id"]]
        artifact_entry["verified"] = verification["verified"]
        artifact_entry["status"] = verification["status"]

    provided_artifact_count = sum(
        1 for artifact in artifact_entries if artifact["provided"]
    )
    verified_artifact_count = sum(
        1 for artifact in artifact_entries if artifact["verified"]
    )
    publication_gate_entries = verification_entries[1:]
    verified_publication_gate_count = sum(
        1 for verification in publication_gate_entries if verification["verified"]
    )
    next_missing_artifact = next(
        (
            artifact["id"]
            for artifact in artifact_entries
            if not artifact["provided"]
        ),
        None,
    )
    next_unverified_verification = next(
        (
            verification["id"]
            for verification in verification_entries
            if not verification["verified"]
        ),
        None,
    )
    status_command = release_evidence_publication_artifact_status_command(
        manifest_path,
        bundle_path,
        archive_record_path,
        publication_index_path,
        publication_index_archive_record_path,
        closeout_path,
        closeout_archive_record_path,
    )
    status_json_command = release_evidence_publication_artifact_status_command(
        manifest_path,
        bundle_path,
        archive_record_path,
        publication_index_path,
        publication_index_archive_record_path,
        closeout_path,
        closeout_archive_record_path,
        json_output=True,
    )
    return {
        "schema_version": 1,
        "manifest": display_path(manifest_path),
        "launch_profile_blocked": bool(blockers),
        "unresolved_blocker_count": len(blockers),
        "unresolved_blockers": blockers,
        "artifact_count": len(artifact_entries),
        "provided_artifact_count": provided_artifact_count,
        "missing_artifact_count": (
            len(artifact_entries) - provided_artifact_count
        ),
        "verified_artifact_count": verified_artifact_count,
        "artifact_verification_count": len(verification_entries),
        "verified_artifact_verification_count": verified_artifact_count,
        "publication_gate_count": len(publication_gate_entries),
        "verified_publication_gate_count": verified_publication_gate_count,
        "ready_for_final_handoff": verification_entries[-1]["verified"],
        "next_missing_artifact": next_missing_artifact,
        "next_unverified_verification": next_unverified_verification,
        "artifact_statuses": artifact_entries,
        "artifact_verifications": verification_entries,
        "artifact_path_flags": [
            {
                "artifact_id": artifact_id,
                "flag": flag,
                "placeholder": placeholder,
            }
            for artifact_id, flag, placeholder in (
                RELEASE_EVIDENCE_PUBLICATION_ARTIFACT_PATH_FLAGS
            )
        ],
        "release_evidence_publication_artifact_status_command": status_command,
        "release_evidence_publication_artifact_status_json_command": (
            status_json_command
        ),
        "commands": {
            "release_evidence_publication_artifact_status": status_command,
            "release_evidence_publication_artifact_status_json": (
                status_json_command
            ),
        },
    }


def release_evidence_publication_artifact_status_text_from_payload(payload):
    lines = [
        "zkCoin public launch profile release evidence publication artifact status:",
        f"  - manifest: {payload['manifest']}",
        f"  - launch profile blocked: {yes_no(payload['launch_profile_blocked'])}",
        f"  - unresolved blockers: {payload['unresolved_blocker_count']}",
        f"  - supplied artifacts: {payload['provided_artifact_count']}/{payload['artifact_count']}",
        f"  - verified artifacts: {payload['verified_artifact_count']}/{payload['artifact_count']}",
        f"  - verified publication gates: {payload['verified_publication_gate_count']}/{payload['publication_gate_count']}",
        f"  - ready for final handoff: {yes_no(payload['ready_for_final_handoff'])}",
        f"  - next missing artifact: {payload['next_missing_artifact'] or 'none'}",
        f"  - next unverified verification: {payload['next_unverified_verification'] or 'none'}",
        f"  - release evidence publication artifact status command: {payload['release_evidence_publication_artifact_status_command']}",
        f"  - release evidence publication artifact status JSON command: {payload['release_evidence_publication_artifact_status_json_command']}",
    ]
    for artifact in payload["artifact_statuses"]:
        lines.extend([
            f"  - artifact {artifact['step']}: {artifact['id']}",
            f"  - artifact {artifact['step']} flag: {artifact['flag']}",
            (
                f"  - artifact {artifact['step']} path: "
                f"{artifact['path'] or artifact['placeholder']}"
            ),
            f"  - artifact {artifact['step']} supplied: {yes_no(artifact['provided'])}",
            f"  - artifact {artifact['step']} status: {artifact['status']}",
            f"  - artifact {artifact['step']} verified: {yes_no(artifact['verified'])}",
        ])
    for verification in payload["artifact_verifications"]:
        lines.extend([
            f"  - verification {verification['step']}: {verification['id']}",
            f"  - verification {verification['step']} status: {verification['status']}",
            f"  - verification {verification['step']} verified: {yes_no(verification['verified'])}",
            (
                f"  - verification {verification['step']} missing artifacts: "
                f"{list_summary(verification['missing_artifacts'])}"
            ),
            (
                f"  - verification {verification['step']} mismatches: "
                f"{verification['mismatch_count'] if verification['mismatch_count'] is not None else 'not checked'}"
            ),
            f"  - verification {verification['step']} command: {verification['command']}",
            (
                f"  - verification {verification['step']} JSON command: "
                f"{verification['json_command']}"
            ),
        ])
        if verification["error"]:
            lines.append(
                f"  - verification {verification['step']} error: {verification['error']}"
            )
        if verification["first_mismatch"] is not None:
            mismatch = verification["first_mismatch"]
            lines.extend([
                f"  - verification {verification['step']} first mismatch path: {mismatch['path']}",
                f"  - verification {verification['step']} first mismatch kind: {mismatch['kind']}",
            ])
    return "\n".join(lines)


def release_evidence_publication_artifact_status_text(
    manifest,
    manifest_path,
    check,
    bundle_path=None,
    archive_record_path=None,
    publication_index_path=None,
    publication_index_archive_record_path=None,
    closeout_path=None,
    closeout_archive_record_path=None,
):
    return release_evidence_publication_artifact_status_text_from_payload(
        release_evidence_publication_artifact_status_payload(
            manifest,
            manifest_path,
            check,
            bundle_path,
            archive_record_path,
            publication_index_path,
            publication_index_archive_record_path,
            closeout_path,
            closeout_archive_record_path,
        )
    )


def release_evidence_publication_artifact_status_json_text_from_payload(payload):
    return json.dumps(payload, indent=2, sort_keys=False)


def release_evidence_publication_artifact_status_json_text(
    manifest,
    manifest_path,
    check,
    bundle_path=None,
    archive_record_path=None,
    publication_index_path=None,
    publication_index_archive_record_path=None,
    closeout_path=None,
    closeout_archive_record_path=None,
):
    return release_evidence_publication_artifact_status_json_text_from_payload(
        release_evidence_publication_artifact_status_payload(
            manifest,
            manifest_path,
            check,
            bundle_path,
            archive_record_path,
            publication_index_path,
            publication_index_archive_record_path,
            closeout_path,
            closeout_archive_record_path,
        )
    )


def network_value_selection_later_blockers_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    later_blockers, later_fields = network_value_selection_later_blocker_state(
        blocked_field_groups,
        network_progress,
    )
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    manifest_arg = shell_quote(display_path(manifest_path))
    json_check_commands = blocker_json_check_commands(later_blockers, manifest_arg)
    later_groups = [
        {
            **groups_by_blocker[blocker],
            "json_check_command": json_check_commands[blocker],
        }
        for blocker in later_blockers
    ]
    checklist = value_selection_candidate_checklist(later_groups)
    next_group = network_progress["next_blocked_field_group"]
    current_blocker_id = next_group["id"] if next_group is not None else None
    return {
        "schema_version": 1,
        "network": network,
        "ready_for_launch_profile": network_progress["ready_for_launch_profile"],
        "current_blocker": current_blocker_id,
        "current_blocker_field_count": (
            next_group["field_count"] if next_group is not None else 0
        ),
        "value_selection_blocker_types": list(
            blocker_types_by_readiness_gate()["value_selection"]
        ),
        "later_value_selection_blockers": later_blockers,
        "later_value_selection_blocker_count": len(later_blockers),
        "later_value_selection_blocker_fields": later_fields,
        "later_value_selection_blocker_field_count": len(later_fields),
        "later_value_selection_blocker_field_groups": later_groups,
        "later_value_selection_json_check_commands": json_check_commands,
        "later_value_selection_json_check_command_count": len(json_check_commands),
        "later_value_selection_candidate_checklist": checklist,
        "later_value_selection_candidate_checklist_summary": (
            value_selection_candidate_checklist_summary(checklist)
        ),
        "later_value_selection_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
        "network_value_selection_later_blockers_command": (
            network_value_selection_later_blockers_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_command": (
            network_value_selection_candidate_template_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_json_command": (
            network_value_selection_candidate_template_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_command": (
            network_value_selection_candidate_check_command(manifest_path, network)
        ),
        "network_value_selection_candidate_check_json_command": (
            network_value_selection_candidate_check_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
    }


def network_value_selection_later_blockers_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        network_value_selection_later_blockers_json_payload(
            manifest,
            manifest_path,
            check,
            network,
        ),
        indent=2,
        sort_keys=False,
    )


def network_handoff_bundle_text(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    next_group = progress["next_blocked_field_group"]
    later_blockers, later_fields = network_value_selection_later_blocker_state(
        blocked_field_groups,
        progress,
    )
    lines = [
        "zkCoin public launch profile network handoff bundle:",
        f"  - network: {network}",
        f"  - ready for launch profile: {yes_no(progress['ready_for_launch_profile'])}",
        f"  - current blocker: {next_group['id'] if next_group is not None else 'none'}",
        f"  - current blocker fields: {next_group['field_count'] if next_group is not None else 0}",
    ]
    if next_group is not None:
        append_blocker_handoff_command_lines(lines, next_group, "  - ")
        if next_group["blocker_type"] == "litecoin_snapshot":
            lines.append(
                "  - current snapshot audit handoff command: "
                + snapshot_audit_handoff_command(manifest_path, network)
            )
    lines.extend([
        (
            "  - current blocker readiness summary command: "
            + (
                blocker_readiness_summary_command(manifest_path, next_group["id"])
                if next_group is not None
                else "none"
            )
        ),
        f"  - network readiness summary command: {network_readiness_summary_command(manifest_path, network)}",
        (
            "  - network value-selection later blockers command: "
            + network_value_selection_later_blockers_command(manifest_path, network)
        ),
        (
            "  - network value-selection candidate template command: "
            + network_value_selection_candidate_template_command(
                manifest_path,
                network,
            )
        ),
        (
            "  - network value-selection candidate check command: "
            + network_value_selection_candidate_check_command(
                manifest_path,
                network,
            )
        ),
        f"  - queued value-selection blockers: {list_summary(later_blockers)}",
        f"  - queued value-selection blocker count: {len(later_blockers)}",
        f"  - queued value-selection blocker fields: {len(later_fields)}",
        (
            "  - queued value-selection blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        ),
    ])
    return "\n".join(lines)


def network_handoff_bundle_json_payload(manifest, manifest_path, check, network):
    if network not in NETWORKS:
        raise ValueError("network must be one of: " + ", ".join(NETWORKS))
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )[network]
    next_group = progress["next_blocked_field_group"]
    later_blockers, later_fields = network_value_selection_later_blocker_state(
        blocked_field_groups,
        progress,
    )
    groups_by_blocker = blocked_field_groups_by_blocker(blocked_field_groups)
    manifest_arg = shell_quote(display_path(manifest_path))
    json_check_commands = blocker_json_check_commands(later_blockers, manifest_arg)
    later_groups = [
        {
            **groups_by_blocker[blocker],
            "json_check_command": json_check_commands[blocker],
        }
        for blocker in later_blockers
    ]
    checklist = value_selection_candidate_checklist(later_groups)
    current_commands = action_command_fields(next_group)
    current_blocker = None
    if next_group is not None:
        current_blocker = {
            **next_group,
            "commands": current_commands,
        }
    current_blocker_id = next_group["id"] if next_group is not None else None
    return {
        "schema_version": 1,
        "network": network,
        "ready_for_launch_profile": progress["ready_for_launch_profile"],
        "unresolved_blockers": progress["unresolved_blockers"],
        "unresolved_blocker_count": progress["unresolved_blocker_count"],
        "blocked_fields": progress["blocked_fields"],
        "blocked_field_count": progress["blocked_field_count"],
        "current_blocker": current_blocker,
        "current_blocker_id": current_blocker_id,
        "current_blocker_field_count": (
            next_group["field_count"] if next_group is not None else 0
        ),
        "current_commands": current_commands,
        "current_snapshot_audit_handoff_command": (
            snapshot_audit_handoff_command(manifest_path, network)
            if next_group is not None
            and next_group["blocker_type"] == "litecoin_snapshot"
            else None
        ),
        "current_blocker_readiness_summary_command": (
            blocker_readiness_summary_command(manifest_path, current_blocker_id)
            if current_blocker_id is not None
            else None
        ),
        "network_readiness_summary_command": network_readiness_summary_command(
            manifest_path,
            network,
        ),
        "network_handoff_bundle_command": network_handoff_bundle_command(
            manifest_path,
            network,
        ),
        "network_value_selection_later_blockers_command": (
            network_value_selection_later_blockers_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_command": (
            network_value_selection_candidate_template_command(manifest_path, network)
        ),
        "network_value_selection_candidate_template_json_command": (
            network_value_selection_candidate_template_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "network_value_selection_candidate_check_command": (
            network_value_selection_candidate_check_command(manifest_path, network)
        ),
        "network_value_selection_candidate_check_json_command": (
            network_value_selection_candidate_check_command(
                manifest_path,
                network,
                json_output=True,
            )
        ),
        "queued_value_selection_blocker_types": list(
            blocker_types_by_readiness_gate()["value_selection"]
        ),
        "queued_value_selection_blockers": later_blockers,
        "queued_value_selection_blocker_count": len(later_blockers),
        "queued_value_selection_blocker_fields": later_fields,
        "queued_value_selection_blocker_field_count": len(later_fields),
        "queued_value_selection_blocker_field_groups": later_groups,
        "queued_value_selection_json_check_commands": json_check_commands,
        "queued_value_selection_json_check_command_count": len(json_check_commands),
        "queued_value_selection_candidate_checklist": checklist,
        "queued_value_selection_candidate_checklist_summary": (
            value_selection_candidate_checklist_summary(checklist)
        ),
        "queued_value_selection_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
    }


def network_handoff_bundle_json_text(manifest, manifest_path, check, network):
    return json.dumps(
        network_handoff_bundle_json_payload(manifest, manifest_path, check, network),
        indent=2,
        sort_keys=False,
    )


def blocker_readiness_summary_text(manifest, manifest_path, check, blocker_id):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    actions_by_id = {
        action["id"]: action
        for action in actions
        if action["kind"] == "blocker"
    }
    action = actions_by_id.get(blocker_id)
    if action is None:
        if blockers:
            raise ValueError(
                "blocker must be an unresolved blocker: " + ", ".join(blockers)
            )
        raise ValueError("manifest has no unresolved blocker summaries")

    step = action["step"]
    network_blockers = items_by_network(blockers)[action["network"]]
    blocker_type_blockers = blockers_by_blocker_type(blockers)[action["blocker_type"]]
    lines = [
        "zkCoin public launch profile blocker readiness summary:",
        f"  - blocker: {blocker_id}",
        f"  - launch order: {step} of {len(blockers)}",
        f"  - network launch order: {network_blockers.index(blocker_id) + 1} of {len(network_blockers)}",
        f"  - blocker-type launch order: {blocker_type_blockers.index(blocker_id) + 1} of {len(blocker_type_blockers)}",
        f"  - network: {action['network']}",
        f"  - blocker type: {action['blocker_type']}",
        f"  - blocked fields: {action['field_count']}",
        f"  - action: {action['action']}",
    ]
    append_blocker_field_lines(lines, action, "  - ", "    - ")
    append_blocker_command_lines(lines, action, "  - ")
    earlier_blockers = blockers[:step - 1]
    later_blockers = blockers[step:]
    if earlier_blockers:
        lines.append("  - earlier blockers: " + ", ".join(earlier_blockers))
        lines.append(
            "  - earlier blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, earlier_blockers)
        )
    if later_blockers:
        lines.append("  - later blockers: " + ", ".join(later_blockers))
        lines.append(
            "  - later blocker readiness summary commands: "
            + blocker_readiness_summary_command_summary(manifest_path, later_blockers)
        )
    return "\n".join(lines)


def blocker_readiness_summary_json_payload(manifest, manifest_path, check, blocker_id):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    actions_by_id = {
        action["id"]: action
        for action in actions
        if action["kind"] == "blocker"
    }
    action = actions_by_id.get(blocker_id)
    if action is None:
        if blockers:
            raise ValueError(
                "blocker must be an unresolved blocker: " + ", ".join(blockers)
            )
        raise ValueError("manifest has no unresolved blocker summaries")

    step = action["step"]
    network_blockers = items_by_network(blockers)[action["network"]]
    blocker_type_blockers = blockers_by_blocker_type(blockers)[action["blocker_type"]]
    earlier_blockers = blockers[:step - 1]
    later_blockers = blockers[step:]
    commands = action_command_fields(action)
    return {
        "schema_version": 1,
        "blocker": blocker_id,
        "unresolved": True,
        "network": action["network"],
        "blocker_type": action["blocker_type"],
        "readiness_gate": blocker_type_readiness_gate(action["blocker_type"]),
        "launch_order": {
            "step": step,
            "count": len(blockers),
        },
        "network_launch_order": {
            "step": network_blockers.index(blocker_id) + 1,
            "count": len(network_blockers),
        },
        "blocker_type_launch_order": {
            "step": blocker_type_blockers.index(blocker_id) + 1,
            "count": len(blocker_type_blockers),
        },
        "blocked_fields": action["fields"],
        "blocked_field_count": action["field_count"],
        "action": {
            **action,
            "commands": commands,
        },
        "commands": commands,
        "template_fields": action.get("template_fields"),
        "template_field_count": action.get("template_field_count", 0),
        "candidate_constraints": action.get("candidate_constraints"),
        "candidate_constraint_count": action.get("candidate_constraint_count", 0),
        "earlier_blockers": earlier_blockers,
        "earlier_blocker_count": len(earlier_blockers),
        "earlier_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, earlier_blockers)
        ),
        "later_blockers": later_blockers,
        "later_blocker_count": len(later_blockers),
        "later_blocker_readiness_summary_commands": (
            blocker_readiness_summary_commands(manifest_path, later_blockers)
        ),
    }


def blocker_readiness_summary_json_text(manifest, manifest_path, check, blocker_id):
    return json.dumps(
        blocker_readiness_summary_json_payload(
            manifest,
            manifest_path,
            check,
            blocker_id,
        ),
        indent=2,
        sort_keys=False,
    )


def status_json_text(manifest, manifest_path, check):
    blockers = ordered_unresolved_blocker_ids(manifest)
    actions = action_plan_entries(manifest, manifest_path)
    blocked_field_groups = blocked_field_group_entries(blockers, check.blockers, actions)
    actions = actions_with_blocked_fields(actions, blocked_field_groups)
    network_progress = network_progress_entries(
        blockers,
        check.blockers,
        blocked_field_groups,
    )
    blocker_type_progress = blocker_type_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    readiness_gate_progress = readiness_gate_progress_entries(
        actions,
        blockers,
        blocked_field_groups,
    )
    blocked_network_list = blocked_networks(network_progress)
    ready_network_list = ready_networks(network_progress)
    blocked_blocker_type_list = blocked_blocker_types(blocker_type_progress)
    ready_blocker_type_list = ready_blocker_types(blocker_type_progress)
    next_action = actions[0] if actions else None
    next_action_id = next_action["id"] if next_action else None
    next_action_kind = next_action["kind"] if next_action else None
    next_action_step = next_action["step"] if next_action else None
    next_action_network = next_action.get("network") if next_action else None
    next_action_blocker_type = next_action.get("blocker_type") if next_action else None
    next_action_field_count = next_action.get("field_count") if next_action else None
    later_actions = actions[1:] if actions else []
    action_commands = [action_command_fields(action) for action in actions]
    later_commands = [action_command_fields(action) for action in later_actions]
    next_blocked_field_group = blocked_field_groups[0] if blocked_field_groups else None
    next_blocked_fields = blocked_field_groups[0]["fields"] if blocked_field_groups else []
    next_blocker = next_blocked_field_group["id"] if next_blocked_field_group else None
    next_blocker_network = next_blocked_field_group["network"] if next_blocked_field_group else None
    next_blocker_type = next_blocked_field_group["blocker_type"] if next_blocked_field_group else None
    next_blocker_step = next_blocked_field_group["step"] if next_blocked_field_group else None
    next_blocker_network_step = next_blocked_field_group["network_step"] if next_blocked_field_group else None
    next_blocker_network_step_count = next_blocked_field_group["network_step_count"] if next_blocked_field_group else None
    next_blocker_type_step = next_blocked_field_group["blocker_type_step"] if next_blocked_field_group else None
    next_blocker_type_step_count = next_blocked_field_group["blocker_type_step_count"] if next_blocked_field_group else None
    next_blocker_field_groups_by_blocker = (
        {next_blocker: next_blocked_field_group}
        if next_blocker
        else {}
    )
    next_blocker_field_group_counts_by_blocker = {
        blocker: 1
        for blocker in next_blocker_field_groups_by_blocker
    }
    next_blocker_commands = action_command_fields(next_blocked_field_group)
    next_blocker_command_count = len(next_blocker_commands) if next_blocker_commands is not None else 0
    next_blocker_command_keys = action_command_keys(next_blocked_field_group)
    next_blocker_command_values = action_command_values(next_blocked_field_group)
    next_blocker_command_pairs = action_command_pairs(next_blocked_field_group)
    next_blocker_commands_by_blocker = (
        {next_blocker: next_blocker_commands}
        if next_blocker
        else {}
    )
    next_blocker_command_counts_by_blocker = {
        blocker: len(commands)
        for blocker, commands in next_blocker_commands_by_blocker.items()
    }
    next_blocker_fields_by_blocker = (
        {next_blocker: next_blocked_fields}
        if next_blocker
        else {}
    )
    next_blocker_field_counts_by_blocker = {
        blocker: len(fields)
        for blocker, fields in next_blocker_fields_by_blocker.items()
    }
    later_blockers = blockers[1:] if blockers else []
    later_blocker_field_groups = blocked_field_groups[1:] if blocked_field_groups else []
    later_blocker_steps = [group.get("step") for group in later_blocker_field_groups]
    later_blocker_network_steps = [group.get("network_step") for group in later_blocker_field_groups]
    later_blocker_network_step_counts = [group.get("network_step_count") for group in later_blocker_field_groups]
    later_blocker_type_steps = [group.get("blocker_type_step") for group in later_blocker_field_groups]
    later_blocker_type_step_counts = [group.get("blocker_type_step_count") for group in later_blocker_field_groups]
    later_blockers_by_network = items_by_network(later_blockers)
    later_blocker_counts_by_network = item_counts_by_network(later_blockers)
    later_blockers_by_blocker_type = blockers_by_blocker_type(later_blockers)
    later_blocker_counts_by_blocker_type = blocker_counts_by_blocker_type(later_blockers)
    later_blockers_by_network_and_blocker_type = blockers_by_network_and_blocker_type(later_blockers)
    later_blocker_counts_by_network_and_blocker_type = blocker_counts_by_network_and_blocker_type(later_blockers)
    later_blockers_by_gate = later_blockers_by_readiness_gate(blockers)
    later_blocker_counts_by_gate = later_blocker_counts_by_readiness_gate(blockers)
    later_blocker_networks = [group.get("network") for group in later_blocker_field_groups]
    later_blocker_types = [group.get("blocker_type") for group in later_blocker_field_groups]
    later_blocker_commands = [action_command_fields(group) for group in later_blocker_field_groups]
    later_blocker_commands_by_blocker = {
        group["id"]: action_command_fields(group)
        for group in later_blocker_field_groups
    }
    later_blocker_command_counts_by_blocker = {
        blocker: len(commands)
        for blocker, commands in later_blocker_commands_by_blocker.items()
    }
    later_blocker_command_keys = [action_command_keys(group) for group in later_blocker_field_groups]
    later_blocker_command_values = [action_command_values(group) for group in later_blocker_field_groups]
    later_blocker_command_pairs = [action_command_pairs(group) for group in later_blocker_field_groups]
    later_blocker_field_groups_by_blocker = {
        group["id"]: group
        for group in later_blocker_field_groups
    }
    later_blocker_field_group_counts_by_blocker = {
        blocker: 1
        for blocker in later_blocker_field_groups_by_blocker
    }
    later_blocker_field_groups_by_network = blocked_field_groups_by_network(later_blocker_field_groups)
    later_blocker_field_group_counts_by_network = blocked_field_group_counts_by_network(later_blocker_field_groups)
    later_blocker_field_groups_by_blocker_type = blocked_field_groups_by_blocker_type(later_blocker_field_groups)
    later_blocker_field_group_counts_by_blocker_type = blocked_field_group_counts_by_blocker_type(later_blocker_field_groups)
    later_blocker_field_groups_by_network_and_blocker_type = blocked_field_groups_by_network_and_blocker_type(later_blocker_field_groups)
    later_blocker_field_group_counts_by_network_and_blocker_type = blocked_field_group_counts_by_network_and_blocker_type(later_blocker_field_groups)
    later_blocker_field_groups_by_gate = later_blocked_field_groups_by_readiness_gate(blocked_field_groups)
    later_blocker_field_group_counts_by_gate = later_blocked_field_group_counts_by_readiness_gate(blocked_field_groups)
    later_blocker_field_counts = [group.get("field_count") for group in later_blocker_field_groups]
    later_blocker_fields_by_blocker = {
        group["id"]: group.get("fields", [])
        for group in later_blocker_field_groups
    }
    later_blocker_field_counts_by_blocker = {
        blocker: len(fields)
        for blocker, fields in later_blocker_fields_by_blocker.items()
    }
    later_blocker_fields_by_blocker_type = blocked_fields_by_blocker_type(later_blocker_field_groups)
    later_blocker_field_counts_by_blocker_type = blocked_field_counts_by_blocker_type(later_blocker_field_groups)
    later_blocker_fields_by_network_and_blocker_type = blocked_fields_by_network_and_blocker_type(later_blocker_field_groups)
    later_blocker_field_counts_by_network_and_blocker_type = blocked_field_counts_by_network_and_blocker_type(later_blocker_field_groups)
    later_blocker_fields_by_gate = later_blocked_fields_by_readiness_gate(blocked_field_groups)
    later_blocker_field_counts_by_gate = later_blocked_field_counts_by_readiness_gate(blocked_field_groups)
    later_blocker_fields = [
        field
        for group in later_blocker_field_groups
        for field in group["fields"]
    ]
    later_blocker_fields_by_network = items_by_network(later_blocker_fields)
    later_blocker_field_counts_by_network = item_counts_by_network(later_blocker_fields)
    snapshot_audit_handoff_commands_by_network = snapshot_audit_handoff_commands(manifest_path)
    network_readiness_commands = network_readiness_summary_commands(manifest_path)
    network_handoff_commands = network_handoff_bundle_commands(manifest_path)
    network_later_commands = network_later_blockers_commands(manifest_path)
    network_value_selection_later_commands = network_value_selection_later_blockers_commands(manifest_path)
    network_value_selection_candidate_template_commands_by_network = network_value_selection_candidate_template_commands(manifest_path)
    network_value_selection_candidate_template_json_commands_by_network = network_value_selection_candidate_template_commands(
        manifest_path,
        json_output=True,
    )
    network_value_selection_candidate_check_commands_by_network = network_value_selection_candidate_check_commands(manifest_path)
    network_value_selection_candidate_check_json_commands_by_network = network_value_selection_candidate_check_commands(
        manifest_path,
        json_output=True,
    )
    value_selection_candidate_artifact_status = value_selection_candidate_artifact_status_command(
        manifest_path,
    )
    value_selection_candidate_artifact_status_json = value_selection_candidate_artifact_status_command(
        manifest_path,
        json_output=True,
    )
    blocker_type_readiness_commands = blocker_type_readiness_summary_commands(manifest_path)
    blocker_type_later_blockers_commands_by_type = blocker_type_later_blockers_commands(manifest_path)
    readiness_gate_summary_commands_by_gate = readiness_gate_summary_commands(manifest_path)
    readiness_gate_later_blockers_commands_by_gate = readiness_gate_later_blockers_commands(manifest_path)
    blocker_readiness_commands = blocker_readiness_summary_commands(manifest_path, blockers)
    later_blocker_readiness_commands = blocker_readiness_summary_commands(
        manifest_path,
        later_blockers,
    )
    later_blocker_readiness_commands_by_gate = later_blocker_readiness_summary_commands_by_readiness_gate(
        manifest_path,
        blockers,
    )
    later_blocker_readiness_command_counts_by_gate = later_blocker_readiness_summary_command_counts_by_readiness_gate(
        manifest_path,
        blockers,
    )
    network_next_commands = network_next_command_fields(network_progress)
    blocker_type_next_commands = next_commands_by_blocker_type(actions)
    readiness_gate_next_commands = next_commands_by_readiness_gate(actions)
    network_blocker_type_next_commands = next_commands_by_network_and_blocker_type(actions)
    next_snapshot_audit_handoff_commands_by_network = command_field_values_by_group(
        network_next_commands,
        "snapshot_audit_handoff_command",
    )
    next_snapshot_audit_handoff_command_counts_by_network = command_field_counts_by_group(
        network_next_commands,
        "snapshot_audit_handoff_command",
    )
    next_snapshot_audit_handoff_commands_by_blocker_type = command_field_values_by_group(
        blocker_type_next_commands,
        "snapshot_audit_handoff_command",
    )
    next_snapshot_audit_handoff_command_counts_by_blocker_type = command_field_counts_by_group(
        blocker_type_next_commands,
        "snapshot_audit_handoff_command",
    )
    next_snapshot_audit_handoff_commands_by_readiness_gate = command_field_values_by_group(
        readiness_gate_next_commands,
        "snapshot_audit_handoff_command",
    )
    next_snapshot_audit_handoff_command_counts_by_readiness_gate = command_field_counts_by_group(
        readiness_gate_next_commands,
        "snapshot_audit_handoff_command",
    )
    snapshot_audit_handoff_readiness_by_network_map = snapshot_audit_handoff_readiness_by_network(
        network_progress,
        blocked_field_groups,
        next_snapshot_audit_handoff_commands_by_network,
    )
    snapshot_audit_handoff_checklist_by_network_map = snapshot_audit_handoff_checklist_by_network(
        manifest_path,
        blocked_field_groups,
    )
    snapshot_audit_handoff_checklist_summary_by_network_map = snapshot_audit_handoff_checklist_summary_by_network(
        snapshot_audit_handoff_checklist_by_network_map,
    )
    value_selection_states = network_value_selection_json_states(
        blocked_field_groups,
        network_progress,
        manifest_path,
    )
    commands = status_command_fields(manifest_path)
    command_keys = list(commands)
    command_values = list(commands.values())
    command_pairs = [
        {"key": command_key, "value": command}
        for command_key, command in commands.items()
    ]
    status = manifest.get("status")
    return json.dumps(
        {
            "schema_version": STATUS_JSON_SCHEMA_VERSION,
            "manifest": display_path(manifest_path),
            "status": status,
            "ready_for_chainparams": status == "ready-for-chainparams" and not blockers,
            "blocked_network_count": len(blocked_network_list),
            "blocked_networks": blocked_network_list,
            "ready_network_count": len(ready_network_list),
            "ready_networks": ready_network_list,
            "blocked_blocker_type_count": len(blocked_blocker_type_list),
            "blocked_blocker_types": blocked_blocker_type_list,
            "ready_blocker_type_count": len(ready_blocker_type_list),
            "ready_blocker_types": ready_blocker_type_list,
            "blocked_blocker_type_counts_by_network": blocked_blocker_type_counts_by_network(blocked_field_groups),
            "blocked_blocker_types_by_network": blocked_blocker_types_by_network(blocked_field_groups),
            "ready_blocker_type_counts_by_network": ready_blocker_type_counts_by_network(blocked_field_groups),
            "ready_blocker_types_by_network": ready_blocker_types_by_network(blocked_field_groups),
            "blocked_network_counts_by_blocker_type": blocked_network_counts_by_blocker_type(blocked_field_groups),
            "blocked_networks_by_blocker_type": blocked_networks_by_blocker_type(blocked_field_groups),
            "ready_network_counts_by_blocker_type": ready_network_counts_by_blocker_type(blocked_field_groups),
            "ready_networks_by_blocker_type": ready_networks_by_blocker_type(blocked_field_groups),
            "readiness_gates": list(READINESS_GATES),
            "readiness_gate_count": len(READINESS_GATES),
            "readiness_gate_by_blocker": readiness_gate_by_blocker(),
            "readiness_gate_by_blocker_type": readiness_gate_by_blocker_type(),
            "readiness_gate_by_network_and_blocker_type": readiness_gate_by_network_and_blocker_type(),
            "blocker_types_by_readiness_gate": blocker_types_by_readiness_gate(),
            "blocker_type_counts_by_readiness_gate": blocker_type_counts_by_readiness_gate(),
            "unresolved_blocker_count": len(blockers),
            "unresolved_blockers": blockers,
            "unresolved_blockers_by_network": items_by_network(blockers),
            "unresolved_blocker_counts_by_network": item_counts_by_network(blockers),
            "unresolved_blockers_by_blocker_type": blockers_by_blocker_type(blockers),
            "unresolved_blocker_counts_by_blocker_type": blocker_counts_by_blocker_type(blockers),
            "unresolved_blockers_by_network_and_blocker_type": blockers_by_network_and_blocker_type(blockers),
            "unresolved_blocker_counts_by_network_and_blocker_type": blocker_counts_by_network_and_blocker_type(blockers),
            "unresolved_blockers_by_readiness_gate": blockers_by_readiness_gate(blockers),
            "unresolved_blocker_counts_by_readiness_gate": blocker_counts_by_readiness_gate(blockers),
            "blocked_fields": check.blockers,
            "blocked_field_count": len(check.blockers),
            "blocked_fields_by_network": items_by_network(check.blockers),
            "blocked_field_counts_by_network": item_counts_by_network(check.blockers),
            "blocked_fields_by_blocker_type": blocked_fields_by_blocker_type(blocked_field_groups),
            "blocked_field_counts_by_blocker_type": blocked_field_counts_by_blocker_type(blocked_field_groups),
            "blocked_fields_by_network_and_blocker_type": blocked_fields_by_network_and_blocker_type(blocked_field_groups),
            "blocked_field_counts_by_network_and_blocker_type": blocked_field_counts_by_network_and_blocker_type(blocked_field_groups),
            "blocked_fields_by_readiness_gate": blocked_fields_by_readiness_gate(blocked_field_groups),
            "blocked_field_counts_by_readiness_gate": blocked_field_counts_by_readiness_gate(blocked_field_groups),
            "action_plan_command": action_plan_command(manifest_path),
            "readiness_summary_command": readiness_summary_command(manifest_path),
            "status_json_command": status_json_command(manifest_path),
            "value_selection_checklists_command": value_selection_checklists_command(
                manifest_path,
            ),
            "snapshot_audit_handoffs_command": snapshot_audit_handoffs_command(
                manifest_path,
            ),
            "launch_gate_preflight_command": launch_gate_preflight_command(
                manifest_path,
            ),
            "operator_runbook_command": operator_runbook_command(manifest_path),
            "release_evidence_bundle_command": release_evidence_bundle_command(
                manifest_path,
            ),
            "release_evidence_bundle_json_command": release_evidence_bundle_json_command(
                manifest_path,
            ),
            "check_release_evidence_bundle_command": (
                check_release_evidence_bundle_command(manifest_path)
            ),
            "check_release_evidence_bundle_json_command": (
                check_release_evidence_bundle_command(manifest_path, json_output=True)
            ),
            "release_evidence_bundle_gate_command": (
                release_evidence_bundle_gate_command(manifest_path)
            ),
            "release_evidence_bundle_gate_json_command": (
                release_evidence_bundle_gate_command(manifest_path, json_output=True)
            ),
            "release_evidence_archive_checklist_command": (
                release_evidence_archive_checklist_command(manifest_path)
            ),
            "release_evidence_archive_checklist_json_command": (
                release_evidence_archive_checklist_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "check_release_evidence_archive_command": (
                check_release_evidence_archive_command(manifest_path)
            ),
            "check_release_evidence_archive_json_command": (
                check_release_evidence_archive_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_archive_gate_command": (
                release_evidence_archive_gate_command(manifest_path)
            ),
            "release_evidence_archive_gate_json_command": (
                release_evidence_archive_gate_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_handoff_summary_command": (
                release_evidence_handoff_summary_command(manifest_path)
            ),
            "release_evidence_handoff_summary_json_command": (
                release_evidence_handoff_summary_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_index_template_command": (
                release_evidence_publication_index_template_command(manifest_path)
            ),
            "release_evidence_publication_index_template_json_command": (
                release_evidence_publication_index_template_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "check_release_evidence_publication_index_command": (
                check_release_evidence_publication_index_command(manifest_path)
            ),
            "check_release_evidence_publication_index_json_command": (
                check_release_evidence_publication_index_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_index_gate_command": (
                release_evidence_publication_index_gate_command(manifest_path)
            ),
            "release_evidence_publication_index_gate_json_command": (
                release_evidence_publication_index_gate_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_index_archive_checklist_command": (
                release_evidence_publication_index_archive_checklist_command(
                    manifest_path,
                )
            ),
            "release_evidence_publication_index_archive_checklist_json_command": (
                release_evidence_publication_index_archive_checklist_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "check_release_evidence_publication_index_archive_command": (
                check_release_evidence_publication_index_archive_command(
                    manifest_path
                )
            ),
            "check_release_evidence_publication_index_archive_json_command": (
                check_release_evidence_publication_index_archive_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_index_archive_gate_command": (
                release_evidence_publication_index_archive_gate_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_index_archive_gate_json_command": (
                release_evidence_publication_index_archive_gate_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_index_archive_handoff_summary_command": (
                release_evidence_publication_index_archive_handoff_summary_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_index_archive_handoff_summary_json_command": (
                release_evidence_publication_index_archive_handoff_summary_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_closeout_checklist_command": (
                release_evidence_publication_closeout_checklist_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_closeout_checklist_json_command": (
                release_evidence_publication_closeout_checklist_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "check_release_evidence_publication_closeout_command": (
                check_release_evidence_publication_closeout_command(
                    manifest_path
                )
            ),
            "check_release_evidence_publication_closeout_json_command": (
                check_release_evidence_publication_closeout_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_closeout_gate_command": (
                release_evidence_publication_closeout_gate_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_closeout_gate_json_command": (
                release_evidence_publication_closeout_gate_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "check_release_evidence_publication_closeout_archive_command": (
                check_release_evidence_publication_closeout_archive_command(
                    manifest_path
                )
            ),
            "check_release_evidence_publication_closeout_archive_json_command": (
                check_release_evidence_publication_closeout_archive_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_closeout_archive_gate_command": (
                release_evidence_publication_closeout_archive_gate_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_closeout_archive_gate_json_command": (
                release_evidence_publication_closeout_archive_gate_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_closeout_archive_handoff_summary_command": (
                release_evidence_publication_closeout_archive_handoff_summary_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_closeout_archive_handoff_summary_json_command": (
                release_evidence_publication_closeout_archive_handoff_summary_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_status_command": (
                release_evidence_publication_status_command(manifest_path)
            ),
            "release_evidence_publication_status_json_command": (
                release_evidence_publication_status_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "release_evidence_publication_artifact_status_command": (
                release_evidence_publication_artifact_status_command(
                    manifest_path
                )
            ),
            "release_evidence_publication_artifact_status_json_command": (
                release_evidence_publication_artifact_status_command(
                    manifest_path,
                    json_output=True,
                )
            ),
            "command_field_order": list(COMMAND_FIELDS),
            "command_field_count": len(COMMAND_FIELDS),
            "commands": commands,
            "command_keys": command_keys,
            "command_key_count": len(command_keys),
            "command_values": command_values,
            "command_value_count": len(command_values),
            "command_pairs": command_pairs,
            "command_pair_count": len(command_pairs),
            "command_count": len(commands),
            "snapshot_audit_handoff_commands_by_network": snapshot_audit_handoff_commands_by_network,
            "snapshot_audit_handoff_command_count": len(snapshot_audit_handoff_commands_by_network),
            "network_readiness_summary_commands_by_network": network_readiness_commands,
            "network_readiness_summary_command_count": len(network_readiness_commands),
            "network_handoff_bundle_commands_by_network": network_handoff_commands,
            "network_handoff_bundle_command_count": len(network_handoff_commands),
            "network_later_blockers_commands_by_network": network_later_commands,
            "network_later_blockers_command_count": len(network_later_commands),
            "network_value_selection_later_blockers_commands_by_network": network_value_selection_later_commands,
            "network_value_selection_later_blockers_command_count": len(network_value_selection_later_commands),
            "network_value_selection_candidate_template_commands_by_network": (
                network_value_selection_candidate_template_commands_by_network
            ),
            "network_value_selection_candidate_template_command_count": len(
                network_value_selection_candidate_template_commands_by_network
            ),
            "network_value_selection_candidate_template_json_commands_by_network": (
                network_value_selection_candidate_template_json_commands_by_network
            ),
            "network_value_selection_candidate_template_json_command_count": len(
                network_value_selection_candidate_template_json_commands_by_network
            ),
            "network_value_selection_candidate_check_commands_by_network": (
                network_value_selection_candidate_check_commands_by_network
            ),
            "network_value_selection_candidate_check_command_count": len(
                network_value_selection_candidate_check_commands_by_network
            ),
            "network_value_selection_candidate_check_json_commands_by_network": (
                network_value_selection_candidate_check_json_commands_by_network
            ),
            "network_value_selection_candidate_check_json_command_count": len(
                network_value_selection_candidate_check_json_commands_by_network
            ),
            "value_selection_candidate_artifact_status_command": (
                value_selection_candidate_artifact_status
            ),
            "value_selection_candidate_artifact_status_json_command": (
                value_selection_candidate_artifact_status_json
            ),
            "queued_value_selection_json_check_commands_by_network": {
                network: state["json_check_commands"]
                for network, state in value_selection_states.items()
            },
            "queued_value_selection_json_check_command_counts_by_network": {
                network: state["json_check_command_count"]
                for network, state in value_selection_states.items()
            },
            "queued_value_selection_candidate_checklists_by_network": {
                network: state["candidate_checklist"]
                for network, state in value_selection_states.items()
            },
            "queued_value_selection_candidate_checklist_summaries_by_network": {
                network: state["candidate_checklist_summary"]
                for network, state in value_selection_states.items()
            },
            "blocker_type_readiness_summary_commands_by_blocker_type": blocker_type_readiness_commands,
            "blocker_type_readiness_summary_command_count": len(blocker_type_readiness_commands),
            "blocker_type_later_blockers_commands_by_blocker_type": blocker_type_later_blockers_commands_by_type,
            "blocker_type_later_blockers_command_count": len(blocker_type_later_blockers_commands_by_type),
            "readiness_gate_summary_commands_by_readiness_gate": readiness_gate_summary_commands_by_gate,
            "readiness_gate_summary_command_count": len(readiness_gate_summary_commands_by_gate),
            "readiness_gate_later_blockers_commands_by_readiness_gate": readiness_gate_later_blockers_commands_by_gate,
            "readiness_gate_later_blockers_command_count": len(readiness_gate_later_blockers_commands_by_gate),
            "blocker_readiness_summary_commands_by_blocker": blocker_readiness_commands,
            "blocker_readiness_summary_command_count": len(blocker_readiness_commands),
            "next_action_command": next_action_command(manifest_path),
            "next_commands_by_network": network_next_commands,
            "next_blocker_commands_by_network": network_next_commands,
            "next_snapshot_audit_handoff_commands_by_network": next_snapshot_audit_handoff_commands_by_network,
            "next_snapshot_audit_handoff_command_counts_by_network": next_snapshot_audit_handoff_command_counts_by_network,
            "next_blocked_field_groups_by_network": network_next_blocked_field_groups(network_progress),
            "next_blocker_field_groups_by_network": network_next_blocked_field_groups(network_progress),
            "next_blocked_fields_by_network": network_next_blocked_fields(network_progress),
            "next_blocked_field_counts_by_network": network_next_blocked_field_counts(network_progress),
            "next_blocker_fields_by_network": network_next_blocked_fields(network_progress),
            "next_blocker_field_counts_by_network": network_next_blocked_field_counts(network_progress),
            "next_blocked_field_groups_by_network_and_blocker_type": next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups),
            "next_blocker_field_groups_by_network_and_blocker_type": next_blocked_field_groups_by_network_and_blocker_type(blocked_field_groups),
            "next_blocked_field_groups_by_readiness_gate": next_blocked_field_groups_by_readiness_gate(blocked_field_groups),
            "next_blocker_field_groups_by_readiness_gate": next_blocked_field_groups_by_readiness_gate(blocked_field_groups),
            "next_blocked_fields_by_network_and_blocker_type": next_blocked_fields_by_network_and_blocker_type(blocked_field_groups),
            "next_blocked_field_counts_by_network_and_blocker_type": next_blocked_field_counts_by_network_and_blocker_type(blocked_field_groups),
            "next_blocker_fields_by_network_and_blocker_type": next_blocked_fields_by_network_and_blocker_type(blocked_field_groups),
            "next_blocker_field_counts_by_network_and_blocker_type": next_blocked_field_counts_by_network_and_blocker_type(blocked_field_groups),
            "next_blocked_fields_by_readiness_gate": next_blocked_fields_by_readiness_gate(blocked_field_groups),
            "next_blocked_field_counts_by_readiness_gate": next_blocked_field_counts_by_readiness_gate(blocked_field_groups),
            "next_blocker_fields_by_readiness_gate": next_blocked_fields_by_readiness_gate(blocked_field_groups),
            "next_blocker_field_counts_by_readiness_gate": next_blocked_field_counts_by_readiness_gate(blocked_field_groups),
            "next_blockers_by_network_and_blocker_type": next_blockers_by_network_and_blocker_type(blocked_field_groups),
            "next_blockers_by_network": network_next_blockers(network_progress),
            "next_blocker_types_by_network": network_next_blocker_types(network_progress),
            "next_blockers_by_readiness_gate": next_blockers_by_readiness_gate(blocked_field_groups),
            "next_blocker_networks_by_readiness_gate": next_blocker_networks_by_readiness_gate(blocked_field_groups),
            "next_blocker_types_by_readiness_gate": next_blocker_types_by_readiness_gate(blocked_field_groups),
            "next_blocked_field_groups_by_blocker_type": next_blocked_field_groups_by_blocker_type(blocked_field_groups),
            "next_blocker_field_groups_by_blocker_type": next_blocked_field_groups_by_blocker_type(blocked_field_groups),
            "next_blocked_fields_by_blocker_type": blocker_type_next_blocked_fields(blocker_type_progress),
            "next_blocked_field_counts_by_blocker_type": blocker_type_next_blocked_field_counts(blocker_type_progress),
            "next_blocker_fields_by_blocker_type": blocker_type_next_blocked_fields(blocker_type_progress),
            "next_blocker_field_counts_by_blocker_type": blocker_type_next_blocked_field_counts(blocker_type_progress),
            "next_blockers_by_blocker_type": blocker_type_next_blockers(blocker_type_progress),
            "next_blocker_networks_by_blocker_type": blocker_type_next_blocker_networks(blocker_type_progress),
            "network_progress": network_progress,
            "blocker_type_progress": blocker_type_progress,
            "readiness_gate_progress": readiness_gate_progress,
            "blocked_field_groups": blocked_field_groups,
            "blocked_field_group_count": len(blocked_field_groups),
            "blocked_field_groups_by_blocker": blocked_field_groups_by_blocker(blocked_field_groups),
            "blocked_field_group_counts_by_blocker": blocked_field_group_counts_by_blocker(blocked_field_groups),
            "blocked_field_groups_by_network": blocked_field_groups_by_network(blocked_field_groups),
            "blocked_field_group_counts_by_network": blocked_field_group_counts_by_network(blocked_field_groups),
            "blocked_field_groups_by_blocker_type": blocked_field_groups_by_blocker_type(blocked_field_groups),
            "blocked_field_group_counts_by_blocker_type": blocked_field_group_counts_by_blocker_type(blocked_field_groups),
            "blocked_field_groups_by_network_and_blocker_type": blocked_field_groups_by_network_and_blocker_type(blocked_field_groups),
            "blocked_field_group_counts_by_network_and_blocker_type": blocked_field_group_counts_by_network_and_blocker_type(blocked_field_groups),
            "blocked_field_groups_by_readiness_gate": blocked_field_groups_by_readiness_gate(blocked_field_groups),
            "blocked_field_group_counts_by_readiness_gate": blocked_field_group_counts_by_readiness_gate(blocked_field_groups),
            "next_blocked_field_group": next_blocked_field_group,
            "next_blocker_field_group": next_blocked_field_group,
            "next_blocker_field_groups_by_blocker": next_blocker_field_groups_by_blocker,
            "next_blocker_field_group_counts_by_blocker": next_blocker_field_group_counts_by_blocker,
            "next_blocker": next_blocker,
            "next_blocker_network": next_blocker_network,
            "next_blocker_type": next_blocker_type,
            "next_blocker_step": next_blocker_step,
            "next_blocker_network_step": next_blocker_network_step,
            "next_blocker_network_step_count": next_blocker_network_step_count,
            "next_blocker_type_step": next_blocker_type_step,
            "next_blocker_type_step_count": next_blocker_type_step_count,
            "next_blocker_commands": next_blocker_commands,
            "next_blocker_command_count": next_blocker_command_count,
            "next_blocker_commands_by_blocker": next_blocker_commands_by_blocker,
            "next_blocker_command_counts_by_blocker": next_blocker_command_counts_by_blocker,
            "next_blocker_command_keys": next_blocker_command_keys,
            "next_blocker_command_key_count": len(next_blocker_command_keys),
            "next_blocker_command_values": next_blocker_command_values,
            "next_blocker_command_value_count": len(next_blocker_command_values),
            "next_blocker_command_pairs": next_blocker_command_pairs,
            "next_blocker_command_pair_count": len(next_blocker_command_pairs),
            "next_blocker_fields": next_blocked_fields,
            "next_blocker_field_count": len(next_blocked_fields),
            "next_blocker_fields_by_blocker": next_blocker_fields_by_blocker,
            "next_blocker_field_counts_by_blocker": next_blocker_field_counts_by_blocker,
            "later_blockers": later_blockers,
            "later_blocker_count": len(later_blockers),
            "later_blocker_steps": later_blocker_steps,
            "later_blocker_network_steps": later_blocker_network_steps,
            "later_blocker_network_step_counts": later_blocker_network_step_counts,
            "later_blocker_type_steps": later_blocker_type_steps,
            "later_blocker_type_step_counts": later_blocker_type_step_counts,
            "later_blockers_by_network": later_blockers_by_network,
            "later_blocker_counts_by_network": later_blocker_counts_by_network,
            "later_blockers_by_blocker_type": later_blockers_by_blocker_type,
            "later_blocker_counts_by_blocker_type": later_blocker_counts_by_blocker_type,
            "later_blockers_by_network_and_blocker_type": later_blockers_by_network_and_blocker_type,
            "later_blocker_counts_by_network_and_blocker_type": later_blocker_counts_by_network_and_blocker_type,
            "later_blockers_by_readiness_gate": later_blockers_by_gate,
            "later_blocker_counts_by_readiness_gate": later_blocker_counts_by_gate,
            "later_blocker_networks": later_blocker_networks,
            "later_blocker_types": later_blocker_types,
            "later_blocker_commands": later_blocker_commands,
            "later_blocker_command_count": len(later_blocker_commands),
            "later_blocker_commands_by_blocker": later_blocker_commands_by_blocker,
            "later_blocker_command_counts_by_blocker": later_blocker_command_counts_by_blocker,
            "later_blocker_command_keys": later_blocker_command_keys,
            "later_blocker_command_key_counts": [len(command_keys) for command_keys in later_blocker_command_keys],
            "later_blocker_command_values": later_blocker_command_values,
            "later_blocker_command_value_counts": [len(command_values) for command_values in later_blocker_command_values],
            "later_blocker_command_pairs": later_blocker_command_pairs,
            "later_blocker_command_pair_counts": [len(command_pairs) for command_pairs in later_blocker_command_pairs],
            "later_blocker_readiness_summary_commands_by_blocker": later_blocker_readiness_commands,
            "later_blocker_readiness_summary_command_count": len(later_blocker_readiness_commands),
            "later_blocker_readiness_summary_commands_by_readiness_gate": later_blocker_readiness_commands_by_gate,
            "later_blocker_readiness_summary_command_counts_by_readiness_gate": later_blocker_readiness_command_counts_by_gate,
            "later_blocker_field_groups": later_blocker_field_groups,
            "later_blocker_field_group_count": len(later_blocker_field_groups),
            "later_blocker_field_groups_by_blocker": later_blocker_field_groups_by_blocker,
            "later_blocker_field_group_counts_by_blocker": later_blocker_field_group_counts_by_blocker,
            "later_blocker_field_groups_by_network": later_blocker_field_groups_by_network,
            "later_blocker_field_group_counts_by_network": later_blocker_field_group_counts_by_network,
            "later_blocker_field_groups_by_blocker_type": later_blocker_field_groups_by_blocker_type,
            "later_blocker_field_group_counts_by_blocker_type": later_blocker_field_group_counts_by_blocker_type,
            "later_blocker_field_groups_by_network_and_blocker_type": later_blocker_field_groups_by_network_and_blocker_type,
            "later_blocker_field_group_counts_by_network_and_blocker_type": later_blocker_field_group_counts_by_network_and_blocker_type,
            "later_blocker_field_groups_by_readiness_gate": later_blocker_field_groups_by_gate,
            "later_blocker_field_group_counts_by_readiness_gate": later_blocker_field_group_counts_by_gate,
            "later_blocker_field_counts": later_blocker_field_counts,
            "later_blocker_fields_by_blocker": later_blocker_fields_by_blocker,
            "later_blocker_field_counts_by_blocker": later_blocker_field_counts_by_blocker,
            "later_blocker_fields_by_blocker_type": later_blocker_fields_by_blocker_type,
            "later_blocker_field_counts_by_blocker_type": later_blocker_field_counts_by_blocker_type,
            "later_blocker_fields_by_network_and_blocker_type": later_blocker_fields_by_network_and_blocker_type,
            "later_blocker_field_counts_by_network_and_blocker_type": later_blocker_field_counts_by_network_and_blocker_type,
            "later_blocker_fields_by_readiness_gate": later_blocker_fields_by_gate,
            "later_blocker_field_counts_by_readiness_gate": later_blocker_field_counts_by_gate,
            "later_blocker_fields_by_network": later_blocker_fields_by_network,
            "later_blocker_field_counts_by_network": later_blocker_field_counts_by_network,
            "later_blocker_fields": later_blocker_fields,
            "later_blocker_field_count": len(later_blocker_fields),
            "next_blocked_fields": next_blocked_fields,
            "next_blocked_field_count": len(next_blocked_fields),
            "action_count": len(actions),
            "action_ids": [action["id"] for action in actions],
            "action_kinds": [action["kind"] for action in actions],
            "action_steps": [action["step"] for action in actions],
            "action_networks": [action.get("network") for action in actions],
            "action_blocker_types": [action.get("blocker_type") for action in actions],
            "action_field_counts": [action.get("field_count") for action in actions],
            "action_commands": action_commands,
            "action_command_count": len(action_commands),
            "action_command_keys": [action_command_keys(action) for action in actions],
            "action_command_key_counts": [len(action_command_keys(action)) for action in actions],
            "action_command_values": [action_command_values(action) for action in actions],
            "action_command_value_counts": [len(action_command_values(action)) for action in actions],
            "action_command_pairs": [action_command_pairs(action) for action in actions],
            "action_command_pair_counts": [len(action_command_pairs(action)) for action in actions],
            "later_actions": later_actions,
            "later_action_count": len(later_actions),
            "later_action_ids": [action["id"] for action in later_actions],
            "later_action_kinds": [action["kind"] for action in later_actions],
            "later_action_steps": [action["step"] for action in later_actions],
            "later_action_networks": [action.get("network") for action in later_actions],
            "later_action_blocker_types": [action.get("blocker_type") for action in later_actions],
            "later_action_field_counts": [action.get("field_count") for action in later_actions],
            "later_commands": later_commands,
            "later_command_count": len(later_commands),
            "later_command_keys": [action_command_keys(action) for action in later_actions],
            "later_command_key_counts": [len(action_command_keys(action)) for action in later_actions],
            "later_command_values": [action_command_values(action) for action in later_actions],
            "later_command_value_counts": [len(action_command_values(action)) for action in later_actions],
            "later_command_pairs": [action_command_pairs(action) for action in later_actions],
            "later_command_pair_counts": [len(action_command_pairs(action)) for action in later_actions],
            "actions_by_network": actions_by_network(actions),
            "action_counts_by_network": action_counts_by_network(actions),
            "actions_by_blocker_type": actions_by_blocker_type(actions),
            "action_counts_by_blocker_type": action_counts_by_blocker_type(actions),
            "actions_by_readiness_gate": actions_by_readiness_gate(actions),
            "action_counts_by_readiness_gate": action_counts_by_readiness_gate(actions),
            "actions_by_network_and_blocker_type": actions_by_network_and_blocker_type(actions),
            "action_counts_by_network_and_blocker_type": action_counts_by_network_and_blocker_type(actions),
            "candidate_constraints_by_blocker": candidate_constraints_by_blocker(),
            "candidate_constraint_counts_by_blocker": candidate_constraint_counts_by_blocker(),
            "candidate_constraints_by_blocker_type": candidate_constraints_by_blocker_type(),
            "candidate_constraint_counts_by_blocker_type": candidate_constraint_counts_by_blocker_type(),
            "candidate_constraints_by_network_and_blocker_type": candidate_constraints_by_network_and_blocker_type(),
            "candidate_constraint_counts_by_network_and_blocker_type": candidate_constraint_counts_by_network_and_blocker_type(),
            "external_artifacts_by_blocker": external_artifacts_by_blocker(),
            "external_artifact_counts_by_blocker": external_artifact_counts_by_blocker(),
            "external_artifacts_by_blocker_type": external_artifacts_by_blocker_type(),
            "external_artifact_counts_by_blocker_type": external_artifact_counts_by_blocker_type(),
            "external_artifacts_by_network_and_blocker_type": external_artifacts_by_network_and_blocker_type(),
            "external_artifact_counts_by_network_and_blocker_type": external_artifact_counts_by_network_and_blocker_type(),
            "snapshot_audit_external_artifacts_by_network": snapshot_audit_external_artifacts_by_network(),
            "snapshot_audit_external_artifact_counts_by_network": snapshot_audit_external_artifact_counts_by_network(),
            "snapshot_audit_handoff_readiness_by_network": snapshot_audit_handoff_readiness_by_network_map,
            "snapshot_audit_handoff_checklist_by_network": snapshot_audit_handoff_checklist_by_network_map,
            "snapshot_audit_handoff_checklist_summary_by_network": snapshot_audit_handoff_checklist_summary_by_network_map,
            "next_actions_by_network_and_blocker_type": next_actions_by_network_and_blocker_type(actions),
            "next_commands_by_network_and_blocker_type": network_blocker_type_next_commands,
            "next_blocker_commands_by_network_and_blocker_type": network_blocker_type_next_commands,
            "next_actions_by_blocker_type": next_actions_by_blocker_type(actions),
            "next_commands_by_blocker_type": blocker_type_next_commands,
            "next_blocker_commands_by_blocker_type": blocker_type_next_commands,
            "next_snapshot_audit_handoff_commands_by_blocker_type": next_snapshot_audit_handoff_commands_by_blocker_type,
            "next_snapshot_audit_handoff_command_counts_by_blocker_type": next_snapshot_audit_handoff_command_counts_by_blocker_type,
            "next_actions_by_readiness_gate": next_actions_by_readiness_gate(actions),
            "next_commands_by_readiness_gate": readiness_gate_next_commands,
            "next_blocker_commands_by_readiness_gate": readiness_gate_next_commands,
            "next_snapshot_audit_handoff_commands_by_readiness_gate": next_snapshot_audit_handoff_commands_by_readiness_gate,
            "next_snapshot_audit_handoff_command_counts_by_readiness_gate": next_snapshot_audit_handoff_command_counts_by_readiness_gate,
            "next": next_action,
            "next_action": next_action,
            "next_action_id": next_action_id,
            "next_action_kind": next_action_kind,
            "next_action_step": next_action_step,
            "next_action_network": next_action_network,
            "next_action_blocker_type": next_action_blocker_type,
            "next_action_field_count": next_action_field_count,
            "next_commands": action_command_fields(next_action),
            "next_command_keys": action_command_keys(next_action),
            "next_command_key_count": len(action_command_keys(next_action)),
            "next_command_values": action_command_values(next_action),
            "next_command_value_count": len(action_command_values(next_action)),
            "next_command_pairs": action_command_pairs(next_action),
            "next_command_pair_count": len(action_command_pairs(next_action)),
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
    if args.snapshot_audit_preflight is not None:
        actions.append("--snapshot-audit-preflight")
    if args.check_snapshot_audit is not None:
        actions.append("--check-snapshot-audit")
    if args.snapshot_audit_handoff is not None:
        actions.append("--snapshot-audit-handoff")
    if args.snapshot_audit_handoffs:
        actions.append("--snapshot-audit-handoffs")
    if args.launch_gate_preflight:
        actions.append("--launch-gate-preflight")
    if args.operator_runbook:
        actions.append("--operator-runbook")
    if args.release_evidence_bundle:
        actions.append("--release-evidence-bundle")
    if args.check_release_evidence_bundle is not None:
        actions.append("--check-release-evidence-bundle")
    if args.check_release_evidence_archive is not None:
        actions.append("--check-release-evidence-archive")
    if args.release_evidence_archive_checklist is not None:
        actions.append("--release-evidence-archive-checklist")
    if args.release_evidence_handoff_summary is not None:
        actions.append("--release-evidence-handoff-summary")
    if args.release_evidence_publication_index_template is not None:
        actions.append("--release-evidence-publication-index-template")
    if args.check_release_evidence_publication_index is not None:
        actions.append("--check-release-evidence-publication-index")
    if args.release_evidence_publication_index_archive_checklist is not None:
        actions.append("--release-evidence-publication-index-archive-checklist")
    if args.check_release_evidence_publication_index_archive is not None:
        actions.append("--check-release-evidence-publication-index-archive")
    if args.release_evidence_publication_index_archive_handoff_summary is not None:
        actions.append(
            "--release-evidence-publication-index-archive-handoff-summary"
        )
    if args.release_evidence_publication_closeout_checklist is not None:
        actions.append("--release-evidence-publication-closeout-checklist")
    if args.check_release_evidence_publication_closeout is not None:
        actions.append("--check-release-evidence-publication-closeout")
    if args.check_release_evidence_publication_closeout_archive is not None:
        actions.append("--check-release-evidence-publication-closeout-archive")
    if (
        args.release_evidence_publication_closeout_archive_handoff_summary
        is not None
    ):
        actions.append(
            "--release-evidence-publication-closeout-archive-handoff-summary"
        )
    if args.release_evidence_publication_status:
        actions.append("--release-evidence-publication-status")
    if args.release_evidence_publication_artifact_status:
        actions.append("--release-evidence-publication-artifact-status")
    if args.snapshot_audit_template_diff is not None:
        actions.append("--snapshot-audit-template-diff")
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
    if args.readiness_summary:
        actions.append("--readiness-summary")
    if args.network_readiness_summary is not None:
        actions.append("--network-readiness-summary")
    if args.network_handoff_bundle is not None:
        actions.append("--network-handoff-bundle")
    if args.network_later_blockers is not None:
        actions.append("--network-later-blockers")
    if args.blocker_type_readiness_summary is not None:
        actions.append("--blocker-type-readiness-summary")
    if args.blocker_type_later_blockers is not None:
        actions.append("--blocker-type-later-blockers")
    if args.readiness_gate_summary is not None:
        actions.append("--readiness-gate-summary")
    if args.readiness_gate_later_blockers is not None:
        actions.append("--readiness-gate-later-blockers")
    if args.network_value_selection_later_blockers is not None:
        actions.append("--network-value-selection-later-blockers")
    if args.network_value_selection_candidate_template is not None:
        actions.append("--network-value-selection-candidate-template")
    if args.check_network_value_selection_candidate is not None:
        actions.append("--check-network-value-selection-candidate")
    if args.value_selection_candidate_artifact_status:
        actions.append("--value-selection-candidate-artifact-status")
    if args.value_selection_checklists:
        actions.append("--value-selection-checklists")
    if args.blocker_readiness_summary is not None:
        actions.append("--blocker-readiness-summary")
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
    parser.add_argument("--readiness-summary", action="store_true", help="print a compact human-readable public launch-profile readiness summary")
    parser.add_argument("--launch-gate-preflight", action="store_true", help="print compact launch-gate preflight handoffs for external artifacts and value selection")
    parser.add_argument("--operator-runbook", action="store_true", help="print ordered public launch-profile operator runbook commands")
    parser.add_argument("--release-evidence-bundle", action="store_true", help="print bundled launch-profile release evidence payloads")
    parser.add_argument(
        "--check-release-evidence-bundle",
        metavar="BUNDLE_JSON",
        type=Path,
        help="verify an archived release evidence bundle against the current launch manifest",
    )
    parser.add_argument(
        "--require-release-evidence-bundle-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-bundle detects mismatches",
    )
    parser.add_argument(
        "--release-evidence-archive-checklist",
        metavar="BUNDLE_JSON",
        type=Path,
        help="print the release evidence bundle archive checklist for one bundle artifact",
    )
    parser.add_argument(
        "--check-release-evidence-archive",
        nargs=2,
        metavar=("ARCHIVE_JSON", "BUNDLE_JSON"),
        type=Path,
        help="verify a filled release evidence archive record against one bundle artifact",
    )
    parser.add_argument(
        "--require-release-evidence-archive-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-archive detects mismatches",
    )
    parser.add_argument(
        "--release-evidence-handoff-summary",
        nargs=2,
        metavar=("ARCHIVE_JSON", "BUNDLE_JSON"),
        type=Path,
        help="summarize release evidence bundle and archive gate readiness for one handoff",
    )
    parser.add_argument(
        "--release-evidence-publication-index-template",
        nargs=2,
        metavar=("ARCHIVE_JSON", "BUNDLE_JSON"),
        type=Path,
        help="print the release evidence publication index JSON template for one handoff",
    )
    parser.add_argument(
        "--check-release-evidence-publication-index",
        nargs=3,
        metavar=("INDEX_JSON", "ARCHIVE_JSON", "BUNDLE_JSON"),
        type=Path,
        help="verify a filled release evidence publication index against one handoff",
    )
    parser.add_argument(
        "--require-release-evidence-publication-index-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-publication-index detects mismatches",
    )
    parser.add_argument(
        "--release-evidence-publication-index-archive-checklist",
        nargs=3,
        metavar=("INDEX_JSON", "ARCHIVE_JSON", "BUNDLE_JSON"),
        type=Path,
        help="print the publication index archive checklist for one filled publication index",
    )
    parser.add_argument(
        "--check-release-evidence-publication-index-archive",
        nargs=4,
        metavar=(
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="verify a filled publication index archive record",
    )
    parser.add_argument(
        "--require-release-evidence-publication-index-archive-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-publication-index-archive detects mismatches",
    )
    parser.add_argument(
        "--release-evidence-publication-index-archive-handoff-summary",
        nargs=4,
        metavar=(
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="summarize publication index and archive gate readiness for one handoff",
    )
    parser.add_argument(
        "--release-evidence-publication-closeout-checklist",
        nargs=4,
        metavar=(
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="summarize the final release evidence publication closeout checklist",
    )
    parser.add_argument(
        "--check-release-evidence-publication-closeout",
        nargs=5,
        metavar=(
            "CLOSEOUT_JSON",
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="verify a generated release evidence publication closeout JSON",
    )
    parser.add_argument(
        "--require-release-evidence-publication-closeout-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-publication-closeout detects mismatches",
    )
    parser.add_argument(
        "--check-release-evidence-publication-closeout-archive",
        nargs=6,
        metavar=(
            "CLOSEOUT_ARCHIVE_JSON",
            "CLOSEOUT_JSON",
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="verify a filled release evidence publication closeout archive record",
    )
    parser.add_argument(
        "--require-release-evidence-publication-closeout-archive-match",
        action="store_true",
        help="return a non-zero exit code when --check-release-evidence-publication-closeout-archive detects mismatches",
    )
    parser.add_argument(
        "--release-evidence-publication-closeout-archive-handoff-summary",
        nargs=6,
        metavar=(
            "CLOSEOUT_ARCHIVE_JSON",
            "CLOSEOUT_JSON",
            "PUBLICATION_INDEX_ARCHIVE_JSON",
            "INDEX_JSON",
            "ARCHIVE_JSON",
            "BUNDLE_JSON",
        ),
        type=Path,
        help="summarize retained publication closeout and closeout archive readiness",
    )
    parser.add_argument(
        "--release-evidence-publication-status",
        action="store_true",
        help="print the ordered release evidence publication command pipeline",
    )
    parser.add_argument(
        "--release-evidence-publication-artifact-status",
        action="store_true",
        help="print supplied/missing release evidence publication artifacts",
    )
    parser.add_argument(
        "--release-evidence-bundle-path",
        type=Path,
        help="release evidence bundle JSON for artifact status",
    )
    parser.add_argument(
        "--release-evidence-archive-record-path",
        type=Path,
        help="release evidence archive record JSON for artifact status",
    )
    parser.add_argument(
        "--release-evidence-publication-index-path",
        type=Path,
        help="release evidence publication index JSON for artifact status",
    )
    parser.add_argument(
        "--release-evidence-publication-index-archive-record-path",
        type=Path,
        help="release evidence publication index archive record JSON for artifact status",
    )
    parser.add_argument(
        "--release-evidence-publication-closeout-path",
        type=Path,
        help="release evidence publication closeout JSON for artifact status",
    )
    parser.add_argument(
        "--release-evidence-publication-closeout-archive-record-path",
        type=Path,
        help="release evidence publication closeout archive record JSON for artifact status",
    )
    parser.add_argument("--network-readiness-summary", metavar="NETWORK", help="print a compact readiness summary for one public network")
    parser.add_argument("--network-handoff-bundle", metavar="NETWORK", help="print current and queued handoff commands for one public network")
    parser.add_argument("--network-later-blockers", metavar="NETWORK", help="print the queued later blockers for one public network")
    parser.add_argument("--blocker-type-readiness-summary", metavar="BLOCKER_TYPE", help="print a compact readiness summary for one launch blocker type")
    parser.add_argument("--blocker-type-later-blockers", metavar="BLOCKER_TYPE", help="print the queued later blockers for one launch blocker type")
    parser.add_argument("--readiness-gate-summary", metavar="READINESS_GATE", help="print a compact readiness summary for one launch readiness gate")
    parser.add_argument("--readiness-gate-later-blockers", metavar="READINESS_GATE", help="print the queued later blockers for one launch readiness gate")
    parser.add_argument("--network-value-selection-later-blockers", metavar="NETWORK", help="print queued later value-selection blockers for one public network")
    parser.add_argument("--network-value-selection-candidate-template", metavar="NETWORK", help="print the value-selection candidate JSON template for one public network")
    parser.add_argument(
        "--check-network-value-selection-candidate",
        nargs=2,
        metavar=("NETWORK", "CANDIDATE_JSON"),
        help="verify a filled value-selection candidate JSON artifact without updating the manifest",
    )
    parser.add_argument(
        "--value-selection-candidate-artifact-status",
        action="store_true",
        help="print supplied/missing value-selection candidate artifact status for public networks",
    )
    parser.add_argument(
        "--main-value-selection-candidate",
        metavar="CANDIDATE_JSON",
        type=Path,
        help="mainnet value-selection candidate JSON artifact for status reporting",
    )
    parser.add_argument(
        "--testnet-value-selection-candidate",
        metavar="CANDIDATE_JSON",
        type=Path,
        help="testnet value-selection candidate JSON artifact for status reporting",
    )
    parser.add_argument("--value-selection-checklists", action="store_true", help="print queued value-selection JSON checklists for all public networks")
    parser.add_argument("--blocker-readiness-summary", metavar="BLOCKER_ID", help="print a compact readiness summary for one unresolved launch blocker")
    parser.add_argument("--status-json", action="store_true", help="print machine-readable public launch-profile status and action guidance")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON for supported read-only output")
    parser.add_argument("--emit-chainparams", action="store_true", help="emit chainparams.cpp assignment snippets from a ready manifest")
    parser.add_argument(
        "--snapshot-audit-template",
        metavar="NETWORK",
        help="print the required snapshot audit summary JSON shape for one public network",
    )
    parser.add_argument(
        "--snapshot-audit-template-diff",
        nargs=2,
        metavar=("NETWORK", "AUDIT_JSON"),
        help="compare one snapshot audit summary with the required template without verifying the artifact",
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
        "--snapshot-audit-preflight",
        nargs=2,
        metavar=("NETWORK", "AUDIT_JSON"),
        help="preflight one network's snapshot audit summary and print ready-to-apply guidance",
    )
    parser.add_argument(
        "--check-snapshot-audit",
        nargs=2,
        metavar=("NETWORK", "AUDIT_JSON"),
        help="verify a snapshot audit summary and artifact without updating the manifest",
    )
    parser.add_argument(
        "--snapshot-audit-handoff",
        metavar="NETWORK",
        help="print the snapshot audit field, artifact, and command checklist for one public network",
    )
    parser.add_argument(
        "--snapshot-audit-handoffs",
        action="store_true",
        help="print snapshot audit field, artifact, and command checklists for all public networks",
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

    if (
        args.require_release_evidence_bundle_match
        and args.check_release_evidence_bundle is None
    ):
        print(
            "error: --require-release-evidence-bundle-match requires "
            "--check-release-evidence-bundle",
            file=sys.stderr,
        )
        return 1

    if (
        args.require_release_evidence_archive_match
        and args.check_release_evidence_archive is None
    ):
        print(
            "error: --require-release-evidence-archive-match requires "
            "--check-release-evidence-archive",
            file=sys.stderr,
        )
        return 1

    if (
        args.require_release_evidence_publication_index_match
        and args.check_release_evidence_publication_index is None
    ):
        print(
            "error: --require-release-evidence-publication-index-match requires "
            "--check-release-evidence-publication-index",
            file=sys.stderr,
        )
        return 1

    if (
        args.require_release_evidence_publication_index_archive_match
        and args.check_release_evidence_publication_index_archive is None
    ):
        print(
            "error: --require-release-evidence-publication-index-archive-match "
            "requires --check-release-evidence-publication-index-archive",
            file=sys.stderr,
        )
        return 1

    if (
        args.require_release_evidence_publication_closeout_match
        and args.check_release_evidence_publication_closeout is None
    ):
        print(
            "error: --require-release-evidence-publication-closeout-match "
            "requires --check-release-evidence-publication-closeout",
            file=sys.stderr,
        )
        return 1

    if (
        args.require_release_evidence_publication_closeout_archive_match
        and args.check_release_evidence_publication_closeout_archive is None
    ):
        print(
            "error: --require-release-evidence-publication-closeout-archive-match "
            "requires --check-release-evidence-publication-closeout-archive",
            file=sys.stderr,
        )
        return 1

    if (
        (
            args.main_value_selection_candidate is not None
            or args.testnet_value_selection_candidate is not None
        )
        and not args.value_selection_candidate_artifact_status
    ):
        print(
            "error: --main-value-selection-candidate and "
            "--testnet-value-selection-candidate require "
            "--value-selection-candidate-artifact-status",
            file=sys.stderr,
        )
        return 1

    if (
        args.json
        and args.snapshot_audit_preflight is None
        and args.check_snapshot_audit is None
        and args.snapshot_audit_handoff is None
        and not args.snapshot_audit_handoffs
        and not args.launch_gate_preflight
        and not args.operator_runbook
        and not args.release_evidence_bundle
        and args.check_release_evidence_bundle is None
        and args.check_release_evidence_archive is None
        and args.release_evidence_archive_checklist is None
        and args.release_evidence_handoff_summary is None
        and args.release_evidence_publication_index_template is None
        and args.check_release_evidence_publication_index is None
        and args.release_evidence_publication_index_archive_checklist is None
        and args.check_release_evidence_publication_index_archive is None
        and args.release_evidence_publication_index_archive_handoff_summary is None
        and args.release_evidence_publication_closeout_checklist is None
        and args.check_release_evidence_publication_closeout is None
        and args.check_release_evidence_publication_closeout_archive is None
        and (
            args.release_evidence_publication_closeout_archive_handoff_summary
            is None
        )
        and not args.release_evidence_publication_status
        and not args.release_evidence_publication_artifact_status
        and args.snapshot_audit_template is None
        and args.snapshot_audit_template_diff is None
        and args.check_auxpow is None
        and args.check_dns_seeds is None
        and args.check_identity is None
        and not args.readiness_summary
        and args.network_handoff_bundle is None
        and args.blocker_readiness_summary is None
        and args.network_value_selection_later_blockers is None
        and args.network_value_selection_candidate_template is None
        and args.check_network_value_selection_candidate is None
        and not args.value_selection_candidate_artifact_status
        and args.network_readiness_summary is None
        and args.network_later_blockers is None
        and args.blocker_type_readiness_summary is None
        and args.blocker_type_later_blockers is None
        and args.readiness_gate_summary is None
        and args.readiness_gate_later_blockers is None
        and not args.value_selection_checklists
    ):
        print(
            "error: --json is only supported with --snapshot-audit-template, "
            "--snapshot-audit-template-diff, "
            "--snapshot-audit-preflight, --check-snapshot-audit, "
            "--snapshot-audit-handoff, --snapshot-audit-handoffs, "
            "--check-auxpow, --check-dns-seeds, "
            "--check-identity, "
            "--readiness-summary, --network-handoff-bundle, "
            "--blocker-readiness-summary, "
            "--network-value-selection-later-blockers, "
            "--network-value-selection-candidate-template, "
            "--check-network-value-selection-candidate, "
            "--value-selection-candidate-artifact-status, "
            "--network-readiness-summary, "
            "--network-later-blockers, "
            "--blocker-type-readiness-summary, --blocker-type-later-blockers, "
            "--readiness-gate-summary, --readiness-gate-later-blockers, "
            "--launch-gate-preflight, --operator-runbook, "
            "--release-evidence-bundle, --check-release-evidence-bundle, "
            "--check-release-evidence-archive, "
            "--release-evidence-handoff-summary, "
            "--release-evidence-publication-index-template, "
            "--check-release-evidence-publication-index, "
            "--release-evidence-publication-index-archive-checklist, "
            "--check-release-evidence-publication-index-archive, "
            "--release-evidence-publication-index-archive-handoff-summary, "
            "--release-evidence-publication-closeout-checklist, "
            "--check-release-evidence-publication-closeout, "
            "--check-release-evidence-publication-closeout-archive, "
            "--release-evidence-publication-closeout-archive-handoff-summary, "
            "--release-evidence-publication-status, "
            "--release-evidence-publication-artifact-status, "
            "--release-evidence-archive-checklist, "
            "or --value-selection-checklists",
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
            template_text = (
                snapshot_audit_template_json_text
                if args.json
                else snapshot_audit_template_text
            )
            if args.json:
                print(template_text(args.snapshot_audit_template, args.manifest))
            else:
                print(template_text(args.snapshot_audit_template))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.snapshot_audit_template_diff is not None:
        if args.in_place:
            print("error: --snapshot-audit-template-diff does not write the manifest", file=sys.stderr)
            return 1
        try:
            diff_text = (
                snapshot_audit_template_diff_json_text
                if args.json
                else snapshot_audit_template_diff_text
            )
            print(
                diff_text(
                    args.snapshot_audit_template_diff[0],
                    args.snapshot_audit_template_diff[1],
                    args.manifest,
                )
            )
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

    if args.snapshot_audit_preflight is not None:
        if args.in_place:
            print("error: --snapshot-audit-preflight does not write the manifest", file=sys.stderr)
            return 1
        try:
            audit, candidate = checked_snapshot_audit_candidate(
                manifest,
                *args.snapshot_audit_preflight,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        preflight_text = (
            snapshot_audit_preflight_json_text
            if args.json
            else snapshot_audit_preflight_text
        )
        print(
            preflight_text(
                args.snapshot_audit_preflight[0],
                audit,
                candidate,
                args.snapshot_audit_preflight[1],
                args.manifest,
            )
        )
        return 0

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
        check_text = (
            snapshot_audit_check_json_text
            if args.json
            else snapshot_audit_check_text
        )
        print(
            check_text(
                args.check_snapshot_audit[0],
                audit,
                candidate,
                args.check_snapshot_audit[1],
                args.manifest,
            )
        )
        return 0

    if args.snapshot_audit_handoff is not None:
        if args.in_place:
            print("error: --snapshot-audit-handoff does not write the manifest", file=sys.stderr)
            return 1
    if args.snapshot_audit_handoffs:
        if args.in_place:
            print("error: --snapshot-audit-handoffs does not write the manifest", file=sys.stderr)
            return 1
    if args.launch_gate_preflight:
        if args.in_place:
            print("error: --launch-gate-preflight does not write the manifest", file=sys.stderr)
            return 1
    if args.operator_runbook:
        if args.in_place:
            print("error: --operator-runbook does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_bundle:
        if args.in_place:
            print("error: --release-evidence-bundle does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_bundle is not None:
        if args.in_place:
            print("error: --check-release-evidence-bundle does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_archive is not None:
        if args.in_place:
            print("error: --check-release-evidence-archive does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_archive_checklist is not None:
        if args.in_place:
            print("error: --release-evidence-archive-checklist does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_handoff_summary is not None:
        if args.in_place:
            print("error: --release-evidence-handoff-summary does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_index_template is not None:
        if args.in_place:
            print("error: --release-evidence-publication-index-template does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_publication_index is not None:
        if args.in_place:
            print("error: --check-release-evidence-publication-index does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_index_archive_checklist is not None:
        if args.in_place:
            print("error: --release-evidence-publication-index-archive-checklist does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_publication_index_archive is not None:
        if args.in_place:
            print("error: --check-release-evidence-publication-index-archive does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_index_archive_handoff_summary is not None:
        if args.in_place:
            print("error: --release-evidence-publication-index-archive-handoff-summary does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_closeout_checklist is not None:
        if args.in_place:
            print("error: --release-evidence-publication-closeout-checklist does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_publication_closeout is not None:
        if args.in_place:
            print("error: --check-release-evidence-publication-closeout does not write the manifest", file=sys.stderr)
            return 1
    if args.check_release_evidence_publication_closeout_archive is not None:
        if args.in_place:
            print("error: --check-release-evidence-publication-closeout-archive does not write the manifest", file=sys.stderr)
            return 1
    if (
        args.release_evidence_publication_closeout_archive_handoff_summary
        is not None
    ):
        if args.in_place:
            print("error: --release-evidence-publication-closeout-archive-handoff-summary does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_status:
        if args.in_place:
            print("error: --release-evidence-publication-status does not write the manifest", file=sys.stderr)
            return 1
    if args.release_evidence_publication_artifact_status:
        if args.in_place:
            print("error: --release-evidence-publication-artifact-status does not write the manifest", file=sys.stderr)
            return 1

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
        check_text = (
            auxpow_check_json_text
            if args.json
            else auxpow_check_text
        )
        print(check_text(args.check_auxpow[0], auxpow, candidate, args.manifest))
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
        check_text = (
            dns_seeds_check_json_text
            if args.json
            else dns_seeds_check_text
        )
        print(check_text(args.check_dns_seeds[0], dns_seeds, candidate, args.manifest))
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
        check_text = (
            identity_check_json_text
            if args.json
            else identity_check_text
        )
        print(check_text(args.check_identity[0], identity, candidate, args.manifest))
        return 0

    if args.check_network_value_selection_candidate is not None:
        if args.in_place:
            print("error: --check-network-value-selection-candidate does not write the manifest", file=sys.stderr)
            return 1
        candidate_network = args.check_network_value_selection_candidate[0]
        candidate_path = Path(args.check_network_value_selection_candidate[1])
        try:
            (
                candidate_json,
                candidate_metadata,
                auxpow,
                identity,
                dns_seeds,
                candidate,
            ) = checked_network_value_selection_candidate(
                manifest,
                candidate_network,
                candidate_path,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        check_text = (
            network_value_selection_candidate_check_json_text
            if args.json
            else network_value_selection_candidate_check_text
        )
        print(
            check_text(
                manifest,
                args.manifest,
                candidate_network,
                candidate_path,
                candidate_json,
                candidate_metadata,
                auxpow,
                identity,
                dns_seeds,
                candidate,
            )
        )
        return 0
    if args.value_selection_candidate_artifact_status:
        if args.in_place:
            print("error: --value-selection-candidate-artifact-status does not write the manifest", file=sys.stderr)
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
    if args.action_plan:
        allow_blocked = True
    if args.readiness_summary:
        allow_blocked = True
    if args.launch_gate_preflight:
        allow_blocked = True
    if args.operator_runbook:
        allow_blocked = True
    if args.release_evidence_bundle:
        allow_blocked = True
    if args.check_release_evidence_bundle is not None:
        allow_blocked = True
    if args.check_release_evidence_archive is not None:
        allow_blocked = True
    if args.release_evidence_archive_checklist is not None:
        allow_blocked = True
    if args.release_evidence_handoff_summary is not None:
        allow_blocked = True
    if args.release_evidence_publication_index_template is not None:
        allow_blocked = True
    if args.check_release_evidence_publication_index is not None:
        allow_blocked = True
    if args.release_evidence_publication_index_archive_checklist is not None:
        allow_blocked = True
    if args.check_release_evidence_publication_index_archive is not None:
        allow_blocked = True
    if args.release_evidence_publication_index_archive_handoff_summary is not None:
        allow_blocked = True
    if args.release_evidence_publication_closeout_checklist is not None:
        allow_blocked = True
    if args.check_release_evidence_publication_closeout is not None:
        allow_blocked = True
    if args.check_release_evidence_publication_closeout_archive is not None:
        allow_blocked = True
    if (
        args.release_evidence_publication_closeout_archive_handoff_summary
        is not None
    ):
        allow_blocked = True
    if args.release_evidence_publication_status:
        allow_blocked = True
    if args.release_evidence_publication_artifact_status:
        allow_blocked = True
    if args.network_readiness_summary is not None:
        allow_blocked = True
    if args.snapshot_audit_handoff is not None:
        allow_blocked = True
    if args.snapshot_audit_handoffs:
        allow_blocked = True
    if args.network_handoff_bundle is not None:
        allow_blocked = True
    if args.network_later_blockers is not None:
        allow_blocked = True
    if args.blocker_type_readiness_summary is not None:
        allow_blocked = True
    if args.blocker_type_later_blockers is not None:
        allow_blocked = True
    if args.readiness_gate_summary is not None:
        allow_blocked = True
    if args.readiness_gate_later_blockers is not None:
        allow_blocked = True
    if args.network_value_selection_later_blockers is not None:
        allow_blocked = True
    if args.network_value_selection_candidate_template is not None:
        allow_blocked = True
    if args.value_selection_candidate_artifact_status:
        allow_blocked = True
    if args.value_selection_checklists:
        allow_blocked = True
    if args.blocker_readiness_summary is not None:
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

    if args.readiness_summary:
        if args.in_place:
            print("error: --readiness-summary does not write the manifest", file=sys.stderr)
            return 1
        summary_text = (
            readiness_summary_json_text
            if args.json
            else readiness_summary_text
        )
        print(summary_text(manifest, args.manifest, check))
        return 0

    if args.snapshot_audit_handoff is not None:
        try:
            handoff_text = (
                snapshot_audit_handoff_json_text
                if args.json
                else snapshot_audit_handoff_text
            )
            print(
                handoff_text(
                    manifest,
                    args.manifest,
                    check,
                    args.snapshot_audit_handoff,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.snapshot_audit_handoffs:
        handoffs_text = (
            snapshot_audit_handoffs_json_text
            if args.json
            else snapshot_audit_handoffs_text
        )
        print(handoffs_text(manifest, args.manifest, check))
        return 0

    if args.launch_gate_preflight:
        preflight_text = (
            launch_gate_preflight_json_text
            if args.json
            else launch_gate_preflight_text
        )
        print(preflight_text(manifest, args.manifest, check))
        return 0

    if args.operator_runbook:
        runbook_text = (
            operator_runbook_json_text
            if args.json
            else operator_runbook_text
        )
        print(runbook_text(manifest, args.manifest, check))
        return 0

    if args.release_evidence_bundle:
        evidence_text = (
            release_evidence_bundle_json_text
            if args.json
            else release_evidence_bundle_text
        )
        print(evidence_text(manifest, args.manifest, check))
        return 0

    if args.check_release_evidence_bundle is not None:
        try:
            evidence_check_payload = release_evidence_bundle_check_payload(
                manifest,
                args.manifest,
                check,
                args.check_release_evidence_bundle,
                require_match=args.require_release_evidence_bundle_match,
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        evidence_check_text = (
            release_evidence_bundle_check_json_text_from_payload
            if args.json
            else release_evidence_bundle_check_text_from_payload
        )
        print(evidence_check_text(evidence_check_payload))
        if (
            args.require_release_evidence_bundle_match
            and not evidence_check_payload["verified"]
        ):
            print(
                "error: release evidence bundle does not match the current manifest",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.release_evidence_archive_checklist is not None:
        archive_checklist_text = (
            release_evidence_archive_checklist_json_text
            if args.json
            else release_evidence_archive_checklist_text
        )
        print(
            archive_checklist_text(
                manifest,
                args.manifest,
                check,
                args.release_evidence_archive_checklist,
            )
        )
        return 0

    if args.check_release_evidence_archive is not None:
        archive_record_path, bundle_path = args.check_release_evidence_archive
        try:
            archive_check_payload = release_evidence_archive_check_payload(
                manifest,
                args.manifest,
                check,
                archive_record_path,
                bundle_path,
                require_match=args.require_release_evidence_archive_match,
            )
            archive_check_text = (
                release_evidence_archive_check_json_text_from_payload
                if args.json
                else release_evidence_archive_check_text_from_payload
            )
            print(archive_check_text(archive_check_payload))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if (
            args.require_release_evidence_archive_match
            and not archive_check_payload["verified"]
        ):
            print(
                "error: release evidence archive record does not match the current bundle gate",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.release_evidence_handoff_summary is not None:
        archive_record_path, bundle_path = args.release_evidence_handoff_summary
        try:
            handoff_summary_payload = release_evidence_handoff_summary_payload(
                manifest,
                args.manifest,
                check,
                archive_record_path,
                bundle_path,
            )
            handoff_summary_text = (
                release_evidence_handoff_summary_json_text_from_payload
                if args.json
                else release_evidence_handoff_summary_text_from_payload
            )
            print(handoff_summary_text(handoff_summary_payload))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.release_evidence_publication_index_template is not None:
        archive_record_path, bundle_path = (
            args.release_evidence_publication_index_template
        )
        try:
            publication_index_template_payload = (
                release_evidence_publication_index_template_payload(
                    manifest,
                    args.manifest,
                    check,
                    archive_record_path,
                    bundle_path,
                )
            )
            publication_index_template_text = (
                release_evidence_publication_index_template_json_text_from_payload
                if args.json
                else release_evidence_publication_index_template_text_from_payload
            )
            print(publication_index_template_text(publication_index_template_payload))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.check_release_evidence_publication_index is not None:
        publication_index_path, archive_record_path, bundle_path = (
            args.check_release_evidence_publication_index
        )
        try:
            publication_index_check_payload = (
                release_evidence_publication_index_check_payload(
                    manifest,
                    args.manifest,
                    check,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                    require_match=(
                        args.require_release_evidence_publication_index_match
                    ),
                )
            )
            publication_index_check_text = (
                release_evidence_publication_index_check_json_text_from_payload
                if args.json
                else release_evidence_publication_index_check_text_from_payload
            )
            print(publication_index_check_text(publication_index_check_payload))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if (
            args.require_release_evidence_publication_index_match
            and not publication_index_check_payload["verified"]
        ):
            print(
                "error: release evidence publication index does not match the current handoff",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.release_evidence_publication_index_archive_checklist is not None:
        publication_index_path, archive_record_path, bundle_path = (
            args.release_evidence_publication_index_archive_checklist
        )
        try:
            publication_index_archive_checklist_payload = (
                release_evidence_publication_index_archive_checklist_payload(
                    manifest,
                    args.manifest,
                    check,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                )
            )
            publication_index_archive_checklist_text = (
                release_evidence_publication_index_archive_checklist_json_text_from_payload
                if args.json
                else release_evidence_publication_index_archive_checklist_text_from_payload
            )
            print(
                publication_index_archive_checklist_text(
                    publication_index_archive_checklist_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.check_release_evidence_publication_index_archive is not None:
        (
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = args.check_release_evidence_publication_index_archive
        try:
            publication_index_archive_check_payload = (
                release_evidence_publication_index_archive_check_payload(
                    manifest,
                    args.manifest,
                    check,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                    require_match=(
                        args.require_release_evidence_publication_index_archive_match
                    ),
                )
            )
            publication_index_archive_check_text = (
                release_evidence_publication_index_archive_check_json_text_from_payload
                if args.json
                else release_evidence_publication_index_archive_check_text_from_payload
            )
            print(
                publication_index_archive_check_text(
                    publication_index_archive_check_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if (
            args.require_release_evidence_publication_index_archive_match
            and not publication_index_archive_check_payload["verified"]
        ):
            print(
                "error: release evidence publication index archive record does "
                "not match the current publication index gate",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.release_evidence_publication_index_archive_handoff_summary is not None:
        (
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = args.release_evidence_publication_index_archive_handoff_summary
        try:
            publication_index_archive_handoff_summary_payload = (
                release_evidence_publication_index_archive_handoff_summary_payload(
                    manifest,
                    args.manifest,
                    check,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                )
            )
            publication_index_archive_handoff_summary_text = (
                release_evidence_publication_index_archive_handoff_summary_json_text_from_payload
                if args.json
                else release_evidence_publication_index_archive_handoff_summary_text_from_payload
            )
            print(
                publication_index_archive_handoff_summary_text(
                    publication_index_archive_handoff_summary_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.release_evidence_publication_closeout_checklist is not None:
        (
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = args.release_evidence_publication_closeout_checklist
        try:
            publication_closeout_checklist_payload = (
                release_evidence_publication_closeout_checklist_payload(
                    manifest,
                    args.manifest,
                    check,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                )
            )
            publication_closeout_checklist_text = (
                release_evidence_publication_closeout_checklist_json_text_from_payload
                if args.json
                else release_evidence_publication_closeout_checklist_text_from_payload
            )
            print(
                publication_closeout_checklist_text(
                    publication_closeout_checklist_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.check_release_evidence_publication_closeout is not None:
        (
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = args.check_release_evidence_publication_closeout
        try:
            publication_closeout_check_payload = (
                release_evidence_publication_closeout_check_payload(
                    manifest,
                    args.manifest,
                    check,
                    closeout_path,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                    require_match=(
                        args.require_release_evidence_publication_closeout_match
                    ),
                )
            )
            publication_closeout_check_text = (
                release_evidence_publication_closeout_check_json_text_from_payload
                if args.json
                else release_evidence_publication_closeout_check_text_from_payload
            )
            print(publication_closeout_check_text(publication_closeout_check_payload))
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if (
            args.require_release_evidence_publication_closeout_match
            and not publication_closeout_check_payload["verified"]
        ):
            print(
                "error: release evidence publication closeout does not match the current closeout checklist",
                file=sys.stderr,
            )
            return 1
        return 0

    if args.check_release_evidence_publication_closeout_archive is not None:
        (
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = args.check_release_evidence_publication_closeout_archive
        try:
            publication_closeout_archive_check_payload = (
                release_evidence_publication_closeout_archive_check_payload(
                    manifest,
                    args.manifest,
                    check,
                    closeout_archive_record_path,
                    closeout_path,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                    require_match=(
                        args.require_release_evidence_publication_closeout_archive_match
                    ),
                )
            )
            publication_closeout_archive_check_text = (
                release_evidence_publication_closeout_archive_check_json_text_from_payload
                if args.json
                else release_evidence_publication_closeout_archive_check_text_from_payload
            )
            print(
                publication_closeout_archive_check_text(
                    publication_closeout_archive_check_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if (
            args.require_release_evidence_publication_closeout_archive_match
            and not publication_closeout_archive_check_payload["verified"]
        ):
            print(
                "error: release evidence publication closeout archive record does not match the current closeout gate",
                file=sys.stderr,
            )
            return 1
        return 0

    if (
        args.release_evidence_publication_closeout_archive_handoff_summary
        is not None
    ):
        (
            closeout_archive_record_path,
            closeout_path,
            publication_index_archive_record_path,
            publication_index_path,
            archive_record_path,
            bundle_path,
        ) = (
            args.release_evidence_publication_closeout_archive_handoff_summary
        )
        try:
            closeout_archive_handoff_summary_payload = (
                release_evidence_publication_closeout_archive_handoff_summary_payload(
                    manifest,
                    args.manifest,
                    check,
                    closeout_archive_record_path,
                    closeout_path,
                    publication_index_archive_record_path,
                    publication_index_path,
                    archive_record_path,
                    bundle_path,
                )
            )
            closeout_archive_handoff_summary_text = (
                release_evidence_publication_closeout_archive_handoff_summary_json_text_from_payload
                if args.json
                else release_evidence_publication_closeout_archive_handoff_summary_text_from_payload
            )
            print(
                closeout_archive_handoff_summary_text(
                    closeout_archive_handoff_summary_payload
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.release_evidence_publication_status:
        publication_status_text = (
            release_evidence_publication_status_json_text
            if args.json
            else release_evidence_publication_status_text
        )
        print(publication_status_text(manifest, args.manifest, check))
        return 0

    if args.release_evidence_publication_artifact_status:
        artifact_status_text = (
            release_evidence_publication_artifact_status_json_text
            if args.json
            else release_evidence_publication_artifact_status_text
        )
        print(
            artifact_status_text(
                manifest,
                args.manifest,
                check,
                args.release_evidence_bundle_path,
                args.release_evidence_archive_record_path,
                args.release_evidence_publication_index_path,
                args.release_evidence_publication_index_archive_record_path,
                args.release_evidence_publication_closeout_path,
                args.release_evidence_publication_closeout_archive_record_path,
            )
        )
        return 0

    if args.value_selection_candidate_artifact_status:
        candidate_artifact_status_text = (
            value_selection_candidate_artifact_status_json_text
            if args.json
            else value_selection_candidate_artifact_status_text
        )
        print(
            candidate_artifact_status_text(
                manifest,
                args.manifest,
                args.main_value_selection_candidate,
                args.testnet_value_selection_candidate,
            )
        )
        return 0

    if args.network_readiness_summary is not None:
        if args.in_place:
            print("error: --network-readiness-summary does not write the manifest", file=sys.stderr)
            return 1
        try:
            summary_text = (
                network_readiness_summary_json_text
                if args.json
                else network_readiness_summary_text
            )
            print(
                summary_text(
                    manifest,
                    args.manifest,
                    check,
                    args.network_readiness_summary,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.network_handoff_bundle is not None:
        if args.in_place:
            print("error: --network-handoff-bundle does not write the manifest", file=sys.stderr)
            return 1
        try:
            handoff_text = (
                network_handoff_bundle_json_text
                if args.json
                else network_handoff_bundle_text
            )
            print(
                handoff_text(
                    manifest,
                    args.manifest,
                    check,
                    args.network_handoff_bundle,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.network_later_blockers is not None:
        if args.in_place:
            print("error: --network-later-blockers does not write the manifest", file=sys.stderr)
            return 1
        try:
            later_text = (
                network_later_blockers_json_text
                if args.json
                else network_later_blockers_text
            )
            print(
                later_text(
                    manifest,
                    args.manifest,
                    check,
                    args.network_later_blockers,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.blocker_type_readiness_summary is not None:
        if args.in_place:
            print("error: --blocker-type-readiness-summary does not write the manifest", file=sys.stderr)
            return 1
        try:
            summary_text = (
                blocker_type_readiness_summary_json_text
                if args.json
                else blocker_type_readiness_summary_text
            )
            print(
                summary_text(
                    manifest,
                    args.manifest,
                    check,
                    args.blocker_type_readiness_summary,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.blocker_type_later_blockers is not None:
        if args.in_place:
            print("error: --blocker-type-later-blockers does not write the manifest", file=sys.stderr)
            return 1
        try:
            later_text = (
                blocker_type_later_blockers_json_text
                if args.json
                else blocker_type_later_blockers_text
            )
            print(
                later_text(
                    manifest,
                    args.manifest,
                    check,
                    args.blocker_type_later_blockers,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.readiness_gate_summary is not None:
        if args.in_place:
            print("error: --readiness-gate-summary does not write the manifest", file=sys.stderr)
            return 1
        try:
            summary_text = (
                readiness_gate_summary_json_text
                if args.json
                else readiness_gate_summary_text
            )
            print(
                summary_text(
                    manifest,
                    args.manifest,
                    check,
                    args.readiness_gate_summary,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.readiness_gate_later_blockers is not None:
        if args.in_place:
            print("error: --readiness-gate-later-blockers does not write the manifest", file=sys.stderr)
            return 1
        try:
            later_text = (
                readiness_gate_later_blockers_json_text
                if args.json
                else readiness_gate_later_blockers_text
            )
            print(
                later_text(
                    manifest,
                    args.manifest,
                    check,
                    args.readiness_gate_later_blockers,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.network_value_selection_later_blockers is not None:
        if args.in_place:
            print("error: --network-value-selection-later-blockers does not write the manifest", file=sys.stderr)
            return 1
        try:
            later_text = (
                network_value_selection_later_blockers_json_text
                if args.json
                else network_value_selection_later_blockers_text
            )
            print(
                later_text(
                    manifest,
                    args.manifest,
                    check,
                    args.network_value_selection_later_blockers,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.network_value_selection_candidate_template is not None:
        if args.in_place:
            print("error: --network-value-selection-candidate-template does not write the manifest", file=sys.stderr)
            return 1
        try:
            template_text = (
                network_value_selection_candidate_template_json_text
                if args.json
                else network_value_selection_candidate_template_text
            )
            print(
                template_text(
                    manifest,
                    args.manifest,
                    check,
                    args.network_value_selection_candidate_template,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.value_selection_checklists:
        if args.in_place:
            print("error: --value-selection-checklists does not write the manifest", file=sys.stderr)
            return 1
        checklists_text = (
            value_selection_checklists_json_text
            if args.json
            else value_selection_checklists_text
        )
        print(checklists_text(manifest, args.manifest, check))
        return 0

    if args.blocker_readiness_summary is not None:
        if args.in_place:
            print("error: --blocker-readiness-summary does not write the manifest", file=sys.stderr)
            return 1
        try:
            summary_text = (
                blocker_readiness_summary_json_text
                if args.json
                else blocker_readiness_summary_text
            )
            print(
                summary_text(
                    manifest,
                    args.manifest,
                    check,
                    args.blocker_readiness_summary,
                )
            )
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
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
