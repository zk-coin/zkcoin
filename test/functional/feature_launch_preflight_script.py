#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the launch preflight shell wrapper with controlled RPC JSON."""

import json
import os
import stat
import subprocess
import textwrap

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class LaunchPreflightScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def write_fake_cli(self):
        path = os.path.join(self.options.tmpdir, "fake-zkcoin-cli.py")
        with open(path, "w", encoding="utf8") as fake_cli:
            fake_cli.write(textwrap.dedent("""\
                #!/usr/bin/env python3
                import os
                import sys

                if sys.argv[-1] != "getblockchaininfo":
                    print("unexpected command", file=sys.stderr)
                    sys.exit(2)

                print(os.environ["ZKCOIN_FAKE_INFO_JSON"])
            """))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def launch_preflight_script(self):
        return os.path.join(
            self.config["environment"]["SRCDIR"],
            "contrib",
            "devtools",
            "zkcoin_launch_preflight.sh",
        )

    def valid_info(self, readiness_overrides=None, omit_readiness_fields=()):
        readiness = {
            "ready": True,
            "snapshot_configured": True,
            "snapshot_imported": True,
            "auxpow_active_at_launch": True,
            "chain_id_configured": True,
            "chain_id_parent_version_safe": True,
            "script_rules_active_at_launch": True,
            "chain_history_clean": True,
            "public_network_identity_configured": True,
            "public_network_identity": {
                "configured": True,
                "inherited_litecoin_message_start": False,
                "message_start_shape_valid": True,
                "inherited_litecoin_default_port": False,
                "default_port_shape_valid": True,
                "inherited_litecoin_dns_seed": False,
                "dns_seeds_shape_valid": True,
                "fixed_seeds_present": False,
                "inherited_litecoin_base58_prefixes": False,
                "base58_prefixes_shape_valid": True,
                "base58_prefixes_unique": True,
                "inherited_litecoin_bech32_hrp": False,
                "bech32_hrp_shape_valid": True,
                "inherited_litecoin_mweb_hrp": False,
                "mweb_hrp_shape_valid": True,
                "hrps_unique": True,
                "failures": [],
            },
            "shielded_inactive_at_launch": True,
            "at_launch_tip": True,
            "failures": [],
        }
        readiness.update(readiness_overrides or {})
        for field in omit_readiness_fields:
            readiness.pop(field)
        return {
            "chain": "regtest",
            "blocks": 0,
            "headers": 0,
            "bestblockhash": "33" * 32,
            "chainwork": "00" * 31 + "01",
            "verificationprogress": 1.0,
            "difficulty": 1.0,
            "size_on_disk": 1024,
            "time": 1600000000,
            "mediantime": 1600000000,
            "initialblockdownload": False,
            "pruned": False,
            "warnings": "",
            "launch_readiness": readiness,
            "ltc_snapshot": {
                "enabled": True,
                "height": 2250000,
                "block_hash": "11" * 32,
                "import_hash": "22" * 32,
                "imported": True,
                "import_in_progress": False,
            },
            "auxpow": {
                "next_block_active": True,
                "start_height": 1,
                "chain_id": 4660,
                "strict_chain_id": True,
                "parent_version_safe": True,
            },
            "shielded_pool": {
                "next_block_active": False,
                "start_height": 2,
                "scaffold_proofs": False,
                "real_proof_backend": "orchard-v1",
                "real_proof_verification": True,
            },
        }

    def run_preflight(self, fake_cli, info):
        return self.run_preflight_raw(fake_cli, json.dumps(info))

    def run_preflight_raw(self, fake_cli, info_json):
        env = os.environ.copy()
        env["ZKCOIN_FAKE_INFO_JSON"] = info_json
        return subprocess.run(
            [self.launch_preflight_script(), fake_cli],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=env,
        )

    def assert_preflight(self, fake_cli, info, expected_code, expected_output):
        result = self.run_preflight(fake_cli, info)
        assert_equal(result.returncode, expected_code)
        assert expected_output in result.stdout + result.stderr

    def run_test(self):
        fake_cli = self.write_fake_cli()

        self.log.info("Accept a complete launch readiness response")
        self.assert_preflight(fake_cli, self.valid_info(), 0, "Launch preflight passed.")

        self.log.info("Reject duplicate getblockchaininfo fields in launch preflight")
        duplicate_field_result = self.run_preflight_raw(
            fake_cli,
            '{"chain": "regtest", "chain": "main", "launch_readiness": {}}',
        )
        assert_equal(duplicate_field_result.returncode, 1)
        assert "getblockchaininfo contains duplicate field: chain" in (
            duplicate_field_result.stdout + duplicate_field_result.stderr
        )

        self.log.info("Reject non-object getblockchaininfo JSON in launch preflight")
        non_object_result = self.run_preflight_raw(fake_cli, "[]")
        assert_equal(non_object_result.returncode, 1)
        assert "getblockchaininfo response must be a JSON object" in (
            non_object_result.stdout + non_object_result.stderr
        )

        self.log.info("Reject missing launch_readiness failures array")
        self.assert_preflight(
            fake_cli,
            self.valid_info(omit_readiness_fields=("failures",)),
            1,
            "missing launch_readiness fields: failures",
        )

        self.log.info("Reject missing required launch_readiness boolean")
        self.assert_preflight(
            fake_cli,
            self.valid_info(omit_readiness_fields=("snapshot_imported",)),
            1,
            "missing launch_readiness fields: snapshot_imported",
        )

        self.log.info("Reject malformed launch_readiness field types")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={"ready": "true"}),
            1,
            "launch_readiness.ready must be a boolean",
        )

        self.log.info("Reject malformed chain name in launch preflight")
        malformed_chain = self.valid_info()
        malformed_chain["chain"] = "unknown"
        self.assert_preflight(
            fake_cli,
            malformed_chain,
            1,
            "getblockchaininfo.chain must be a recognized chain name",
        )

        self.log.info("Reject malformed chain height in launch preflight")
        malformed_blocks = self.valid_info()
        malformed_blocks["blocks"] = "0"
        self.assert_preflight(
            fake_cli,
            malformed_blocks,
            1,
            "getblockchaininfo.blocks must be a non-negative integer",
        )

        self.log.info("Reject malformed header height in launch preflight")
        malformed_headers = self.valid_info()
        malformed_headers["headers"] = "0"
        self.assert_preflight(
            fake_cli,
            malformed_headers,
            1,
            "getblockchaininfo.headers must be a non-negative integer",
        )
        headers_below_blocks = self.valid_info()
        headers_below_blocks["blocks"] = 1
        headers_below_blocks["headers"] = 0
        headers_below_blocks["launch_readiness"]["at_launch_tip"] = False
        self.assert_preflight(
            fake_cli,
            headers_below_blocks,
            1,
            "getblockchaininfo.headers must be greater than or equal to blocks",
        )

        self.log.info("Reject malformed best block hash in launch preflight")
        malformed_bestblockhash = self.valid_info()
        malformed_bestblockhash["bestblockhash"] = "33" * 31
        self.assert_preflight(
            fake_cli,
            malformed_bestblockhash,
            1,
            "getblockchaininfo.bestblockhash must be a non-null lowercase 64-character hex string",
        )

        self.log.info("Reject malformed chainwork in launch preflight")
        malformed_chainwork = self.valid_info()
        malformed_chainwork["chainwork"] = "00" * 32
        self.assert_preflight(
            fake_cli,
            malformed_chainwork,
            1,
            "getblockchaininfo.chainwork must be a non-null lowercase 64-character hex string",
        )

        self.log.info("Reject malformed verification progress in launch preflight")
        malformed_verification_progress = self.valid_info()
        malformed_verification_progress["verificationprogress"] = -0.1
        self.assert_preflight(
            fake_cli,
            malformed_verification_progress,
            1,
            "getblockchaininfo.verificationprogress must be a non-negative number",
        )
        over_one_verification_progress = self.valid_info()
        over_one_verification_progress["verificationprogress"] = 1.1
        self.assert_preflight(
            fake_cli,
            over_one_verification_progress,
            1,
            "getblockchaininfo.verificationprogress must be a non-negative number not exceeding 1",
        )

        self.log.info("Reject malformed difficulty in launch preflight")
        malformed_difficulty = self.valid_info()
        malformed_difficulty["difficulty"] = -1
        self.assert_preflight(
            fake_cli,
            malformed_difficulty,
            1,
            "getblockchaininfo.difficulty must be a non-negative number",
        )

        self.log.info("Reject malformed size on disk in launch preflight")
        malformed_size_on_disk = self.valid_info()
        malformed_size_on_disk["size_on_disk"] = 0
        self.assert_preflight(
            fake_cli,
            malformed_size_on_disk,
            1,
            "getblockchaininfo.size_on_disk must be a positive integer",
        )

        self.log.info("Reject malformed launch-tip times in launch preflight")
        malformed_tip_time = self.valid_info()
        malformed_tip_time["time"] = "1600000000"
        self.assert_preflight(
            fake_cli,
            malformed_tip_time,
            1,
            "getblockchaininfo.time must be a non-negative integer",
        )
        malformed_median_time = self.valid_info()
        malformed_median_time["mediantime"] = malformed_median_time["time"] + 1
        self.assert_preflight(
            fake_cli,
            malformed_median_time,
            1,
            "getblockchaininfo.mediantime must be less than or equal to time",
        )

        self.log.info("Reject initial block download in launch preflight")
        malformed_ibd = self.valid_info()
        malformed_ibd["initialblockdownload"] = "false"
        self.assert_preflight(
            fake_cli,
            malformed_ibd,
            1,
            "getblockchaininfo.initialblockdownload must be a boolean",
        )
        initial_block_download = self.valid_info()
        initial_block_download["initialblockdownload"] = True
        self.assert_preflight(
            fake_cli,
            initial_block_download,
            1,
            "node is still in initial block download",
        )

        self.log.info("Reject pruned mode in launch preflight")
        malformed_pruned = self.valid_info()
        malformed_pruned["pruned"] = "false"
        self.assert_preflight(
            fake_cli,
            malformed_pruned,
            1,
            "getblockchaininfo.pruned must be a boolean",
        )
        pruned_node = self.valid_info()
        pruned_node["pruned"] = True
        self.assert_preflight(
            fake_cli,
            pruned_node,
            1,
            "launch node is running in pruned mode",
        )

        self.log.info("Reject node warnings in launch preflight")
        malformed_warnings = self.valid_info()
        malformed_warnings["warnings"] = []
        self.assert_preflight(
            fake_cli,
            malformed_warnings,
            1,
            "getblockchaininfo.warnings must be a string",
        )
        warned_node = self.valid_info()
        warned_node["warnings"] = "Unknown block versions being mined"
        self.assert_preflight(
            fake_cli,
            warned_node,
            1,
            "launch node reports warnings",
        )

        self.log.info("Reject launch-tip readiness away from genesis height")
        non_genesis_launch_tip = self.valid_info()
        non_genesis_launch_tip["blocks"] = 1
        self.assert_preflight(
            fake_cli,
            non_genesis_launch_tip,
            1,
            "getblockchaininfo.blocks must be 0 when launch_readiness.at_launch_tip is true",
        )
        headers_ahead_launch_tip = self.valid_info()
        headers_ahead_launch_tip["headers"] = 1
        self.assert_preflight(
            fake_cli,
            headers_ahead_launch_tip,
            1,
            "getblockchaininfo.headers must be 0 when launch_readiness.at_launch_tip is true",
        )

        self.log.info("Reject inconsistent ready response with false invariants")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={"chain_history_clean": False}),
            1,
            "required readiness fields are false: chain_history_clean",
        )

        self.log.info("Reject missing snapshot detail fields")
        missing_snapshot_detail = self.valid_info()
        missing_snapshot_detail["ltc_snapshot"] = {
            "height": 2250000,
            "block_hash": "11" * 32,
            "import_hash": "22" * 32,
        }
        self.assert_preflight(
            fake_cli,
            missing_snapshot_detail,
            1,
            "missing getblockchaininfo.ltc_snapshot fields: enabled, imported, import_in_progress",
        )

        self.log.info("Reject inconsistent snapshot import detail")
        inconsistent_snapshot_detail = self.valid_info()
        inconsistent_snapshot_detail["ltc_snapshot"]["imported"] = False
        self.assert_preflight(
            fake_cli,
            inconsistent_snapshot_detail,
            1,
            "getblockchaininfo.ltc_snapshot.imported must match launch_readiness.snapshot_imported",
        )

        self.log.info("Reject malformed configured snapshot detail shape")
        malformed_snapshot_height = self.valid_info()
        malformed_snapshot_height["ltc_snapshot"]["height"] = "2250000"
        self.assert_preflight(
            fake_cli,
            malformed_snapshot_height,
            1,
            "getblockchaininfo.ltc_snapshot.height must be a positive integer",
        )
        null_snapshot_block_hash = self.valid_info()
        null_snapshot_block_hash["ltc_snapshot"]["block_hash"] = "00" * 32
        self.assert_preflight(
            fake_cli,
            null_snapshot_block_hash,
            1,
            "getblockchaininfo.ltc_snapshot.block_hash must be a non-null lowercase 64-character hex string",
        )
        uppercase_snapshot_import_hash = self.valid_info()
        uppercase_snapshot_import_hash["ltc_snapshot"]["import_hash"] = ("aa" * 32).upper()
        self.assert_preflight(
            fake_cli,
            uppercase_snapshot_import_hash,
            1,
            "getblockchaininfo.ltc_snapshot.import_hash must be a non-null lowercase 64-character hex string",
        )

        self.log.info("Reject in-progress snapshot imports")
        snapshot_import_in_progress = self.valid_info()
        snapshot_import_in_progress["ltc_snapshot"]["import_in_progress"] = True
        self.assert_preflight(
            fake_cli,
            snapshot_import_in_progress,
            1,
            "snapshot import is still in progress",
        )

        self.log.info("Reject inactive launch script rules")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={"script_rules_active_at_launch": False}),
            1,
            "required readiness fields are false: script_rules_active_at_launch",
        )

        self.log.info("Reject inconsistent AuxPoW next-block activation detail")
        inconsistent_auxpow_next_block = self.valid_info()
        inconsistent_auxpow_next_block["auxpow"]["next_block_active"] = False
        self.assert_preflight(
            fake_cli,
            inconsistent_auxpow_next_block,
            1,
            "getblockchaininfo.auxpow.next_block_active must match launch_readiness.auxpow_active_at_launch at the launch tip",
        )

        self.log.info("Reject malformed or non-launch AuxPoW start height")
        malformed_auxpow_start = self.valid_info()
        malformed_auxpow_start["auxpow"]["start_height"] = "1"
        self.assert_preflight(
            fake_cli,
            malformed_auxpow_start,
            1,
            "getblockchaininfo.auxpow.start_height must be an integer",
        )
        late_auxpow_start = self.valid_info()
        late_auxpow_start["auxpow"]["start_height"] = 2
        self.assert_preflight(
            fake_cli,
            late_auxpow_start,
            1,
            "getblockchaininfo.auxpow.start_height must be 1 when launch_readiness.auxpow_active_at_launch is true",
        )

        self.log.info("Reject inconsistent AuxPoW strict chain-id detail")
        inconsistent_auxpow_strict_chain_id = self.valid_info()
        inconsistent_auxpow_strict_chain_id["auxpow"]["strict_chain_id"] = False
        self.assert_preflight(
            fake_cli,
            inconsistent_auxpow_strict_chain_id,
            1,
            "getblockchaininfo.auxpow.strict_chain_id must be true when launch_readiness.chain_id_configured is true",
        )

        self.log.info("Reject inconsistent ready response with parent-version-unsafe AuxPoW detail")
        false_parent_version_detail = self.valid_info(readiness_overrides={
            "chain_id_parent_version_safe": False,
        })
        false_parent_version_detail["auxpow"]["parent_version_safe"] = False
        result = self.run_preflight(fake_cli, false_parent_version_detail)
        assert_equal(result.returncode, 1)
        combined_output = result.stdout + result.stderr
        assert "auxpow parent version safe: false" in combined_output
        assert "required readiness fields are false: chain_id_parent_version_safe" in combined_output

        self.log.info("Reject parent-version-unsafe AuxPoW chain id")
        unsafe_parent_version_chain_id = self.valid_info(readiness_overrides={
            "ready": False,
            "chain_id_configured": False,
            "chain_id_parent_version_safe": False,
            "failures": ["AuxPoW chain id overlaps Litecoin parent versionbits chain-id range"],
        })
        unsafe_parent_version_chain_id["auxpow"]["chain_id"] = 8192
        unsafe_parent_version_chain_id["auxpow"]["parent_version_safe"] = False
        self.assert_preflight(
            fake_cli,
            unsafe_parent_version_chain_id,
            1,
            "AuxPoW chain id overlaps Litecoin parent versionbits chain-id range",
        )

        self.log.info("Reject placeholder AuxPoW chain id in launch preflight")
        placeholder_chain_id = self.valid_info()
        placeholder_chain_id["auxpow"]["chain_id"] = 0x5A4B
        self.assert_preflight(
            fake_cli,
            placeholder_chain_id,
            1,
            "AuxPoW chain id is still the local launch placeholder 0x5a4b",
        )

        self.log.info("Reject inconsistent AuxPoW parent version safety detail")
        inconsistent_parent_version_detail = self.valid_info()
        inconsistent_parent_version_detail["auxpow"]["parent_version_safe"] = False
        self.assert_preflight(
            fake_cli,
            inconsistent_parent_version_detail,
            1,
            "getblockchaininfo.auxpow.parent_version_safe must match launch_readiness.chain_id_parent_version_safe",
        )

        self.log.info("Reject malformed AuxPoW parent version safety field types")
        malformed_parent_version_detail = self.valid_info()
        malformed_parent_version_detail["auxpow"]["parent_version_safe"] = "false"
        self.assert_preflight(
            fake_cli,
            malformed_parent_version_detail,
            1,
            "getblockchaininfo.auxpow.parent_version_safe must be a boolean",
        )

        self.log.info("Reject inherited public network identity in launch readiness")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={
                "public_network_identity_configured": False,
                "public_network_identity": {
                    "configured": False,
                    "inherited_litecoin_message_start": True,
                    "message_start_shape_valid": True,
                    "inherited_litecoin_default_port": True,
                    "default_port_shape_valid": True,
                    "inherited_litecoin_dns_seed": True,
                    "dns_seeds_shape_valid": True,
                    "fixed_seeds_present": True,
                    "inherited_litecoin_base58_prefixes": True,
                    "base58_prefixes_shape_valid": True,
                    "base58_prefixes_unique": True,
                    "inherited_litecoin_bech32_hrp": True,
                    "bech32_hrp_shape_valid": True,
                    "inherited_litecoin_mweb_hrp": True,
                    "mweb_hrp_shape_valid": True,
                    "hrps_unique": True,
                    "failures": ["P2P message start still matches Litecoin"],
                },
            }),
            1,
            "P2P message start still matches Litecoin",
        )

        self.log.info("Reject missing public network identity detail")
        missing_public_identity = self.valid_info()
        del missing_public_identity["launch_readiness"]["public_network_identity"]
        self.assert_preflight(
            fake_cli,
            missing_public_identity,
            1,
            "launch_readiness.public_network_identity must be an object",
        )

        self.log.info("Reject not-ready response and print returned failure")
        snapshot_not_imported = self.valid_info(readiness_overrides={
            "ready": False,
            "snapshot_imported": False,
            "failures": ["configured snapshot has not been imported"],
        })
        snapshot_not_imported["ltc_snapshot"]["imported"] = False
        self.assert_preflight(
            fake_cli,
            snapshot_not_imported,
            1,
            "configured snapshot has not been imported",
        )

        self.log.info("Reject missing detail sections used by the operator report")
        truncated_info = self.valid_info()
        truncated_info["auxpow"] = {}
        self.assert_preflight(
            fake_cli,
            truncated_info,
            1,
            "missing getblockchaininfo.auxpow fields: next_block_active, start_height, chain_id, strict_chain_id, parent_version_safe",
        )

        self.log.info("Reject missing shielded proof posture fields")
        missing_shielded_posture = self.valid_info()
        missing_shielded_posture["shielded_pool"] = {"next_block_active": False, "start_height": 2}
        self.assert_preflight(
            fake_cli,
            missing_shielded_posture,
            1,
            "missing getblockchaininfo.shielded_pool fields: scaffold_proofs, real_proof_backend, real_proof_verification",
        )

        self.log.info("Reject malformed shielded proof posture field types")
        malformed_shielded_posture = self.valid_info()
        malformed_shielded_posture["shielded_pool"]["scaffold_proofs"] = "false"
        self.assert_preflight(
            fake_cli,
            malformed_shielded_posture,
            1,
            "getblockchaininfo.shielded_pool.scaffold_proofs must be a boolean",
        )

        self.log.info("Reject inconsistent shielded next-block activation detail")
        inconsistent_shielded_next_block = self.valid_info()
        inconsistent_shielded_next_block["shielded_pool"]["next_block_active"] = True
        self.assert_preflight(
            fake_cli,
            inconsistent_shielded_next_block,
            1,
            "getblockchaininfo.shielded_pool.next_block_active must agree with launch_readiness.shielded_inactive_at_launch at the launch tip",
        )

        self.log.info("Reject malformed or launch-height shielded start height")
        malformed_shielded_start = self.valid_info()
        malformed_shielded_start["shielded_pool"]["start_height"] = "2"
        self.assert_preflight(
            fake_cli,
            malformed_shielded_start,
            1,
            "getblockchaininfo.shielded_pool.start_height must be an integer",
        )
        launch_height_shielded_start = self.valid_info()
        launch_height_shielded_start["shielded_pool"]["start_height"] = 1
        self.assert_preflight(
            fake_cli,
            launch_height_shielded_start,
            1,
            "getblockchaininfo.shielded_pool.start_height must not be 1 when launch_readiness.shielded_inactive_at_launch is true",
        )

        self.log.info("Reject scaffold proof acceptance in the launch preflight")
        scaffold_enabled = self.valid_info()
        scaffold_enabled["shielded_pool"]["scaffold_proofs"] = True
        self.assert_preflight(
            fake_cli,
            scaffold_enabled,
            1,
            "shielded scaffold proofs are enabled",
        )

        self.log.info("Reject unsupported shielded proof backends in the launch preflight")
        unsupported_backend = self.valid_info()
        unsupported_backend["shielded_pool"]["real_proof_backend"] = "unsupported"
        self.assert_preflight(
            fake_cli,
            unsupported_backend,
            1,
            "shielded real proof backend is not orchard-v1: unsupported",
        )

        self.log.info("Reject unavailable real shielded proof verification in the launch preflight")
        proof_verification_unavailable = self.valid_info()
        proof_verification_unavailable["shielded_pool"]["real_proof_verification"] = False
        self.assert_preflight(
            fake_cli,
            proof_verification_unavailable,
            1,
            "shielded real proof verification is not available",
        )


if __name__ == "__main__":
    LaunchPreflightScriptTest().main()
