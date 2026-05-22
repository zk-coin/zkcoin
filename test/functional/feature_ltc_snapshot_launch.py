#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Litecoin block-X snapshot import during launch."""

import errno
import http.client
import os
import subprocess

from test_framework.test_node import ErrorMatch
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


def reversed_hex(hex_string):
    return bytes.fromhex(hex_string)[::-1].hex()


class LitecoinSnapshotLaunchTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def setup_network(self):
        self.setup_nodes()

    def assert_launch_block_rejected(self, node, message):
        assert_raises_rpc_error(
            -1,
            message,
            node.generatetodescriptor,
            1,
            "raw(51)",
        )
        if self.is_wallet_compiled():
            assert_raises_rpc_error(
                -1,
                message,
                node.getauxblock,
            )
        else:
            assert_raises_rpc_error(
                -18,
                "requires a loaded wallet",
                node.getauxblock,
            )
        assert_raises_rpc_error(
            -1,
            message,
            node.createauxblock,
            node.get_deterministic_priv_key().address,
        )

    def assert_import_crashes(self, node, path):
        try:
            node.importsnapshotmanifest(path)
        except (http.client.CannotSendRequest, http.client.RemoteDisconnected):
            node.wait_until_stopped(timeout=30)
            return
        except OSError as e:
            if e.errno not in [errno.EPIPE, errno.ECONNREFUSED, errno.ECONNRESET]:
                raise
            node.wait_until_stopped(timeout=30)
            return

        raise AssertionError("Expected importsnapshotmanifest to trigger -dbcrashratio=1")

    def assert_launch_preflight(self, node, expected_returncode, expected_output):
        if not self.is_cli_compiled():
            self.log.info("Skipping launch preflight script check because litecoin-cli is not compiled")
            return

        script = os.path.join(
            self.config["environment"]["SRCDIR"],
            "contrib",
            "devtools",
            "zkcoin_launch_preflight.sh",
        )
        result = subprocess.run(
            [script, self.options.bitcoincli, f"-datadir={node.datadir}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        assert_equal(result.returncode, expected_returncode)
        assert expected_output in result.stdout + result.stderr

    def run_test(self):
        source = self.nodes[0]
        launch = self.nodes[1]

        self.log.info("Create a deterministic source-chain UTXO snapshot")
        source.generatetodescriptor(100, "raw(51)")
        dump = source.dumptxoutset("ltc-block-x.dat")
        verify = source.verifysnapshotmanifest(dump["path"])
        wrong_block_hash = ("00" if verify["base_hash"][:2] != "00" else "01") + verify["base_hash"][2:]
        wrong_import_hash = ("00" if verify["import_hash"][:2] != "00" else "01") + verify["import_hash"][2:]

        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["base_height"], dump["base_height"])
        assert_equal(verify["coins"], dump["coins_written"])
        assert_equal(verify["metadata_coins"], dump["coins_written"])
        assert_equal(verify["matches_configured_snapshot"], False)

        self.log.info("Reject configuring a snapshot on an already-started chain")
        self.stop_node(0)
        self.nodes[0].assert_start_raises_init_error(
            extra_args=[
                "-auxpowheight=1",
                f"-ltcsnapshotheight={dump['base_height']}",
                f"-ltcsnapshotblockhash={verify['base_hash']}",
                f"-ltcsnapshotutxoroot={verify['import_hash']}",
            ],
            expected_msg="Error initializing block database",
            match=ErrorMatch.PARTIAL_REGEX,
        )
        self.start_node(0)

        self.log.info("Reject snapshot configured with the right hash and root but wrong height")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height'] + 1}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        mismatch_verify = launch.verifysnapshotmanifest(dump["path"])
        assert_equal(mismatch_verify["matches_configured_snapshot"], False)
        assert_raises_rpc_error(
            -8,
            "snapshot base height mismatch",
            launch.importsnapshotmanifest,
            dump["path"],
        )

        self.log.info("Reject snapshot configured with the wrong block hash before import")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={wrong_block_hash}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        mismatch_verify = launch.verifysnapshotmanifest(dump["path"])
        assert_equal(mismatch_verify["matches_configured_snapshot"], False)
        assert_raises_rpc_error(
            -8,
            "snapshot base hash mismatch",
            launch.importsnapshotmanifest,
            dump["path"],
        )

        self.log.info("Reject snapshot configured with the wrong import root before import")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={wrong_import_hash}",
        ])
        mismatch_verify = launch.verifysnapshotmanifest(dump["path"])
        assert_equal(mismatch_verify["matches_configured_snapshot"], False)
        assert_raises_rpc_error(
            -8,
            "snapshot import hash mismatch",
            launch.importsnapshotmanifest,
            dump["path"],
        )

        self.log.info("Restart launch node with block-X snapshot and AuxPoW activation parameters")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])

        launch_info = launch.getblockchaininfo()
        snapshot_info = launch_info["ltc_snapshot"]
        assert_equal(snapshot_info["enabled"], True)
        assert_equal(snapshot_info["height"], dump["base_height"])
        assert_equal(snapshot_info["block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["import_hash"], verify["import_hash"])
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["import_in_progress"], False)
        launch_readiness = launch_info["launch_readiness"]
        assert_equal(launch_readiness["ready"], False)
        assert_equal(launch_readiness["snapshot_configured"], True)
        assert_equal(launch_readiness["snapshot_imported"], False)
        assert_equal(launch_readiness["auxpow_active_at_launch"], True)
        assert_equal(launch_readiness["chain_id_configured"], True)
        assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
        assert_equal(launch_readiness["at_launch_tip"], True)
        assert "configured snapshot has not been imported" in launch_readiness["failures"]
        self.assert_launch_preflight(launch, 1, "configured snapshot has not been imported")

        self.log.info("Require configured snapshot import before launch mining")
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot has not been imported")
        assert_equal(launch.getblockcount(), 0)

        self.log.info("Crash during snapshot import and verify same-manifest recovery marker")
        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
            "-dbbatchsize=1",
            "-dbcrashratio=1",
        ])
        launch = self.nodes[1]
        self.assert_import_crashes(launch, dump["path"])
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        launch = self.nodes[1]
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["import_in_progress"], True)
        assert_equal(snapshot_info["import_in_progress_height"], dump["base_height"])
        assert_equal(snapshot_info["import_in_progress_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["import_in_progress_hash"], verify["import_hash"])

        self.log.info("Import the configured snapshot at genesis")
        imported = launch.importsnapshotmanifest(dump["path"])
        assert_equal(imported["configured_snapshot"], True)
        assert_equal(imported["base_hash"], verify["base_hash"])
        assert_equal(imported["base_height"], verify["base_height"])
        assert_equal(imported["import_hash"], verify["import_hash"])
        assert_equal(imported["coins_imported"], verify["coins"])

        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        assert_equal(snapshot_info["import_in_progress"], False)
        launch_readiness = launch.getblockchaininfo()["launch_readiness"]
        assert_equal(launch_readiness["ready"], True)
        assert_equal(launch_readiness["snapshot_configured"], True)
        assert_equal(launch_readiness["snapshot_imported"], True)
        assert_equal(launch_readiness["auxpow_active_at_launch"], True)
        assert_equal(launch_readiness["chain_id_configured"], True)
        assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
        assert_equal(launch_readiness["at_launch_tip"], True)
        assert_equal(launch_readiness["failures"], [])
        self.assert_launch_preflight(launch, 0, "Launch preflight passed.")

        self.log.info("Reject launch preflight when AuxPoW chain id is not production-safe")
        for extra_arg in ["-auxpowchainid=0", "-noauxpowstrictchainid"]:
            self.restart_node(1, extra_args=[
                "-auxpowheight=1",
                f"-ltcsnapshotheight={dump['base_height']}",
                f"-ltcsnapshotblockhash={verify['base_hash']}",
                f"-ltcsnapshotutxoroot={verify['import_hash']}",
                extra_arg,
            ])
            launch = self.nodes[1]
            launch_readiness = launch.getblockchaininfo()["launch_readiness"]
            assert_equal(launch_readiness["ready"], False)
            assert_equal(launch_readiness["snapshot_configured"], True)
            assert_equal(launch_readiness["snapshot_imported"], True)
            assert_equal(launch_readiness["auxpow_active_at_launch"], True)
            assert_equal(launch_readiness["chain_id_configured"], False)
            assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
            assert_equal(launch_readiness["at_launch_tip"], True)
            assert "AuxPoW chain id is not configured for strict merge mining" in launch_readiness["failures"]
            self.assert_launch_preflight(launch, 1, "AuxPoW chain id is not configured for strict merge mining")
        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        launch = self.nodes[1]

        self.log.info("Allow replaying the same snapshot import before launch mining")
        replayed = launch.importsnapshotmanifest(dump["path"])
        assert_equal(replayed["configured_snapshot"], True)
        assert_equal(replayed["base_hash"], verify["base_hash"])
        assert_equal(replayed["base_height"], verify["base_height"])
        assert_equal(replayed["import_hash"], verify["import_hash"])
        assert_equal(replayed["coins_imported"], verify["coins"])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["import_in_progress"], False)

        self.log.info("Persist imported snapshot marker across restart and reject wrong-root reconfiguration")
        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])

        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height'] + 1}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={wrong_block_hash}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={wrong_import_hash}",
        ])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        if self.is_wallet_compiled():
            assert_equal(launch.getauxblock()["height"], 1)
        else:
            assert_raises_rpc_error(-18, "requires a loaded wallet", launch.getauxblock)
        assert_equal(launch.createauxblock(launch.get_deterministic_priv_key().address)["height"], 1)

        block_template = launch.getblocktemplate({"rules": ["mweb", "segwit"]})
        snapshot_commitment_hex = reversed_hex(verify["base_hash"])
        assert_equal(block_template["coinbaseaux"]["zkcoin"], "7a6b636f696e")
        assert_equal(block_template["coinbaseaux"]["zkcoin_snapshot"], snapshot_commitment_hex)

        self.log.info("Mine first launch block after importing balances")
        mined = launch.generatetodescriptor(1, "raw(51)")
        assert_equal(len(mined), 1)
        assert_equal(launch.getblockcount(), 1)
        launch_info = launch.getblockchaininfo()
        assert_equal(launch_info["auxpow"]["next_block_active"], True)
        assert_equal(launch_info["ltc_snapshot"]["imported"], True)
        launch_readiness = launch_info["launch_readiness"]
        assert_equal(launch_readiness["ready"], False)
        assert_equal(launch_readiness["snapshot_configured"], True)
        assert_equal(launch_readiness["snapshot_imported"], True)
        assert_equal(launch_readiness["auxpow_active_at_launch"], True)
        assert_equal(launch_readiness["chain_id_configured"], True)
        assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
        assert_equal(launch_readiness["at_launch_tip"], False)
        assert "node is not at the genesis launch tip" in launch_readiness["failures"]
        self.assert_launch_preflight(launch, 1, "node is not at the genesis launch tip")
        coinbase_sig = launch.getblock(mined[0], 2)["tx"][0]["vin"][0]["coinbase"]
        assert "7a6b636f696e" in coinbase_sig
        assert snapshot_commitment_hex in coinbase_sig

        self.log.info("Reject snapshot import after launch has started")
        assert_raises_rpc_error(
            -25,
            "snapshot import is only allowed at the genesis chain tip",
            launch.importsnapshotmanifest,
            dump["path"],
        )


if __name__ == "__main__":
    LitecoinSnapshotLaunchTest().main()
