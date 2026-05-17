#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Litecoin block-X snapshot import during launch."""

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

    def run_test(self):
        source = self.nodes[0]
        launch = self.nodes[1]

        self.log.info("Create a deterministic source-chain UTXO snapshot")
        source.generatetodescriptor(100, "raw(51)")
        dump = source.dumptxoutset("ltc-block-x.dat")
        verify = source.verifysnapshotmanifest(dump["path"])

        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["base_height"], dump["base_height"])
        assert_equal(verify["coins"], dump["coins_written"])
        assert_equal(verify["metadata_coins"], dump["coins_written"])
        assert_equal(verify["matches_configured_snapshot"], False)

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

        self.log.info("Restart launch node with block-X snapshot and AuxPoW activation parameters")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])

        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["enabled"], True)
        assert_equal(snapshot_info["height"], dump["base_height"])
        assert_equal(snapshot_info["block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["import_hash"], verify["import_hash"])
        assert_equal(snapshot_info["imported"], False)

        self.log.info("Require configured snapshot import before launch mining")
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot has not been imported",
            launch.generatetodescriptor,
            1,
            "raw(51)",
        )
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot has not been imported",
            launch.getauxblock,
        )
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot has not been imported",
            launch.createauxblock,
            launch.get_deterministic_priv_key().address,
        )
        assert_equal(launch.getblockcount(), 0)

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
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot import hash mismatch",
            launch.generatetodescriptor,
            1,
            "raw(51)",
        )
        assert_equal(launch.getblockcount(), 0)

        wrong_block_hash = ("00" if verify["base_hash"][:2] != "00" else "01") + verify["base_hash"][2:]
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
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot import hash mismatch",
            launch.generatetodescriptor,
            1,
            "raw(51)",
        )
        assert_equal(launch.getblockcount(), 0)

        wrong_import_hash = ("00" if verify["import_hash"][:2] != "00" else "01") + verify["import_hash"][2:]
        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={wrong_import_hash}",
        ])
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        assert_raises_rpc_error(
            -1,
            "configured Litecoin snapshot import hash mismatch",
            launch.generatetodescriptor,
            1,
            "raw(51)",
        )
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        assert_equal(launch.getauxblock()["height"], 1)
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
