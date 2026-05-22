#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Litecoin block-X snapshot import during launch."""

import errno
import http.client
import os
import subprocess
from decimal import Decimal

from test_framework.auxpow import parse_auxpow, solve_parent_header
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

    def assert_production_launch_preflight(self, node):
        shielded = node.getblockchaininfo()["shielded_pool"]
        if shielded["scaffold_proofs"] is True:
            self.assert_launch_preflight(node, 1, "shielded scaffold proofs are enabled")
        elif shielded["real_proof_backend"] != "orchard-v1":
            self.assert_launch_preflight(node, 1, "shielded real proof backend is not orchard-v1")
        elif shielded["real_proof_verification"] is not True:
            self.assert_launch_preflight(node, 1, "shielded real proof verification is not available")
        else:
            self.assert_launch_preflight(node, 0, "Launch preflight passed.")

    def assert_snapshot_utxos(self, node, snapshot_utxos):
        for snapshot_utxo in snapshot_utxos:
            txout = node.gettxout(snapshot_utxo["txid"], snapshot_utxo["vout"], False)
            assert txout is not None, f"missing imported snapshot UTXO {snapshot_utxo['txid']}:{snapshot_utxo['vout']}"
            assert_equal(Decimal(str(txout["value"])), snapshot_utxo["value"])
            assert_equal(txout["scriptPubKey"]["hex"], snapshot_utxo["script_hex"])

    def assert_snapshot_imported(self, node, dump, verify):
        snapshot_info = node.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])

    def wait_for_reindexed_launch_block(self, node, expected_hash):
        self.wait_until(lambda: node.getblockcount() == 1, timeout=30)
        assert_equal(node.getbestblockhash(), expected_hash)

    def launch_args(self, dump, verify, *, height=None, block_hash=None, import_hash=None, include_snapshot_file=True, extra_args=()):
        args = [
            "-auxpowheight=1",
            "-noshieldedscaffoldproofs",
            f"-ltcsnapshotheight={height if height is not None else dump['base_height']}",
            f"-ltcsnapshotblockhash={block_hash if block_hash is not None else verify['base_hash']}",
            f"-ltcsnapshotutxoroot={import_hash if import_hash is not None else verify['import_hash']}",
        ]
        if include_snapshot_file:
            args.append(f"-ltcsnapshotfile={dump['path']}")
        return args + list(extra_args)

    def run_test(self):
        source = self.nodes[0]
        launch = self.nodes[1]

        self.log.info("Create a deterministic source-chain UTXO snapshot")
        source_blocks = source.generatetodescriptor(100, "raw(51)")
        source_snapshot_utxos = []
        expected_snapshot_total = Decimal("0")
        for block_hash in source_blocks:
            coinbase = source.getblock(block_hash, 2)["tx"][0]
            output = coinbase["vout"][0]
            value = Decimal(str(output["value"]))
            expected_snapshot_total += value
            source_snapshot_utxos.append({
                "txid": coinbase["txid"],
                "vout": output["n"],
                "value": value,
                "script_hex": output["scriptPubKey"]["hex"],
            })
        snapshot_sample_utxos = [
            source_snapshot_utxos[0],
            source_snapshot_utxos[len(source_snapshot_utxos) // 2],
            source_snapshot_utxos[-1],
        ]
        assert_equal(Decimal(str(source.gettxoutsetinfo()["total_amount"])), expected_snapshot_total)
        self.assert_snapshot_utxos(source, snapshot_sample_utxos)

        dump = source.dumptxoutset("ltc-block-x.dat")
        verify = source.verifysnapshotmanifest(dump["path"])
        wrong_block_hash = ("00" if verify["base_hash"][:2] != "00" else "01") + verify["base_hash"][2:]
        wrong_import_hash = ("00" if verify["import_hash"][:2] != "00" else "01") + verify["import_hash"][2:]

        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["base_height"], dump["base_height"])
        assert_equal(verify["coins"], dump["coins_written"])
        assert_equal(verify["metadata_coins"], dump["coins_written"])
        assert_equal(verify["matches_configured_snapshot"], False)
        assert_equal(Decimal(str(verify["total_amount"])), expected_snapshot_total)

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
        self.start_node(1, extra_args=self.launch_args(dump, verify, height=dump["base_height"] + 1))
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
        self.start_node(1, extra_args=self.launch_args(dump, verify, block_hash=wrong_block_hash))
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
        self.start_node(1, extra_args=self.launch_args(dump, verify, import_hash=wrong_import_hash))
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
        self.start_node(1, extra_args=self.launch_args(dump, verify))

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
        self.restart_node(1, extra_args=self.launch_args(dump, verify, extra_args=[
            "-dbbatchsize=1",
            "-dbcrashratio=1",
        ]))
        launch = self.nodes[1]
        self.assert_import_crashes(launch, dump["path"])
        self.start_node(1, extra_args=self.launch_args(dump, verify))
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
        assert_equal(Decimal(str(imported["total_amount"])), expected_snapshot_total)
        assert_equal(Decimal(str(launch.gettxoutsetinfo()["total_amount"])), expected_snapshot_total)
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)

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
        assert_equal(launch_readiness["chain_id_parent_version_safe"], True)
        assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
        assert_equal(launch_readiness["at_launch_tip"], True)
        assert_equal(launch_readiness["failures"], [])
        self.assert_production_launch_preflight(launch)

        self.log.info("Reject launch preflight when AuxPoW chain id is not production-safe")
        unsafe_chain_id_args = [
            ("-auxpowchainid=0", "AuxPoW chain id is not configured for strict merge mining", True),
            ("-noauxpowstrictchainid", "AuxPoW chain id is not configured for strict merge mining", True),
            ("-auxpowchainid=8192", "AuxPoW chain id overlaps Litecoin parent versionbits chain-id range", False),
        ]
        for extra_arg, failure, parent_version_safe in unsafe_chain_id_args:
            self.restart_node(1, extra_args=self.launch_args(dump, verify, extra_args=[extra_arg]))
            launch = self.nodes[1]
            launch_readiness = launch.getblockchaininfo()["launch_readiness"]
            assert_equal(launch_readiness["ready"], False)
            assert_equal(launch_readiness["snapshot_configured"], True)
            assert_equal(launch_readiness["snapshot_imported"], True)
            assert_equal(launch_readiness["auxpow_active_at_launch"], True)
            assert_equal(launch_readiness["chain_id_configured"], False)
            assert_equal(launch_readiness["chain_id_parent_version_safe"], parent_version_safe)
            assert_equal(launch_readiness["shielded_inactive_at_launch"], True)
            assert_equal(launch_readiness["at_launch_tip"], True)
            assert failure in launch_readiness["failures"]
            self.assert_launch_preflight(launch, 1, failure)
        self.restart_node(1, extra_args=self.launch_args(dump, verify))
        launch = self.nodes[1]

        self.log.info("Allow replaying the same snapshot import before launch mining")
        replayed = launch.importsnapshotmanifest(dump["path"])
        assert_equal(replayed["configured_snapshot"], True)
        assert_equal(replayed["base_hash"], verify["base_hash"])
        assert_equal(replayed["base_height"], verify["base_height"])
        assert_equal(replayed["import_hash"], verify["import_hash"])
        assert_equal(replayed["coins_imported"], verify["coins"])
        assert_equal(Decimal(str(replayed["total_amount"])), expected_snapshot_total)
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["import_in_progress"], False)

        self.log.info("Persist imported snapshot marker across restart and reject wrong-root reconfiguration")
        self.restart_node(1, extra_args=self.launch_args(dump, verify))
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], True)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)

        self.log.info("Reject snapshot reindex startup without the snapshot manifest path")
        self.stop_node(1)
        for reindex_arg in ("-reindex-chainstate", "-reindex"):
            self.nodes[1].assert_start_raises_init_error(
                extra_args=self.launch_args(dump, verify, include_snapshot_file=False, extra_args=[reindex_arg]),
                expected_msg="-ltcsnapshotfile is required when rebuilding chainstate with configured Litecoin snapshot parameters",
                match=ErrorMatch.PARTIAL_REGEX,
            )
        self.start_node(1, extra_args=self.launch_args(dump, verify))
        launch = self.nodes[1]

        self.restart_node(1, extra_args=self.launch_args(dump, verify, height=dump["base_height"] + 1))
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=self.launch_args(dump, verify, block_hash=wrong_block_hash))
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_height"], dump["base_height"])
        assert_equal(snapshot_info["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=self.launch_args(dump, verify, import_hash=wrong_import_hash))
        snapshot_info = launch.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["imported_hash"], verify["import_hash"])
        self.assert_launch_block_rejected(launch, "configured Litecoin snapshot import hash mismatch")
        assert_equal(launch.getblockcount(), 0)

        self.restart_node(1, extra_args=self.launch_args(dump, verify))
        if self.is_wallet_compiled():
            assert_equal(launch.getauxblock()["height"], 1)
        else:
            assert_raises_rpc_error(-18, "requires a loaded wallet", launch.getauxblock)
        launch_candidate = launch.createauxblock(launch.get_deterministic_priv_key().address)
        assert_equal(launch_candidate["height"], 1)

        block_template = launch.getblocktemplate({"rules": ["mweb", "segwit"]})
        snapshot_commitment_hex = reversed_hex(verify["base_hash"])
        assert_equal(block_template["coinbaseaux"]["zkcoin"], "7a6b636f696e")
        assert_equal(block_template["coinbaseaux"]["zkcoin_snapshot"], snapshot_commitment_hex)

        self.log.info("Mine first launch block through an AuxPoW candidate after importing balances")
        launch_auxpow = parse_auxpow(launch_candidate["defaultauxpow"])
        solve_parent_header(launch_auxpow, int(launch_candidate["bits"], 16))
        assert_equal(launch.submitauxblock(launch_candidate["hash"], launch_auxpow.serialize().hex()), True)
        assert_equal(launch.getblockcount(), 1)
        assert_equal(launch.getbestblockhash(), launch_candidate["hash"])
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
        coinbase_sig = launch.getblock(launch_candidate["hash"], 2)["tx"][0]["vin"][0]["coinbase"]
        assert "7a6b636f696e" in coinbase_sig
        assert snapshot_commitment_hex in coinbase_sig
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)

        self.log.info("Rebuild snapshot launch state with reindex-chainstate")
        self.restart_node(1, extra_args=self.launch_args(dump, verify, extra_args=["-reindex-chainstate"]))
        launch = self.nodes[1]
        self.wait_for_reindexed_launch_block(launch, launch_candidate["hash"])
        self.assert_snapshot_imported(launch, dump, verify)
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)

        self.log.info("Rebuild snapshot launch state with full reindex")
        self.restart_node(1, extra_args=self.launch_args(dump, verify, extra_args=["-reindex"]))
        launch = self.nodes[1]
        self.wait_for_reindexed_launch_block(launch, launch_candidate["hash"])
        self.assert_snapshot_imported(launch, dump, verify)
        self.assert_snapshot_utxos(launch, snapshot_sample_utxos)

        self.log.info("Reject snapshot import after launch has started")
        assert_raises_rpc_error(
            -25,
            "snapshot import is only allowed at the genesis chain tip",
            launch.importsnapshotmanifest,
            dump["path"],
        )


if __name__ == "__main__":
    LitecoinSnapshotLaunchTest().main()
