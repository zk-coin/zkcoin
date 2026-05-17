#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the shielded pool consensus marker scaffold."""

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import CScript, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error
from test_framework.wallet import MiniWallet


MARKER_PREFIX = b"zkcoin-shielded-v0"
ACTION_MINT = 0x01
ACTION_SPEND = 0x02


class ShieldedPoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 3
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [
            [],
            ["-shieldedheight=1"],
            ["-shieldedheight=200"],
        ]

    def setup_network(self):
        self.setup_nodes()

    def make_marker_tx(self, wallet, *, action=ACTION_MINT, marker_value=0, marker_count=1):
        utxo = wallet._utxos.pop(0)
        input_value = int(utxo["value"] * COIN)
        fee = 1000

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(input_value - fee, wallet._scriptPubKey)]

        payload = MARKER_PREFIX + bytes([action])
        for _ in range(marker_count):
            tx.vout.append(CTxOut(marker_value, CScript([OP_RETURN, payload])))

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [CScript([OP_TRUE])]
        tx.rehash()
        return tx.serialize().hex(), tx.hash

    def run_test(self):
        disabled = self.nodes[0]
        active = self.nodes[1]
        future = self.nodes[2]
        wallets = [MiniWallet(node) for node in self.nodes]

        for wallet in wallets:
            wallet.generate(120)

        self.log.info("Expose disabled and activated shielded pool state")
        assert_equal(disabled.getblockchaininfo()["shielded_pool"]["start_height"], -1)
        assert_equal(disabled.getblockchaininfo()["shielded_pool"]["next_block_active"], False)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["start_height"], 1)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["next_block_active"], True)
        assert_equal(future.getblockchaininfo()["shielded_pool"]["start_height"], 200)
        assert_equal(future.getblockchaininfo()["shielded_pool"]["next_block_active"], False)

        self.log.info("Reject shielded marker transactions before activation")
        raw_disabled, _ = self.make_marker_tx(wallets[0])
        assert_raises_rpc_error(-26, "bad-shielded-before-activation", disabled.sendrawtransaction, raw_disabled)
        assert_raises_rpc_error(
            -25,
            "TestBlockValidity failed: bad-shielded-before-activation",
            disabled.generateblock,
            ADDRESS_BCRT1_P2WSH_OP_TRUE,
            [raw_disabled],
        )

        raw_future, _ = self.make_marker_tx(wallets[2])
        assert_raises_rpc_error(-26, "bad-shielded-before-activation", future.sendrawtransaction, raw_future)

        self.log.info("Reject malformed active shielded marker transactions")
        raw_bad_action, _ = self.make_marker_tx(wallets[1], action=0xFF)
        assert_raises_rpc_error(-26, "bad-shielded-payload", active.sendrawtransaction, raw_bad_action)

        raw_nonzero, _ = self.make_marker_tx(wallets[1], marker_value=1)
        assert_raises_rpc_error(-26, "bad-shielded-value", active.sendrawtransaction, raw_nonzero)

        raw_duplicate, _ = self.make_marker_tx(wallets[1], marker_count=2)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate", active.sendrawtransaction, raw_duplicate)

        self.log.info("Accept and mine activated shielded marker transactions")
        raw_active, txid = self.make_marker_tx(wallets[1], action=ACTION_SPEND)
        accepted_txid = active.sendrawtransaction(raw_active)
        assert_equal(accepted_txid, txid)
        block_hash = active.generatetoaddress(1, ADDRESS_BCRT1_P2WSH_OP_TRUE)[0]
        assert txid in active.getblock(block_hash)["tx"]


if __name__ == "__main__":
    ShieldedPoolTest().main()
