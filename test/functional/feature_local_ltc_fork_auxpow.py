#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a local Litecoin-style fork launch followed by AuxPoW merge mining."""

from decimal import Decimal

from test_framework.auxpow import build_parent_auxpow
from test_framework.blocktools import (
    COIN,
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    create_coinbase,
    script_BIP34_coinbase_height,
)
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut
from test_framework.script import CScript
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class LocalLitecoinForkAuxPowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def setup_network(self):
        self.setup_nodes()

    def create_parent_balance_tx(self, coinbase_tx, alice_script, bob_script):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(coinbase_tx.sha256, 0), b"", 0xffffffff))
        tx.vout.append(CTxOut(5 * COIN, alice_script))
        tx.vout.append(CTxOut(7 * COIN, bob_script))
        tx.vout.append(CTxOut(coinbase_tx.vout[0].nValue - 12 * COIN - 100000, bob_script))
        tx.calc_sha256()
        return tx

    def mine_parent_block(self, parent, *, txlist=None, commitment_hex=None):
        tmpl = parent.getblocktemplate(NORMAL_GBT_REQUEST_PARAMS)
        height = tmpl["height"]
        coinbase = create_coinbase(height)
        if commitment_hex is not None:
            coinbase.vin[0].scriptSig = CScript(
                bytes(script_BIP34_coinbase_height(height)) + bytes(CScript([bytes.fromhex(commitment_hex)]))
            )
            coinbase.rehash()

        block = create_block(coinbase=coinbase, tmpl=tmpl, txlist=txlist)
        block.solve()
        assert_equal(parent.submitblock(block.serialize().hex()), None)
        assert_equal(parent.getbestblockhash(), block.hash)
        return block

    def assert_child_snapshot_imported(self, child, dump, verify):
        snapshot = child.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot["imported"], True)
        assert_equal(snapshot["imported_height"], dump["base_height"])
        assert_equal(snapshot["imported_block_hash"], verify["base_hash"])
        assert_equal(snapshot["imported_hash"], verify["import_hash"])

    def run_test(self):
        parent = self.nodes[0]
        child = self.nodes[1]

        self.log.info("Build a local Litecoin-style parent chain with named balances")
        alice_key = child.get_deterministic_priv_key()
        bob_key = parent.get_deterministic_priv_key()
        alice_script = bytes.fromhex(child.validateaddress(alice_key.address)["scriptPubKey"])
        bob_script = bytes.fromhex(child.validateaddress(bob_key.address)["scriptPubKey"])
        parent_blocks = [self.mine_parent_block(parent) for _ in range(101)]
        parent_balance_tx = self.create_parent_balance_tx(parent_blocks[0].vtx[0], alice_script, bob_script)
        self.mine_parent_block(parent, txlist=[parent_balance_tx])

        alice_outpoint = {"txid": parent_balance_tx.hash, "vout": 0}
        bob_outpoint = {"txid": parent_balance_tx.hash, "vout": 1}
        parent_alice = parent.gettxout(alice_outpoint["txid"], alice_outpoint["vout"])
        parent_bob = parent.gettxout(bob_outpoint["txid"], bob_outpoint["vout"])
        assert_equal(Decimal(str(parent_alice["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(parent_bob["value"])), Decimal("7.00000000"))

        self.log.info("Snapshot the local parent chain at block X")
        dump = parent.dumptxoutset("local-ltc-block-x.dat")
        verify = parent.verifysnapshotmanifest(dump["path"])
        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["import_hash"], parent.verifysnapshotmanifest(dump["path"])["import_hash"])

        self.log.info("Start child chain with block-X snapshot and AuxPoW activation")
        self.stop_node(1)
        self.start_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        child = self.nodes[1]
        imported = child.importsnapshotmanifest(dump["path"])
        assert_equal(imported["configured_snapshot"], True)
        assert_equal(imported["base_height"], dump["base_height"])
        assert_equal(imported["import_hash"], verify["import_hash"])
        self.assert_child_snapshot_imported(child, dump, verify)

        self.log.info("Verify Alice and Bob UTXOs exist on the child chain")
        child_alice = child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"])
        child_bob = child.gettxout(bob_outpoint["txid"], bob_outpoint["vout"])
        assert_equal(Decimal(str(child_alice["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(child_bob["value"])), Decimal("7.00000000"))

        self.log.info("Spend Alice's imported UTXO on the child before mining the AuxPoW block")
        raw_spend = child.createrawtransaction(
            [alice_outpoint],
            {bob_key.address: Decimal("4.99900000")},
        )
        signed_spend = child.signrawtransactionwithkey(raw_spend, [alice_key.key], [{
            "txid": alice_outpoint["txid"],
            "vout": alice_outpoint["vout"],
            "scriptPubKey": child_alice["scriptPubKey"]["hex"],
            "amount": Decimal("5.00000000"),
        }])
        assert_equal(signed_spend["complete"], True)
        spend_txid = child.sendrawtransaction(signed_spend["hex"])

        self.log.info("Reject a local parent AuxPoW proof with the wrong commitment")
        candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(candidate["height"], 1)
        assert_equal(candidate["previousblockhash"], child.getbestblockhash())
        assert_equal(candidate["chainid"], child.getblockchaininfo()["auxpow"]["chain_id"])
        assert_equal(candidate["auxpowcommitment"], "fabe6d6d" + candidate["hash"] + "0100000000000000")
        wrong_commitment = (
            candidate["auxpowcommitment"][:8] +
            ("00" if candidate["auxpowcommitment"][8:10] != "00" else "01") +
            candidate["auxpowcommitment"][10:]
        )
        bad_parent_block = self.mine_parent_block(parent, commitment_hex=wrong_commitment)
        bad_auxpow = build_parent_auxpow(bad_parent_block)
        assert_equal(child.getauxblock(candidate["hash"], bad_auxpow.serialize().hex()), "high-hash")
        assert_equal(child.getblockcount(), 0)
        assert spend_txid in child.getrawmempool()
        assert_equal(child.getbestblockhash(), child.getblockhash(0))

        self.log.info("Mine a child block using a real local parent block AuxPoW proof")
        parent_aux_tx = self.create_parent_balance_tx(parent_blocks[1].vtx[0], bob_script, bob_script)
        parent_block = self.mine_parent_block(parent, txlist=[parent_aux_tx], commitment_hex=candidate["auxpowcommitment"])
        non_coinbase_auxpow = build_parent_auxpow(parent_block, tx_index=1)
        assert_equal(non_coinbase_auxpow.index, 1)
        assert_equal(len(non_coinbase_auxpow.merkle_branch), 1)
        assert_equal(child.getauxblock(candidate["hash"], non_coinbase_auxpow.serialize().hex()), "high-hash")
        assert_equal(child.getblockcount(), 0)
        assert spend_txid in child.getrawmempool()
        assert_equal(child.getbestblockhash(), child.getblockhash(0))

        auxpow = build_parent_auxpow(parent_block)
        assert_equal(auxpow.index, 0)
        assert_equal(len(auxpow.merkle_branch), 1)
        assert_equal(child.submitauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getbestblockhash(), candidate["hash"])
        assert spend_txid in child.getblock(candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        child_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(child_spend["value"])), Decimal("4.99900000"))

        self.log.info("Invalidate and reconsider the AuxPoW block to test imported UTXO undo")
        child.invalidateblock(candidate["hash"])
        assert_equal(child.getblockcount(), 0)
        restored_alice = child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False)
        assert_equal(Decimal(str(restored_alice["value"])), Decimal("5.00000000"))
        assert_equal(child.gettxout(spend_txid, 0, False), None)

        child.reconsiderblock(candidate["hash"])
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getbestblockhash(), candidate["hash"])
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        reconsidered_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(reconsidered_spend["value"])), Decimal("4.99900000"))

        self.log.info("Persist and reload child AuxPoW header from disk")
        child_header_hex = child.getblockheader(candidate["hash"], False)
        assert child_header_hex.startswith(candidate["header"])
        assert len(child_header_hex) > len(candidate["header"])
        self.restart_node(1, extra_args=[
            "-auxpowheight=1",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={verify['import_hash']}",
        ])
        child = self.nodes[1]
        assert_equal(child.getblockheader(candidate["hash"], False), child_header_hex)
        self.assert_child_snapshot_imported(child, dump, verify)
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        reloaded_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_spend["value"])), Decimal("4.99900000"))


if __name__ == "__main__":
    LocalLitecoinForkAuxPowTest().main()
