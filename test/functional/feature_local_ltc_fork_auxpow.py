#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test a local Litecoin-style fork launch followed by AuxPoW merge mining."""

import hashlib

from decimal import Decimal

from test_framework.auxpow import build_parent_auxpow
from test_framework.blocktools import (
    COIN,
    NORMAL_GBT_REQUEST_PARAMS,
    create_block,
    create_coinbase,
    script_BIP34_coinbase_height,
)
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_array_result, assert_equal, assert_raises_rpc_error


MARKER_PREFIX = b"zkc0"
ACTION_MINT = 0x01
ACTION_SPEND = 0x02
PROOF_TAG_SIZE = 3
PROOF_ENVELOPE_PREFIX = b"zkc-p4"
PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX = b"zkc-public-input-v1"
PROOF_BUNDLE_PREIMAGE_PREFIX = b"zkc-proof-bundle-v4"
ORCHARD_PROOF_PAYLOAD_PREFIX = b"zkc-orchard-proof-v1"
ORCHARD_PROOF_BODY_PREFIX = b"zkc-orchard-body-v1"
ORCHARD_REAL_PROOF_PREFIX = b"zkc-orchard-real-v1"
ORCHARD_REAL_NATIVE_PROOF_PREFIX = b"zkc-orchard-native-proof-v1"
ORCHARD_REAL_VERIFIER_INPUT_PREIMAGE_PREFIX = b"zkc-orchard-real-input-v1"
ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX = b"zkc-orchard-real-vk-v1"
PROOF_BUNDLE_VERSION = 0x01
PROOF_SYSTEM_ORCHARD = 0x01
PROOF_BUNDLE_FLAGS_NONE = 0x00
ORCHARD_PROOF_BODY_MODE_SCAFFOLD = 0x00
ORCHARD_PROOF_BODY_MODE_REAL = 0x01
PROOF_SCRIPT = CScript([OP_DROP, OP_TRUE])


class LocalLitecoinForkAuxPowTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False

    def setup_network(self):
        self.setup_nodes()

    def create_parent_balance_tx(self, coinbase_tx, alice_script, bob_script, proof_script):
        tx = CTransaction()
        tx.vin.append(CTxIn(COutPoint(coinbase_tx.sha256, 0), b"", 0xffffffff))
        tx.vout.append(CTxOut(5 * COIN, alice_script))
        tx.vout.append(CTxOut(7 * COIN, bob_script))
        tx.vout.append(CTxOut(5 * COIN, proof_script))
        tx.vout.append(CTxOut(6 * COIN, proof_script))
        tx.vout.append(CTxOut(coinbase_tx.vout[0].nValue - 23 * COIN - 100000, bob_script))
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

    def assert_wallet_coinbase(self, node, block_hash, coinbasevalue, previous_immature):
        amount = Decimal(coinbasevalue) / Decimal(COIN)
        coinbase_txid = node.getblock(block_hash)["tx"][0]
        wallet_tx = node.gettransaction(coinbase_txid)
        assert_equal(wallet_tx["generated"], True)
        assert_equal(wallet_tx["blockhash"], block_hash)
        assert_array_result(wallet_tx["details"], {"category": "immature"}, {"amount": amount})
        assert_equal(node.getbalances()["mine"]["immature"], previous_immature + amount)

    def child_launch_args(self, dump, verify, import_hash=None):
        return [
            "-acceptnonstdtxn=1",
            "-auxpowheight=1",
            "-shieldedheight=2",
            f"-ltcsnapshotheight={dump['base_height']}",
            f"-ltcsnapshotblockhash={verify['base_hash']}",
            f"-ltcsnapshotutxoroot={import_hash or verify['import_hash']}",
            f"-ltcsnapshotfile={dump['path']}",
        ]

    def shielded_commitment(self, label):
        return hashlib.sha256(label.encode()).digest()

    def shielded_nullifier(self, label):
        return hashlib.sha256(label.encode()).digest()

    def root_hex_to_payload_bytes(self, root_hex):
        return bytes.fromhex(root_hex)[::-1]

    def shielded_proof_hash(self, action, shielded_value, commitment=None, nullifier=None, anchor=None):
        if action == ACTION_MINT:
            preimage = b"zkc-proof-v0" + bytes([action]) + shielded_value.to_bytes(8, "little") + commitment
        elif action == ACTION_SPEND:
            preimage = b"zkc-proof-v0" + bytes([action]) + shielded_value.to_bytes(8, "little") + nullifier + anchor
        else:
            raise AssertionError(f"unknown shielded action {action}")
        return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()

    def shielded_proof_tag(self, action, shielded_value, commitment=None, nullifier=None, anchor=None):
        return self.shielded_proof_hash(action, shielded_value, commitment=commitment, nullifier=nullifier, anchor=anchor)[:PROOF_TAG_SIZE]

    def hash256(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def shielded_proof_envelope(self, tx, action, shielded_value, commitment=None, nullifier=None, anchor=None):
        proof_hash = self.shielded_proof_hash(action, shielded_value, commitment=commitment, nullifier=nullifier, anchor=anchor)
        tx_binding_hash = self.hash256(tx.serialize_without_witness())
        public_input_hash = self.hash256(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX + bytes([action]) + proof_hash + tx_binding_hash)
        proof_digest = self.hash256(PROOF_BUNDLE_PREIMAGE_PREFIX + bytes([PROOF_BUNDLE_VERSION, action, PROOF_SYSTEM_ORCHARD, PROOF_BUNDLE_FLAGS_NONE]) + public_input_hash)
        proof_body = (
            ORCHARD_PROOF_BODY_PREFIX
            + bytes([ORCHARD_PROOF_BODY_MODE_SCAFFOLD])
            + len(proof_digest).to_bytes(4, "little")
            + proof_digest
        )
        proof_payload = (
            ORCHARD_PROOF_PAYLOAD_PREFIX
            + bytes([action])
            + public_input_hash
            + len(proof_body).to_bytes(4, "little")
            + proof_body
        )
        return (
            PROOF_ENVELOPE_PREFIX
            + bytes([PROOF_BUNDLE_VERSION, action, PROOF_SYSTEM_ORCHARD, PROOF_BUNDLE_FLAGS_NONE])
            + public_input_hash
            + len(proof_payload).to_bytes(4, "little")
            + proof_payload
        )

    def shielded_real_proof_envelope(self, tx, action, shielded_value, commitment=None, nullifier=None, anchor=None, native_proof_bytes=None):
        if native_proof_bytes is None:
            native_proof_bytes = b"\x42" * 192

        proof_hash = self.shielded_proof_hash(action, shielded_value, commitment=commitment, nullifier=nullifier, anchor=anchor)
        tx_binding_hash = self.hash256(tx.serialize_without_witness())
        public_input_hash = self.hash256(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX + bytes([action]) + proof_hash + tx_binding_hash)
        verifier_key_hash = self.hash256(ORCHARD_REAL_VERIFIER_KEY_HASH_PREIMAGE_PREFIX)
        verifier_input_hash = self.hash256(ORCHARD_REAL_VERIFIER_INPUT_PREIMAGE_PREFIX + bytes([action]) + public_input_hash + verifier_key_hash)
        native_proof = (
            ORCHARD_REAL_NATIVE_PROOF_PREFIX
            + bytes([PROOF_BUNDLE_FLAGS_NONE])
            + verifier_key_hash
            + verifier_input_hash
            + len(native_proof_bytes).to_bytes(4, "little")
            + native_proof_bytes
        )
        real_proof = (
            ORCHARD_REAL_PROOF_PREFIX
            + bytes([PROOF_BUNDLE_FLAGS_NONE, action])
            + public_input_hash
            + verifier_key_hash
            + len(native_proof).to_bytes(4, "little")
            + native_proof
        )
        proof_body = (
            ORCHARD_PROOF_BODY_PREFIX
            + bytes([ORCHARD_PROOF_BODY_MODE_REAL])
            + len(real_proof).to_bytes(4, "little")
            + real_proof
        )
        proof_payload = (
            ORCHARD_PROOF_PAYLOAD_PREFIX
            + bytes([action])
            + public_input_hash
            + len(proof_body).to_bytes(4, "little")
            + proof_body
        )
        return (
            PROOF_ENVELOPE_PREFIX
            + bytes([PROOF_BUNDLE_VERSION, action, PROOF_SYSTEM_ORCHARD, PROOF_BUNDLE_FLAGS_NONE])
            + public_input_hash
            + len(proof_payload).to_bytes(4, "little")
            + proof_payload
        )

    def flip_proof_byte(self, proof_envelope, offset):
        return proof_envelope[:offset] + bytes([proof_envelope[offset] ^ 0x01]) + proof_envelope[offset + 1 :]

    def create_shielded_mint_tx(self, node, outpoint, prev_txout, destination, commitment, shielded_value=COIN, proof_mode=ORCHARD_PROOF_BODY_MODE_SCAFFOLD, native_proof_bytes=None, mutate_public_input=False, mutate_proof_payload=False):
        prev_value = int(Decimal(str(prev_txout["value"])) * Decimal(COIN))
        payload = (
            MARKER_PREFIX
            + bytes([ACTION_MINT])
            + shielded_value.to_bytes(8, "little")
            + commitment
            + self.shielded_proof_tag(ACTION_MINT, shielded_value, commitment=commitment)
        )
        destination_script = bytes.fromhex(node.validateaddress(destination)["scriptPubKey"])

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(outpoint["txid"], 16), outpoint["vout"]))]
        tx.vout = [
            CTxOut(prev_value - shielded_value - 100000, destination_script),
            CTxOut(0, CScript([OP_RETURN, payload])),
        ]
        if proof_mode == ORCHARD_PROOF_BODY_MODE_REAL:
            proof_envelope = self.shielded_real_proof_envelope(
                tx,
                ACTION_MINT,
                shielded_value,
                commitment=commitment,
                native_proof_bytes=native_proof_bytes,
            )
        elif proof_mode == ORCHARD_PROOF_BODY_MODE_SCAFFOLD:
            proof_envelope = self.shielded_proof_envelope(tx, ACTION_MINT, shielded_value, commitment=commitment)
        else:
            raise AssertionError(f"unknown proof body mode {proof_mode}")
        if mutate_public_input:
            proof_envelope = self.flip_proof_byte(proof_envelope, len(PROOF_ENVELOPE_PREFIX) + 4)
        if mutate_proof_payload:
            proof_envelope = self.flip_proof_byte(proof_envelope, len(proof_envelope) - 1)

        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [proof_envelope, PROOF_SCRIPT]
        tx.rehash()
        return tx.serialize().hex()

    def create_shielded_spend_tx(self, outpoint, prev_txout, destination_script, nullifier, anchor, shielded_value=COIN):
        prev_value = int(Decimal(str(prev_txout["value"])) * Decimal(COIN))
        payload = (
            MARKER_PREFIX
            + bytes([ACTION_SPEND])
            + shielded_value.to_bytes(8, "little")
            + nullifier
            + anchor
            + self.shielded_proof_tag(ACTION_SPEND, shielded_value, nullifier=nullifier, anchor=anchor)
        )

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(outpoint["txid"], 16), outpoint["vout"]))]
        tx.vout = [
            CTxOut(prev_value + shielded_value - 100000, destination_script),
            CTxOut(0, CScript([OP_RETURN, payload])),
        ]
        proof_envelope = self.shielded_proof_envelope(tx, ACTION_SPEND, shielded_value, nullifier=nullifier, anchor=anchor)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = [proof_envelope, PROOF_SCRIPT]
        tx.rehash()
        return tx.serialize().hex(), tx.hash

    def run_test(self):
        parent = self.nodes[0]
        child = self.nodes[1]

        self.log.info("Build a local Litecoin-style parent chain with named balances")
        alice_key = child.get_deterministic_priv_key()
        bob_key = parent.get_deterministic_priv_key()
        alice_script = bytes.fromhex(child.validateaddress(alice_key.address)["scriptPubKey"])
        bob_script = bytes.fromhex(child.validateaddress(bob_key.address)["scriptPubKey"])
        proof_script = script_to_p2wsh_script(PROOF_SCRIPT)
        parent_blocks = [self.mine_parent_block(parent) for _ in range(101)]
        parent_balance_tx = self.create_parent_balance_tx(parent_blocks[0].vtx[0], alice_script, bob_script, proof_script)
        block_x = self.mine_parent_block(parent, txlist=[parent_balance_tx])

        alice_outpoint = {"txid": parent_balance_tx.hash, "vout": 0}
        bob_outpoint = {"txid": parent_balance_tx.hash, "vout": 1}
        proof_outpoint = {"txid": parent_balance_tx.hash, "vout": 2}
        duplicate_proof_outpoint = {"txid": parent_balance_tx.hash, "vout": 3}
        miner_coinbase_outpoint = {"txid": block_x.vtx[0].hash, "vout": 0}
        parent_alice = parent.gettxout(alice_outpoint["txid"], alice_outpoint["vout"])
        parent_bob = parent.gettxout(bob_outpoint["txid"], bob_outpoint["vout"])
        parent_proof = parent.gettxout(proof_outpoint["txid"], proof_outpoint["vout"])
        parent_duplicate_proof = parent.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"])
        parent_miner_coinbase = parent.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"])
        assert_equal(Decimal(str(parent_alice["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(parent_bob["value"])), Decimal("7.00000000"))
        assert_equal(Decimal(str(parent_proof["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(parent_duplicate_proof["value"])), Decimal("6.00000000"))
        assert_equal(Decimal(str(parent_miner_coinbase["value"])), Decimal("50.00000000"))
        assert_equal(parent_miner_coinbase["coinbase"], True)

        self.log.info("Snapshot the local parent chain at block X")
        dump = parent.dumptxoutset("local-ltc-block-x.dat")
        verify = parent.verifysnapshotmanifest(dump["path"])
        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["import_hash"], parent.verifysnapshotmanifest(dump["path"])["import_hash"])
        block_x_plus_one = self.mine_parent_block(parent)
        excluded_miner_coinbase_outpoint = {"txid": block_x_plus_one.vtx[0].hash, "vout": 0}
        parent_excluded_miner_coinbase = parent.gettxout(excluded_miner_coinbase_outpoint["txid"], excluded_miner_coinbase_outpoint["vout"])
        assert_equal(Decimal(str(parent_excluded_miner_coinbase["value"])), Decimal("50.00000000"))
        assert_equal(parent_excluded_miner_coinbase["coinbase"], True)
        parent_immature_coinbase_spend = parent.createrawtransaction(
            [miner_coinbase_outpoint],
            {bob_key.address: Decimal("49.99900000")},
        )
        assert_raises_rpc_error(
            -26,
            "bad-txns-premature-spend-of-coinbase",
            parent.sendrawtransaction,
            parent_immature_coinbase_spend,
        )

        self.log.info("Reject a wrong-root local snapshot import without mutating named child UTXOs")
        wrong_import_hash = ("00" if verify["import_hash"][:2] != "00" else "01") + verify["import_hash"][2:]
        self.stop_node(1)
        self.start_node(1, extra_args=self.child_launch_args(dump, verify, wrong_import_hash))
        child = self.nodes[1]
        assert_raises_rpc_error(
            -8,
            "snapshot import hash mismatch",
            child.importsnapshotmanifest,
            dump["path"],
        )
        snapshot_info = child.getblockchaininfo()["ltc_snapshot"]
        assert_equal(snapshot_info["imported"], False)
        assert_equal(snapshot_info["import_in_progress"], False)
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"]), None)
        assert_equal(child.gettxout(bob_outpoint["txid"], bob_outpoint["vout"]), None)
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"]), None)
        assert_equal(child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"]), None)
        assert_equal(child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"]), None)
        assert_equal(child.gettxout(excluded_miner_coinbase_outpoint["txid"], excluded_miner_coinbase_outpoint["vout"]), None)

        self.log.info("Start child chain with block-X snapshot and AuxPoW activation")
        self.stop_node(1)
        self.start_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        imported = child.importsnapshotmanifest(dump["path"])
        assert_equal(imported["configured_snapshot"], True)
        assert_equal(imported["base_height"], dump["base_height"])
        assert_equal(imported["import_hash"], verify["import_hash"])
        self.assert_child_snapshot_imported(child, dump, verify)
        assert_equal(child.getblockchaininfo()["shielded_pool"]["start_height"], 2)
        assert_equal(child.getblockchaininfo()["shielded_pool"]["next_block_active"], False)
        assert_equal(child.getblockchaininfo()["shielded_pool"]["scaffold_proofs"], True)
        assert_equal(Decimal(str(child.getblockchaininfo()["shielded_pool"]["value_pool"])), Decimal("0.00000000"))

        self.log.info("Replay the same local parent snapshot before mining starts")
        replayed = child.importsnapshotmanifest(dump["path"])
        assert_equal(replayed["configured_snapshot"], True)
        assert_equal(replayed["base_height"], dump["base_height"])
        assert_equal(replayed["import_hash"], verify["import_hash"])
        self.assert_child_snapshot_imported(child, dump, verify)

        self.log.info("Verify Alice, Bob, and block-X miner coinbase exist on the child chain")
        child_alice = child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"])
        child_bob = child.gettxout(bob_outpoint["txid"], bob_outpoint["vout"])
        child_proof = child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"])
        child_duplicate_proof = child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"])
        child_miner_coinbase = child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"])
        assert_equal(Decimal(str(child_alice["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(child_bob["value"])), Decimal("7.00000000"))
        assert_equal(Decimal(str(child_proof["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(child_duplicate_proof["value"])), Decimal("6.00000000"))
        assert_equal(Decimal(str(child_miner_coinbase["value"])), Decimal("50.00000000"))
        assert_equal(child_miner_coinbase["coinbase"], False)
        assert_equal(child.gettxout(excluded_miner_coinbase_outpoint["txid"], excluded_miner_coinbase_outpoint["vout"]), None)

        self.log.info("Spend Alice's imported normal UTXO on the child before mining the AuxPoW block")
        raw_alice_spend = child.createrawtransaction(
            [alice_outpoint],
            {bob_key.address: Decimal("4.99900000")},
        )
        signed_spend = child.signrawtransactionwithkey(raw_alice_spend, [alice_key.key], [{
            "txid": alice_outpoint["txid"],
            "vout": alice_outpoint["vout"],
            "scriptPubKey": child_alice["scriptPubKey"]["hex"],
            "amount": Decimal("5.00000000"),
        }])
        assert_equal(signed_spend["complete"], True)
        spend_txid = child.sendrawtransaction(signed_spend["hex"])

        self.log.info("Spend the imported block-X parent miner coinbase before the first child block")
        raw_miner_spend = child.createrawtransaction(
            [miner_coinbase_outpoint],
            {bob_key.address: Decimal("49.99900000")},
        )
        miner_spend_txid = child.sendrawtransaction(raw_miner_spend)

        self.log.info("Reject a local parent AuxPoW proof with the wrong commitment")
        if self.is_wallet_compiled():
            previous_immature = child.getbalances()["mine"]["immature"]
            candidate = child.getauxblock()
            wallet_candidate_repeat = child.getauxblock()
            assert_equal(wallet_candidate_repeat["hash"], candidate["hash"])
        else:
            previous_immature = None
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
        assert_equal(child.getauxblock(candidate["hash"], bad_auxpow.serialize().hex()), False)
        assert_equal(child.getblockcount(), 0)
        assert spend_txid in child.getrawmempool()
        assert miner_spend_txid in child.getrawmempool()
        assert_equal(child.getbestblockhash(), child.getblockhash(0))

        self.log.info("Mine a child block using a real local parent block AuxPoW proof")
        parent_aux_tx = self.create_parent_balance_tx(parent_blocks[1].vtx[0], bob_script, bob_script, proof_script)
        parent_block = self.mine_parent_block(parent, txlist=[parent_aux_tx], commitment_hex=candidate["auxpowcommitment"])
        non_coinbase_auxpow = build_parent_auxpow(parent_block, tx_index=1)
        assert_equal(non_coinbase_auxpow.index, 1)
        assert_equal(len(non_coinbase_auxpow.merkle_branch), 1)
        assert_equal(child.getauxblock(candidate["hash"], non_coinbase_auxpow.serialize().hex()), False)
        assert_equal(child.getblockcount(), 0)
        assert spend_txid in child.getrawmempool()
        assert miner_spend_txid in child.getrawmempool()
        assert_equal(child.getbestblockhash(), child.getblockhash(0))

        auxpow = build_parent_auxpow(parent_block)
        assert_equal(auxpow.index, 0)
        assert_equal(len(auxpow.merkle_branch), 1)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getbestblockhash(), candidate["hash"])
        if self.is_wallet_compiled():
            self.assert_wallet_coinbase(child, candidate["hash"], candidate["coinbasevalue"], previous_immature)
        assert spend_txid in child.getblock(candidate["hash"])["tx"]
        assert miner_spend_txid in child.getblock(candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        assert_equal(child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"], False), None)
        assert_equal(Decimal(str(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False)["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False)["value"])), Decimal("6.00000000"))
        child_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(child_spend["value"])), Decimal("4.99900000"))
        child_miner_spend = child.gettxout(miner_spend_txid, 0, False)
        assert_equal(Decimal(str(child_miner_spend["value"])), Decimal("49.99900000"))

        self.log.info("Invalidate and reconsider the AuxPoW block to test imported UTXO undo")
        child.invalidateblock(candidate["hash"])
        assert_equal(child.getblockcount(), 0)
        restored_alice = child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False)
        assert_equal(Decimal(str(restored_alice["value"])), Decimal("5.00000000"))
        restored_miner_coinbase = child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"], False)
        assert_equal(Decimal(str(restored_miner_coinbase["value"])), Decimal("50.00000000"))
        assert_equal(restored_miner_coinbase["coinbase"], False)
        assert_equal(child.gettxout(spend_txid, 0, False), None)
        assert_equal(child.gettxout(miner_spend_txid, 0, False), None)

        child.reconsiderblock(candidate["hash"])
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getbestblockhash(), candidate["hash"])
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        assert_equal(child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"], False), None)
        reconsidered_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(reconsidered_spend["value"])), Decimal("4.99900000"))
        reconsidered_miner_spend = child.gettxout(miner_spend_txid, 0, False)
        assert_equal(Decimal(str(reconsidered_miner_spend["value"])), Decimal("49.99900000"))

        self.log.info("Persist and reload child AuxPoW header from disk")
        child_header_hex = child.getblockheader(candidate["hash"], False)
        assert child_header_hex.startswith(candidate["header"])
        assert len(child_header_hex) > len(candidate["header"])
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        assert_equal(child.getblockheader(candidate["hash"], False), child_header_hex)
        self.assert_child_snapshot_imported(child, dump, verify)
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.gettxout(alice_outpoint["txid"], alice_outpoint["vout"], False), None)
        assert_equal(child.gettxout(miner_coinbase_outpoint["txid"], miner_coinbase_outpoint["vout"], False), None)
        reloaded_proof = child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False)
        reloaded_duplicate_proof = child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False)
        assert_equal(Decimal(str(reloaded_proof["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(reloaded_duplicate_proof["value"])), Decimal("6.00000000"))
        reloaded_spend = child.gettxout(spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_spend["value"])), Decimal("4.99900000"))
        reloaded_miner_spend = child.gettxout(miner_spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_miner_spend["value"])), Decimal("49.99900000"))

        self.log.info("Mine an activated shielded marker through local parent AuxPoW")
        assert_equal(child.getblockchaininfo()["shielded_pool"]["next_block_active"], True)
        real_mode_commitment = self.shielded_commitment("local-parent-fork-real-mode-unsupported")
        raw_real_mode_mint = self.create_shielded_mint_tx(
            child,
            duplicate_proof_outpoint,
            reloaded_duplicate_proof,
            bob_key.address,
            real_mode_commitment,
            proof_mode=ORCHARD_PROOF_BODY_MODE_REAL,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_real_mode_mint)

        shielded_commitment = self.shielded_commitment("local-parent-fork-auxpow-shielded")
        raw_shielded_mint = self.create_shielded_mint_tx(
            child,
            proof_outpoint,
            reloaded_proof,
            bob_key.address,
            shielded_commitment,
        )
        shielded_txid = child.sendrawtransaction(raw_shielded_mint)

        raw_duplicate_mint = self.create_shielded_mint_tx(
            child,
            duplicate_proof_outpoint,
            reloaded_duplicate_proof,
            bob_key.address,
            shielded_commitment,
        )
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-commitment", child.sendrawtransaction, raw_duplicate_mint)

        bad_public_input_commitment = self.shielded_commitment("local-parent-fork-bad-public-input")
        raw_bad_public_input_mint = self.create_shielded_mint_tx(
            child,
            duplicate_proof_outpoint,
            reloaded_duplicate_proof,
            bob_key.address,
            bad_public_input_commitment,
            mutate_public_input=True,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_bad_public_input_mint)

        bad_payload_commitment = self.shielded_commitment("local-parent-fork-bad-proof-payload")
        raw_bad_payload_mint = self.create_shielded_mint_tx(
            child,
            duplicate_proof_outpoint,
            reloaded_duplicate_proof,
            bob_key.address,
            bad_payload_commitment,
            mutate_proof_payload=True,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_bad_payload_mint)

        if self.is_wallet_compiled():
            shielded_candidate = child.getauxblock()
        else:
            shielded_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(shielded_candidate["height"], 2)
        shielded_parent_block = self.mine_parent_block(parent, commitment_hex=shielded_candidate["auxpowcommitment"])
        shielded_auxpow = build_parent_auxpow(shielded_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(shielded_candidate["hash"], shielded_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(shielded_candidate["hash"], shielded_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 2)
        assert_equal(child.getbestblockhash(), shielded_candidate["hash"])
        assert shielded_txid in child.getblock(shielded_candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False), None)
        shielded_output = child.gettxout(shielded_txid, 0, False)
        assert_equal(Decimal(str(shielded_output["value"])), Decimal("3.99900000"))
        shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 0)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-commitment", child.sendrawtransaction, raw_duplicate_mint)

        self.log.info("Restart child after merge-mined shielded block and replay shielded state")
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        assert_equal(child.getblockcount(), 2)
        assert_equal(child.getbestblockhash(), shielded_candidate["hash"])
        self.assert_child_snapshot_imported(child, dump, verify)
        assert shielded_txid in child.getblock(shielded_candidate["hash"])["tx"]
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False), None)
        reloaded_shielded_output = child.gettxout(shielded_txid, 0, False)
        assert_equal(Decimal(str(reloaded_shielded_output["value"])), Decimal("3.99900000"))
        reloaded_shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(reloaded_shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(reloaded_shielded_info["commitments"], 1)
        assert_equal(reloaded_shielded_info["nullifiers"], 0)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-commitment", child.sendrawtransaction, raw_duplicate_mint)

        self.log.info("Mine a shielded spend through local parent AuxPoW")
        spend_anchor = self.root_hex_to_payload_bytes(reloaded_shielded_info["root"])
        spend_nullifier = self.shielded_nullifier("local-parent-fork-auxpow-shielded-spend")
        spend_source = child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False)
        assert_equal(Decimal(str(spend_source["value"])), Decimal("6.00000000"))
        raw_shielded_spend, shielded_spend_txid = self.create_shielded_spend_tx(
            duplicate_proof_outpoint,
            spend_source,
            proof_script,
            spend_nullifier,
            spend_anchor,
        )
        assert_equal(child.sendrawtransaction(raw_shielded_spend), shielded_spend_txid)

        if self.is_wallet_compiled():
            shielded_spend_candidate = child.getauxblock()
        else:
            shielded_spend_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(shielded_spend_candidate["height"], 3)
        shielded_spend_parent_block = self.mine_parent_block(parent, commitment_hex=shielded_spend_candidate["auxpowcommitment"])
        shielded_spend_auxpow = build_parent_auxpow(shielded_spend_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(shielded_spend_candidate["hash"], shielded_spend_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(shielded_spend_candidate["hash"], shielded_spend_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 3)
        assert_equal(child.getbestblockhash(), shielded_spend_candidate["hash"])
        assert shielded_spend_txid in child.getblock(shielded_spend_candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False), None)
        shielded_spend_output = child.gettxout(shielded_spend_txid, 0, False)
        assert_equal(Decimal(str(shielded_spend_output["value"])), Decimal("6.99900000"))
        shielded_spend_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(shielded_spend_info["commitments"], 1)
        assert_equal(shielded_spend_info["nullifiers"], 1)

        duplicate_nullifier_outpoint = {"txid": shielded_spend_txid, "vout": 0}
        duplicate_nullifier_source = child.gettxout(duplicate_nullifier_outpoint["txid"], duplicate_nullifier_outpoint["vout"], False)
        raw_duplicate_nullifier, _ = self.create_shielded_spend_tx(
            duplicate_nullifier_outpoint,
            duplicate_nullifier_source,
            proof_script,
            spend_nullifier,
            spend_anchor,
        )
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier)

        self.log.info("Restart child after merge-mined shielded spend and replay shielded nullifier state")
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        assert_equal(child.getblockcount(), 3)
        assert_equal(child.getbestblockhash(), shielded_spend_candidate["hash"])
        self.assert_child_snapshot_imported(child, dump, verify)
        reloaded_spend_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(reloaded_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(reloaded_spend_info["commitments"], 1)
        assert_equal(reloaded_spend_info["nullifiers"], 1)
        assert_equal(child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False), None)
        reloaded_shielded_spend_output = child.gettxout(shielded_spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_shielded_spend_output["value"])), Decimal("6.99900000"))
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier)


if __name__ == "__main__":
    LocalLitecoinForkAuxPowTest().main()
