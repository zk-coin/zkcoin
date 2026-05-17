#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the shielded pool consensus marker scaffold."""

import hashlib

from decimal import Decimal

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE, script_to_p2wsh
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
)
from test_framework.script import CScript, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


MARKER_PREFIX = b"zkc0"
ACTION_MINT = 0x01
ACTION_SPEND = 0x02
EMPTY_ROOT = "00" * 32
PROOF_TAG_SIZE = 3
PROOF_ENVELOPE_PREFIX = b"zkc-proof-v3"
PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX = b"zkc-public-input-v1"
PROOF_ENVELOPE_PREIMAGE_PREFIX = b"zkc-proof-envelope-v3"
PROOF_SCRIPT = CScript([OP_DROP, OP_TRUE])


class ShieldedProofWallet:
    def __init__(self, test_node):
        self._test_node = test_node
        self._utxos = []
        self._address = script_to_p2wsh(PROOF_SCRIPT)
        self._scriptPubKey = bytes.fromhex(self._test_node.validateaddress(self._address)["scriptPubKey"])

    def generate(self, num_blocks):
        blocks = self._test_node.generatetoaddress(num_blocks, self._address)
        for block_hash in blocks:
            coinbase_tx = self._test_node.getblock(blockhash=block_hash, verbosity=2)["tx"][0]
            self._utxos.append({"txid": coinbase_tx["txid"], "vout": 0, "value": coinbase_tx["vout"][0]["value"]})
        return blocks


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

    def unique_field(self, label):
        self.marker_nonce += 1
        return hashlib.sha256(f"{label}-{self.marker_nonce}".encode()).digest()

    def root_hex_to_payload_bytes(self, root_hex):
        return bytes.fromhex(root_hex)[::-1]

    def proof_hash(self, *, action, shielded_value, commitment=None, nullifier=None, anchor=None):
        preimage = b"zkc-proof-v0" + bytes([action]) + shielded_value.to_bytes(8, "little")
        if action == ACTION_MINT:
            preimage += commitment
        elif action == ACTION_SPEND:
            preimage += nullifier + anchor
        return hashlib.sha256(hashlib.sha256(preimage).digest()).digest()

    def proof_tag(self, **kwargs):
        return self.proof_hash(**kwargs)[:PROOF_TAG_SIZE]

    def hash256(self, data):
        return hashlib.sha256(hashlib.sha256(data).digest()).digest()

    def proof_envelope(self, tx, **kwargs):
        field_hash = self.proof_hash(**kwargs)
        tx_binding_hash = self.hash256(tx.serialize_without_witness())
        action = kwargs["action"]
        public_input_hash = self.hash256(PROOF_PUBLIC_INPUT_PREIMAGE_PREFIX + bytes([action]) + field_hash + tx_binding_hash)
        proof_payload = self.hash256(PROOF_ENVELOPE_PREIMAGE_PREFIX + bytes([action]) + public_input_hash)
        return PROOF_ENVELOPE_PREFIX + bytes([action]) + public_input_hash + proof_payload

    def make_marker_payload(self, *, action=ACTION_MINT, commitment=None, nullifier=None, anchor=None, shielded_value=COIN, proof_tag=None):
        if commitment is None:
            commitment = self.unique_field("commitment")

        if action == ACTION_MINT:
            if proof_tag is None:
                proof_tag = self.proof_tag(action=action, shielded_value=shielded_value, commitment=commitment)
            payload = MARKER_PREFIX + bytes([action]) + shielded_value.to_bytes(8, "little") + commitment + proof_tag
            return payload, commitment, None, {"action": action, "shielded_value": shielded_value, "commitment": commitment}

        if nullifier is None:
            nullifier = self.unique_field("nullifier")
        if anchor is None:
            anchor = self.unique_field("anchor")

        if action == ACTION_SPEND:
            if proof_tag is None:
                proof_tag = self.proof_tag(action=action, shielded_value=shielded_value, nullifier=nullifier, anchor=anchor)
            payload = MARKER_PREFIX + bytes([action]) + shielded_value.to_bytes(8, "little") + nullifier + anchor + proof_tag
            return payload, commitment, nullifier, {"action": action, "shielded_value": shielded_value, "nullifier": nullifier, "anchor": anchor}

        payload = MARKER_PREFIX + bytes([action]) + shielded_value.to_bytes(8, "little") + commitment
        return payload, commitment, nullifier, {"action": action, "shielded_value": shielded_value, "commitment": commitment}

    def make_marker_tx(self, wallet, *, action=ACTION_MINT, marker_value=0, marker_count=1, commitment=None, nullifier=None, anchor=None, shielded_value=COIN, proof_tag=None, proof_envelope=None, include_proof=True, mutate_after_proof=False):
        utxo = wallet._utxos.pop(0)
        input_value = int(utxo["value"] * COIN)
        fee = 1000
        output_value = input_value - fee
        if action == ACTION_MINT:
            output_value -= shielded_value
        elif action == ACTION_SPEND:
            output_value += shielded_value

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]))]
        tx.vout = [CTxOut(output_value, wallet._scriptPubKey)]

        payload, commitment, nullifier, proof_kwargs = self.make_marker_payload(
            action=action,
            commitment=commitment,
            nullifier=nullifier,
            anchor=anchor,
            shielded_value=shielded_value,
            proof_tag=proof_tag,
        )
        for _ in range(marker_count):
            tx.vout.append(CTxOut(marker_value, CScript([OP_RETURN, payload])))

        if proof_envelope is None:
            proof_envelope = self.proof_envelope(tx, **proof_kwargs)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = []
        if include_proof:
            tx.wit.vtxinwit[0].scriptWitness.stack.append(proof_envelope)
        tx.wit.vtxinwit[0].scriptWitness.stack.append(PROOF_SCRIPT)
        if mutate_after_proof:
            tx.vout[0].nValue -= 1
        tx.rehash()
        return tx.serialize().hex(), tx.hash, commitment, nullifier

    def run_test(self):
        self.marker_nonce = 0
        disabled = self.nodes[0]
        active = self.nodes[1]
        future = self.nodes[2]
        wallets = [ShieldedProofWallet(node) for node in self.nodes]

        for wallet in wallets:
            wallet.generate(120)

        self.log.info("Expose disabled and activated shielded pool state")
        assert_equal(disabled.getblockchaininfo()["shielded_pool"]["start_height"], -1)
        assert_equal(disabled.getblockchaininfo()["shielded_pool"]["next_block_active"], False)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["start_height"], 1)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["next_block_active"], True)
        assert_equal(Decimal(str(active.getblockchaininfo()["shielded_pool"]["value_pool"])), Decimal("0E-8"))
        assert_equal(active.getblockchaininfo()["shielded_pool"]["commitments"], 0)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["nullifiers"], 0)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["root"], EMPTY_ROOT)
        assert_equal(active.getblockchaininfo()["shielded_pool"]["anchors"], 1)
        assert_equal(future.getblockchaininfo()["shielded_pool"]["start_height"], 200)
        assert_equal(future.getblockchaininfo()["shielded_pool"]["next_block_active"], False)

        self.log.info("Reject shielded marker transactions before activation")
        raw_disabled, _, _, _ = self.make_marker_tx(wallets[0])
        assert_raises_rpc_error(-26, "bad-shielded-before-activation", disabled.sendrawtransaction, raw_disabled)
        assert_raises_rpc_error(
            -25,
            "TestBlockValidity failed: bad-shielded-before-activation",
            disabled.generateblock,
            ADDRESS_BCRT1_P2WSH_OP_TRUE,
            [raw_disabled],
        )

        raw_future, _, _, _ = self.make_marker_tx(wallets[2])
        assert_raises_rpc_error(-26, "bad-shielded-before-activation", future.sendrawtransaction, raw_future)

        self.log.info("Reject malformed active shielded marker transactions")
        raw_bad_action, _, _, _ = self.make_marker_tx(wallets[1], action=0xFF)
        assert_raises_rpc_error(-26, "bad-shielded-payload", active.sendrawtransaction, raw_bad_action)

        raw_nonzero, _, _, _ = self.make_marker_tx(wallets[1], marker_value=1)
        assert_raises_rpc_error(-26, "bad-shielded-value", active.sendrawtransaction, raw_nonzero)

        raw_duplicate, _, _, _ = self.make_marker_tx(wallets[1], marker_count=2)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate", active.sendrawtransaction, raw_duplicate)

        raw_zero_amount, _, _, _ = self.make_marker_tx(wallets[1], shielded_value=0)
        assert_raises_rpc_error(-26, "bad-shielded-amount", active.sendrawtransaction, raw_zero_amount)

        raw_zero_commitment, _, _, _ = self.make_marker_tx(wallets[1], commitment=bytes(32))
        assert_raises_rpc_error(-26, "bad-shielded-commitment", active.sendrawtransaction, raw_zero_commitment)

        raw_zero_nullifier, _, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND, nullifier=bytes(32))
        assert_raises_rpc_error(-26, "bad-shielded-nullifier", active.sendrawtransaction, raw_zero_nullifier)

        bad_proof_commitment = self.unique_field("bad-proof-commitment")
        good_proof_tag = self.proof_tag(action=ACTION_MINT, shielded_value=COIN, commitment=bad_proof_commitment)
        bad_proof_tag = bytes([good_proof_tag[0] ^ 0x01]) + good_proof_tag[1:]
        raw_bad_proof, _, _, _ = self.make_marker_tx(wallets[1], commitment=bad_proof_commitment, proof_tag=bad_proof_tag)
        assert_raises_rpc_error(-26, "bad-shielded-proof", active.sendrawtransaction, raw_bad_proof)

        raw_missing_proof, _, _, _ = self.make_marker_tx(wallets[1], proof_envelope=b"not-a-shielded-proof")
        assert_raises_rpc_error(-26, "bad-shielded-proof", active.sendrawtransaction, raw_missing_proof)

        raw_bad_envelope, _, _, _ = self.make_marker_tx(wallets[1], proof_envelope=PROOF_ENVELOPE_PREFIX + bytes(32))
        assert_raises_rpc_error(-26, "bad-shielded-proof", active.sendrawtransaction, raw_bad_envelope)

        raw_bad_binding, _, _, _ = self.make_marker_tx(wallets[1], mutate_after_proof=True)
        assert_raises_rpc_error(-26, "bad-shielded-proof", active.sendrawtransaction, raw_bad_binding)

        raw_wrong_kind, _, _, _ = self.make_marker_tx(wallets[1], proof_envelope=PROOF_ENVELOPE_PREFIX + bytes([ACTION_SPEND]) + bytes(64))
        assert_raises_rpc_error(-26, "bad-shielded-proof", active.sendrawtransaction, raw_wrong_kind)

        self.log.info("Reject shielded spends with unknown anchors")
        raw_unfunded_spend, _, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND)
        assert_raises_rpc_error(-26, "bad-shielded-anchor", active.sendrawtransaction, raw_unfunded_spend)

        self.log.info("Reject duplicate shielded state inside a candidate block")
        duplicate_block_commitment = self.unique_field("duplicate-block-commitment")
        raw_block_dup_a, _, _, _ = self.make_marker_tx(wallets[1], commitment=duplicate_block_commitment)
        raw_block_dup_b, _, _, _ = self.make_marker_tx(wallets[1], commitment=duplicate_block_commitment)
        assert_raises_rpc_error(
            -25,
            "TestBlockValidity failed: bad-shielded-duplicate-commitment",
            active.generateblock,
            ADDRESS_BCRT1_P2WSH_OP_TRUE,
            [raw_block_dup_a, raw_block_dup_b],
        )

        self.log.info("Accept and mine activated shielded commitments")
        raw_active, txid, mined_commitment, _ = self.make_marker_tx(wallets[1])
        assert_equal(active.sendrawtransaction(raw_active), txid)
        block_hash = active.generatetoaddress(1, ADDRESS_BCRT1_P2WSH_OP_TRUE)[0]
        assert txid in active.getblock(block_hash)["tx"]
        coinbase_value = sum(Decimal(str(vout["value"])) for vout in active.getblock(block_hash, 2)["tx"][0]["vout"])
        assert_equal(coinbase_value, Decimal("50.00001000"))
        shielded_info = active.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 0)
        assert shielded_info["root"] != EMPTY_ROOT
        assert_equal(shielded_info["anchors"], 2)
        mined_anchor = self.root_hex_to_payload_bytes(shielded_info["root"])

        self.log.info("Reject duplicate shielded commitments from active-chain state")
        raw_chain_duplicate, _, _, _ = self.make_marker_tx(wallets[1], commitment=mined_commitment)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-commitment", active.sendrawtransaction, raw_chain_duplicate)

        raw_overspend, _, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND, anchor=mined_anchor, shielded_value=2 * COIN)
        assert_raises_rpc_error(-26, "bad-shielded-value-pool", active.sendrawtransaction, raw_overspend)

        self.log.info("Reject duplicate shielded nullifiers from mempool and active-chain state")
        shared_nullifier = self.unique_field("shared-nullifier")
        raw_spend, spend_txid, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND, nullifier=shared_nullifier, anchor=mined_anchor)
        assert_equal(active.sendrawtransaction(raw_spend), spend_txid)

        raw_mempool_duplicate, _, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND, nullifier=shared_nullifier, anchor=mined_anchor)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", active.sendrawtransaction, raw_mempool_duplicate)

        spend_block_hash = active.generatetoaddress(1, ADDRESS_BCRT1_P2WSH_OP_TRUE)[0]
        assert spend_txid in active.getblock(spend_block_hash)["tx"]
        shielded_info = active.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("0E-8"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 1)
        assert_equal(shielded_info["anchors"], 2)

        raw_chain_nullifier_duplicate, _, _, _ = self.make_marker_tx(wallets[1], action=ACTION_SPEND, nullifier=shared_nullifier, anchor=mined_anchor)
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", active.sendrawtransaction, raw_chain_nullifier_duplicate)

        self.log.info("Invalidate and reconsider shielded spend block to test state replay")
        active.invalidateblock(spend_block_hash)
        shielded_info = active.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 0)
        assert_equal(shielded_info["anchors"], 2)

        active.reconsiderblock(spend_block_hash)
        assert_equal(active.getbestblockhash(), spend_block_hash)
        shielded_info = active.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("0E-8"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 1)
        assert_equal(shielded_info["anchors"], 2)


if __name__ == "__main__":
    ShieldedPoolTest().main()
