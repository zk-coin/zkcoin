#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mine real Orchard shielded mint and spend transactions through local AuxPoW."""

from decimal import Decimal
from pathlib import Path

from feature_local_ltc_fork_auxpow import (
    ACTION_MINT,
    ACTION_SPEND,
    MARKER_PREFIX,
    ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
    LocalLitecoinForkAuxPowTest,
)
from test_framework.auxpow import build_parent_auxpow
from test_framework.blocktools import COIN
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut
from test_framework.script import CScript, OP_DROP, OP_RETURN, OP_TRUE
from test_framework.script_util import script_to_p2wsh_script
from test_framework.test_framework import SkipTest
from test_framework.util import assert_equal, assert_raises_rpc_error


ORCHARD_HALO2_BUNDLE_PROOF_PREFIX = b"zkc-orchard-halo2-bundle-v1"
FIRST_PROOF_CHUNK_SIZE = 520
STANDARD_PROOF_CHUNK_SIZE = 80
ORCHARD_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "rust"
    / "shielded-verifier"
    / "tests"
    / "vectors"
    / "orchard_mint_vector.txt"
)
ORCHARD_SPEND_VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "rust"
    / "shielded-verifier"
    / "tests"
    / "vectors"
    / "orchard_spend_vector.txt"
)


class OrchardAuxPowRealProofTest(LocalLitecoinForkAuxPowTest):
    def set_test_params(self):
        super().set_test_params()

    def child_launch_args(self, dump, verify, import_hash=None):
        return super().child_launch_args(dump, verify, import_hash) + ["-noshieldedscaffoldproofs"]

    def load_orchard_vector(self, path):
        values = {}
        for line in path.read_text(encoding="utf8").splitlines():
            if not line or line.startswith("#"):
                continue
            key, value = line.split("=", 1)
            values[key] = value

        action_count = int(values["action_count"])
        actions = []
        anchor = bytes.fromhex(values["anchor"])
        for index in range(action_count):
            prefix = f"action{index}."
            actions.append({
                "anchor": anchor,
                "cv_net": bytes.fromhex(values[prefix + "cv_net"]),
                "nf_old": bytes.fromhex(values[prefix + "nf_old"]),
                "rk": bytes.fromhex(values[prefix + "rk"]),
                "cmx": bytes.fromhex(values[prefix + "cmx"]),
            })

        vector = {
            "shielded_value": int(values["shielded_value"]),
            "marker_action_index": int(values["marker_action_index"]),
            "enable_spend": int(values["enable_spend"]) == 1,
            "enable_output": int(values["enable_output"]) == 1,
            "anchor": anchor,
            "actions": actions,
            "proof": bytes.fromhex(values["proof"]),
        }
        if "source_commitment" in values:
            vector["source_commitment"] = bytes.fromhex(values["source_commitment"])
        return vector

    def load_orchard_mint_vector(self):
        return self.load_orchard_vector(ORCHARD_VECTOR_PATH)

    def load_orchard_spend_vector(self):
        return self.load_orchard_vector(ORCHARD_SPEND_VECTOR_PATH)

    def orchard_halo2_bundle_native_payload(self, tx, vector, *, action=ACTION_MINT, mutate_proof=False):
        payload = bytearray()
        payload += ORCHARD_HALO2_BUNDLE_PROOF_PREFIX
        payload += bytes([action])
        payload += len(vector["actions"]).to_bytes(4, "little")
        payload += vector["marker_action_index"].to_bytes(4, "little")
        payload += vector["shielded_value"].to_bytes(8, "little")
        payload += self.hash256(tx.serialize_without_witness())
        payload += bytes([int(vector["enable_spend"]), int(vector["enable_output"])])
        for proof_action in vector["actions"]:
            payload += proof_action["anchor"]
            payload += proof_action["cv_net"]
            payload += proof_action["nf_old"]
            payload += proof_action["rk"]
            payload += proof_action["cmx"]

        proof = bytearray(vector["proof"])
        if mutate_proof:
            proof[-1] ^= 0x01
        payload += len(proof).to_bytes(4, "little")
        payload += proof
        return bytes(payload)

    def proof_chunks(self, proof_envelope):
        chunks = [proof_envelope[:FIRST_PROOF_CHUNK_SIZE]]
        offset = FIRST_PROOF_CHUNK_SIZE
        while offset < len(proof_envelope):
            chunks.append(proof_envelope[offset:offset + STANDARD_PROOF_CHUNK_SIZE])
            offset += STANDARD_PROOF_CHUNK_SIZE
        assert len(chunks) <= 100
        assert all(len(chunk) <= FIRST_PROOF_CHUNK_SIZE for chunk in chunks)
        assert all(len(chunk) <= STANDARD_PROOF_CHUNK_SIZE for chunk in chunks[1:])
        return chunks

    def proof_drop_script(self, chunk_count):
        return CScript([OP_DROP] * chunk_count + [OP_TRUE])

    def real_orchard_proof_script(self, vector, *, action=ACTION_MINT):
        tx = CTransaction()
        marker_action = vector["actions"][vector["marker_action_index"]]
        native_proof_bytes = self.orchard_halo2_bundle_native_payload(tx, vector, action=action)
        if action == ACTION_MINT:
            proof_envelope = self.shielded_real_proof_envelope(
                tx,
                ACTION_MINT,
                vector["shielded_value"],
                commitment=marker_action["cmx"],
                native_proof_bytes=native_proof_bytes,
            )
        elif action == ACTION_SPEND:
            proof_envelope = self.shielded_real_proof_envelope(
                tx,
                ACTION_SPEND,
                vector["shielded_value"],
                nullifier=marker_action["nf_old"],
                anchor=vector["anchor"],
                native_proof_bytes=native_proof_bytes,
            )
        else:
            raise AssertionError(f"unknown Orchard action {action}")
        return self.proof_drop_script(len(self.proof_chunks(proof_envelope)))

    def create_real_orchard_mint_tx(self, node, outpoint, prev_txout, destination, vector, *, destination_script=None, commitment=None, mutate_proof=False):
        shielded_value = vector["shielded_value"]
        if commitment is None:
            commitment = vector["actions"][vector["marker_action_index"]]["cmx"]

        prev_value = int(Decimal(str(prev_txout["value"])) * Decimal(COIN))
        payload = (
            MARKER_PREFIX
            + bytes([ACTION_MINT])
            + shielded_value.to_bytes(8, "little")
            + commitment
            + self.shielded_proof_tag(ACTION_MINT, shielded_value, commitment=commitment)
        )
        if destination_script is None:
            destination_script = bytes.fromhex(node.validateaddress(destination)["scriptPubKey"])

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(outpoint["txid"], 16), outpoint["vout"]))]
        tx.vout = [
            CTxOut(prev_value - shielded_value - 100000, destination_script),
            CTxOut(0, CScript([OP_RETURN, payload])),
        ]
        native_proof_bytes = self.orchard_halo2_bundle_native_payload(tx, vector, mutate_proof=mutate_proof)
        proof_envelope = self.shielded_real_proof_envelope(
            tx,
            ACTION_MINT,
            shielded_value,
            commitment=commitment,
            native_proof_bytes=native_proof_bytes,
        )
        proof_chunks = self.proof_chunks(proof_envelope)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = proof_chunks + [self.proof_drop_script(len(proof_chunks))]
        tx.rehash()
        return tx.serialize().hex(), tx.hash

    def create_real_orchard_spend_tx(self, node, outpoint, prev_txout, destination, vector, *, destination_script=None, nullifier=None, anchor=None, mutate_proof=False):
        shielded_value = vector["shielded_value"]
        marker_action = vector["actions"][vector["marker_action_index"]]
        if nullifier is None:
            nullifier = marker_action["nf_old"]
        if anchor is None:
            anchor = vector["anchor"]

        prev_value = int(Decimal(str(prev_txout["value"])) * Decimal(COIN))
        payload = (
            MARKER_PREFIX
            + bytes([ACTION_SPEND])
            + shielded_value.to_bytes(8, "little")
            + nullifier
            + anchor
            + self.shielded_proof_tag(ACTION_SPEND, shielded_value, nullifier=nullifier, anchor=anchor)
        )
        if destination_script is None:
            destination_script = bytes.fromhex(node.validateaddress(destination)["scriptPubKey"])

        tx = CTransaction()
        tx.vin = [CTxIn(COutPoint(int(outpoint["txid"], 16), outpoint["vout"]))]
        tx.vout = [
            CTxOut(prev_value + shielded_value - 100000, destination_script),
            CTxOut(0, CScript([OP_RETURN, payload])),
        ]
        native_proof_bytes = self.orchard_halo2_bundle_native_payload(
            tx,
            vector,
            action=ACTION_SPEND,
            mutate_proof=mutate_proof,
        )
        proof_envelope = self.shielded_real_proof_envelope(
            tx,
            ACTION_SPEND,
            shielded_value,
            nullifier=nullifier,
            anchor=anchor,
            native_proof_bytes=native_proof_bytes,
        )
        proof_chunks = self.proof_chunks(proof_envelope)
        tx.wit.vtxinwit = [CTxInWitness()]
        tx.wit.vtxinwit[0].scriptWitness.stack = proof_chunks + [self.proof_drop_script(len(proof_chunks))]
        tx.rehash()
        return tx.serialize().hex(), tx.hash

    def run_test(self):
        parent = self.nodes[0]
        child = self.nodes[1]

        if child.getblockchaininfo()["shielded_pool"]["real_proof_backend"] != "orchard-v1":
            raise SkipTest("node was not built with --enable-rust-orchard-verifier")

        self.log.info("Build a local Litecoin-style parent chain and block-X snapshot")
        vector = self.load_orchard_mint_vector()
        spend_vector = self.load_orchard_spend_vector()
        assert_equal(vector["shielded_value"], COIN)
        assert_equal(spend_vector["shielded_value"], COIN)
        assert_equal(spend_vector["source_commitment"], vector["actions"][vector["marker_action_index"]]["cmx"])
        bob_key = parent.get_deterministic_priv_key()
        bob_script = bytes.fromhex(child.validateaddress(bob_key.address)["scriptPubKey"])
        mint_drop_script = self.real_orchard_proof_script(vector, action=ACTION_MINT)
        spend_drop_script = self.real_orchard_proof_script(spend_vector, action=ACTION_SPEND)
        proof_script = script_to_p2wsh_script(mint_drop_script)
        spend_proof_script = script_to_p2wsh_script(spend_drop_script)
        parent_blocks = [self.mine_parent_block(parent) for _ in range(101)]
        parent_balance_tx = self.create_parent_balance_tx(parent_blocks[0].vtx[0], bob_script, bob_script, proof_script)
        self.mine_parent_block(parent, txlist=[parent_balance_tx])

        proof_outpoint = {"txid": parent_balance_tx.hash, "vout": 2}
        duplicate_proof_outpoint = {"txid": parent_balance_tx.hash, "vout": 3}
        parent_proof = parent.gettxout(proof_outpoint["txid"], proof_outpoint["vout"])
        parent_duplicate_proof = parent.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"])
        assert_equal(Decimal(str(parent_proof["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(parent_duplicate_proof["value"])), Decimal("6.00000000"))

        dump = parent.dumptxoutset("orchard-local-ltc-block-x.dat")
        verify = parent.verifysnapshotmanifest(dump["path"])
        assert_equal(verify["base_hash"], dump["base_hash"])
        assert_equal(verify["import_hash"], parent.verifysnapshotmanifest(dump["path"])["import_hash"])

        self.log.info("Start child with block-X balances, AuxPoW, Orchard verifier, and scaffold disabled")
        self.stop_node(1)
        self.start_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        child.importsnapshotmanifest(dump["path"])
        self.assert_child_snapshot_imported(child, dump, verify)
        shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(shielded_info["start_height"], 2)
        assert_equal(shielded_info["scaffold_proofs"], False)
        assert_equal(shielded_info["real_proof_backend"], "orchard-v1")
        assert_equal(shielded_info["real_proof_verification"], True)

        child_proof = child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"])
        child_duplicate_proof = child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"])
        assert_equal(Decimal(str(child_proof["value"])), Decimal("5.00000000"))
        assert_equal(Decimal(str(child_duplicate_proof["value"])), Decimal("6.00000000"))

        self.log.info("Mine the first child block through local parent AuxPoW")
        if self.is_wallet_compiled():
            candidate = child.getauxblock()
        else:
            candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(candidate["height"], 1)
        parent_block = self.mine_parent_block(parent, commitment_hex=candidate["auxpowcommitment"])
        auxpow = build_parent_auxpow(parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getblockchaininfo()["shielded_pool"]["next_block_active"], True)

        self.log.info("Reject scaffold and malformed real proofs while scaffold is disabled")
        scaffold_commitment = self.shielded_commitment("orchard-auxpow-scaffold-disabled")
        raw_scaffold_mint = self.create_shielded_mint_tx(
            child,
            duplicate_proof_outpoint,
            child_duplicate_proof,
            bob_key.address,
            scaffold_commitment,
            proof_mode=ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_scaffold_mint)

        raw_bad_proof_mint, _ = self.create_real_orchard_mint_tx(
            child,
            duplicate_proof_outpoint,
            child_duplicate_proof,
            bob_key.address,
            vector,
            mutate_proof=True,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_bad_proof_mint)

        wrong_commitment = vector["actions"][1]["cmx"]
        raw_wrong_marker_mint, _ = self.create_real_orchard_mint_tx(
            child,
            duplicate_proof_outpoint,
            child_duplicate_proof,
            bob_key.address,
            vector,
            commitment=wrong_commitment,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_wrong_marker_mint)

        self.log.info("Accept a real Orchard shielded mint and mine it through local AuxPoW")
        raw_real_mint, real_mint_txid = self.create_real_orchard_mint_tx(
            child,
            proof_outpoint,
            child_proof,
            bob_key.address,
            vector,
            destination_script=spend_proof_script,
        )
        assert_equal(child.sendrawtransaction(raw_real_mint), real_mint_txid)

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
        assert real_mint_txid in child.getblock(shielded_candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False), None)
        real_mint_output = child.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(real_mint_output["value"])), Decimal("3.99900000"))
        shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(shielded_info["commitments"], 1)
        assert_equal(shielded_info["nullifiers"], 0)
        assert_equal(shielded_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(shielded_info["root"]), spend_vector["anchor"])

        self.log.info("Restart child and replay the merge-mined real-proof mint state")
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        assert_equal(child.getblockcount(), 2)
        assert_equal(child.getbestblockhash(), shielded_candidate["hash"])
        self.assert_child_snapshot_imported(child, dump, verify)
        assert real_mint_txid in child.getblock(shielded_candidate["hash"])["tx"]
        reloaded_shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(reloaded_shielded_info["real_proof_backend"], "orchard-v1")
        assert_equal(reloaded_shielded_info["real_proof_verification"], True)
        assert_equal(reloaded_shielded_info["scaffold_proofs"], False)
        assert_equal(Decimal(str(reloaded_shielded_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(reloaded_shielded_info["commitments"], 1)
        assert_equal(reloaded_shielded_info["nullifiers"], 0)
        assert_equal(reloaded_shielded_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(reloaded_shielded_info["root"]), spend_vector["anchor"])
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False), None)
        reloaded_real_mint_output = child.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(reloaded_real_mint_output["value"])), Decimal("3.99900000"))

        self.log.info("Reject malformed real Orchard spends while scaffold is disabled")
        real_mint_outpoint = {"txid": real_mint_txid, "vout": 0}
        raw_bad_spend_proof, _ = self.create_real_orchard_spend_tx(
            child,
            real_mint_outpoint,
            reloaded_real_mint_output,
            bob_key.address,
            spend_vector,
            mutate_proof=True,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_bad_spend_proof)

        wrong_anchor = bytes([spend_vector["anchor"][0] ^ 0x01]) + spend_vector["anchor"][1:]
        raw_wrong_anchor_spend, _ = self.create_real_orchard_spend_tx(
            child,
            real_mint_outpoint,
            reloaded_real_mint_output,
            bob_key.address,
            spend_vector,
            anchor=wrong_anchor,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_wrong_anchor_spend)

        self.log.info("Accept a real Orchard shielded spend and mine it through local AuxPoW")
        raw_real_spend, real_spend_txid = self.create_real_orchard_spend_tx(
            child,
            real_mint_outpoint,
            reloaded_real_mint_output,
            bob_key.address,
            spend_vector,
            destination_script=spend_proof_script,
        )
        assert_equal(child.sendrawtransaction(raw_real_spend), real_spend_txid)

        if self.is_wallet_compiled():
            spend_candidate = child.getauxblock()
        else:
            spend_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(spend_candidate["height"], 3)
        spend_parent_block = self.mine_parent_block(parent, commitment_hex=spend_candidate["auxpowcommitment"])
        spend_auxpow = build_parent_auxpow(spend_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(spend_candidate["hash"], spend_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(spend_candidate["hash"], spend_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 3)
        assert real_spend_txid in child.getblock(spend_candidate["hash"])["tx"]
        assert_equal(child.getrawmempool(), [])
        assert_equal(child.gettxout(real_mint_txid, 0, False), None)
        real_spend_output = child.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(real_spend_output["value"])), Decimal("4.99800000"))
        spend_shielded_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(spend_shielded_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(spend_shielded_info["commitments"], 1)
        assert_equal(spend_shielded_info["nullifiers"], 1)
        assert_equal(spend_shielded_info["anchors"], 2)

        real_spend_outpoint = {"txid": real_spend_txid, "vout": 0}
        raw_duplicate_nullifier_spend, _ = self.create_real_orchard_spend_tx(
            child,
            real_spend_outpoint,
            real_spend_output,
            bob_key.address,
            spend_vector,
        )
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier_spend)

        self.log.info("Restart child and replay the merge-mined real-proof spend state")
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        assert_equal(child.getblockcount(), 3)
        assert_equal(child.getbestblockhash(), spend_candidate["hash"])
        self.assert_child_snapshot_imported(child, dump, verify)
        assert real_mint_txid in child.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in child.getblock(spend_candidate["hash"])["tx"]
        reloaded_spend_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(reloaded_spend_info["real_proof_backend"], "orchard-v1")
        assert_equal(reloaded_spend_info["real_proof_verification"], True)
        assert_equal(reloaded_spend_info["scaffold_proofs"], False)
        assert_equal(Decimal(str(reloaded_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(reloaded_spend_info["commitments"], 1)
        assert_equal(reloaded_spend_info["nullifiers"], 1)
        assert_equal(reloaded_spend_info["anchors"], 2)
        assert_equal(child.gettxout(real_mint_txid, 0, False), None)
        reloaded_real_spend_output = child.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_real_spend_output["value"])), Decimal("4.99800000"))
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier_spend)

        self.log.info("Invalidate and reconsider the merge-mined real-proof spend block")
        child.invalidateblock(spend_candidate["hash"])
        assert_equal(child.getblockcount(), 2)
        assert_equal(child.getbestblockhash(), shielded_candidate["hash"])
        assert real_spend_txid in child.getrawmempool()
        undo_spend_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(undo_spend_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(undo_spend_info["commitments"], 1)
        assert_equal(undo_spend_info["nullifiers"], 0)
        assert_equal(undo_spend_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(undo_spend_info["root"]), spend_vector["anchor"])
        restored_mint_output = child.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(restored_mint_output["value"])), Decimal("3.99900000"))
        assert_equal(child.gettxout(real_spend_txid, 0, False), None)

        child.reconsiderblock(spend_candidate["hash"])
        assert_equal(child.getblockcount(), 3)
        assert_equal(child.getbestblockhash(), spend_candidate["hash"])
        assert_equal(child.getrawmempool(), [])
        reconsidered_spend_info = child.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(reconsidered_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(reconsidered_spend_info["commitments"], 1)
        assert_equal(reconsidered_spend_info["nullifiers"], 1)
        assert_equal(reconsidered_spend_info["anchors"], 2)
        assert_equal(child.gettxout(real_mint_txid, 0, False), None)
        reconsidered_real_spend_output = child.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(reconsidered_real_spend_output["value"])), Decimal("4.99800000"))
        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier_spend)


if __name__ == "__main__":
    OrchardAuxPowRealProofTest().main()
