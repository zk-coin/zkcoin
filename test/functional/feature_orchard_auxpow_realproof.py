#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mine a real Orchard shielded mint through local Litecoin-style AuxPoW."""

from decimal import Decimal
from pathlib import Path

from feature_local_ltc_fork_auxpow import (
    ACTION_MINT,
    MARKER_PREFIX,
    ORCHARD_PROOF_BODY_MODE_REAL,
    ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
    PROOF_SCRIPT,
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


class OrchardAuxPowRealProofTest(LocalLitecoinForkAuxPowTest):
    def set_test_params(self):
        super().set_test_params()

    def child_launch_args(self, dump, verify, import_hash=None):
        return super().child_launch_args(dump, verify, import_hash) + ["-noshieldedscaffoldproofs"]

    def load_orchard_mint_vector(self):
        values = {}
        for line in ORCHARD_VECTOR_PATH.read_text(encoding="utf8").splitlines():
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

        return {
            "shielded_value": int(values["shielded_value"]),
            "marker_action_index": int(values["marker_action_index"]),
            "enable_spend": int(values["enable_spend"]) == 1,
            "enable_output": int(values["enable_output"]) == 1,
            "actions": actions,
            "proof": bytes.fromhex(values["proof"]),
        }

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

    def real_orchard_proof_script(self, vector):
        tx = CTransaction()
        commitment = vector["actions"][vector["marker_action_index"]]["cmx"]
        native_proof_bytes = self.orchard_halo2_bundle_native_payload(tx, vector)
        proof_envelope = self.shielded_real_proof_envelope(
            tx,
            ACTION_MINT,
            vector["shielded_value"],
            commitment=commitment,
            native_proof_bytes=native_proof_bytes,
        )
        return self.proof_drop_script(len(self.proof_chunks(proof_envelope)))

    def create_real_orchard_mint_tx(self, node, outpoint, prev_txout, destination, vector, *, commitment=None, mutate_proof=False):
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

    def run_test(self):
        parent = self.nodes[0]
        child = self.nodes[1]

        if child.getblockchaininfo()["shielded_pool"]["real_proof_backend"] != "orchard-v1":
            raise SkipTest("node was not built with --enable-rust-orchard-verifier")

        self.log.info("Build a local Litecoin-style parent chain and block-X snapshot")
        vector = self.load_orchard_mint_vector()
        assert_equal(vector["shielded_value"], COIN)
        bob_key = parent.get_deterministic_priv_key()
        bob_script = bytes.fromhex(child.validateaddress(bob_key.address)["scriptPubKey"])
        proof_script = script_to_p2wsh_script(self.real_orchard_proof_script(vector))
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

        self.log.info("Restart child and replay the merge-mined real-proof shielded state")
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
        assert_equal(child.gettxout(proof_outpoint["txid"], proof_outpoint["vout"], False), None)
        reloaded_real_mint_output = child.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(reloaded_real_mint_output["value"])), Decimal("3.99900000"))


if __name__ == "__main__":
    OrchardAuxPowRealProofTest().main()
