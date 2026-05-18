#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Mine real Orchard shielded mint and spend transactions through local AuxPoW."""

from decimal import Decimal
from io import BytesIO
from pathlib import Path

from feature_local_ltc_fork_auxpow import (
    ACTION_MINT,
    ACTION_SPEND,
    MARKER_PREFIX,
    ORCHARD_PROOF_BODY_MODE_SCAFFOLD,
    LocalLitecoinForkAuxPowTest,
)
from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.auxpow import build_parent_auxpow
from test_framework.blocktools import COIN, add_witness_commitment, create_block, create_coinbase
from test_framework.messages import CBlockHeader, COutPoint, CTransaction, CTxIn, CTxInWitness, CTxOut, FromHex
from test_framework.p2p import P2PDataStore
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


class AuxPowP2PBlock:
    """P2P block wrapper for child block bytes with AuxPoW inserted after the header."""

    def __init__(self, block_hex):
        self.raw = bytes.fromhex(block_hex)
        header = CBlockHeader()
        header.deserialize(BytesIO(self.raw[:80]))
        header.calc_sha256()

        self.nVersion = header.nVersion
        self.hashPrevBlock = header.hashPrevBlock
        self.hashMerkleRoot = header.hashMerkleRoot
        self.nTime = header.nTime
        self.nBits = header.nBits
        self.nNonce = header.nNonce
        self.sha256 = header.sha256
        self.hash = header.hash
        self.scrypt256 = header.scrypt256

    def serialize(self, *args, **kwargs):
        return self.raw


class OrchardAuxPowRealProofTest(LocalLitecoinForkAuxPowTest):
    def set_test_params(self):
        super().set_test_params()
        self.num_nodes = 4

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

    def auxpow_block_hex_with_txs(self, parent, candidate, txs):
        child_header = CBlockHeader()
        child_header.deserialize(BytesIO(bytes.fromhex(candidate["header"])))

        coinbase = create_coinbase(candidate["height"])
        block = create_block(
            int(candidate["previousblockhash"], 16),
            coinbase,
            child_header.nTime,
            version=child_header.nVersion,
            txlist=txs,
        )
        block.nBits = child_header.nBits
        block.nNonce = child_header.nNonce
        add_witness_commitment(block)
        block.hashMerkleRoot = block.calc_merkle_root()
        block.rehash()

        parent_block = self.mine_parent_block(
            parent,
            commitment_hex="fabe6d6d" + block.hash + "0100000000000000",
        )
        auxpow = build_parent_auxpow(parent_block)
        serialized_block = block.serialize()
        return (serialized_block[:80] + auxpow.serialize() + serialized_block[80:]).hex(), block.hash

    def assert_orchard_child_config(self, node):
        shielded_info = node.getblockchaininfo()["shielded_pool"]
        assert_equal(shielded_info["start_height"], 2)
        assert_equal(shielded_info["scaffold_proofs"], False)
        assert_equal(shielded_info["real_proof_backend"], "orchard-v1")
        assert_equal(shielded_info["real_proof_verification"], True)

    def connect_node_to_child(self, node_index):
        if not any("testnode1" in peer["subver"] for peer in self.nodes[node_index].getpeerinfo()):
            self.connect_nodes(node_index, 1)

    def connect_peer_to_child(self):
        self.connect_node_to_child(2)

    def shielded_pool_snapshot(self, node):
        shielded_info = node.getblockchaininfo()["shielded_pool"]
        return {
            "value_pool": Decimal(str(shielded_info["value_pool"])),
            "commitments": shielded_info["commitments"],
            "nullifiers": shielded_info["nullifiers"],
            "anchors": shielded_info["anchors"],
            "root": shielded_info["root"],
            "scaffold_proofs": shielded_info["scaffold_proofs"],
            "real_proof_backend": shielded_info["real_proof_backend"],
            "real_proof_verification": shielded_info["real_proof_verification"],
        }

    def assert_peer_rejects_bad_shielded_tx_without_relay(
        self,
        peer,
        child,
        raw_tx,
        reject_reason,
        watched_outpoints=(),
        expect_disconnect=True,
    ):
        assert_equal(peer.getbestblockhash(), child.getbestblockhash())
        peer_tip = peer.getbestblockhash()
        peer_height = peer.getblockcount()
        child_tip = child.getbestblockhash()
        child_height = child.getblockcount()
        peer_shielded_state = self.shielded_pool_snapshot(peer)
        child_shielded_state = self.shielded_pool_snapshot(child)
        peer_utxos = [peer.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints]
        child_utxos = [child.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints]

        bad_tx = FromHex(CTransaction(), raw_tx)
        if not hasattr(self, "bad_tx_peer") or not self.bad_tx_peer.is_connected:
            self.bad_tx_peer = peer.add_p2p_connection(P2PDataStore())
        self.bad_tx_peer.send_txs_and_test(
            [bad_tx],
            peer,
            success=False,
            expect_disconnect=expect_disconnect,
            reject_reason=reject_reason,
        )

        assert_equal(peer.getrawmempool(), [])
        assert_equal(child.getrawmempool(), [])
        assert_equal(peer.getblockcount(), peer_height)
        assert_equal(peer.getbestblockhash(), peer_tip)
        assert_equal(child.getblockcount(), child_height)
        assert_equal(child.getbestblockhash(), child_tip)
        assert_equal(self.shielded_pool_snapshot(peer), peer_shielded_state)
        assert_equal(self.shielded_pool_snapshot(child), child_shielded_state)
        assert_equal(
            [peer.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints],
            peer_utxos,
        )
        assert_equal(
            [child.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints],
            child_utxos,
        )

    def assert_peer_rejects_bad_auxpow_block_without_relay(self, peer, child, block_hex, block_hash, reject_reason, watched_outpoints=()):
        assert_equal(peer.getbestblockhash(), child.getbestblockhash())
        peer_tip = peer.getbestblockhash()
        peer_height = peer.getblockcount()
        child_tip = child.getbestblockhash()
        child_height = child.getblockcount()
        peer_shielded_state = self.shielded_pool_snapshot(peer)
        child_shielded_state = self.shielded_pool_snapshot(child)
        peer_utxos = [peer.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints]
        child_utxos = [child.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints]

        bad_block = AuxPowP2PBlock(block_hex)
        assert_equal(bad_block.hash, block_hash)
        block_peer = peer.add_p2p_connection(P2PDataStore())
        block_peer.send_blocks_and_test(
            [bad_block],
            peer,
            success=False,
            force_send=True,
            expect_disconnect=True,
            reject_reason=reject_reason,
        )

        assert_equal(peer.getrawmempool(), [])
        assert_equal(child.getrawmempool(), [])
        assert_equal(peer.getblockcount(), peer_height)
        assert_equal(peer.getbestblockhash(), peer_tip)
        assert_equal(child.getblockcount(), child_height)
        assert_equal(child.getbestblockhash(), child_tip)
        assert bad_block.hash not in [tip["hash"] for tip in peer.getchaintips() if tip["status"] != "invalid"]
        assert bad_block.hash not in [tip["hash"] for tip in child.getchaintips() if tip["status"] != "invalid"]
        assert_equal(self.shielded_pool_snapshot(peer), peer_shielded_state)
        assert_equal(self.shielded_pool_snapshot(child), child_shielded_state)
        assert_equal(
            [peer.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints],
            peer_utxos,
        )
        assert_equal(
            [child.gettxout(outpoint["txid"], outpoint["vout"], False) for outpoint in watched_outpoints],
            child_utxos,
        )

    def assert_bad_auxpow_block_did_not_poison_valid_sibling(self, peer, child, bad_block_hash, good_candidate):
        assert good_candidate["hash"] != bad_block_hash
        assert bad_block_hash not in [tip["hash"] for tip in peer.getchaintips() if tip["status"] != "invalid"]
        assert bad_block_hash not in [tip["hash"] for tip in child.getchaintips() if tip["status"] != "invalid"]
        assert_equal(peer.getbestblockhash(), good_candidate["hash"])
        assert_equal(child.getbestblockhash(), good_candidate["hash"])
        assert_equal(peer.getblockcount(), good_candidate["height"])
        assert_equal(child.getblockcount(), good_candidate["height"])

    def assert_valid_shielded_tx_relayed(self, source, peer, txid):
        assert txid in source.getrawmempool()
        self.sync_mempools([source, peer])
        assert_equal(source.getrawmempool(), [txid])
        assert_equal(peer.getrawmempool(), [txid])

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
        peer = self.nodes[2]
        self.stop_node(3)

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
        self.assert_orchard_child_config(child)

        self.log.info("Start a second child node to validate relayed Orchard AuxPoW blocks")
        self.stop_node(2)
        self.start_node(2, extra_args=self.child_launch_args(dump, verify))
        peer = self.nodes[2]
        peer.importsnapshotmanifest(dump["path"])
        self.assert_child_snapshot_imported(peer, dump, verify)
        self.assert_orchard_child_config(peer)
        self.connect_peer_to_child()

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
        self.sync_blocks([child, peer])
        assert_equal(peer.getblockcount(), 1)
        assert_equal(peer.getbestblockhash(), candidate["hash"])
        assert_equal(peer.getblockchaininfo()["shielded_pool"]["next_block_active"], True)

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
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_scaffold_mint,
            "bad-shielded-proof",
            watched_outpoints=[duplicate_proof_outpoint],
        )

        raw_bad_proof_mint, _ = self.create_real_orchard_mint_tx(
            child,
            duplicate_proof_outpoint,
            child_duplicate_proof,
            bob_key.address,
            vector,
            mutate_proof=True,
        )
        assert_raises_rpc_error(-26, "bad-shielded-proof", child.sendrawtransaction, raw_bad_proof_mint)
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_bad_proof_mint,
            "bad-shielded-proof",
            watched_outpoints=[duplicate_proof_outpoint],
        )

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
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_wrong_marker_mint,
            "bad-shielded-proof",
            watched_outpoints=[duplicate_proof_outpoint],
        )

        self.log.info("Reject a direct AuxPoW block containing a malformed real Orchard proof")
        bad_block_candidate = child.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)
        assert_equal(bad_block_candidate["height"], 2)
        bad_block_hex, bad_block_hash = self.auxpow_block_hex_with_txs(parent, bad_block_candidate, [raw_bad_proof_mint])
        assert_equal(child.submitblock(bad_block_hex), "bad-shielded-proof")
        assert_equal(child.getblockcount(), 1)
        assert_equal(child.getbestblockhash(), candidate["hash"])
        unspent_duplicate_proof = child.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"])
        assert_equal(Decimal(str(unspent_duplicate_proof["value"])), Decimal("6.00000000"))
        assert bad_block_hash not in [tip["hash"] for tip in child.getchaintips() if tip["status"] != "invalid"]
        self.assert_peer_rejects_bad_auxpow_block_without_relay(
            peer,
            child,
            bad_block_hex,
            bad_block_hash,
            "bad-shielded-proof",
            watched_outpoints=[duplicate_proof_outpoint],
        )

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
        self.assert_valid_shielded_tx_relayed(child, peer, real_mint_txid)

        if self.is_wallet_compiled():
            shielded_candidate = child.getauxblock()
        else:
            shielded_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(shielded_candidate["height"], 2)
        assert_equal(shielded_candidate["height"], bad_block_candidate["height"])
        assert shielded_candidate["hash"] != bad_block_hash
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

        self.sync_blocks([child, peer])
        assert_equal(peer.getblockcount(), 2)
        assert_equal(peer.getbestblockhash(), shielded_candidate["hash"])
        assert real_mint_txid in peer.getblock(shielded_candidate["hash"])["tx"]
        assert_equal(peer.getrawmempool(), [])
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(peer, child, bad_block_hash, shielded_candidate)
        peer_mint_info = peer.getblockchaininfo()["shielded_pool"]
        assert_equal(peer_mint_info["real_proof_backend"], "orchard-v1")
        assert_equal(peer_mint_info["real_proof_verification"], True)
        assert_equal(peer_mint_info["scaffold_proofs"], False)
        assert_equal(Decimal(str(peer_mint_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(peer_mint_info["commitments"], 1)
        assert_equal(peer_mint_info["nullifiers"], 0)
        assert_equal(peer_mint_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(peer_mint_info["root"]), spend_vector["anchor"])

        self.log.info("Restart child and replay the merge-mined real-proof mint state")
        self.restart_node(1, extra_args=self.child_launch_args(dump, verify))
        child = self.nodes[1]
        self.connect_peer_to_child()
        self.sync_blocks([child, peer])
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
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_bad_spend_proof,
            "bad-shielded-proof",
            watched_outpoints=[real_mint_outpoint],
        )

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
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_wrong_anchor_spend,
            "bad-shielded-proof",
            watched_outpoints=[real_mint_outpoint],
        )

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
        self.assert_valid_shielded_tx_relayed(child, peer, real_spend_txid)

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

        self.sync_blocks([child, peer])
        assert_equal(peer.getblockcount(), 3)
        assert_equal(peer.getbestblockhash(), spend_candidate["hash"])
        assert real_spend_txid in peer.getblock(spend_candidate["hash"])["tx"]
        assert_equal(peer.getrawmempool(), [])
        peer_spend_info = peer.getblockchaininfo()["shielded_pool"]
        assert_equal(peer_spend_info["real_proof_backend"], "orchard-v1")
        assert_equal(peer_spend_info["real_proof_verification"], True)
        assert_equal(peer_spend_info["scaffold_proofs"], False)
        assert_equal(Decimal(str(peer_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(peer_spend_info["commitments"], 1)
        assert_equal(peer_spend_info["nullifiers"], 1)
        assert_equal(peer_spend_info["anchors"], 2)

        self.log.info("Restart peer after relayed merge-mined real-proof spend state")
        self.restart_node(2, extra_args=self.child_launch_args(dump, verify))
        peer = self.nodes[2]
        self.connect_peer_to_child()
        self.sync_blocks([child, peer])
        assert_equal(peer.getblockcount(), 3)
        assert_equal(peer.getbestblockhash(), spend_candidate["hash"])
        self.assert_child_snapshot_imported(peer, dump, verify)
        self.assert_orchard_child_config(peer)
        assert real_mint_txid in peer.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in peer.getblock(spend_candidate["hash"])["tx"]
        replayed_peer_spend_info = peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(replayed_peer_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(replayed_peer_spend_info["commitments"], 1)
        assert_equal(replayed_peer_spend_info["nullifiers"], 1)
        assert_equal(replayed_peer_spend_info["anchors"], 2)
        assert_equal(peer.gettxout(real_mint_txid, 0, False), None)
        replayed_peer_spend_output = peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(replayed_peer_spend_output["value"])), Decimal("4.99800000"))
        assert_equal(peer.getrawmempool(), [])

        self.log.info("Invalidate and reconsider the relayed real-proof spend block on peer")
        peer.invalidateblock(spend_candidate["hash"])
        assert_equal(peer.getblockcount(), 2)
        assert_equal(peer.getbestblockhash(), shielded_candidate["hash"])
        assert real_spend_txid in peer.getrawmempool()
        peer_undo_spend_info = peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(peer_undo_spend_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(peer_undo_spend_info["commitments"], 1)
        assert_equal(peer_undo_spend_info["nullifiers"], 0)
        assert_equal(peer_undo_spend_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(peer_undo_spend_info["root"]), spend_vector["anchor"])
        peer_restored_mint_output = peer.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(peer_restored_mint_output["value"])), Decimal("3.99900000"))
        assert_equal(peer.gettxout(real_spend_txid, 0, False), None)

        peer.reconsiderblock(spend_candidate["hash"])
        assert_equal(peer.getblockcount(), 3)
        assert_equal(peer.getbestblockhash(), spend_candidate["hash"])
        assert_equal(peer.getrawmempool(), [])
        peer_reconsidered_spend_info = peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(peer_reconsidered_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(peer_reconsidered_spend_info["commitments"], 1)
        assert_equal(peer_reconsidered_spend_info["nullifiers"], 1)
        assert_equal(peer_reconsidered_spend_info["anchors"], 2)
        assert_equal(peer.gettxout(real_mint_txid, 0, False), None)
        peer_reconsidered_spend_output = peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(peer_reconsidered_spend_output["value"])), Decimal("4.99800000"))

        self.log.info("Start late peer and sync existing real-proof AuxPoW chain")
        self.start_node(3, extra_args=self.child_launch_args(dump, verify))
        late_peer = self.nodes[3]
        late_peer.importsnapshotmanifest(dump["path"])
        self.assert_child_snapshot_imported(late_peer, dump, verify)
        self.assert_orchard_child_config(late_peer)
        assert_equal(late_peer.getblockcount(), 0)
        assert_equal(late_peer.getrawmempool(), [])
        self.connect_node_to_child(3)
        self.sync_blocks([child, peer, late_peer])
        assert_equal(late_peer.getblockcount(), 3)
        assert_equal(late_peer.getbestblockhash(), spend_candidate["hash"])
        assert real_mint_txid in late_peer.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in late_peer.getblock(spend_candidate["hash"])["tx"]
        late_peer_spend_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(late_peer_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(late_peer_spend_info["commitments"], 1)
        assert_equal(late_peer_spend_info["nullifiers"], 1)
        assert_equal(late_peer_spend_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(late_peer_spend_info["root"]), spend_vector["anchor"])
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        late_peer_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(late_peer_spend_output["value"])), Decimal("4.99800000"))
        assert_equal(late_peer.getrawmempool(), [])

        self.log.info("Restart late peer after full-syncing real-proof AuxPoW chain")
        self.restart_node(3, extra_args=self.child_launch_args(dump, verify))
        late_peer = self.nodes[3]
        self.assert_child_snapshot_imported(late_peer, dump, verify)
        self.assert_orchard_child_config(late_peer)
        assert_equal(late_peer.getblockcount(), 3)
        assert_equal(late_peer.getbestblockhash(), spend_candidate["hash"])
        assert real_mint_txid in late_peer.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in late_peer.getblock(spend_candidate["hash"])["tx"]
        reloaded_late_peer_spend_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(reloaded_late_peer_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(reloaded_late_peer_spend_info["commitments"], 1)
        assert_equal(reloaded_late_peer_spend_info["nullifiers"], 1)
        assert_equal(reloaded_late_peer_spend_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(reloaded_late_peer_spend_info["root"]), spend_vector["anchor"])
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        reloaded_late_peer_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_late_peer_spend_output["value"])), Decimal("4.99800000"))
        assert_equal(late_peer.getrawmempool(), [])

        self.log.info("Invalidate and reconsider the replayed real-proof spend block on late peer")
        late_peer.invalidateblock(spend_candidate["hash"])
        assert_equal(late_peer.getblockcount(), 2)
        assert_equal(late_peer.getbestblockhash(), shielded_candidate["hash"])
        assert real_spend_txid in late_peer.getrawmempool()
        late_peer_undo_spend_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(late_peer_undo_spend_info["value_pool"])), Decimal("1.00000000"))
        assert_equal(late_peer_undo_spend_info["commitments"], 1)
        assert_equal(late_peer_undo_spend_info["nullifiers"], 0)
        assert_equal(late_peer_undo_spend_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(late_peer_undo_spend_info["root"]), spend_vector["anchor"])
        late_peer_restored_mint_output = late_peer.gettxout(real_mint_txid, 0, False)
        assert_equal(Decimal(str(late_peer_restored_mint_output["value"])), Decimal("3.99900000"))
        assert_equal(late_peer.gettxout(real_spend_txid, 0, False), None)

        late_peer.reconsiderblock(spend_candidate["hash"])
        assert_equal(late_peer.getblockcount(), 3)
        assert_equal(late_peer.getbestblockhash(), spend_candidate["hash"])
        assert_equal(late_peer.getrawmempool(), [])
        late_peer_reconsidered_spend_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(late_peer_reconsidered_spend_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(late_peer_reconsidered_spend_info["commitments"], 1)
        assert_equal(late_peer_reconsidered_spend_info["nullifiers"], 1)
        assert_equal(late_peer_reconsidered_spend_info["anchors"], 2)
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        late_peer_reconsidered_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(late_peer_reconsidered_spend_output["value"])), Decimal("4.99800000"))

        real_spend_outpoint = {"txid": real_spend_txid, "vout": 0}
        raw_duplicate_nullifier_spend, _ = self.create_real_orchard_spend_tx(
            child,
            real_spend_outpoint,
            real_spend_output,
            bob_key.address,
            spend_vector,
        )

        self.log.info("Reject duplicate nullifier on late peer after synced restart and reorg replay")
        late_peer_duplicate_state = self.shielded_pool_snapshot(late_peer)
        late_peer_duplicate_utxo = late_peer.gettxout(real_spend_txid, 0, False)
        assert_raises_rpc_error(
            -26,
            "bad-shielded-duplicate-nullifier",
            late_peer.sendrawtransaction,
            raw_duplicate_nullifier_spend,
        )
        late_bad_tx_peer = late_peer.add_p2p_connection(P2PDataStore())
        late_bad_tx_peer.send_txs_and_test(
            [FromHex(CTransaction(), raw_duplicate_nullifier_spend)],
            late_peer,
            success=False,
            expect_disconnect=False,
            reject_reason="bad-shielded-duplicate-nullifier",
        )
        assert_equal(late_peer.getrawmempool(), [])
        assert_equal(self.shielded_pool_snapshot(late_peer), late_peer_duplicate_state)
        assert_equal(late_peer.gettxout(real_spend_txid, 0, False), late_peer_duplicate_utxo)

        assert_raises_rpc_error(-26, "bad-shielded-duplicate-nullifier", child.sendrawtransaction, raw_duplicate_nullifier_spend)
        self.assert_peer_rejects_bad_shielded_tx_without_relay(
            peer,
            child,
            raw_duplicate_nullifier_spend,
            "bad-shielded-duplicate-nullifier",
            watched_outpoints=[real_spend_outpoint],
            expect_disconnect=False,
        )

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

        self.log.info("Reject duplicate-nullifier AuxPoW block on late peer without poisoning valid continuation")
        if self.is_wallet_compiled():
            duplicate_nullifier_candidate = child.getauxblock()
        else:
            duplicate_nullifier_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(duplicate_nullifier_candidate["height"], 4)
        duplicate_nullifier_block_hex, duplicate_nullifier_block_hash = self.auxpow_block_hex_with_txs(
            parent,
            duplicate_nullifier_candidate,
            [FromHex(CTransaction(), raw_duplicate_nullifier_spend)],
        )
        self.assert_peer_rejects_bad_auxpow_block_without_relay(
            late_peer,
            child,
            duplicate_nullifier_block_hex,
            duplicate_nullifier_block_hash,
            "bad-shielded-duplicate-nullifier",
            watched_outpoints=[real_spend_outpoint],
        )

        if self.is_wallet_compiled():
            continuation_candidate = child.getauxblock()
        else:
            continuation_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(continuation_candidate["height"], 4)
        assert continuation_candidate["hash"] != duplicate_nullifier_block_hash
        continuation_parent_block = self.mine_parent_block(parent, commitment_hex=continuation_candidate["auxpowcommitment"])
        continuation_auxpow = build_parent_auxpow(continuation_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(continuation_candidate["hash"], continuation_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(continuation_candidate["hash"], continuation_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 4)
        assert_equal(child.getbestblockhash(), continuation_candidate["hash"])
        self.connect_node_to_child(3)
        self.sync_blocks([child, late_peer])
        assert_equal(late_peer.getblockcount(), 4)
        assert_equal(late_peer.getbestblockhash(), continuation_candidate["hash"])
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(
            late_peer,
            child,
            duplicate_nullifier_block_hash,
            continuation_candidate,
        )
        continuation_child_info = child.getblockchaininfo()["shielded_pool"]
        continuation_late_peer_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(continuation_child_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(continuation_child_info["commitments"], 1)
        assert_equal(continuation_child_info["nullifiers"], 1)
        assert_equal(continuation_child_info["anchors"], 2)
        assert_equal(Decimal(str(continuation_late_peer_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(continuation_late_peer_info["commitments"], 1)
        assert_equal(continuation_late_peer_info["nullifiers"], 1)
        assert_equal(continuation_late_peer_info["anchors"], 2)

        self.log.info("Reject malformed-proof AuxPoW block on late peer without poisoning later continuation")
        if self.is_wallet_compiled():
            bad_proof_late_candidate = child.getauxblock()
        else:
            bad_proof_late_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(bad_proof_late_candidate["height"], 5)
        bad_proof_late_block_hex, bad_proof_late_block_hash = self.auxpow_block_hex_with_txs(
            parent,
            bad_proof_late_candidate,
            [FromHex(CTransaction(), raw_bad_proof_mint)],
        )
        self.assert_peer_rejects_bad_auxpow_block_without_relay(
            late_peer,
            child,
            bad_proof_late_block_hex,
            bad_proof_late_block_hash,
            "bad-shielded-proof",
            watched_outpoints=[duplicate_proof_outpoint],
        )

        if self.is_wallet_compiled():
            post_bad_proof_candidate = child.getauxblock()
        else:
            post_bad_proof_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(post_bad_proof_candidate["height"], 5)
        assert post_bad_proof_candidate["hash"] != bad_proof_late_block_hash
        post_bad_proof_parent_block = self.mine_parent_block(parent, commitment_hex=post_bad_proof_candidate["auxpowcommitment"])
        post_bad_proof_auxpow = build_parent_auxpow(post_bad_proof_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(post_bad_proof_candidate["hash"], post_bad_proof_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(post_bad_proof_candidate["hash"], post_bad_proof_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 5)
        assert_equal(child.getbestblockhash(), post_bad_proof_candidate["hash"])
        self.connect_node_to_child(3)
        self.sync_blocks([child, late_peer])
        assert_equal(late_peer.getblockcount(), 5)
        assert_equal(late_peer.getbestblockhash(), post_bad_proof_candidate["hash"])
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(
            late_peer,
            child,
            bad_proof_late_block_hash,
            post_bad_proof_candidate,
        )
        post_bad_proof_child_info = child.getblockchaininfo()["shielded_pool"]
        post_bad_proof_late_peer_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(post_bad_proof_child_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(post_bad_proof_child_info["commitments"], 1)
        assert_equal(post_bad_proof_child_info["nullifiers"], 1)
        assert_equal(post_bad_proof_child_info["anchors"], 2)
        assert_equal(Decimal(str(post_bad_proof_late_peer_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(post_bad_proof_late_peer_info["commitments"], 1)
        assert_equal(post_bad_proof_late_peer_info["nullifiers"], 1)
        assert_equal(post_bad_proof_late_peer_info["anchors"], 2)

        self.log.info("Restart late peer after malformed-proof rejection and replay valid continuation")
        self.restart_node(3, extra_args=self.child_launch_args(dump, verify))
        late_peer = self.nodes[3]
        self.assert_child_snapshot_imported(late_peer, dump, verify)
        self.assert_orchard_child_config(late_peer)
        assert_equal(late_peer.getblockcount(), 5)
        assert_equal(late_peer.getbestblockhash(), post_bad_proof_candidate["hash"])
        assert real_mint_txid in late_peer.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in late_peer.getblock(spend_candidate["hash"])["tx"]
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(
            late_peer,
            child,
            bad_proof_late_block_hash,
            post_bad_proof_candidate,
        )
        reloaded_post_bad_proof_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(reloaded_post_bad_proof_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(reloaded_post_bad_proof_info["commitments"], 1)
        assert_equal(reloaded_post_bad_proof_info["nullifiers"], 1)
        assert_equal(reloaded_post_bad_proof_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(reloaded_post_bad_proof_info["root"]), spend_vector["anchor"])
        assert_equal(late_peer.getrawmempool(), [])
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        reloaded_post_bad_proof_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(reloaded_post_bad_proof_spend_output["value"])), Decimal("4.99800000"))
        reloaded_duplicate_proof_output = late_peer.gettxout(duplicate_proof_outpoint["txid"], duplicate_proof_outpoint["vout"], False)
        assert_equal(Decimal(str(reloaded_duplicate_proof_output["value"])), Decimal("6.00000000"))

        self.log.info("Verify restarted late peer persists malformed-proof AuxPoW rejection")
        reloaded_bad_proof_state = self.shielded_pool_snapshot(late_peer)
        assert_equal(late_peer.submitblock(bad_proof_late_block_hex), "duplicate-invalid")
        assert_equal(late_peer.getblockcount(), 5)
        assert_equal(late_peer.getbestblockhash(), post_bad_proof_candidate["hash"])
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(
            late_peer,
            child,
            bad_proof_late_block_hash,
            post_bad_proof_candidate,
        )
        assert_equal(self.shielded_pool_snapshot(late_peer), reloaded_bad_proof_state)
        assert_equal(late_peer.getrawmempool(), [])
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        late_peer_after_duplicate_invalid_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(late_peer_after_duplicate_invalid_spend_output["value"])), Decimal("4.99800000"))
        late_peer_after_duplicate_invalid_proof_output = late_peer.gettxout(
            duplicate_proof_outpoint["txid"],
            duplicate_proof_outpoint["vout"],
            False,
        )
        assert_equal(Decimal(str(late_peer_after_duplicate_invalid_proof_output["value"])), Decimal("6.00000000"))

        self.log.info("Extend late peer after restarting with prior malformed-proof rejection")
        if self.is_wallet_compiled():
            post_restart_candidate = child.getauxblock()
        else:
            post_restart_candidate = child.createauxblock(child.get_deterministic_priv_key().address)
        assert_equal(post_restart_candidate["height"], 6)
        post_restart_parent_block = self.mine_parent_block(parent, commitment_hex=post_restart_candidate["auxpowcommitment"])
        post_restart_auxpow = build_parent_auxpow(post_restart_parent_block)
        if self.is_wallet_compiled():
            assert_equal(child.getauxblock(post_restart_candidate["hash"], post_restart_auxpow.serialize().hex()), True)
        else:
            assert_equal(child.submitauxblock(post_restart_candidate["hash"], post_restart_auxpow.serialize().hex()), True)
        assert_equal(child.getblockcount(), 6)
        assert_equal(child.getbestblockhash(), post_restart_candidate["hash"])
        self.connect_node_to_child(3)
        self.sync_blocks([child, late_peer])
        assert_equal(late_peer.getblockcount(), 6)
        assert_equal(late_peer.getbestblockhash(), post_restart_candidate["hash"])
        assert real_mint_txid in late_peer.getblock(shielded_candidate["hash"])["tx"]
        assert real_spend_txid in late_peer.getblock(spend_candidate["hash"])["tx"]
        self.assert_bad_auxpow_block_did_not_poison_valid_sibling(
            late_peer,
            child,
            bad_proof_late_block_hash,
            post_restart_candidate,
        )
        post_restart_late_peer_info = late_peer.getblockchaininfo()["shielded_pool"]
        assert_equal(Decimal(str(post_restart_late_peer_info["value_pool"])), Decimal("0.00000000"))
        assert_equal(post_restart_late_peer_info["commitments"], 1)
        assert_equal(post_restart_late_peer_info["nullifiers"], 1)
        assert_equal(post_restart_late_peer_info["anchors"], 2)
        assert_equal(self.root_hex_to_payload_bytes(post_restart_late_peer_info["root"]), spend_vector["anchor"])
        assert_equal(late_peer.getrawmempool(), [])
        assert_equal(late_peer.gettxout(real_mint_txid, 0, False), None)
        late_peer_post_restart_spend_output = late_peer.gettxout(real_spend_txid, 0, False)
        assert_equal(Decimal(str(late_peer_post_restart_spend_output["value"])), Decimal("4.99800000"))
        late_peer_post_restart_duplicate_output = late_peer.gettxout(
            duplicate_proof_outpoint["txid"],
            duplicate_proof_outpoint["vout"],
            False,
        )
        assert_equal(Decimal(str(late_peer_post_restart_duplicate_output["value"])), Decimal("6.00000000"))


if __name__ == "__main__":
    OrchardAuxPowRealProofTest().main()
