#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AuxPoW merge-mining RPC flow."""

from io import BytesIO

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE
from test_framework.blocktools import create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    hash256,
)
from test_framework.auxpow import parse_auxpow, solve_parent_header
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AuxPowRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-auxpowheight=1"], ["-auxpowheight=2"]]

    def setup_network(self):
        self.setup_nodes()

    def create_plain_block(self, node):
        height = node.getblockcount() + 1
        tip_hash = node.getbestblockhash()
        block_time = node.getblockheader(tip_hash)["time"] + 1
        block = create_block(int(tip_hash, 16), create_coinbase(height), block_time)
        block.solve()
        return block

    def with_wrong_child_chain_id(self, header_hex):
        version = int.from_bytes(bytes.fromhex(header_hex[:8]), "little")
        wrong_version = version + (1 << 16)
        header = wrong_version.to_bytes(4, "little").hex() + header_hex[8:]
        child_hash = hash256(bytes.fromhex(header))[::-1].hex()
        return header, child_hash

    def make_auxpow_commitment(self, auxpow, original_child_hash, child_hash):
        script_sig = auxpow.coinbase_tx.vin[0].scriptSig
        if bytes.fromhex(original_child_hash)[::-1] in script_sig:
            child_hash_bytes = bytes.fromhex(child_hash)[::-1]
        elif bytes.fromhex(original_child_hash) in script_sig:
            child_hash_bytes = bytes.fromhex(child_hash)
        else:
            raise AssertionError("default AuxPoW commitment does not contain the child hash")

        input_data = child_hash_bytes + b"\x01" + b"\x00" * 7
        auxpow.coinbase_tx.vin[0].scriptSig = bytes([len(input_data)]) + input_data
        auxpow.coinbase_tx.rehash()
        auxpow.parent_header.hashMerkleRoot = auxpow.coinbase_tx.sha256
        auxpow.parent_header.rehash()
        assert script_sig != auxpow.coinbase_tx.vin[0].scriptSig

    def run_test(self):
        node = self.nodes[0]
        boundary_node = self.nodes[1]

        self.log.info("Reject partial getauxblock submission arguments")
        assert_raises_rpc_error(-8, "Either provide both hash and auxpow, or provide neither.", node.getauxblock, "00")

        self.log.info("Create Dogecoin-style AuxPoW candidates keyed by payout address")
        address = node.get_deterministic_priv_key().address
        pool_candidate = node.createauxblock(address)
        pool_candidate_repeat = node.createauxblock(address)
        assert_equal(pool_candidate_repeat["hash"], pool_candidate["hash"])
        other_pool_candidate = node.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)
        assert other_pool_candidate["hash"] != pool_candidate["hash"]
        assert_equal(other_pool_candidate["height"], pool_candidate["height"])
        assert_equal(other_pool_candidate["previousblockhash"], pool_candidate["previousblockhash"])
        pool_candidate_after_other = node.createauxblock(address)
        assert_equal(pool_candidate_after_other["hash"], pool_candidate["hash"])
        assert_equal(pool_candidate["height"], 1)
        assert_equal(pool_candidate["chainid"], node.getblockchaininfo()["auxpow"]["chain_id"])
        assert_equal(pool_candidate["auxpowcommitment"], "fabe6d6d" + pool_candidate["hash"] + "0100000000000000")

        self.log.info("Submit solved AuxPoW through Dogecoin-style RPC")
        other_pool_auxpow = parse_auxpow(other_pool_candidate["defaultauxpow"])
        solve_parent_header(other_pool_auxpow, int(other_pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(other_pool_candidate["hash"], other_pool_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), other_pool_candidate["hash"])
        auxpow_height_one_hex = node.getblock(other_pool_candidate["hash"], False)

        self.log.info("Reject stale Dogecoin-style AuxPoW candidate after tip advances")
        pool_auxpow = parse_auxpow(pool_candidate["defaultauxpow"])
        solve_parent_header(pool_auxpow, int(pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(pool_candidate["hash"], pool_auxpow.serialize().hex()), False)
        assert_raises_rpc_error(
            -8,
            "block hash unknown",
            node.submitauxblock,
            pool_candidate["hash"],
            pool_auxpow.serialize().hex(),
        )

        header_hex = node.getblockheader(other_pool_candidate["hash"], False)
        assert header_hex.startswith(other_pool_candidate["header"])
        assert len(header_hex) > len(other_pool_candidate["header"])

        self.log.info("Reload AuxPoW header payload from block index after restart")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockheader(other_pool_candidate["hash"], False), header_hex)

        self.log.info("Reject unknown AuxPoW candidate through Dogecoin-style RPC")
        assert_raises_rpc_error(
            -8,
            "block hash unknown",
            node.submitauxblock,
            other_pool_candidate["hash"],
            other_pool_auxpow.serialize().hex(),
        )

        self.log.info("Create AuxPoW candidate")
        candidate = node.getauxblock()
        assert_equal(candidate["height"], 2)
        assert_equal(candidate["chainid"], node.getblockchaininfo()["auxpow"]["chain_id"])
        assert_equal(candidate["previousblockhash"], node.getbestblockhash())
        assert_equal(candidate["auxpowcommitment"], "fabe6d6d" + candidate["hash"] + "0100000000000000")

        header = CBlockHeader()
        header.deserialize(BytesIO(bytes.fromhex(candidate["header"])))
        header.rehash()
        assert_equal(header.hash, candidate["hash"])

        self.log.info("Mine parent AuxPoW header and submit candidate")
        auxpow = parse_auxpow(candidate["defaultauxpow"])
        solve_parent_header(auxpow, int(candidate["bits"], 16))
        assert_equal(node.getauxblock(candidate["hash"], auxpow.serialize().hex()), None)
        assert_equal(node.getblockcount(), 2)
        assert_equal(node.getbestblockhash(), candidate["hash"])

        self.log.info("Reject unknown AuxPoW candidate")
        assert_raises_rpc_error(
            -8,
            "Unknown AuxPoW candidate",
            node.getauxblock,
            candidate["hash"],
            auxpow.serialize().hex(),
        )

        self.log.info("Reject malformed AuxPoW proof")
        next_candidate = node.getauxblock()
        bad_auxpow = parse_auxpow(next_candidate["defaultauxpow"])
        solve_parent_header(bad_auxpow, int(next_candidate["bits"], 16))
        bad_auxpow.index = 1
        assert_equal(node.getauxblock(next_candidate["hash"], bad_auxpow.serialize().hex()), "high-hash")
        assert_equal(node.getblockcount(), 2)

        self.log.info("Enforce AuxPoW activation boundary")
        assert_equal(boundary_node.getblockchaininfo()["auxpow"]["next_block_active"], False)
        assert_raises_rpc_error(-1, "AuxPoW is not active for the next block", boundary_node.getauxblock)
        assert_raises_rpc_error(
            -1,
            "AuxPoW is not active for the next block",
            boundary_node.createauxblock,
            boundary_node.get_deterministic_priv_key().address,
        )
        assert_equal(boundary_node.submitblock(auxpow_height_one_hex), "bad-auxpow-unexpected")
        assert_equal(boundary_node.getblockcount(), 0)

        boundary_node.generatetodescriptor(1, "raw(51)")
        assert_equal(boundary_node.getblockcount(), 1)
        assert_equal(boundary_node.getblockchaininfo()["auxpow"]["next_block_active"], True)

        plain_height_two = self.create_plain_block(boundary_node)
        assert_equal(boundary_node.submitblock(plain_height_two.serialize().hex()), "bad-auxpow-missing")
        assert_equal(boundary_node.getblockcount(), 1)

        height_two_candidate = boundary_node.getauxblock()
        height_two_auxpow = parse_auxpow(height_two_candidate["defaultauxpow"])
        solve_parent_header(height_two_auxpow, int(height_two_candidate["bits"], 16))
        assert_equal(boundary_node.getauxblock(height_two_candidate["hash"], height_two_auxpow.serialize().hex()), None)
        assert_equal(boundary_node.getblockcount(), 2)
        height_two_hex = boundary_node.getblock(height_two_candidate["hash"], False)

        boundary_node.invalidateblock(height_two_candidate["hash"])
        assert_equal(boundary_node.getblockcount(), 1)
        wrong_header, wrong_hash = self.with_wrong_child_chain_id(height_two_candidate["header"])
        wrong_auxpow = parse_auxpow(height_two_candidate["defaultauxpow"])
        self.make_auxpow_commitment(wrong_auxpow, height_two_candidate["hash"], wrong_hash)
        solve_parent_header(wrong_auxpow, int(height_two_candidate["bits"], 16))
        tx_payload_hex = height_two_hex[160 + len(height_two_auxpow.serialize().hex()):]
        assert_equal(boundary_node.submitblock(wrong_header + wrong_auxpow.serialize().hex() + tx_payload_hex), "bad-auxpow-chainid")
        assert_equal(boundary_node.getblockcount(), 1)


if __name__ == "__main__":
    AuxPowRPCTest().main()
