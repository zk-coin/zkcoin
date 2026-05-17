#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AuxPoW merge-mining RPC flow."""

from io import BytesIO
import struct

from test_framework.messages import (
    CBlockHeader,
    CTransaction,
    deser_uint256,
    deser_uint256_vector,
    ser_uint256,
    ser_uint256_vector,
    uint256_from_compact,
)
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class AuxPow:
    def deserialize(self, f):
        self.coinbase_tx = CTransaction()
        self.coinbase_tx.deserialize(f)
        self.hash_block = deser_uint256(f)
        self.merkle_branch = deser_uint256_vector(f)
        self.index = struct.unpack("<i", f.read(4))[0]
        self.chain_merkle_branch = deser_uint256_vector(f)
        self.chain_index = struct.unpack("<i", f.read(4))[0]
        self.parent_header = CBlockHeader()
        self.parent_header.deserialize(f)
        assert_equal(f.read(), b"")

    def serialize(self):
        r = self.coinbase_tx.serialize()
        r += ser_uint256(self.hash_block)
        r += ser_uint256_vector(self.merkle_branch)
        r += struct.pack("<i", self.index)
        r += ser_uint256_vector(self.chain_merkle_branch)
        r += struct.pack("<i", self.chain_index)
        r += self.parent_header.serialize()
        return r


def parse_auxpow(hex_auxpow):
    auxpow = AuxPow()
    auxpow.deserialize(BytesIO(bytes.fromhex(hex_auxpow)))
    return auxpow


def solve_parent_header(auxpow, child_bits):
    auxpow.parent_header.nBits = child_bits
    auxpow.parent_header.nNonce = 0
    target = uint256_from_compact(child_bits)
    auxpow.parent_header.rehash()
    while auxpow.parent_header.scrypt256 > target:
        auxpow.parent_header.nNonce += 1
        auxpow.parent_header.rehash()


class AuxPowRPCTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [["-auxpowheight=1"]]

    def run_test(self):
        node = self.nodes[0]

        self.log.info("Reject partial getauxblock submission arguments")
        assert_raises_rpc_error(-8, "Either provide both hash and auxpow, or provide neither.", node.getauxblock, "00")

        self.log.info("Create Dogecoin-style AuxPoW candidate with payout address")
        address = node.get_deterministic_priv_key().address
        pool_candidate = node.createauxblock(address)
        pool_candidate_repeat = node.createauxblock(address)
        assert_equal(pool_candidate_repeat["hash"], pool_candidate["hash"])
        assert_equal(pool_candidate["height"], 1)
        assert_equal(pool_candidate["chainid"], node.getblockchaininfo()["auxpow"]["chain_id"])
        assert_equal(pool_candidate["auxpowcommitment"], "fabe6d6d" + pool_candidate["hash"] + "0100000000000000")

        self.log.info("Submit solved AuxPoW through Dogecoin-style RPC")
        pool_auxpow = parse_auxpow(pool_candidate["defaultauxpow"])
        solve_parent_header(pool_auxpow, int(pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(pool_candidate["hash"], pool_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), pool_candidate["hash"])

        header_hex = node.getblockheader(pool_candidate["hash"], False)
        assert header_hex.startswith(pool_candidate["header"])
        assert len(header_hex) > len(pool_candidate["header"])

        self.log.info("Reload AuxPoW header payload from block index after restart")
        self.restart_node(0)
        node = self.nodes[0]
        assert_equal(node.getblockheader(pool_candidate["hash"], False), header_hex)

        self.log.info("Reject unknown AuxPoW candidate through Dogecoin-style RPC")
        assert_raises_rpc_error(
            -8,
            "block hash unknown",
            node.submitauxblock,
            pool_candidate["hash"],
            pool_auxpow.serialize().hex(),
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


if __name__ == "__main__":
    AuxPowRPCTest().main()
