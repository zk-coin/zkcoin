#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""AuxPoW helpers for functional tests."""

from io import BytesIO
import struct

from test_framework.messages import (
    CBlockHeader,
    CTransaction,
    deser_uint256,
    deser_uint256_vector,
    hash256,
    ser_uint256,
    ser_uint256_vector,
    uint256_from_str,
    uint256_from_compact,
)
from test_framework.util import assert_equal


class AuxPow:
    """Serialized AuxPoW payload returned by getauxblock/createauxblock."""

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


def _merkle_branch_for_index(txs, tx_index):
    branch = []
    hashes = []
    for tx in txs:
        tx.calc_sha256()
        hashes.append(tx.sha256)

    index = tx_index
    while len(hashes) > 1:
        sibling_index = index ^ 1
        if sibling_index >= len(hashes):
            sibling_index = index
        branch.append(hashes[sibling_index])

        new_hashes = []
        for i in range(0, len(hashes), 2):
            j = min(i + 1, len(hashes) - 1)
            new_hashes.append(uint256_from_str(hash256(ser_uint256(hashes[i]) + ser_uint256(hashes[j]))))
        hashes = new_hashes
        index >>= 1

    return branch


def build_parent_auxpow(parent_block, tx_index=0):
    """Build an AuxPoW payload from a submitted parent block."""
    auxpow = AuxPow()
    auxpow.coinbase_tx = parent_block.vtx[tx_index]
    auxpow.hash_block = parent_block.sha256
    auxpow.merkle_branch = _merkle_branch_for_index(parent_block.vtx, tx_index)
    auxpow.index = tx_index
    auxpow.chain_merkle_branch = []
    auxpow.chain_index = 0
    auxpow.parent_header = CBlockHeader(parent_block)
    return auxpow


def solve_parent_header(auxpow, child_bits):
    auxpow.parent_header.nBits = child_bits
    auxpow.parent_header.nNonce = 0
    target = uint256_from_compact(child_bits)
    auxpow.parent_header.rehash()
    while auxpow.parent_header.scrypt256 > target:
        auxpow.parent_header.nNonce += 1
        auxpow.parent_header.rehash()


def solve_auxpow_hex(hex_auxpow, bits):
    """Return serialized AuxPoW with a parent header solved to the child target."""
    auxpow = parse_auxpow(hex_auxpow)
    solve_parent_header(auxpow, bits)
    return auxpow.serialize().hex()
