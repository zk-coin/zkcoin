#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test AuxPoW merge-mining RPC flow."""

import time
from decimal import Decimal
from io import BytesIO

from test_framework.address import ADDRESS_BCRT1_P2WSH_OP_TRUE, keyhash_to_p2pkh
from test_framework.blocktools import COIN, create_block, create_coinbase
from test_framework.messages import (
    CBlockHeader,
    hash256,
    ser_uint256,
    uint256_from_str,
    uint256_from_compact,
)
from test_framework.auxpow import parse_auxpow, solve_parent_header
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_array_result, assert_equal, assert_raises_rpc_error, hex_str_to_bytes


class AuxPowRPCTest(BitcoinTestFramework):
    CUSTOM_CHAIN_ID = 4660

    def set_test_params(self):
        self.num_nodes = 5
        self.setup_clean_chain = True
        self.supports_cli = False
        self.extra_args = [
            ["-auxpowheight=1"],
            ["-auxpowheight=2"],
            ["-auxpowheight=1"],
            ["-auxpowheight=1"],
            ["-auxpowheight=1", f"-auxpowchainid={self.CUSTOM_CHAIN_ID}"],
        ]

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

    def assert_auxpow_target(self, candidate):
        expected_target = ser_uint256(uint256_from_compact(int(candidate["bits"], 16))).hex()
        assert_equal(candidate["target"], expected_target)
        assert_equal(candidate["_target"], expected_target)

    def expected_chain_index(self, nonce, chain_id, merkle_height):
        modulo = 1 << merkle_height
        rand = nonce
        rand = (rand * 1103515245 + 12345) % modulo
        rand += chain_id
        rand = (rand * 1103515245 + 12345) % modulo
        return rand

    def chain_merkle_root(self, leaf_hash, merkle_branch, chain_index):
        root = leaf_hash
        index = chain_index
        for branch_hash in merkle_branch:
            if index & 1:
                root = uint256_from_str(hash256(ser_uint256(branch_hash) + ser_uint256(root)))
            else:
                root = uint256_from_str(hash256(ser_uint256(root) + ser_uint256(branch_hash)))
            index >>= 1
        return root

    def add_chain_merkle_branch(self, auxpow, candidate, chain_id=None):
        if chain_id is None:
            chain_id = candidate["chainid"]
        nonce = 0
        sibling = uint256_from_str(hash256(b"zkcoin-auxpow-rpc-chain-merkle-sibling"))
        auxpow.chain_merkle_branch = [sibling]
        auxpow.chain_index = self.expected_chain_index(nonce, chain_id, len(auxpow.chain_merkle_branch))

        root = self.chain_merkle_root(int(candidate["hash"], 16), auxpow.chain_merkle_branch, auxpow.chain_index)
        input_data = (
            bytes.fromhex("fabe6d6d")
            + bytes.fromhex(f"{root:064x}")
            + (1 << len(auxpow.chain_merkle_branch)).to_bytes(4, "little")
            + nonce.to_bytes(4, "little")
        )
        auxpow.coinbase_tx.vin[0].scriptSig = bytes([len(input_data)]) + input_data
        auxpow.coinbase_tx.rehash()
        auxpow.parent_header.hashMerkleRoot = auxpow.coinbase_tx.sha256

    def assert_wallet_coinbase(self, node, block_hash, coinbasevalue, previous_immature):
        amount = Decimal(coinbasevalue) / Decimal(COIN)
        coinbase_txid = node.getblock(block_hash)["tx"][0]
        wallet_tx = node.gettransaction(coinbase_txid)
        assert_equal(wallet_tx["generated"], True)
        assert_equal(wallet_tx["blockhash"], block_hash)
        assert_array_result(wallet_tx["details"], {"category": "immature"}, {"amount": amount})
        assert_equal(node.getbalances()["mine"]["immature"], previous_immature + amount)

    def assert_duplicate_valid_getauxblock_keeps_wallet_reservation(self):
        if not self.is_wallet_compiled() or self.options.descriptors:
            return

        miner = self.nodes[2]
        duplicate = self.nodes[3]

        seed = duplicate.dumpprivkey(
            keyhash_to_p2pkh(hex_str_to_bytes(duplicate.getwalletinfo()["hdseedid"])[::-1])
        )
        miner.sethdseed(seed=seed)
        self.connect_nodes(3, 2)
        self.sync_blocks([miner, duplicate])

        mock_time = miner.getblockheader(miner.getbestblockhash())["time"] + 1
        miner.setmocktime(mock_time)
        duplicate.setmocktime(mock_time)

        previous_immature = duplicate.getbalances()["mine"]["immature"]
        candidate = duplicate.getauxblock()
        pool_candidate = miner.getauxblock()
        assert_equal(pool_candidate["hash"], candidate["hash"])

        auxpow = parse_auxpow(pool_candidate["defaultauxpow"])
        solve_parent_header(auxpow, int(pool_candidate["bits"], 16))
        auxpow_hex = auxpow.serialize().hex()
        assert_equal(miner.getauxblock(pool_candidate["hash"], auxpow_hex), True)
        self.sync_blocks([miner, duplicate])
        duplicate.syncwithvalidationinterfacequeue()

        coinbase_address = duplicate.getblock(candidate["hash"], 2)["tx"][0]["vout"][0]["scriptPubKey"]["addresses"][0]
        assert_equal(duplicate.getauxblock(candidate["hash"], auxpow_hex), False)
        self.assert_wallet_coinbase(duplicate, candidate["hash"], candidate["coinbasevalue"], previous_immature)
        duplicate.syncwithvalidationinterfacequeue()
        assert duplicate.getnewaddress("", "bech32") != coinbase_address

        miner.setmocktime(0)
        duplicate.setmocktime(0)

    def assert_auxpow_block_relays_between_child_nodes(self):
        miner = self.nodes[2]
        peer = self.nodes[3]

        self.connect_nodes(2, 3)

        candidate = miner.createauxblock(miner.get_deterministic_priv_key().address)
        auxpow = parse_auxpow(candidate["defaultauxpow"])
        solve_parent_header(auxpow, int(candidate["bits"], 16))
        assert_equal(miner.submitauxblock(candidate["hash"], auxpow.serialize().hex()), True)

        self.sync_blocks([miner, peer])
        assert_equal(peer.getbestblockhash(), candidate["hash"])
        relayed_header_hex = peer.getblockheader(candidate["hash"], False)
        assert relayed_header_hex.startswith(candidate["header"])
        assert len(relayed_header_hex) > len(candidate["header"])

    def assert_custom_chain_id_accepts_auxpow(self):
        node = self.nodes[4]
        chain_id = self.CUSTOM_CHAIN_ID
        blockchain_info = node.getblockchaininfo()
        assert_equal(blockchain_info["auxpow"]["chain_id"], chain_id)
        assert_equal(blockchain_info["auxpow"]["strict_chain_id"], True)
        assert_equal(blockchain_info["auxpow"]["next_block_active"], True)
        assert_equal(blockchain_info["launch_readiness"]["chain_id_configured"], True)
        assert_equal(blockchain_info["launch_readiness"]["chain_history_clean"], True)

        candidate = node.createauxblock(node.get_deterministic_priv_key().address)
        assert_equal(candidate["chainid"], chain_id)
        assert_equal(candidate["height"], 1)

        header = CBlockHeader()
        header.deserialize(BytesIO(bytes.fromhex(candidate["header"])))
        header.rehash()
        assert_equal(header.hash, candidate["hash"])
        assert_equal(header.nVersion & 0xff, 4)
        assert_equal(header.nVersion >> 16, chain_id)
        assert header.nVersion & (1 << 8)

        wrong_auxpow = parse_auxpow(candidate["defaultauxpow"])
        self.add_chain_merkle_branch(wrong_auxpow, candidate, chain_id=chain_id + 1)
        solve_parent_header(wrong_auxpow, int(candidate["bits"], 16))
        assert_equal(node.submitauxblock(candidate["hash"], wrong_auxpow.serialize().hex()), False)
        assert_equal(node.getblockcount(), 0)

        auxpow = parse_auxpow(candidate["defaultauxpow"])
        assert_equal(auxpow.parent_header.nVersion >> 16, 0)
        self.add_chain_merkle_branch(auxpow, candidate)
        solve_parent_header(auxpow, int(candidate["bits"], 16))
        assert_equal(node.submitauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), candidate["hash"])

        mined_header_hex = node.getblockheader(candidate["hash"], False)
        assert mined_header_hex.startswith(candidate["header"])
        assert len(mined_header_hex) > len(candidate["header"])

        generated_hash = node.generatetodescriptor(1, f"addr({node.get_deterministic_priv_key().address})")[0]
        generated_header = CBlockHeader()
        generated_header.deserialize(BytesIO(bytes.fromhex(node.getblockheader(generated_hash, False)[:160])))
        assert_equal(generated_header.nVersion & 0xff, 4)
        assert_equal(generated_header.nVersion >> 16, chain_id)
        assert generated_header.nVersion & (1 << 8)
        assert_equal(node.getblockcount(), 2)

    def make_parent_header_unsolved(self, auxpow, bits):
        target = uint256_from_compact(bits)
        auxpow.parent_header.nNonce = 0
        auxpow.parent_header.rehash()
        while auxpow.parent_header.scrypt256 <= target:
            auxpow.parent_header.nNonce += 1
            auxpow.parent_header.rehash()

    def run_test(self):
        node = self.nodes[0]
        boundary_node = self.nodes[1]

        self.log.info("Accept AuxPoW with a non-default regtest chain id")
        self.assert_custom_chain_id_accepts_auxpow()

        self.log.info("Reject partial getauxblock submission arguments")
        assert_raises_rpc_error(-8, "Either provide both hash and auxpow, or provide neither.", node.getauxblock, "00")
        if not self.is_wallet_compiled():
            assert_raises_rpc_error(-18, "requires a loaded wallet", node.getauxblock)
            self.log.info("Relay an AuxPoW block between no-wallet child nodes")
            self.assert_auxpow_block_relays_between_child_nodes()
        elif not self.options.descriptors:
            self.log.info("Keep wallet reservation for duplicate-valid getauxblock submits")
            self.assert_duplicate_valid_getauxblock_keeps_wallet_reservation()

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
        self.assert_auxpow_target(pool_candidate)
        self.assert_auxpow_target(other_pool_candidate)

        self.log.info("Submit solved AuxPoW through Dogecoin-style RPC")
        other_pool_auxpow = parse_auxpow(other_pool_candidate["defaultauxpow"])
        solve_parent_header(other_pool_auxpow, int(other_pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(other_pool_candidate["hash"], other_pool_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 1)
        assert_equal(node.getbestblockhash(), other_pool_candidate["hash"])
        auxpow_height_one_hex = node.getblock(other_pool_candidate["hash"], False)

        self.log.info("Reject stale AuxPoW candidate with chain merkle branch built for the wrong chain id")
        wrong_chain_auxpow = parse_auxpow(pool_candidate["defaultauxpow"])
        self.add_chain_merkle_branch(wrong_chain_auxpow, pool_candidate, chain_id=pool_candidate["chainid"] ^ 1)
        solve_parent_header(wrong_chain_auxpow, int(pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(pool_candidate["hash"], wrong_chain_auxpow.serialize().hex()), False)
        assert_equal(node.getblockcount(), 1)

        self.log.info("Accept stale AuxPoW candidate with non-empty chain merkle branch as a side branch")
        pool_auxpow = parse_auxpow(pool_candidate["defaultauxpow"])
        self.add_chain_merkle_branch(pool_auxpow, pool_candidate)
        solve_parent_header(pool_auxpow, int(pool_candidate["bits"], 16))
        assert_equal(node.submitauxblock(pool_candidate["hash"], pool_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 1)
        chain_tips = {tip["hash"]: tip for tip in node.getchaintips()}
        assert_equal(chain_tips[other_pool_candidate["hash"]]["height"], 1)
        assert_equal(chain_tips[pool_candidate["hash"]]["height"], 1)
        assert_equal(chain_tips[pool_candidate["hash"]]["status"], "valid-headers")

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
        if self.is_wallet_compiled():
            previous_immature = node.getbalances()["mine"]["immature"]
            candidate = node.getauxblock()
            wallet_candidate_repeat = node.getauxblock()
            assert_equal(wallet_candidate_repeat["hash"], candidate["hash"])
        else:
            previous_immature = None
            candidate = node.createauxblock(address)
        assert_equal(candidate["height"], 2)
        assert_equal(candidate["chainid"], node.getblockchaininfo()["auxpow"]["chain_id"])
        assert_equal(candidate["previousblockhash"], node.getbestblockhash())
        assert_equal(candidate["auxpowcommitment"], "fabe6d6d" + candidate["hash"] + "0100000000000000")
        self.assert_auxpow_target(candidate)

        header = CBlockHeader()
        header.deserialize(BytesIO(bytes.fromhex(candidate["header"])))
        header.rehash()
        assert_equal(header.hash, candidate["hash"])

        self.log.info("Mine parent AuxPoW header and submit candidate")
        auxpow = parse_auxpow(candidate["defaultauxpow"])
        solve_parent_header(auxpow, int(candidate["bits"], 16))
        assert_equal(node.getauxblock(candidate["hash"], auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 2)
        assert_equal(node.getbestblockhash(), candidate["hash"])
        if self.is_wallet_compiled():
            self.assert_wallet_coinbase(node, candidate["hash"], candidate["coinbasevalue"], previous_immature)

        self.log.info("Reject unknown AuxPoW candidate")
        assert_raises_rpc_error(
            -8,
            "block hash unknown",
            node.getauxblock,
            candidate["hash"],
            auxpow.serialize().hex(),
        )

        self.log.info("Reject malformed AuxPoW proof")
        next_candidate = node.createauxblock(address)
        for malformed_auxpow in ("zz", "00", next_candidate["defaultauxpow"] + "00"):
            assert_raises_rpc_error(-22, "decode failed", node.getauxblock, next_candidate["hash"], malformed_auxpow)
            assert_raises_rpc_error(-22, "decode failed", node.submitauxblock, next_candidate["hash"], malformed_auxpow)

        bad_auxpow = parse_auxpow(next_candidate["defaultauxpow"])
        solve_parent_header(bad_auxpow, int(next_candidate["bits"], 16))
        bad_auxpow.index = 1
        assert_equal(node.getauxblock(next_candidate["hash"], bad_auxpow.serialize().hex()), False)
        assert_equal(node.getblockcount(), 2)

        retry_auxpow = parse_auxpow(next_candidate["defaultauxpow"])
        solve_parent_header(retry_auxpow, int(next_candidate["bits"], 16))
        assert_equal(node.submitauxblock(next_candidate["hash"], retry_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 3)
        assert_equal(node.getbestblockhash(), next_candidate["hash"])

        self.log.info("Reject unsolved parent AuxPoW header")
        unsolved_candidate = node.createauxblock(ADDRESS_BCRT1_P2WSH_OP_TRUE)
        unsolved_auxpow = parse_auxpow(unsolved_candidate["defaultauxpow"])
        self.make_parent_header_unsolved(unsolved_auxpow, int(unsolved_candidate["bits"], 16))
        assert_equal(node.submitauxblock(unsolved_candidate["hash"], unsolved_auxpow.serialize().hex()), False)
        assert_equal(node.getblockcount(), 3)

        retry_unsolved_auxpow = parse_auxpow(unsolved_candidate["defaultauxpow"])
        solve_parent_header(retry_unsolved_auxpow, int(unsolved_candidate["bits"], 16))
        assert_equal(node.submitauxblock(unsolved_candidate["hash"], retry_unsolved_auxpow.serialize().hex()), True)
        assert_equal(node.getblockcount(), 4)
        assert_equal(node.getbestblockhash(), unsolved_candidate["hash"])

        self.log.info("Refresh cached AuxPoW candidate after delayed mempool update")
        mined_blocks = node.generatetodescriptor(100, f"addr({address})")
        spend_coinbase = node.getblock(mined_blocks[0], 2)["tx"][0]
        cached_candidate = node.createauxblock(address)
        node.setmocktime(max(int(time.time()), node.getblockheader(node.getbestblockhash())["time"]) + 120)
        raw_spend = node.createrawtransaction(
            [{"txid": spend_coinbase["txid"], "vout": 0}],
            {ADDRESS_BCRT1_P2WSH_OP_TRUE: Decimal("49.99900000")},
        )
        signed_spend = node.signrawtransactionwithkey(raw_spend, [node.get_deterministic_priv_key().key], [{
            "txid": spend_coinbase["txid"],
            "vout": 0,
            "scriptPubKey": spend_coinbase["vout"][0]["scriptPubKey"]["hex"],
            "amount": spend_coinbase["vout"][0]["value"],
        }])
        assert_equal(signed_spend["complete"], True)
        spend_txid = node.sendrawtransaction(signed_spend["hex"])
        refreshed_candidate = node.createauxblock(address)
        assert refreshed_candidate["hash"] != cached_candidate["hash"]
        assert_equal(refreshed_candidate["height"], cached_candidate["height"])
        stale_auxpow = parse_auxpow(cached_candidate["defaultauxpow"])
        self.make_parent_header_unsolved(stale_auxpow, int(cached_candidate["bits"], 16))
        assert_equal(node.submitauxblock(cached_candidate["hash"], stale_auxpow.serialize().hex()), False)
        refreshed_auxpow = parse_auxpow(refreshed_candidate["defaultauxpow"])
        solve_parent_header(refreshed_auxpow, int(refreshed_candidate["bits"], 16))
        assert_equal(node.submitauxblock(refreshed_candidate["hash"], refreshed_auxpow.serialize().hex()), True)
        assert spend_txid in node.getblock(refreshed_candidate["hash"])["tx"]
        node.setmocktime(0)

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
        assert_raises_rpc_error(
            -25,
            "bad-auxpow-missing",
            boundary_node.submitheader,
            CBlockHeader(plain_height_two).serialize().hex(),
        )
        assert_equal(boundary_node.getblockcount(), 1)

        height_two_candidate = boundary_node.createauxblock(boundary_node.get_deterministic_priv_key().address)
        height_two_unsolved_auxpow = parse_auxpow(height_two_candidate["defaultauxpow"])
        self.make_parent_header_unsolved(height_two_unsolved_auxpow, int(height_two_candidate["bits"], 16))
        assert_raises_rpc_error(
            -25,
            "high-hash",
            boundary_node.submitheader,
            height_two_candidate["header"] + height_two_unsolved_auxpow.serialize().hex(),
        )
        assert_equal(boundary_node.getblockcount(), 1)

        height_two_auxpow = parse_auxpow(height_two_candidate["defaultauxpow"])
        solve_parent_header(height_two_auxpow, int(height_two_candidate["bits"], 16))
        height_two_header_hex = height_two_candidate["header"] + height_two_auxpow.serialize().hex()
        boundary_node.submitheader(height_two_header_hex)
        chain_tips = {tip["hash"]: tip for tip in boundary_node.getchaintips()}
        assert_equal(chain_tips[height_two_candidate["hash"]]["height"], 2)
        assert_equal(chain_tips[height_two_candidate["hash"]]["status"], "headers-only")
        assert_equal(boundary_node.getblockcount(), 1)
        assert_equal(boundary_node.getauxblock(height_two_candidate["hash"], height_two_auxpow.serialize().hex()), True)
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
