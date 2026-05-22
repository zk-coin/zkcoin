#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test mempool RPC behavior for MWEB-only transactions."""

from test_framework.ltc_util import setup_mweb_chain
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class MWEBMempoolTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [
            [
                "-rpcserialversion=0",
                "-whitelist=noban@127.0.0.1",
            ],
            [
                "-rpcserialversion=1",
                "-whitelist=noban@127.0.0.1",
            ],
            [
                "-whitelist=noban@127.0.0.1",
            ],
        ]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def run_test(self):
        legacy_no_witness = self.nodes[0]
        legacy_no_mweb = self.nodes[1]
        current_rpc = self.nodes[2]

        self.log.info("Set up an activated MWEB chain")
        setup_mweb_chain(legacy_no_witness)
        self.sync_all()

        self.log.info("Peg in coins to fund an MWEB-only spend")
        legacy_no_witness.sendtoaddress(legacy_no_witness.getnewaddress(address_type="mweb"), 10)
        legacy_no_witness.generate(1)
        self.sync_all()

        self.log.info("Create an MWEB-to-MWEB mempool transaction")
        txid = legacy_no_witness.sendtoaddress(legacy_no_witness.getnewaddress(address_type="mweb"), 2)
        self.sync_mempools()

        self.log.info("Return the txid but not the entry for rpcserialversion=0")
        assert_equal([txid], legacy_no_witness.getrawmempool())
        assert_raises_rpc_error(
            -22,
            "MWEB-only transaction not serializable for rpcserialversion<2",
            legacy_no_witness.getmempoolentry,
            txid,
        )

        self.log.info("Return the txid but not the entry for rpcserialversion=1")
        assert_equal([txid], legacy_no_mweb.getrawmempool())
        assert_raises_rpc_error(
            -22,
            "MWEB-only transaction not serializable for rpcserialversion<2",
            legacy_no_mweb.getmempoolentry,
            txid,
        )

        self.log.info("Return the txid and mempool entry for rpcserialversion=2")
        assert_equal([txid], current_rpc.getrawmempool())
        assert current_rpc.getmempoolentry(txid) is not None


if __name__ == "__main__":
    MWEBMempoolTest().main()
