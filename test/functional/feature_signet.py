#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Assert zkCoin signet stays explicitly disabled until it has real params."""

from test_framework.test_framework import BitcoinTestFramework


SIGNET_DISABLED_ERROR = (
    "Error: CreateChainParams: zkCoin signet is disabled until dedicated "
    "zkCoin signet chainparams are implemented."
)


class SignetUnsupportedTest(BitcoinTestFramework):
    def set_test_params(self):
        self.chain = "signet"
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.add_nodes(self.num_nodes)

    def run_test(self):
        self.nodes[0].assert_start_raises_init_error(
            expected_msg=SIGNET_DISABLED_ERROR,
        )


if __name__ == '__main__':
    SignetUnsupportedTest().main()
