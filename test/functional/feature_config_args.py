#!/usr/bin/env python3
# Copyright (c) 2017-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test various command line arguments and configuration file parameters."""

import os

from test_framework.test_framework import BitcoinTestFramework


class ConfArgsTest(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1
        self.supports_cli = False
        self.wallet_names = []

    def test_config_file_parser(self):
        # Assume node is stopped

        inc_conf_file_path = os.path.join(self.nodes[0].datadir, 'include.conf')
        with open(os.path.join(self.nodes[0].datadir, 'litecoin.conf'), 'a', encoding='utf-8') as conf:
            conf.write('includeconf={}\n'.format(inc_conf_file_path))

        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: Error parsing command line arguments: Invalid parameter -dash_cli=1',
            extra_args=['-dash_cli=1'],
        )
        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('dash_conf=1\n')
        with self.nodes[0].assert_debug_log(expected_msgs=['Ignoring unknown configuration value dash_conf']):
            self.start_node(0)
        self.stop_node(0)

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('-dash=1\n')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 1: -dash=1, options in configuration file must be specified without leading -')

        if self.is_wallet_compiled():
            with open(inc_conf_file_path, 'w', encoding='utf8') as conf:
                conf.write("wallet=foo\n")
            self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Config setting for -wallet only applied on %s network when in [%s] section.' % (self.chain, self.chain))

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('regtest=0\n') # mainnet
            conf.write('acceptnonstdtxn=1\n')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: acceptnonstdtxn is not currently supported for main chain')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('nono\n')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 1: nono, if you intended to specify a negated option, use nono=1 instead')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\nrpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 3, using # in rpcpassword can be ambiguous and should be avoided')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\nmain.rpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 3, using # in rpcpassword can be ambiguous and should be avoided')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('server=1\nrpcuser=someuser\n[main]\nrpcpassword=some#pass')
        self.nodes[0].assert_start_raises_init_error(expected_msg='Error: Error reading configuration file: parse error on line 4, using # in rpcpassword can be ambiguous and should be avoided')

        inc_conf_file2_path = os.path.join(self.nodes[0].datadir, 'include2.conf')
        with open(os.path.join(self.nodes[0].datadir, 'litecoin.conf'), 'a', encoding='utf-8') as conf:
            conf.write('includeconf={}\n'.format(inc_conf_file2_path))

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('testnot.datadir=1\n')
        with open(inc_conf_file2_path, 'w', encoding='utf-8') as conf:
            conf.write('[testnet]\n')
        self.restart_node(0)
        self.nodes[0].stop_node(expected_stderr='Warning: ' + inc_conf_file_path + ':1 Section [testnot] is not recognized.' + os.linesep + inc_conf_file2_path + ':1 Section [testnet] is not recognized.')

        with open(inc_conf_file_path, 'w', encoding='utf-8') as conf:
            conf.write('')  # clear
        with open(inc_conf_file2_path, 'w', encoding='utf-8') as conf:
            conf.write('')  # clear

    def test_invalid_command_line_options(self):
        self.nodes[0].assert_start_raises_init_error(
            expected_msg='Error: No proxy server specified. Use -proxy=<ip> or -proxy=<ip:port>.',
            extra_args=['-proxy'],
        )
        invalid_activation_args = [
            ("-auxpowheight=-2", "Activation height -2 for auxpow is out of valid range. Use -1 to disable auxpow."),
            ("-auxpowheight=2147483647", "Activation height 2147483647 for auxpow is out of valid range. Use -1 to disable auxpow."),
            ("-auxpowchainid=-1", "AuxPoW chain id -1 is out of valid range. Use 0 through 32767."),
            ("-auxpowchainid=32768", "AuxPoW chain id 32768 is out of valid range. Use 0 through 32767."),
            ("-shieldedheight=-2", "Activation height -2 for shielded pool is out of valid range. Use -1 to disable shielded pool."),
            ("-shieldedheight=2147483647", "Activation height 2147483647 for shielded pool is out of valid range. Use -1 to disable shielded pool."),
        ]
        for arg, error in invalid_activation_args:
            self.nodes[0].assert_start_raises_init_error(
                expected_msg=f"Error: {error}",
                extra_args=[arg],
            )

        public_launch_override_args = [
            "-auxpowheight=1",
            "-auxpowchainid=4660",
            "-noauxpowstrictchainid",
            "-shieldedheight=2",
            "-noshieldedscaffoldproofs",
            "-ltcsnapshotheight=123",
            "-ltcsnapshotblockhash=" + "11" * 32,
            "-ltcsnapshotutxoroot=" + "22" * 32,
        ]
        for chain in ["main", "test"]:
            for arg in public_launch_override_args:
                normalized_arg = "-" + arg[3:] if arg.startswith("-no") else arg.split("=", 1)[0]
                self.nodes[0].assert_start_raises_init_error(
                    expected_msg=(
                        f"Error: {normalized_arg} is only supported on regtest; "
                        "production launch consensus parameters must be hardcoded in chainparams."
                    ),
                    extra_args=["-regtest=0", f"-chain={chain}", arg],
                )

        public_launch_disabled_error = (
            "Error: zkCoin public networks are disabled until the production launch profile is hardcoded in chainparams: "
            "configure the Litecoin block-X snapshot, activate strict AuxPoW for the first launch block with a parent-version-safe chain id, "
            "activate script validation rules for the first launch block, keep shielded transactions inactive for the first launch block, "
            "clear inherited Litecoin chain history assumptions, "
            "and replace the inherited Litecoin public network identity. "
            "Missing hardcoded launch checks: snapshot consensus parameters are not configured; "
            "AuxPoW is not active for the first launch block; "
            "script validation rules are not active for the first launch block; "
            "public network identity is inherited from Litecoin or malformed."
        )
        for chain in ["main", "test"]:
            self.nodes[0].assert_start_raises_init_error(
                expected_msg=public_launch_disabled_error,
                extra_args=["-regtest=0", f"-chain={chain}"],
            )

        snapshot_args = [
            "-ltcsnapshotheight=123",
            "-ltcsnapshotblockhash=" + "11" * 32,
            "-ltcsnapshotutxoroot=" + "22" * 32,
        ]
        snapshot_file_error = (
            "Error: -ltcsnapshotfile is required when rebuilding chainstate with configured Litecoin snapshot parameters. "
            "Set -ltcsnapshotfile=<path> to the block-X snapshot manifest."
        )
        for reindex_arg in ["-reindex", "-reindex-chainstate"]:
            self.nodes[0].assert_start_raises_init_error(
                expected_msg=snapshot_file_error,
                extra_args=snapshot_args + [reindex_arg],
            )

    def test_log_buffer(self):
        with self.nodes[0].assert_debug_log(expected_msgs=['Warning: parsed potentially confusing double-negative -connect=0\n']):
            self.start_node(0, extra_args=['-noconnect=0'])
        self.stop_node(0)

    def test_args_log(self):
        self.log.info('Test config args logging')
        with self.nodes[0].assert_debug_log(
                expected_msgs=[
                    'Command-line arg: addnode="some.node"',
                    'Command-line arg: rpcauth=****',
                    'Command-line arg: rpcbind=****',
                    'Command-line arg: rpcpassword=****',
                    'Command-line arg: rpcuser=****',
                    'Command-line arg: torpassword=****',
                    'Config file arg: %s="1"' % self.chain,
                    'Config file arg: [%s] server="1"' % self.chain,
                ],
                unexpected_msgs=[
                    'alice:f7efda5c189b999524f151318c0c86$d5b51b3beffbc0',
                    '127.1.1.1',
                    'secret-rpcuser',
                    'secret-torpassword',
                ]):
            self.start_node(0, extra_args=[
                '-addnode=some.node',
                '-rpcauth=alice:f7efda5c189b999524f151318c0c86$d5b51b3beffbc0',
                '-rpcbind=127.1.1.1',
                '-rpcpassword=',
                '-rpcuser=secret-rpcuser',
                '-torpassword=secret-torpassword',
            ])
        self.stop_node(0)

    def test_networkactive(self):
        self.log.info('Test -networkactive option')
        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0)
        self.stop_node(0)

        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0, extra_args=['-networkactive'])
        self.stop_node(0)

        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: true\n']):
            self.start_node(0, extra_args=['-networkactive=1'])
        self.stop_node(0)

        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-networkactive=0'])
        self.stop_node(0)

        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-nonetworkactive'])
        self.stop_node(0)

        with self.nodes[0].assert_debug_log(expected_msgs=['SetNetworkActive: false\n']):
            self.start_node(0, extra_args=['-nonetworkactive=1'])
        self.stop_node(0)

    def run_test(self):
        self.stop_node(0)

        self.test_log_buffer()
        self.test_args_log()
        self.test_networkactive()

        self.test_config_file_parser()
        self.test_invalid_command_line_options()

        # Remove the -datadir argument so it doesn't override the config file
        self.nodes[0].args = [arg for arg in self.nodes[0].args if not arg.startswith("-datadir")]

        default_data_dir = self.nodes[0].datadir
        new_data_dir = os.path.join(default_data_dir, 'newdatadir')
        new_data_dir_2 = os.path.join(default_data_dir, 'newdatadir2')

        # Check that using -datadir argument on non-existent directory fails
        self.nodes[0].datadir = new_data_dir
        self.nodes[0].assert_start_raises_init_error(['-datadir=' + new_data_dir], 'Error: Specified data directory "' + new_data_dir + '" does not exist.')

        # Check that using non-existent datadir in conf file fails
        conf_file = os.path.join(default_data_dir, "litecoin.conf")

        # datadir needs to be set before [chain] section
        conf_file_contents = open(conf_file, encoding='utf8').read()
        with open(conf_file, 'w', encoding='utf8') as f:
            f.write("datadir=" + new_data_dir + "\n")
            f.write(conf_file_contents)

        self.nodes[0].assert_start_raises_init_error(['-conf=' + conf_file], 'Error: Error reading configuration file: specified data directory "' + new_data_dir + '" does not exist.')

        # Create the directory and ensure the config file now works
        os.mkdir(new_data_dir)
        self.start_node(0, ['-conf='+conf_file])
        self.stop_node(0)
        assert os.path.exists(os.path.join(new_data_dir, self.chain, 'blocks'))

        # Ensure command line argument overrides datadir in conf
        os.mkdir(new_data_dir_2)
        self.nodes[0].datadir = new_data_dir_2
        self.start_node(0, ['-datadir='+new_data_dir_2, '-conf='+conf_file])
        assert os.path.exists(os.path.join(new_data_dir_2, self.chain, 'blocks'))


if __name__ == '__main__':
    ConfArgsTest().main()
