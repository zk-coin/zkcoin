#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Litecoin snapshot operator shell wrapper with controlled CLI JSON."""

import hashlib
import json
import os
import stat
import subprocess
import textwrap

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


HEIGHT = 7
BLOCK_HASH = "aa" * 32
RESTORE_HASH = "bb" * 32
SNAPSHOT_HASH = "cc" * 32
IMPORT_HASH = "dd" * 32


class LtcSnapshotScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def write_fake_cli(self, name):
        path = os.path.join(self.options.tmpdir, name)
        with open(path, "w", encoding="utf8") as fake_cli:
            fake_cli.write(textwrap.dedent("""\
                #!/usr/bin/env python3
                import json
                import os
                import sys

                def fail(message):
                    print(message, file=sys.stderr)
                    sys.exit(2)

                scenario = json.loads(os.environ["ZKCOIN_SNAPSHOT_FAKE_SCENARIO"])
                role = os.path.basename(sys.argv[0]).split("-")[1]
                args = [arg for arg in sys.argv[1:] if not arg.startswith("-rpcclienttimeout=")]
                if not args:
                    fail("missing command")
                command = args[0]
                command_args = args[1:]

                log_path = os.environ["ZKCOIN_SNAPSHOT_FAKE_LOG"]
                with open(log_path, "a", encoding="utf8") as log:
                    log.write(json.dumps({
                        "role": role,
                        "cmd": command,
                        "args": command_args,
                    }, sort_keys=True) + "\\n")

                if role == "litecoin":
                    if command == "getblockchaininfo":
                        source_tip = scenario.get("source_tip", scenario["height"])
                        chaininfo = {
                            "chain": scenario.get("source_chain", "main"),
                            "blocks": source_tip,
                            "headers": scenario.get("source_headers", source_tip),
                            "initialblockdownload": scenario.get("initialblockdownload", False),
                            "pruned": scenario.get("pruned", False),
                        }
                        chaininfo.update(scenario.get("chaininfo_overrides", {}))
                        print(scenario.get("chaininfo_raw", json.dumps(chaininfo)))
                    elif command == "getblockhash":
                        requested_height = int(command_args[0])
                        block_hashes = scenario.get("block_hashes", {})
                        if str(requested_height) in block_hashes:
                            print(block_hashes[str(requested_height)])
                        elif requested_height == scenario["height"]:
                            print(scenario["expected_hash"])
                        elif requested_height == scenario["height"] + 1:
                            print(scenario["restore_hash"])
                        else:
                            print("00" * 32)
                    elif command == "getblockcount":
                        print(scenario.get("post_rewind_tip", scenario["height"]))
                    elif command == "invalidateblock":
                        if scenario.get("fail_invalidate", False):
                            fail("invalidate failed")
                        print("{}")
                    elif command == "reconsiderblock":
                        if scenario.get("fail_reconsider", False):
                            fail("reconsider failed")
                        print("{}")
                    elif command == "dumptxoutset":
                        if not scenario.get("skip_snapshot_write", False):
                            with open(command_args[0], "wb") as snapshot_file:
                                if not scenario.get("empty_snapshot_write", False):
                                    snapshot_file.write(b"snapshot")
                        print(scenario.get("dump_raw", json.dumps(scenario["dump_json"])))
                    else:
                        fail(f"unexpected litecoin command: {command}")
                elif role == "zkcoin":
                    if command != "verifysnapshotmanifest":
                        fail(f"unexpected zkcoin command: {command}")
                    if scenario.get("mutate_snapshot_during_verify", False):
                        with open(command_args[0], "ab") as snapshot_file:
                            snapshot_file.write(b"mutated")
                    print(scenario.get("verify_raw", json.dumps(scenario["verify_json"])))
                else:
                    fail(f"unexpected role: {role}")
            """))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def snapshot_script(self):
        return os.path.join(
            self.config["environment"]["SRCDIR"],
            "contrib",
            "devtools",
            "zkcoin_ltc_snapshot.sh",
        )

    def dump_json(self, **overrides):
        response = {
            "base_height": HEIGHT,
            "base_hash": BLOCK_HASH,
            "coins_written": 4,
        }
        response.update(overrides)
        return response

    def verify_json(self, **overrides):
        response = {
            "base_height": HEIGHT,
            "base_hash": BLOCK_HASH,
            "coins": 4,
            "metadata_coins": 4,
            "base_nchaintx": 11,
            "snapshot_hash": SNAPSHOT_HASH,
            "import_hash": IMPORT_HASH,
            "total_amount": "50.00000000",
        }
        response.update(overrides)
        return response

    def scenario(self, **overrides):
        value = {
            "height": HEIGHT,
            "expected_hash": BLOCK_HASH,
            "restore_hash": RESTORE_HASH,
            "source_tip": HEIGHT,
            "dump_json": self.dump_json(),
            "verify_json": self.verify_json(),
        }
        value.update(overrides)
        return value

    def run_snapshot(
        self,
        name,
        scenario,
        *,
        height=HEIGHT,
        expected_hash=BLOCK_HASH,
        allow_rewind=False,
        write_audit=False,
        precreate_snapshot=False,
        precreate_audit=False,
        snapshot_path_symlink=False,
        audit_path_symlink=False,
        audit_path_same_as_snapshot=False,
        audit_path_aliases_snapshot=False,
        audit_path_parent_missing=False,
        snapshot_path_parent_missing=False,
        audit_path_parent_unwritable=False,
        snapshot_path_parent_unwritable=False,
    ):
        log_path = os.path.join(self.options.tmpdir, f"{name}.jsonl")
        snapshot_path = os.path.join(self.options.tmpdir, f"{name}.dat")
        audit_path = os.path.join(self.options.tmpdir, f"{name}.audit.json")
        dirs_to_restore = []
        if snapshot_path_parent_missing:
            snapshot_path = os.path.join(self.options.tmpdir, "missing-snapshot-dir", f"{name}.dat")
        elif snapshot_path_parent_unwritable:
            snapshot_dir = os.path.join(self.options.tmpdir, f"{name}-snapshot-dir")
            os.makedirs(snapshot_dir, exist_ok=True)
            os.chmod(snapshot_dir, stat.S_IRUSR | stat.S_IXUSR)
            dirs_to_restore.append(snapshot_dir)
            snapshot_path = os.path.join(snapshot_dir, f"{name}.dat")
        if audit_path_same_as_snapshot:
            audit_path = snapshot_path
        elif audit_path_aliases_snapshot:
            alias_dir = os.path.join(self.options.tmpdir, "snapshot-path-alias")
            os.makedirs(alias_dir, exist_ok=True)
            audit_path = os.path.join(alias_dir, "..", os.path.basename(snapshot_path))
        elif audit_path_parent_missing:
            audit_path = os.path.join(self.options.tmpdir, "missing-audit-dir", f"{name}.audit.json")
        elif audit_path_parent_unwritable:
            audit_dir = os.path.join(self.options.tmpdir, f"{name}-audit-dir")
            os.makedirs(audit_dir, exist_ok=True)
            os.chmod(audit_dir, stat.S_IRUSR | stat.S_IXUSR)
            dirs_to_restore.append(audit_dir)
            audit_path = os.path.join(audit_dir, f"{name}.audit.json")
        if snapshot_path_symlink:
            os.symlink(os.path.join(self.options.tmpdir, f"{name}.target"), snapshot_path)
        if audit_path_symlink:
            os.symlink(os.path.join(self.options.tmpdir, f"{name}.audit.target"), audit_path)
        if precreate_snapshot:
            with open(snapshot_path, "wb") as snapshot_file:
                snapshot_file.write(b"existing")
        if precreate_audit:
            with open(audit_path, "w", encoding="utf8") as audit_file:
                audit_file.write("{}\n")

        env = os.environ.copy()
        env["ZKCOIN_SNAPSHOT_FAKE_LOG"] = log_path
        env["ZKCOIN_SNAPSHOT_FAKE_SCENARIO"] = json.dumps(scenario)
        if (
            write_audit
            or precreate_audit
            or audit_path_same_as_snapshot
            or audit_path_aliases_snapshot
            or audit_path_parent_missing
            or audit_path_parent_unwritable
            or audit_path_symlink
        ):
            env["ZKCOIN_SNAPSHOT_AUDIT_JSON"] = audit_path
        else:
            env.pop("ZKCOIN_SNAPSHOT_AUDIT_JSON", None)
        if allow_rewind:
            env["ZKCOIN_SNAPSHOT_ALLOW_REWIND"] = "1"
        else:
            env.pop("ZKCOIN_SNAPSHOT_ALLOW_REWIND", None)

        result = subprocess.run(
            [
                self.snapshot_script(),
                str(height),
                expected_hash,
                snapshot_path,
                self.fake_litecoin_cli,
                "--",
                self.fake_zkcoin_cli,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=env,
        )
        for directory in dirs_to_restore:
            os.chmod(directory, stat.S_IRWXU)

        calls = []
        if os.path.exists(log_path):
            with open(log_path, encoding="utf8") as log:
                calls = [json.loads(line) for line in log]

        return result, calls, snapshot_path

    def assert_snapshot(self, name, scenario, expected_code, expected_output, **kwargs):
        result, calls, snapshot_path = self.run_snapshot(name, scenario, **kwargs)
        assert_equal(result.returncode, expected_code)
        assert expected_output in result.stdout + result.stderr
        return result, calls, snapshot_path

    def assert_command(self, calls, role, command, args=None):
        expected_args = args if args is not None else []
        assert {
            "role": role,
            "cmd": command,
            "args": expected_args,
        } in calls

    def run_test(self):
        self.fake_litecoin_cli = self.write_fake_cli("fake-litecoin-cli.py")
        self.fake_zkcoin_cli = self.write_fake_cli("fake-zkcoin-cli.py")

        self.log.info("Reject a zero snapshot height before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "zero-height",
            self.scenario(),
            1,
            "height must be a positive integer",
            height=0,
        )
        assert_equal(calls, [])

        self.log.info("Reject a null expected snapshot block hash before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "null-expected-hash",
            self.scenario(),
            1,
            "expected block hash must not be the null uint256",
            expected_hash="00" * 32,
        )
        assert_equal(calls, [])

        self.log.info("Accept a complete snapshot dump and manifest verification")
        result, calls, snapshot_path = self.assert_snapshot(
            "happy",
            self.scenario(),
            0,
            "Snapshot verified.",
            write_audit=True,
        )
        audit_path = os.path.join(self.options.tmpdir, "happy.audit.json")
        assert f"-ltcsnapshotheight={HEIGHT}" in result.stdout
        assert f"-ltcsnapshotblockhash={BLOCK_HASH}" in result.stdout
        assert f"-ltcsnapshotutxoroot={IMPORT_HASH}" in result.stdout
        assert f"-ltcsnapshotfile={snapshot_path}" in result.stdout
        assert f"Snapshot audit summary written: {audit_path}" in result.stdout
        assert "Snapshot public launch-profile manifest update:" in result.stdout
        assert (
            "contrib/devtools/zkcoin_public_launch_profile.py "
            f"--set-snapshot-audit main {audit_path} "
            "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ) in result.stdout
        with open(audit_path, encoding="utf8") as audit_file:
            audit = json.load(audit_file)
        assert_equal(audit["height"], HEIGHT)
        assert_equal(audit["source_chain"], "main")
        assert_equal(audit["block_hash"], BLOCK_HASH)
        assert_equal(audit["import_hash"], IMPORT_HASH)
        assert_equal(audit["snapshot_hash"], SNAPSHOT_HASH)
        assert_equal(audit["snapshot_file"], snapshot_path)
        with open(snapshot_path, "rb") as snapshot_file:
            snapshot_bytes = snapshot_file.read()
        assert_equal(audit["snapshot_file_size"], len(snapshot_bytes))
        assert_equal(audit["snapshot_file_sha256"], hashlib.sha256(snapshot_bytes).hexdigest())
        self.assert_command(calls, "litecoin", "dumptxoutset", [snapshot_path])
        self.assert_command(calls, "zkcoin", "verifysnapshotmanifest", [snapshot_path])

        self.log.info("Print the testnet snapshot audit manifest handoff for a Litecoin test source")
        testnet_result, _, _ = self.assert_snapshot(
            "testnet-handoff",
            self.scenario(source_chain="test"),
            0,
            "Snapshot verified.",
            write_audit=True,
        )
        testnet_audit_path = os.path.join(self.options.tmpdir, "testnet-handoff.audit.json")
        assert (
            "contrib/devtools/zkcoin_public_launch_profile.py "
            f"--set-snapshot-audit testnet {testnet_audit_path} "
            "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ) in testnet_result.stdout

        self.log.info("Reject a pre-existing audit summary output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "preexisting-audit",
            self.scenario(),
            1,
            "snapshot audit summary already exists",
            precreate_audit=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject an audit summary path matching the snapshot output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "audit-path-matches-snapshot",
            self.scenario(),
            1,
            "snapshot audit summary path must differ from snapshot output path",
            audit_path_same_as_snapshot=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject an audit summary path aliasing the snapshot output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "audit-path-aliases-snapshot",
            self.scenario(),
            1,
            "snapshot audit summary path must differ from snapshot output path",
            audit_path_aliases_snapshot=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject a missing audit summary output directory before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "missing-audit-dir",
            self.scenario(),
            1,
            "snapshot audit summary directory does not exist",
            audit_path_parent_missing=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject an unwritable audit summary output directory before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "unwritable-audit-dir",
            self.scenario(),
            1,
            "snapshot audit summary directory is not writable",
            audit_path_parent_unwritable=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject a missing snapshot output directory before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "missing-snapshot-dir",
            self.scenario(),
            1,
            "snapshot output directory does not exist",
            snapshot_path_parent_missing=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject an unwritable snapshot output directory before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "unwritable-snapshot-dir",
            self.scenario(),
            1,
            "snapshot output directory is not writable",
            snapshot_path_parent_unwritable=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject a pre-existing output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "preexisting",
            self.scenario(),
            1,
            "snapshot output already exists",
            precreate_snapshot=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject a symlinked snapshot output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "symlink-snapshot-output",
            self.scenario(),
            1,
            "snapshot output path must not be a symlink",
            snapshot_path_symlink=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject a symlinked audit summary output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "symlink-audit-output",
            self.scenario(),
            1,
            "snapshot audit summary path must not be a symlink",
            audit_path_symlink=True,
        )
        assert_equal(calls, [])

        self.log.info("Reject malformed Litecoin source chain info")
        _, calls, _ = self.assert_snapshot(
            "malformed-chaininfo-json",
            self.scenario(chaininfo_raw="{not json"),
            1,
            "litecoin-cli getblockchaininfo did not return JSON",
        )
        assert_equal(calls, [{"role": "litecoin", "cmd": "getblockchaininfo", "args": []}])

        self.log.info("Reject a Litecoin source with headers ahead of downloaded blocks")
        _, calls, _ = self.assert_snapshot(
            "source-headers-ahead",
            self.scenario(source_headers=HEIGHT + 1),
            1,
            "Litecoin source node headers are ahead of downloaded blocks",
        )
        assert_equal(calls, [{"role": "litecoin", "cmd": "getblockchaininfo", "args": []}])

        self.log.info("Reject a Litecoin source still in initial block download")
        _, calls, _ = self.assert_snapshot(
            "source-ibd",
            self.scenario(initialblockdownload=True),
            1,
            "Litecoin source node is still in initial block download",
        )
        assert_equal(calls, [{"role": "litecoin", "cmd": "getblockchaininfo", "args": []}])

        self.log.info("Reject a pruned Litecoin snapshot source")
        _, calls, _ = self.assert_snapshot(
            "source-pruned",
            self.scenario(pruned=True),
            1,
            "Litecoin source node must not be pruned for snapshot generation",
        )
        assert_equal(calls, [{"role": "litecoin", "cmd": "getblockchaininfo", "args": []}])

        self.log.info("Reject a non-public Litecoin source chain")
        _, calls, _ = self.assert_snapshot(
            "source-regtest",
            self.scenario(source_chain="regtest"),
            1,
            "Litecoin source node chain must be main or test for public snapshot generation",
        )
        assert_equal(calls, [{"role": "litecoin", "cmd": "getblockchaininfo", "args": []}])

        self.log.info("Reject a Litecoin source below the requested snapshot height")
        self.assert_snapshot(
            "source-below-height",
            self.scenario(source_tip=HEIGHT - 1),
            1,
            "is below requested snapshot height",
        )

        self.log.info("Reject a Litecoin source beyond the snapshot height without explicit rewind")
        self.assert_snapshot(
            "source-above-height",
            self.scenario(source_tip=HEIGHT + 1),
            1,
            "Set ZKCOIN_SNAPSHOT_ALLOW_REWIND=1",
        )

        self.log.info("Reject malformed rewind restore block hash before invalidating the source")
        _, calls, _ = self.assert_snapshot(
            "rewind-malformed-restore-hash",
            self.scenario(
                source_tip=HEIGHT + 1,
                block_hashes={str(HEIGHT + 1): "not-a-uint256"},
            ),
            1,
            f"restore block hash at height {HEIGHT + 1} must be 64 hex characters",
            allow_rewind=True,
        )
        assert_equal(
            calls,
            [
                {"role": "litecoin", "cmd": "getblockchaininfo", "args": []},
                {"role": "litecoin", "cmd": "getblockhash", "args": [str(HEIGHT + 1)]},
            ],
        )

        self.log.info("Rewind and restore a disposable snapshot source when explicitly allowed")
        _, calls, _ = self.assert_snapshot(
            "rewind-happy",
            self.scenario(source_tip=HEIGHT + 1),
            0,
            "Snapshot verified.",
            allow_rewind=True,
        )
        self.assert_command(calls, "litecoin", "invalidateblock", [RESTORE_HASH])
        self.assert_command(calls, "litecoin", "getblockcount")
        self.assert_command(calls, "litecoin", "reconsiderblock", [RESTORE_HASH])

        self.log.info("Reject rewind that does not leave the source at the snapshot height")
        _, calls, _ = self.assert_snapshot(
            "rewind-tip-mismatch",
            self.scenario(source_tip=HEIGHT + 1, post_rewind_tip=HEIGHT + 1),
            1,
            f"Litecoin source tip after rewind is {HEIGHT + 1}; expected {HEIGHT}",
            allow_rewind=True,
        )
        self.assert_command(calls, "litecoin", "invalidateblock", [RESTORE_HASH])
        self.assert_command(calls, "litecoin", "getblockcount")
        self.assert_command(calls, "litecoin", "reconsiderblock", [RESTORE_HASH])
        assert not any(call["cmd"] == "dumptxoutset" for call in calls)
        assert not any(call["role"] == "zkcoin" for call in calls)

        self.log.info("Fail closed when rewind cleanup cannot restore the source chain")
        self.assert_snapshot(
            "rewind-restore-fails",
            self.scenario(source_tip=HEIGHT + 1, fail_reconsider=True),
            1,
            "failed to restore Litecoin source chain",
            allow_rewind=True,
        )

        self.log.info("Reject an unexpected source block hash")
        self.assert_snapshot(
            "hash-mismatch",
            self.scenario(block_hashes={str(HEIGHT): "11" * 32}),
            1,
            "snapshot block hash mismatch",
        )

        self.log.info("Reject malformed source snapshot block hash before dumping UTXOs")
        _, calls, _ = self.assert_snapshot(
            "malformed-source-block-hash",
            self.scenario(block_hashes={str(HEIGHT): "not-a-uint256"}),
            1,
            f"snapshot block hash at height {HEIGHT} must be 64 hex characters",
        )
        self.assert_command(calls, "litecoin", "getblockhash", [str(HEIGHT)])
        assert not any(call["cmd"] == "dumptxoutset" for call in calls)
        assert not any(call["role"] == "zkcoin" for call in calls)

        self.log.info("Reject malformed dumptxoutset JSON")
        self.assert_snapshot(
            "malformed-dump-json",
            self.scenario(dump_raw="{not json"),
            1,
            "dumptxoutset did not return JSON",
        )

        self.log.info("Reject missing snapshot dump file before verification")
        _, calls, _ = self.assert_snapshot(
            "missing-dump-file",
            self.scenario(skip_snapshot_write=True),
            1,
            "snapshot output was not created by dumptxoutset",
        )
        assert not any(call["role"] == "zkcoin" for call in calls)

        self.log.info("Reject empty snapshot dump file before verification")
        _, calls, _ = self.assert_snapshot(
            "empty-dump-file",
            self.scenario(empty_snapshot_write=True),
            1,
            "snapshot output is empty after dumptxoutset",
        )
        assert not any(call["role"] == "zkcoin" for call in calls)

        self.log.info("Reject snapshot artifact mutation during verification")
        _, calls, snapshot_path = self.assert_snapshot(
            "mutated-during-verify",
            self.scenario(mutate_snapshot_during_verify=True),
            1,
            "snapshot output changed during verification",
        )
        self.assert_command(calls, "zkcoin", "verifysnapshotmanifest", [snapshot_path])

        self.log.info("Reject missing verifier manifest fields")
        missing_import_hash = self.verify_json()
        missing_import_hash.pop("import_hash")
        self.assert_snapshot(
            "missing-import-hash",
            self.scenario(verify_json=missing_import_hash),
            1,
            "missing verifysnapshotmanifest field: import_hash",
        )

        self.log.info("Reject malformed verifier total amount")
        self.assert_snapshot(
            "malformed-total-amount",
            self.scenario(verify_json=self.verify_json(total_amount="50")),
            1,
            "verifysnapshotmanifest.total_amount must be a positive decimal amount with 8 fractional digits",
        )

        self.log.info("Reject over maximum verifier total amount")
        self.assert_snapshot(
            "over-maximum-total-amount",
            self.scenario(verify_json=self.verify_json(total_amount="84000000.00000001")),
            1,
            "verifysnapshotmanifest.total_amount must not exceed 84000000.00000000",
        )

        self.log.info("Reject zero snapshot dump coin count")
        self.assert_snapshot(
            "zero-dump-coins",
            self.scenario(dump_json=self.dump_json(coins_written=0)),
            1,
            "dumptxoutset.coins_written must be positive",
        )

        self.log.info("Reject zero verifier base transaction count")
        self.assert_snapshot(
            "zero-base-nchaintx",
            self.scenario(verify_json=self.verify_json(base_nchaintx=0)),
            1,
            "verifysnapshotmanifest.base_nchaintx must be positive",
        )

        self.log.info("Reject dump/verify coin count mismatches")
        self.assert_snapshot(
            "coin-count-mismatch",
            self.scenario(verify_json=self.verify_json(coins=5)),
            1,
            "coin count mismatch",
        )


if __name__ == "__main__":
    LtcSnapshotScriptTest().main()
