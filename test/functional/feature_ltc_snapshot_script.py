#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the Litecoin snapshot operator shell wrapper with controlled CLI JSON."""

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
                    if command == "getblockcount":
                        print(scenario.get("source_tip", scenario["height"]))
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
                                snapshot_file.write(b"snapshot")
                        print(scenario.get("dump_raw", json.dumps(scenario["dump_json"])))
                    else:
                        fail(f"unexpected litecoin command: {command}")
                elif role == "zkcoin":
                    if command != "verifysnapshotmanifest":
                        fail(f"unexpected zkcoin command: {command}")
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

    def run_snapshot(self, name, scenario, *, expected_hash=BLOCK_HASH, allow_rewind=False, precreate_snapshot=False):
        log_path = os.path.join(self.options.tmpdir, f"{name}.jsonl")
        snapshot_path = os.path.join(self.options.tmpdir, f"{name}.dat")
        if precreate_snapshot:
            with open(snapshot_path, "wb") as snapshot_file:
                snapshot_file.write(b"existing")

        env = os.environ.copy()
        env["ZKCOIN_SNAPSHOT_FAKE_LOG"] = log_path
        env["ZKCOIN_SNAPSHOT_FAKE_SCENARIO"] = json.dumps(scenario)
        if allow_rewind:
            env["ZKCOIN_SNAPSHOT_ALLOW_REWIND"] = "1"
        else:
            env.pop("ZKCOIN_SNAPSHOT_ALLOW_REWIND", None)

        result = subprocess.run(
            [
                self.snapshot_script(),
                str(HEIGHT),
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

        self.log.info("Accept a complete snapshot dump and manifest verification")
        result, calls, snapshot_path = self.assert_snapshot(
            "happy",
            self.scenario(),
            0,
            "Snapshot verified.",
        )
        assert f"-ltcsnapshotheight={HEIGHT}" in result.stdout
        assert f"-ltcsnapshotblockhash={BLOCK_HASH}" in result.stdout
        assert f"-ltcsnapshotutxoroot={IMPORT_HASH}" in result.stdout
        assert f"-ltcsnapshotfile={snapshot_path}" in result.stdout
        assert "Snapshot public launch-profile manifest update:" in result.stdout
        assert (
            "contrib/devtools/zkcoin_public_launch_profile.py "
            f"--set-snapshot NETWORK {HEIGHT} {BLOCK_HASH} {IMPORT_HASH} "
            "--in-place contrib/devtools/zkcoin_public_launch_profile_manifest.json"
        ) in result.stdout
        self.assert_command(calls, "litecoin", "dumptxoutset", [snapshot_path])
        self.assert_command(calls, "zkcoin", "verifysnapshotmanifest", [snapshot_path])

        self.log.info("Reject a pre-existing output path before calling either CLI")
        _, calls, _ = self.assert_snapshot(
            "preexisting",
            self.scenario(),
            1,
            "snapshot output already exists",
            precreate_snapshot=True,
        )
        assert_equal(calls, [])

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

        self.log.info("Rewind and restore a disposable snapshot source when explicitly allowed")
        _, calls, _ = self.assert_snapshot(
            "rewind-happy",
            self.scenario(source_tip=HEIGHT + 1),
            0,
            "Snapshot verified.",
            allow_rewind=True,
        )
        self.assert_command(calls, "litecoin", "invalidateblock", [RESTORE_HASH])
        self.assert_command(calls, "litecoin", "reconsiderblock", [RESTORE_HASH])

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

        self.log.info("Reject malformed dumptxoutset JSON")
        self.assert_snapshot(
            "malformed-dump-json",
            self.scenario(dump_raw="{not json"),
            1,
            "dumptxoutset did not return JSON",
        )

        self.log.info("Reject missing verifier manifest fields")
        missing_import_hash = self.verify_json()
        missing_import_hash.pop("import_hash")
        self.assert_snapshot(
            "missing-import-hash",
            self.scenario(verify_json=missing_import_hash),
            1,
            "missing verifysnapshotmanifest field: import_hash",
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
