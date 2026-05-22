#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the launch preflight shell wrapper with controlled RPC JSON."""

import json
import os
import stat
import subprocess
import textwrap

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal


class LaunchPreflightScriptTest(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 0

    def setup_network(self):
        pass

    def write_fake_cli(self):
        path = os.path.join(self.options.tmpdir, "fake-zkcoin-cli.py")
        with open(path, "w", encoding="utf8") as fake_cli:
            fake_cli.write(textwrap.dedent("""\
                #!/usr/bin/env python3
                import os
                import sys

                if sys.argv[-1] != "getblockchaininfo":
                    print("unexpected command", file=sys.stderr)
                    sys.exit(2)

                print(os.environ["ZKCOIN_FAKE_INFO_JSON"])
            """))
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def launch_preflight_script(self):
        return os.path.join(
            self.config["environment"]["SRCDIR"],
            "contrib",
            "devtools",
            "zkcoin_launch_preflight.sh",
        )

    def valid_info(self, readiness_overrides=None, omit_readiness_fields=()):
        readiness = {
            "ready": True,
            "snapshot_configured": True,
            "snapshot_imported": True,
            "auxpow_active_at_launch": True,
            "chain_id_configured": True,
            "chain_id_parent_version_safe": True,
            "shielded_inactive_at_launch": True,
            "at_launch_tip": True,
            "failures": [],
        }
        readiness.update(readiness_overrides or {})
        for field in omit_readiness_fields:
            readiness.pop(field)
        return {
            "blocks": 0,
            "launch_readiness": readiness,
            "ltc_snapshot": {
                "height": 2250000,
                "block_hash": "11" * 32,
                "import_hash": "22" * 32,
            },
            "auxpow": {
                "start_height": 1,
                "chain_id": 4660,
                "strict_chain_id": True,
                "parent_version_safe": True,
            },
            "shielded_pool": {
                "start_height": 2,
                "scaffold_proofs": False,
                "real_proof_backend": "orchard-v1",
                "real_proof_verification": True,
            },
        }

    def run_preflight(self, fake_cli, info):
        env = os.environ.copy()
        env["ZKCOIN_FAKE_INFO_JSON"] = json.dumps(info)
        return subprocess.run(
            [self.launch_preflight_script(), fake_cli],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            env=env,
        )

    def assert_preflight(self, fake_cli, info, expected_code, expected_output):
        result = self.run_preflight(fake_cli, info)
        assert_equal(result.returncode, expected_code)
        assert expected_output in result.stdout + result.stderr

    def run_test(self):
        fake_cli = self.write_fake_cli()

        self.log.info("Accept a complete launch readiness response")
        self.assert_preflight(fake_cli, self.valid_info(), 0, "Launch preflight passed.")

        self.log.info("Reject missing launch_readiness failures array")
        self.assert_preflight(
            fake_cli,
            self.valid_info(omit_readiness_fields=("failures",)),
            1,
            "missing launch_readiness fields: failures",
        )

        self.log.info("Reject missing required launch_readiness boolean")
        self.assert_preflight(
            fake_cli,
            self.valid_info(omit_readiness_fields=("snapshot_imported",)),
            1,
            "missing launch_readiness fields: snapshot_imported",
        )

        self.log.info("Reject malformed launch_readiness field types")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={"ready": "true"}),
            1,
            "launch_readiness.ready must be a boolean",
        )

        self.log.info("Reject inconsistent ready response with false invariants")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={"snapshot_imported": False}),
            1,
            "required readiness fields are false: snapshot_imported",
        )

        self.log.info("Reject not-ready response and print returned failure")
        self.assert_preflight(
            fake_cli,
            self.valid_info(readiness_overrides={
                "ready": False,
                "snapshot_imported": False,
                "failures": ["configured snapshot has not been imported"],
            }),
            1,
            "configured snapshot has not been imported",
        )

        self.log.info("Reject missing detail sections used by the operator report")
        truncated_info = self.valid_info()
        truncated_info["auxpow"] = {}
        self.assert_preflight(
            fake_cli,
            truncated_info,
            1,
            "missing getblockchaininfo.auxpow fields: start_height, chain_id, strict_chain_id, parent_version_safe",
        )

        self.log.info("Reject missing shielded proof posture fields")
        missing_shielded_posture = self.valid_info()
        missing_shielded_posture["shielded_pool"] = {"start_height": 2}
        self.assert_preflight(
            fake_cli,
            missing_shielded_posture,
            1,
            "missing getblockchaininfo.shielded_pool fields: scaffold_proofs, real_proof_backend, real_proof_verification",
        )

        self.log.info("Reject malformed shielded proof posture field types")
        malformed_shielded_posture = self.valid_info()
        malformed_shielded_posture["shielded_pool"]["scaffold_proofs"] = "false"
        self.assert_preflight(
            fake_cli,
            malformed_shielded_posture,
            1,
            "getblockchaininfo.shielded_pool.scaffold_proofs must be a boolean",
        )

        self.log.info("Reject scaffold proof acceptance in the launch preflight")
        scaffold_enabled = self.valid_info()
        scaffold_enabled["shielded_pool"]["scaffold_proofs"] = True
        self.assert_preflight(
            fake_cli,
            scaffold_enabled,
            1,
            "shielded scaffold proofs are enabled",
        )

        self.log.info("Reject unsupported shielded proof backends in the launch preflight")
        unsupported_backend = self.valid_info()
        unsupported_backend["shielded_pool"]["real_proof_backend"] = "unsupported"
        self.assert_preflight(
            fake_cli,
            unsupported_backend,
            1,
            "shielded real proof backend is not orchard-v1: unsupported",
        )

        self.log.info("Reject unavailable real shielded proof verification in the launch preflight")
        proof_verification_unavailable = self.valid_info()
        proof_verification_unavailable["shielded_pool"]["real_proof_verification"] = False
        self.assert_preflight(
            fake_cli,
            proof_verification_unavailable,
            1,
            "shielded real proof verification is not available",
        )


if __name__ == "__main__":
    LaunchPreflightScriptTest().main()
