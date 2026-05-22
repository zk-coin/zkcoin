#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that CI keeps zkCoin's launch validation lane fail-closed."""

from pathlib import Path
import re
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
CIRRUS_CONFIG = ROOT_DIR / ".cirrus.yml"
LAUNCH_WRAPPER = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_validation.sh"
ORCHARD_WRAPPER = ROOT_DIR / "contrib" / "devtools" / "zkcoin_orchard_auxpow.sh"
TASK_NAME = "zkCoin canonical launch validation [real Orchard AuxPoW]"
CANONICAL_WRAPPER = "contrib/devtools/zkcoin_launch_validation.sh"
ORCHARD_WRAPPER_PATH = "contrib/devtools/zkcoin_orchard_auxpow.sh"
REAL_PROOF_FUNCTIONAL_TEST = "test/functional/feature_orchard_auxpow_realproof.py"
GENERIC_TEST_RUNNER = "test_runner.py"
REQUIRE_ORCHARD_VERIFIER = "ZKCOIN_REQUIRE_ORCHARD_VERIFIER=1"


def iter_task_blocks(lines):
    block = None
    for line in lines:
        if line == "task:\n":
            if block is not None:
                yield block
            block = [line]
        elif block is not None:
            block.append(line)

    if block is not None:
        yield block


def unquote(value):
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        return value[1:-1]
    return value


def task_name(block):
    for line in block:
        match = re.match(r"^\s+name:\s*(.+?)\s*$", line)
        if match:
            return unquote(match.group(1))
    return None


def section_lines(block, section):
    section_regex = re.compile(r"^(\s*){}:\s*$".format(re.escape(section)))
    for index, line in enumerate(block):
        match = section_regex.match(line)
        if not match:
            continue

        section_indent = len(match.group(1))
        lines = []
        for child in block[index + 1:]:
            if not child.strip() or child.lstrip().startswith("#"):
                lines.append(child)
                continue

            child_indent = len(child) - len(child.lstrip())
            if child_indent <= section_indent and re.match(r"^\s*[\w_-]+:", child):
                break
            lines.append(child)
        return lines

    return []


def fail(message):
    print("{}: {}".format(CIRRUS_CONFIG, message), file=sys.stderr)
    return 1


def main():
    lines = CIRRUS_CONFIG.read_text(encoding="utf8").splitlines(keepends=True)
    task_blocks = list(iter_task_blocks(lines))
    matches = [block for block in task_blocks if task_name(block) == TASK_NAME]

    if len(matches) != 1:
        return fail(
            "expected exactly one {!r} task, found {}".format(TASK_NAME, len(matches))
        )

    ci_script = section_lines(matches[0], "ci_script")
    ci_script_text = "\n".join(
        line for line in ci_script if not line.lstrip().startswith("#")
    )

    if CANONICAL_WRAPPER not in ci_script_text:
        return fail(
            "{!r} must invoke {} in ci_script".format(TASK_NAME, CANONICAL_WRAPPER)
        )

    if GENERIC_TEST_RUNNER in ci_script_text:
        return fail(
            "{!r} must not route launch validation through {}".format(
                TASK_NAME,
                GENERIC_TEST_RUNNER,
            )
        )

    launch_wrapper_text = LAUNCH_WRAPPER.read_text(encoding="utf8")
    if ORCHARD_WRAPPER_PATH not in launch_wrapper_text:
        return fail(
            "{} must delegate to {}".format(
                LAUNCH_WRAPPER.relative_to(ROOT_DIR),
                ORCHARD_WRAPPER_PATH,
            )
        )

    orchard_wrapper_text = ORCHARD_WRAPPER.read_text(encoding="utf8")
    if REAL_PROOF_FUNCTIONAL_TEST not in orchard_wrapper_text:
        return fail(
            "{} must run {}".format(
                ORCHARD_WRAPPER.relative_to(ROOT_DIR),
                REAL_PROOF_FUNCTIONAL_TEST,
            )
        )
    if REQUIRE_ORCHARD_VERIFIER not in orchard_wrapper_text:
        return fail(
            "{} must require the real Orchard verifier with {}".format(
                ORCHARD_WRAPPER.relative_to(ROOT_DIR),
                REQUIRE_ORCHARD_VERIFIER,
            )
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
