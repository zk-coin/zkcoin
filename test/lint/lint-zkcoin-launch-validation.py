#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Check that CI keeps zkCoin's launch validation lane fail-closed."""

from pathlib import Path
import json
import re
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
CIRRUS_CONFIG = ROOT_DIR / ".cirrus.yml"
LAUNCH_WRAPPER = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_validation.sh"
ORCHARD_WRAPPER = ROOT_DIR / "contrib" / "devtools" / "zkcoin_orchard_auxpow.sh"
SMOKE_WRAPPER = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_smoke.sh"
VALIDATION_MANIFEST = ROOT_DIR / "contrib" / "devtools" / "zkcoin_launch_validation_manifest.json"
TASK_NAME = "zkCoin canonical launch validation [real Orchard AuxPoW]"
CANONICAL_WRAPPER = "contrib/devtools/zkcoin_launch_validation.sh"
ORCHARD_WRAPPER_PATH = "contrib/devtools/zkcoin_orchard_auxpow.sh"
GENERIC_TEST_RUNNER = "test_runner.py"
REQUIRED_MANIFEST_LISTS = {
    "canonical": (
        "lints",
        "configure_flags",
        "build_commands",
        "unit_tests",
        "rust_verifier_commands",
        "functional_tests",
    ),
    "smoke": (
        "lints",
        "unit_tests",
        "functional_tests",
    ),
}
REQUIRED_MANIFEST_BLOCKS = {
    "smoke": (
        "build",
        "source_dist",
    ),
}


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


def shell_commands(path):
    commands = []
    pending = ""
    for raw_line in path.read_text(encoding="utf8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith("echo "):
            continue

        if line.endswith("\\"):
            pending += line[:-1].strip() + " "
            continue

        command = (pending + line).strip()
        pending = ""
        if not command or command in ("(", ")") or command.startswith("echo "):
            continue
        commands.append(re.sub(r"\s+", " ", command))

    if pending:
        commands.append(re.sub(r"\s+", " ", pending.strip()))

    return commands


def contains_command(commands, token):
    return any(token in command for command in commands)


def check_tokens(commands, tokens, label):
    for token in tokens:
        if not contains_command(commands, token):
            return "{} must execute {}".format(label, token)
    return None


def check_exact_commands(commands, required_commands, label):
    command_set = set(commands)
    for required_command in required_commands:
        if required_command not in command_set:
            return "{} must execute {}".format(label, required_command)
    return None


def check_conditional_block(commands, condition, required_commands, label):
    try:
        start = commands.index(condition)
    except ValueError:
        return "{} must guard commands with {}".format(label, condition)

    try:
        end = commands.index("fi", start + 1)
    except ValueError:
        return "{} must close guard {}".format(label, condition)

    block_commands = set(commands[start + 1:end])
    for required_command in required_commands:
        if required_command not in block_commands:
            return "{} must execute {} under {}".format(label, required_command, condition)
    return None


def check_unit_tests(commands, suites, label):
    for suite in suites:
        token = "--run_test={}".format(suite)
        if not contains_command(commands, token):
            return "{} must execute unit suite {}".format(label, suite)
    return None


def check_functional_tests(commands, tests, label):
    for test in tests:
        path = test["path"] if isinstance(test, dict) else test
        env = test.get("env", {}) if isinstance(test, dict) else {}
        matching_commands = [command for command in commands if path in command]
        if not matching_commands:
            return "{} must execute {}".format(label, path)

        for key, value in env.items():
            token = "{}={}".format(key, value)
            if not any(token in command for command in matching_commands):
                return "{} must execute {} with {}".format(label, path, token)

    return None


def load_manifest():
    manifest = json.loads(VALIDATION_MANIFEST.read_text(encoding="utf8"))
    if manifest.get("version") != 1:
        raise ValueError("{} version must be 1".format(VALIDATION_MANIFEST))
    for section, required_lists in REQUIRED_MANIFEST_LISTS.items():
        if not isinstance(manifest.get(section), dict):
            raise ValueError("{} must contain a {} object".format(VALIDATION_MANIFEST, section))
        for key in required_lists:
            if not isinstance(manifest[section].get(key), list):
                raise ValueError(
                    "{} {}.{} must be a list".format(VALIDATION_MANIFEST, section, key)
                )
    for section, required_blocks in REQUIRED_MANIFEST_BLOCKS.items():
        if not isinstance(manifest.get(section), dict):
            raise ValueError("{} must contain a {} object".format(VALIDATION_MANIFEST, section))
        for key in required_blocks:
            block = manifest[section].get(key)
            if not isinstance(block, dict):
                raise ValueError(
                    "{} {}.{} must be an object".format(VALIDATION_MANIFEST, section, key)
                )
            if not isinstance(block.get("condition"), str):
                raise ValueError(
                    "{} {}.{}.condition must be a string".format(VALIDATION_MANIFEST, section, key)
                )
            if not isinstance(block.get("commands"), list):
                raise ValueError(
                    "{} {}.{}.commands must be a list".format(VALIDATION_MANIFEST, section, key)
                )
    return manifest


def main():
    lines = CIRRUS_CONFIG.read_text(encoding="utf8").splitlines(keepends=True)
    try:
        manifest = load_manifest()
    except (json.JSONDecodeError, ValueError) as exc:
        return fail(str(exc))

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

    canonical = manifest["canonical"]
    canonical_commands = shell_commands(ORCHARD_WRAPPER)
    canonical_label = str(ORCHARD_WRAPPER.relative_to(ROOT_DIR))
    for error in (
        check_tokens(canonical_commands, canonical["lints"], canonical_label),
        check_tokens(canonical_commands, canonical["configure_flags"], canonical_label),
        check_exact_commands(canonical_commands, canonical["build_commands"], canonical_label),
        check_unit_tests(canonical_commands, canonical["unit_tests"], canonical_label),
        check_exact_commands(canonical_commands, canonical["rust_verifier_commands"], canonical_label),
        check_functional_tests(canonical_commands, canonical["functional_tests"], canonical_label),
    ):
        if error:
            return fail(error)

    smoke = manifest["smoke"]
    smoke_commands = shell_commands(SMOKE_WRAPPER)
    smoke_label = str(SMOKE_WRAPPER.relative_to(ROOT_DIR))
    for error in (
        check_conditional_block(
            smoke_commands,
            smoke["build"]["condition"],
            smoke["build"]["commands"],
            smoke_label,
        ),
        check_tokens(smoke_commands, smoke["lints"], smoke_label),
        check_unit_tests(smoke_commands, smoke["unit_tests"], smoke_label),
        check_functional_tests(smoke_commands, smoke["functional_tests"], smoke_label),
        check_conditional_block(
            smoke_commands,
            smoke["source_dist"]["condition"],
            smoke["source_dist"]["commands"],
            smoke_label,
        ),
    ):
        if error:
            return fail(error)

    return 0


if __name__ == "__main__":
    sys.exit(main())
