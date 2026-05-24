#!/usr/bin/env python3
# Copyright (c) 2026 The zkCoin developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Verify zkCoin release artifacts from a signed SHA256SUMS manifest."""

import argparse
import fnmatch
import hashlib
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote
from urllib.request import urlopen


CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})\s+[* ]?(.+)$")


class VerifyError(Exception):
    pass


def normalize_fingerprint(value):
    return "".join(ch for ch in value.upper() if ch.isalnum())


def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "Verify zkCoin release artifacts against a clearsigned SHA256SUMS.asc "
            "file and an explicit trusted release signing key fingerprint."
        )
    )
    parser.add_argument(
        "--checksums",
        required=True,
        type=Path,
        help="Path to the clearsigned SHA256SUMS.asc file.",
    )
    parser.add_argument(
        "--trusted-fingerprint",
        action="append",
        required=True,
        help="Trusted zkCoin release signing key fingerprint. May be repeated.",
    )
    parser.add_argument(
        "--artifacts-dir",
        default=Path("."),
        type=Path,
        help="Directory containing release artifacts. Defaults to the current directory.",
    )
    parser.add_argument(
        "--download-base",
        help=(
            "Optional base URL used to fetch missing artifacts listed in the "
            "signed checksum manifest."
        ),
    )
    parser.add_argument(
        "--match",
        action="append",
        default=[],
        help="Only verify artifact names matching this shell glob. May be repeated.",
    )
    parser.add_argument(
        "--gpg",
        default="gpg",
        help="GPG executable to use. Defaults to gpg.",
    )
    parser.add_argument(
        "--download-timeout",
        default=60,
        type=int,
        help="Timeout in seconds for each artifact download.",
    )
    return parser.parse_args()


def run_gpg_decrypt(args, output_path):
    gpg = shutil.which(args.gpg)
    if gpg is None:
        raise VerifyError("GPG executable not found: {}".format(args.gpg))

    command = [
        gpg,
        "--batch",
        "--status-fd",
        "1",
        "--decrypt",
        "--output",
        str(output_path),
        str(args.checksums),
    ]
    result = subprocess.run(command, check=False, text=True, capture_output=True)
    if result.returncode != 0:
        raise VerifyError("GPG signature verification failed:\n{}".format(result.stderr.strip()))

    valid_fingerprints = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "[GNUPG:]" and parts[1] == "VALIDSIG":
            valid_fingerprints.append(normalize_fingerprint(parts[2]))
    if not valid_fingerprints:
        raise VerifyError("GPG did not report a valid signature fingerprint")

    trusted = {normalize_fingerprint(fp) for fp in args.trusted_fingerprint}
    if not trusted.intersection(valid_fingerprints):
        raise VerifyError(
            "signed checksums were not produced by a trusted zkCoin release key"
        )


def parse_checksum_manifest(path):
    entries = []
    seen_artifacts = set()
    for line_number, line in enumerate(path.read_text(encoding="utf8").splitlines(), 1):
        if not line.strip():
            continue
        match = CHECKSUM_RE.match(line)
        if match is None:
            raise VerifyError("invalid checksum line {}: {}".format(line_number, line))
        digest, filename = match.groups()
        filename = filename.strip()
        pure_path = PurePosixPath(filename)
        if pure_path.is_absolute() or ".." in pure_path.parts:
            raise VerifyError("unsafe artifact path in checksum manifest: {}".format(filename))
        if not pure_path.parts:
            raise VerifyError("empty artifact path in checksum manifest")
        artifact_key = pure_path.as_posix()
        if artifact_key in seen_artifacts:
            raise VerifyError("duplicate artifact path in checksum manifest: {}".format(artifact_key))
        seen_artifacts.add(artifact_key)
        entries.append((digest.lower(), filename))
    if not entries:
        raise VerifyError("checksum manifest did not contain any artifacts")
    return entries


def selected_entries(entries, patterns):
    if not patterns:
        return entries
    selected = [
        entry
        for entry in entries
        if any(fnmatch.fnmatch(entry[1], pattern) for pattern in patterns)
    ]
    if not selected:
        raise VerifyError("no artifacts matched: {}".format(", ".join(patterns)))
    return selected


def artifact_path(artifacts_dir, filename):
    target = artifacts_dir.joinpath(*PurePosixPath(filename).parts)
    artifacts_root = artifacts_dir.resolve()
    resolved_parent = target.parent.resolve()
    try:
        resolved_parent.relative_to(artifacts_root)
    except ValueError as exc:
        raise VerifyError("artifact path escapes artifacts directory: {}".format(filename)) from exc
    return target


def require_regular_artifact(target, filename):
    if target.is_symlink():
        raise VerifyError("artifact path must not be a symlink: {}".format(filename))
    if not target.is_file():
        raise VerifyError("artifact path must be a regular file: {}".format(filename))


def download_artifact(base_url, filename, target, timeout):
    if not base_url:
        raise VerifyError("missing artifact and no --download-base provided: {}".format(filename))
    if target.is_symlink():
        raise VerifyError("artifact path must not be a symlink: {}".format(filename))
    target.parent.mkdir(parents=True, exist_ok=True)
    url = base_url.rstrip("/") + "/" + quote(filename, safe="/._-+~")
    with urlopen(url, timeout=timeout) as response, target.open("wb") as output:
        output.write(response.read())


def sha256_file(path):
    hasher = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_artifacts(args, entries):
    artifacts_dir = args.artifacts_dir
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    failures = []
    for expected_digest, filename in entries:
        target = artifact_path(artifacts_dir, filename)
        if not target.exists():
            download_artifact(args.download_base, filename, target, args.download_timeout)
        require_regular_artifact(target, filename)
        actual_digest = sha256_file(target)
        if actual_digest != expected_digest:
            failures.append((filename, expected_digest, actual_digest))

    if failures:
        details = "\n".join(
            "{} expected {} actual {}".format(filename, expected, actual)
            for filename, expected, actual in failures
        )
        raise VerifyError("artifact hash verification failed:\n{}".format(details))


def main():
    args = parse_args()
    if not args.checksums.is_file():
        print("error: checksums file does not exist: {}".format(args.checksums), file=sys.stderr)
        return 2

    try:
        with tempfile.TemporaryDirectory(prefix="zkcoin-verify-") as tempdir:
            decrypted = Path(tempdir) / "SHA256SUMS"
            run_gpg_decrypt(args, decrypted)
            entries = selected_entries(parse_checksum_manifest(decrypted), args.match)
            verify_artifacts(args, entries)
    except VerifyError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    print("Verified {} zkCoin release artifact(s).".format(len(entries)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
