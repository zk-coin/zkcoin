### Verify Binaries

#### zkCoin verifier

Use `verify-zkcoin-release.py` for zkCoin release artifacts. It verifies that a
clearsigned `SHA256SUMS.asc` was signed by an explicitly supplied zkCoin release
signing key fingerprint, then verifies every selected artifact hash from the
signed manifest.

```sh
./verify-zkcoin-release.py \
  --checksums ./SHA256SUMS.asc \
  --trusted-fingerprint "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" \
  --artifacts-dir ./release-artifacts
```

If artifacts are not already present locally, pass the resolved release artifact
base URL:

```sh
./verify-zkcoin-release.py \
  --checksums ./SHA256SUMS.asc \
  --trusted-fingerprint "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" \
  --artifacts-dir ./release-artifacts \
  --download-base "$ZKCOIN_RELEASE_ARTIFACT_BASE_URL"
```

The verifier intentionally has no embedded production signing key, checksum URL,
artifact prefix, or download host. Those values must come from the resolved
zkCoin release infrastructure for the release being verified.

#### Inherited Bitcoin Core verifier

`verify.sh` is Bitcoin Core-only inherited tooling. It is not zkCoin release
verification and is disabled by default. Do not use it to verify zkCoin release
artifacts.

To run the legacy Bitcoin Core verifier intentionally for upstream reference,
set `ZKCOIN_ALLOW_BITCOIN_VERIFYBINARIES=1`.

#### Preparation:

Make sure you obtain the proper release signing key and verify the fingerprint with several independent sources.

```sh
$ gpg --fingerprint "Bitcoin Core binary release signing key"
pub   4096R/36C2E964 2015-06-24 [expires: YYYY-MM-DD]
      Key fingerprint = 01EA 5486 DE18 A882 D4C2  6845 90C8 019E 36C2 E964
uid                  Wladimir J. van der Laan (Bitcoin Core binary release signing key) <laanwj@gmail.com>
```

#### Usage:

This script attempts to download the signature file `SHA256SUMS.asc` from https://bitcoin.org.

It first checks if the signature passes, and then downloads the files specified in the file, and checks if the hashes of these files match those that are specified in the signature file.

The script returns 0 if everything passes the checks. It returns 1 if either the signature check or the hash check doesn't pass. If an error occurs the return value is 2.


```sh
./verify.sh bitcoin-core-0.11.2
./verify.sh bitcoin-core-0.12.0
./verify.sh bitcoin-core-0.13.0-rc3
```

If you only want to download the binaries of certain platform, add the corresponding suffix, e.g.:

```sh
./verify.sh bitcoin-core-0.11.2-osx
./verify.sh 0.12.0-linux
./verify.sh bitcoin-core-0.13.0-rc3-win64
```

If you do not want to keep the downloaded binaries, specify anything as the second parameter.

```sh
./verify.sh bitcoin-core-0.13.0 delete
```
