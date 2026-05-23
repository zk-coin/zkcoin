Release Process
====================

## zkCoin release status

zkCoin release infrastructure is not production-ready. This file still contains
inherited Litecoin and Bitcoin Core release procedures, Gitian repositories,
detached-signature repositories, notarization identifiers, upload destinations,
and artifact names. Do not publish zkCoin artifacts from this process until the
blockers in
[`contrib/devtools/zkcoin_release_infrastructure_manifest.json`](../contrib/devtools/zkcoin_release_infrastructure_manifest.json)
are resolved. The inherited `contrib/gitian-build.py` helper is also blocked by
default because it builds Bitcoin Core artifacts, not zkCoin.

The current `litecoin-*` binaries, tarballs, app names, and installer names are
a temporary compatibility namespace retained until the binary, datadir,
config-file, and artifact migration is handled as an explicit release step.
Any release candidate must either document that namespace as intentional for
that release or migrate it in a dedicated PR before signing artifacts.

## Source release-candidate validation

Before tagging a source release candidate, run the zkCoin release-candidate
validation gate:

```bash
JOBS="$(sysctl -n hw.ncpu 2>/dev/null || nproc 2>/dev/null || echo 4)" \
  TEST_RUNNER_PORT_MIN=28000 \
  contrib/devtools/zkcoin_release_candidate_validation.sh
```

This gate runs the canonical launch validation loop, then builds the source
tarball, unpacks it into a temporary build root, configures the real Orchard
verifier backend, rebuilds `litecoind`, `litecoin-cli`, and `test_litecoin`,
and reruns the real Orchard AuxPoW regression from the unpacked release source.

Passing `zkcoin_release_candidate_validation.sh` only proves source
release-candidate readiness for the current compatibility namespace.
It is not binary release readiness.
It does not authorize publishing binaries, checksums, signatures, installers,
notarized applications, or detached signing payloads. Keep Gitian, binary
verification, signing, notarization, upload, and artifact naming blocked until
`zkcoin_release_infrastructure_manifest.json` is updated with resolved zkCoin
release infrastructure.

## Binary verification tooling

Use `contrib/verifybinaries/verify-zkcoin-release.py` to verify zkCoin binary
release artifacts from a clearsigned `SHA256SUMS.asc` and an explicitly supplied
zkCoin release signing key fingerprint. The verifier is parameterized; it does
not embed production signing keys, checksum URLs, artifact prefixes, or download
hosts. Keep release publication blocked until those values are resolved in
`zkcoin_release_infrastructure_manifest.json`.

## Branch updates

### Before every release candidate

* Update translations (ping wumpus on IRC) see [translation_process.md](https://github.com/bitcoin/bitcoin/blob/master/doc/translation_process.md#synchronising-translations).
* Update manpages, see [gen-manpages.sh](https://github.com/bitcoin/bitcoin/blob/master/contrib/devtools/README.md#gen-manpagessh).
* Update release candidate version in `configure.ac` (`CLIENT_VERSION_RC`).

### Before every major and minor release

* Update [bips.md](bips.md) to account for changes since the last release (don't forget to bump the version number on the first line).
* Update version in `configure.ac` (don't forget to set `CLIENT_VERSION_RC` to `0`).
* Write release notes (see "Write the release notes" below).

### Before every major release

* On both the master branch and the new release branch:
  - update `CLIENT_VERSION_MINOR` in [`configure.ac`](../configure.ac)
  - update `CLIENT_VERSION_MINOR`, `PACKAGE_VERSION`, and `PACKAGE_STRING` in [`build_msvc/bitcoin_config.h`](/build_msvc/bitcoin_config.h)
* On the new release branch in [`configure.ac`](../configure.ac) and [`build_msvc/bitcoin_config.h`](/build_msvc/bitcoin_config.h) (see [this commit](https://github.com/bitcoin/bitcoin/commit/742f7dd)):
  - set `CLIENT_VERSION_REVISION` to `0`
  - set `CLIENT_VERSION_IS_RELEASE` to `true`

#### Before branch-off

* Update hardcoded [seeds](/contrib/seeds/README.md), see [this pull request](https://github.com/bitcoin/bitcoin/pull/7415) for an example.
* Update [`src/chainparams.cpp`](/src/chainparams.cpp) m_assumed_blockchain_size and m_assumed_chain_state_size with the current size plus some overhead (see [this](#how-to-calculate-assumed-blockchain-and-chain-state-size) for information on how to calculate them).
* Update [`src/chainparams.cpp`](/src/chainparams.cpp) chainTxData with statistics about the transaction count and rate. Use the output of the `getchaintxstats` RPC, see
  [this pull request](https://github.com/bitcoin/bitcoin/pull/20263) for an example. Reviewers can verify the results by running `getchaintxstats <window_block_count> <window_final_block_hash>` with the `window_block_count` and `window_final_block_hash` from your output.
* Update `src/chainparams.cpp` nMinimumChainWork and defaultAssumeValid (and the block height comment) with information from the `getblockheader` (and `getblockhash`) RPCs.
  - The selected value must not be orphaned so it may be useful to set the value two blocks back from the tip.
  - Testnet should be set some tens of thousands back from the tip due to reorgs there.
  - This update should be reviewed with a reindex-chainstate with assumevalid=0 to catch any defect
     that causes rejection of blocks in the past history.
- Clear the release notes and move them to the wiki (see "Write the release notes" below).

#### After branch-off (on master)

- Update the version of `contrib/gitian-descriptors/*.yml`.

#### After branch-off (on the major release branch)

- Update the versions.
- Create a pinned meta-issue for testing the release candidate (see [this issue](https://github.com/bitcoin/bitcoin/issues/17079) for an example) and provide a link to it in the release announcements where useful.

#### Before final release

- Merge the release notes from the wiki into the branch.
- Ensure the "Needs release note" label is removed from all relevant pull requests and issues.


## Building

### First time / New builders

If you're using the automated script (found in [contrib/gitian-build.py](/contrib/gitian-build.py)), then at this point you should run it with the "--setup" command. Otherwise ignore this.

Check out the source code in the following directory hierarchy.

    cd /path/to/your/toplevel/build
    export GITIAN_SIGS_DIR="${GITIAN_SIGS_DIR:-zkcoin-gitian.sigs}"
    export ZKCOIN_DETACHED_SIGS_DIR="${ZKCOIN_DETACHED_SIGS_DIR:-zkcoin-detached-sigs}"
    : "${ZKCOIN_GITIAN_SIGS_REPO_URL:?set the resolved zkCoin Gitian signatures repository URL}"
    : "${ZKCOIN_DETACHED_SIGS_REPO_URL:?set the resolved zkCoin detached-signatures repository URL}"
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_REF:?set the resolved zkCoin detached-signatures release branch}"
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_TAG:?set the signed zkCoin detached-signatures release tag}"
    git clone "$ZKCOIN_GITIAN_SIGS_REPO_URL" "$GITIAN_SIGS_DIR"
    git clone "$ZKCOIN_DETACHED_SIGS_REPO_URL" "$ZKCOIN_DETACHED_SIGS_DIR"
    git clone https://github.com/devrandom/gitian-builder.git
    git clone https://github.com/zk-coin/zkcoin.git litecoin

### Litecoin maintainers/release engineers, suggestion for writing release notes

Write the release notes. `git shortlog` helps a lot, for example:

    git shortlog --no-merges v(current version, e.g. 0.19.2)..v(new version, e.g. 0.20.0)

(or ping @wumpus on IRC, he has specific tooling to generate the list of merged pulls
and sort them into categories based on labels).

Generate list of authors:

    git log --format='- %aN' v(current version, e.g. 0.20.0)..v(new version, e.g. 0.20.1) | sort -fiu

Resolve and sign the zkCoin release source tag before any Gitian build:

```bash
: "${ZKCOIN_RELEASE_VERSION:?set the zkCoin release version, without a leading v}"
: "${ZKCOIN_RELEASE_TAG:?set the signed zkCoin source tag, usually v${ZKCOIN_RELEASE_VERSION}}"
: "${ZKCOIN_RELEASE_SOURCE_COMMIT:?set the exact zkCoin source commit for the release tag}"

case "$ZKCOIN_RELEASE_VERSION" in
  v*|*/*|*..*|*[\ \	]*)
    echo "ZKCOIN_RELEASE_VERSION must be a bare version without v, slashes, spaces, or repeated dots" >&2
    exit 1
    ;;
esac

if [ "$ZKCOIN_RELEASE_TAG" != "v${ZKCOIN_RELEASE_VERSION}" ]; then
  echo "ZKCOIN_RELEASE_TAG must be v${ZKCOIN_RELEASE_VERSION}" >&2
  exit 1
fi

git check-ref-format "refs/tags/$ZKCOIN_RELEASE_TAG" || {
  echo "ZKCOIN_RELEASE_TAG is not a valid tag name" >&2
  exit 1
}

ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED="$(git rev-parse --verify "$ZKCOIN_RELEASE_SOURCE_COMMIT^{commit}")"
git tag -s "$ZKCOIN_RELEASE_TAG" "$ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED"
git verify-tag "$ZKCOIN_RELEASE_TAG"
ZKCOIN_RELEASE_TAG_COMMIT="$(git rev-list -n 1 "$ZKCOIN_RELEASE_TAG")"
if [ "$ZKCOIN_RELEASE_TAG_COMMIT" != "$ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED" ]; then
  echo "ZKCOIN_RELEASE_TAG does not point at ZKCOIN_RELEASE_SOURCE_COMMIT" >&2
  exit 1
fi
```

### Setup and perform Gitian builds

If you're using the automated script (found in [contrib/gitian-build.py](/contrib/gitian-build.py)), then at this point you should run it with the "--build" command. Otherwise ignore this.

Setup Gitian descriptors:

    pushd ./litecoin
    : "${ZKCOIN_GITIAN_SIGNER:?set your authorized zkCoin Gitian signer id}"
    : "${ZKCOIN_GITIAN_SIGNER_FINGERPRINT:?set your authorized zkCoin Gitian signer fingerprint}"
    : "${ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE:?set the published zkCoin Gitian authorized signers file}"
    : "${ZKCOIN_RELEASE_VERSION:?set the zkCoin release version, without a leading v}"
    : "${ZKCOIN_RELEASE_TAG:?set the signed zkCoin source tag}"
    : "${ZKCOIN_RELEASE_SOURCE_COMMIT:?set the exact zkCoin source commit for the release tag}"
    case "$ZKCOIN_GITIAN_SIGNER" in
      ''|*/*|*..*|*[!A-Za-z0-9_.@+-]*)
        echo "ZKCOIN_GITIAN_SIGNER must be a single authorized signer id" >&2
        exit 1
        ;;
    esac
    case "$ZKCOIN_GITIAN_SIGNER_FINGERPRINT" in
      ''|*[!0-9A-Fa-f]*)
        echo "ZKCOIN_GITIAN_SIGNER_FINGERPRINT must be hexadecimal" >&2
        exit 1
        ;;
    esac
    if [ "${#ZKCOIN_GITIAN_SIGNER_FINGERPRINT}" -lt 40 ]; then
        echo "ZKCOIN_GITIAN_SIGNER_FINGERPRINT must be at least 40 hex characters" >&2
        exit 1
    fi
    if [ ! -f "$ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" ]; then
        echo "ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE must point to the published signer list" >&2
        exit 1
    fi
    ZKCOIN_GITIAN_SIGNER_FINGERPRINT_NORMALIZED="$(printf '%s' "$ZKCOIN_GITIAN_SIGNER_FINGERPRINT" | tr '[:lower:]' '[:upper:]')"
    awk -v signer="$ZKCOIN_GITIAN_SIGNER" -v fingerprint="$ZKCOIN_GITIAN_SIGNER_FINGERPRINT_NORMALIZED" '
      /^[[:space:]]*(#|$)/ { next }
      $1 == signer && toupper($2) == fingerprint { found = 1 }
      END { exit found ? 0 : 1 }
    ' "$ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" || {
        echo "ZKCOIN_GITIAN_SIGNER and fingerprint are not in the authorized zkCoin Gitian signer list" >&2
        exit 1
    }
    export SIGNER="$ZKCOIN_GITIAN_SIGNER"
    export VERSION="$ZKCOIN_RELEASE_VERSION"
    git fetch --tags
    git verify-tag "$ZKCOIN_RELEASE_TAG"
    ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED="$(git rev-parse --verify "$ZKCOIN_RELEASE_SOURCE_COMMIT^{commit}")"
    git checkout --detach "$ZKCOIN_RELEASE_TAG^{commit}"
    if [ "$(git rev-parse HEAD)" != "$ZKCOIN_RELEASE_SOURCE_COMMIT_RESOLVED" ]; then
        echo "Gitian checkout does not match ZKCOIN_RELEASE_SOURCE_COMMIT" >&2
        exit 1
    fi
    popd

Ensure your zkCoin Gitian signatures repository is up-to-date if you wish to
gverify your builds against other Gitian signatures.

    pushd "./${GITIAN_SIGS_DIR}"
    git pull
    popd

Ensure gitian-builder is up-to-date:

    pushd ./gitian-builder
    git pull
    popd

### Fetch and create inputs: (first time, or when dependency versions change)

    pushd ./gitian-builder
    mkdir -p inputs
    wget -O inputs/osslsigncode-2.0.tar.gz https://github.com/mtrojnar/osslsigncode/archive/2.0.tar.gz
    echo '5a60e0a4b3e0b4d655317b2f12a810211c50242138322b16e7e01c6fbb89d92f inputs/osslsigncode-2.0.tar.gz' | sha256sum -c
    popd

Create the macOS SDK tarball, see the [macdeploy instructions](/contrib/macdeploy/README.md#deterministic-macos-dmg-notes) for details, and copy it into the inputs directory.

### Optional: Seed the Gitian sources cache and offline git repositories

NOTE: Gitian is sometimes unable to download files. If you have errors, try the step below.

By default, Gitian will fetch source files as needed. To cache them ahead of time, make sure you have checked out the tag you want to build in litecoin, then:

    pushd ./gitian-builder
    make -C ../litecoin/depends download SOURCES_PATH=`pwd`/cache/common
    popd

Only missing files will be fetched, so this is safe to re-run for each build.

NOTE: Offline builds must use the --url flag to ensure Gitian fetches only from local URLs. For example:

    pushd ./gitian-builder
    ./bin/gbuild --url litecoin=/path/to/litecoin,signature=/path/to/zkcoin-detached-sigs {rest of arguments}
    popd

The gbuild invocations below <b>DO NOT DO THIS</b> by default.

### Build and sign Litecoin Core for Linux, Windows, and macOS:

    export GITIAN_THREADS=2
    export GITIAN_MEMORY=3000
    
    pushd ./gitian-builder
    ./bin/gbuild --num-make $GITIAN_THREADS --memory $GITIAN_MEMORY --commit "litecoin=${ZKCOIN_RELEASE_TAG}" ../litecoin/contrib/gitian-descriptors/gitian-linux.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-linux --destination "../${GITIAN_SIGS_DIR}/" ../litecoin/contrib/gitian-descriptors/gitian-linux.yml
    mv build/out/litecoin-*.tar.gz build/out/src/litecoin-*.tar.gz ../

    ./bin/gbuild --num-make $GITIAN_THREADS --memory $GITIAN_MEMORY --commit "litecoin=${ZKCOIN_RELEASE_TAG}" ../litecoin/contrib/gitian-descriptors/gitian-win.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-win-unsigned --destination "../${GITIAN_SIGS_DIR}/" ../litecoin/contrib/gitian-descriptors/gitian-win.yml
    mv build/out/litecoin-*-win-unsigned.tar.gz inputs/litecoin-win-unsigned.tar.gz
    mv build/out/litecoin-*.zip build/out/litecoin-*.exe ../

    ./bin/gbuild --num-make $GITIAN_THREADS --memory $GITIAN_MEMORY --commit "litecoin=${ZKCOIN_RELEASE_TAG}" ../litecoin/contrib/gitian-descriptors/gitian-osx.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-osx-unsigned --destination "../${GITIAN_SIGS_DIR}/" ../litecoin/contrib/gitian-descriptors/gitian-osx.yml
    mv build/out/litecoin-*-osx-unsigned.tar.gz inputs/litecoin-osx-unsigned.tar.gz
    mv build/out/litecoin-*.tar.gz build/out/litecoin-*.dmg ../
    popd

Build output expected:

  1. source tarball (`litecoin-${VERSION}.tar.gz`)
  2. linux 32-bit and 64-bit dist tarballs (`litecoin-${VERSION}-linux[32|64].tar.gz`)
  3. windows 32-bit and 64-bit unsigned installers and dist zips (`litecoin-${VERSION}-win[32|64]-setup-unsigned.exe`, `litecoin-${VERSION}-win[32|64].zip`)
  4. macOS unsigned installer and dist tarball (`litecoin-${VERSION}-osx-unsigned.dmg`, `litecoin-${VERSION}-osx64.tar.gz`)
  5. Gitian signatures (in `${GITIAN_SIGS_DIR}/${VERSION}-<linux|{win,osx}-unsigned>/(your Gitian key)/`)

### Verify other gitian builders signatures to your own. (Optional)

Add other gitian builders keys to your gpg keyring, and/or refresh keys: See `../litecoin/contrib/gitian-keys/README.md`.

Verify the signatures

    pushd ./gitian-builder
    ./bin/gverify -v -d "../${GITIAN_SIGS_DIR}/" -r ${VERSION}-linux ../litecoin/contrib/gitian-descriptors/gitian-linux.yml
    ./bin/gverify -v -d "../${GITIAN_SIGS_DIR}/" -r ${VERSION}-win-unsigned ../litecoin/contrib/gitian-descriptors/gitian-win.yml
    ./bin/gverify -v -d "../${GITIAN_SIGS_DIR}/" -r ${VERSION}-osx-unsigned ../litecoin/contrib/gitian-descriptors/gitian-osx.yml
    popd

### Next steps:

Commit your signature to the zkCoin Gitian signatures repository:

    pushd "${GITIAN_SIGS_DIR}"
    git add ${VERSION}-linux/"${SIGNER}"
    git add ${VERSION}-win-unsigned/"${SIGNER}"
    git add ${VERSION}-osx-unsigned/"${SIGNER}"
    git commit -m "Add ${VERSION} unsigned sigs for ${SIGNER}"
    git push  # Assuming you can push to the gitian.sigs tree
    popd

Codesigner only: Create Windows/macOS detached signatures:
- Only one person handles codesigning. Everyone else should skip to the next step.
- Only once the Windows/macOS builds each satisfy the published zkCoin Gitian
  signer quorum may they be signed with their respective release keys.

Codesigner only: Sign the macOS binary:

    transfer litecoin-osx-unsigned.tar.gz to macOS for signing
    tar xf litecoin-osx-unsigned.tar.gz
    : "${ZKCOIN_MACOS_BUNDLE_ID:?set the resolved zkCoin macOS bundle identifier}"
    : "${ZKCOIN_MACOS_APPLE_ID:?set the Apple ID used for zkCoin notarization}"
    : "${ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM:?set the zkCoin notarization keychain item name}"
    : "${ZKCOIN_MACOS_ASC_PROVIDER:?set the zkCoin Apple provider shortcode}"
    : "${ZKCOIN_MACOS_CODESIGN_IDENTITY:?set the authorized zkCoin macOS code-signing identity}"
    : "${ZKCOIN_MACOS_CODESIGN_CERT_CUSTODY:?set the approved zkCoin macOS signing certificate custody record}"
    : "${ZKCOIN_MACOS_CODESIGN_CERT_OWNER:?set the accountable zkCoin macOS signing certificate custody owner}"
    : "${ZKCOIN_MACOS_CODESIGN_PAYLOAD_APPROVAL:?set the approved zkCoin macOS signing payload approval record}"
    for ZKCOIN_MACOS_CODESIGN_CUSTODY_FIELD in \
      "$ZKCOIN_MACOS_CODESIGN_IDENTITY" \
      "$ZKCOIN_MACOS_CODESIGN_CERT_CUSTODY" \
      "$ZKCOIN_MACOS_CODESIGN_CERT_OWNER" \
      "$ZKCOIN_MACOS_CODESIGN_PAYLOAD_APPROVAL"; do
        case "$ZKCOIN_MACOS_CODESIGN_CUSTODY_FIELD" in
          ''|TODO|TBD|todo|tbd|'Key ID'|*'<'*|*'>'*)
            echo "ZKCOIN_MACOS_CODESIGN custody fields must not be placeholders" >&2
            exit 1
            ;;
        esac
    done
    ./detached-sig-create.sh -s "$ZKCOIN_MACOS_CODESIGN_IDENTITY"
    Enter the signing credential passphrase according to the approved custody record and authorize the signature
    
    Now a manual deterministic disk image (dmg) creation is required.

    First time setup for codesigner, requires creation of app-specific-password via Apple ID website.
    Once password is obtained, save it to the macOS Keychain for future reference:

    $   xcrun altool -u "$ZKCOIN_MACOS_APPLE_ID" -p "<app-specific-password>" --store-password-in-keychain-item "$ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM"

    If the Apple provider shortcode is unknown for team accounts with multiple organisations, query:

    $   xcrun altool --list-providers -u "$ZKCOIN_MACOS_APPLE_ID" -p "@keychain:$ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM"

    Notarize the disk image:

    $   xcrun altool --notarize-app --primary-bundle-id "$ZKCOIN_MACOS_BUNDLE_ID" -u "$ZKCOIN_MACOS_APPLE_ID" -p "@keychain:$ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM" --asc-provider "$ZKCOIN_MACOS_ASC_PROVIDER" -t osx -f litecoin-${VERSION}-osx.dmg

    The notarization takes a few minutes. Check the status:

    $   xcrun altool --notarization-info <request-uuid> -u "$ZKCOIN_MACOS_APPLE_ID" -p "@keychain:$ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM" --asc-provider "$ZKCOIN_MACOS_ASC_PROVIDER"

    If notarization fails, query log with uuid:

    $   xcrun altool --notarization-info <request-uuid> -u "$ZKCOIN_MACOS_APPLE_ID" -p "@keychain:$ZKCOIN_MACOS_NOTARIZATION_KEYCHAIN_ITEM" --asc-provider "$ZKCOIN_MACOS_ASC_PROVIDER"

    Staple the notarization ticket onto the application

    $   xcrun stapler staple dist/Litecoin-Qt.app

Codesigner only: Sign the windows binaries:

    tar xf litecoin-win-unsigned.tar.gz
    : "${ZKCOIN_WINDOWS_CODESIGN_KEY_PATH:?set the authorized zkCoin Windows code-signing key path}"
    : "${ZKCOIN_WINDOWS_CODESIGN_KEY_CUSTODY:?set the approved zkCoin Windows signing key custody record}"
    : "${ZKCOIN_WINDOWS_CODESIGN_KEY_OWNER:?set the accountable zkCoin Windows signing key custody owner}"
    : "${ZKCOIN_WINDOWS_CODESIGN_PAYLOAD_APPROVAL:?set the approved zkCoin Windows signing payload approval record}"
    for ZKCOIN_WINDOWS_CODESIGN_CUSTODY_FIELD in \
      "$ZKCOIN_WINDOWS_CODESIGN_KEY_PATH" \
      "$ZKCOIN_WINDOWS_CODESIGN_KEY_CUSTODY" \
      "$ZKCOIN_WINDOWS_CODESIGN_KEY_OWNER" \
      "$ZKCOIN_WINDOWS_CODESIGN_PAYLOAD_APPROVAL"; do
        case "$ZKCOIN_WINDOWS_CODESIGN_CUSTODY_FIELD" in
          ''|TODO|TBD|todo|tbd|*'<'*|*'>'*)
            echo "ZKCOIN_WINDOWS_CODESIGN custody fields must not be placeholders" >&2
            exit 1
            ;;
        esac
    done
    ./detached-sig-create.sh -key "$ZKCOIN_WINDOWS_CODESIGN_KEY_PATH"
    Enter the passphrase according to the approved custody record when prompted
    signature-win.tar.gz will be created

Codesigner only: Commit the detached codesign payloads:

    cd "${ZKCOIN_DETACHED_SIGS_DIR}"
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_REF:?set the resolved zkCoin detached-signatures release branch}"
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_TAG:?set the signed zkCoin detached-signatures release tag}"
    : "${ZKCOIN_DETACHED_SIGS_CUSTODY_RECORD:?set the published zkCoin detached-signatures custody record}"
    : "${ZKCOIN_DETACHED_SIGS_CUSTODY_OWNER:?set the accountable zkCoin detached-signatures custody owner}"
    : "${ZKCOIN_DETACHED_SIGS_PAYLOAD_APPROVAL:?set the approved zkCoin detached-signatures payload approval record}"
    for ZKCOIN_DETACHED_SIGS_CUSTODY_FIELD in \
      "$ZKCOIN_DETACHED_SIGS_CUSTODY_RECORD" \
      "$ZKCOIN_DETACHED_SIGS_CUSTODY_OWNER" \
      "$ZKCOIN_DETACHED_SIGS_PAYLOAD_APPROVAL"; do
        case "$ZKCOIN_DETACHED_SIGS_CUSTODY_FIELD" in
          ''|TODO|TBD|todo|tbd|*'<'*|*'>'*)
            echo "ZKCOIN_DETACHED_SIGS custody fields must not be placeholders" >&2
            exit 1
            ;;
        esac
    done
    git fetch origin "$ZKCOIN_DETACHED_SIGS_RELEASE_REF:$ZKCOIN_DETACHED_SIGS_RELEASE_REF" --tags
    git rev-parse --verify --quiet "$ZKCOIN_DETACHED_SIGS_RELEASE_REF^{commit}" >/dev/null
    git checkout "$ZKCOIN_DETACHED_SIGS_RELEASE_REF"
    rm -rf *
    tar xf signature-osx.tar.gz
    tar xf signature-win.tar.gz
    #copy the notarization ticket to detached-sigs repo
    cp dist/Litecoin-Qt.app/Contents/CodeResources osx/dist/Litecoin-Qt.app/Contents/
    git add -A
    git commit -m "point to ${VERSION}"
    git tag -s "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG" HEAD
    git verify-tag "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"
    git push origin "$ZKCOIN_DETACHED_SIGS_RELEASE_REF" "$ZKCOIN_DETACHED_SIGS_RELEASE_TAG"

Non-codesigners: wait for Windows/macOS detached signatures:

- Once the Windows/macOS builds satisfy the published zkCoin Gitian signer
  quorum, they will be signed with their respective release keys.
- Detached signatures will then be committed to the configured zkCoin detached-signatures repository, which can be combined with the unsigned apps to create signed binaries.

Create (and optionally verify) the signed macOS binary:

    pushd ./gitian-builder
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_TAG:?set the signed zkCoin detached-signatures release tag}"
    ./bin/gbuild -i --url "signature=../${ZKCOIN_DETACHED_SIGS_DIR}" --commit "signature=${ZKCOIN_DETACHED_SIGS_RELEASE_TAG}" ../litecoin/contrib/gitian-descriptors/gitian-osx-signer.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-osx-signed --destination "../${GITIAN_SIGS_DIR}/" ../litecoin/contrib/gitian-descriptors/gitian-osx-signer.yml
    ./bin/gverify -v -d "../${GITIAN_SIGS_DIR}/" -r ${VERSION}-osx-signed ../litecoin/contrib/gitian-descriptors/gitian-osx-signer.yml
    mv build/out/litecoin-osx-signed.dmg ../litecoin-${VERSION}-osx.dmg
    popd

Create (and optionally verify) the signed Windows binaries:

    pushd ./gitian-builder
    : "${ZKCOIN_DETACHED_SIGS_RELEASE_TAG:?set the signed zkCoin detached-signatures release tag}"
    ./bin/gbuild -i --url "signature=../${ZKCOIN_DETACHED_SIGS_DIR}" --commit "signature=${ZKCOIN_DETACHED_SIGS_RELEASE_TAG}" ../litecoin/contrib/gitian-descriptors/gitian-win-signer.yml
    ./bin/gsign --signer "$SIGNER" --release ${VERSION}-win-signed --destination "../${GITIAN_SIGS_DIR}/" ../litecoin/contrib/gitian-descriptors/gitian-win-signer.yml
    ./bin/gverify -v -d "../${GITIAN_SIGS_DIR}/" -r ${VERSION}-win-signed ../litecoin/contrib/gitian-descriptors/gitian-win-signer.yml
    mv build/out/litecoin-*win64-setup.exe ../litecoin-${VERSION}-win64-setup.exe
    popd

Commit your signature for the signed macOS/Windows binaries:

    pushd "${GITIAN_SIGS_DIR}"
    git add ${VERSION}-osx-signed/"${SIGNER}"
    git add ${VERSION}-win-signed/"${SIGNER}"
    git commit -m "Add ${SIGNER} ${VERSION} signed binaries signatures"
    git push  # Assuming you can push to the zkCoin Gitian signatures tree
    popd

### After the published zkCoin Gitian signer quorum has built and results match:

- Verify that every Gitian release output set satisfies the published zkCoin
  signer quorum before creating checksums:

```bash
: "${ZKCOIN_GITIAN_SIGNER_QUORUM:?set the resolved zkCoin Gitian signer quorum count}"
: "${ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE:?set the published zkCoin Gitian authorized signers file}"

case "$ZKCOIN_GITIAN_SIGNER_QUORUM" in
  ''|*[!0-9]*)
    echo "ZKCOIN_GITIAN_SIGNER_QUORUM must be a positive integer" >&2
    exit 1
    ;;
esac

if [ "$ZKCOIN_GITIAN_SIGNER_QUORUM" -lt 1 ]; then
    echo "ZKCOIN_GITIAN_SIGNER_QUORUM must be at least 1" >&2
    exit 1
fi
if [ ! -f "$ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" ]; then
    echo "ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE must point to the published signer list" >&2
    exit 1
fi

for ZKCOIN_GITIAN_RELEASE in \
  "${VERSION}-linux" \
  "${VERSION}-win-unsigned" \
  "${VERSION}-osx-unsigned" \
  "${VERSION}-win-signed" \
  "${VERSION}-osx-signed"; do
    ZKCOIN_GITIAN_UNAUTHORIZED_SIGNERS="$(
      find "${GITIAN_SIGS_DIR}/${ZKCOIN_GITIAN_RELEASE}" \
        -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
        -exec basename {} \; \
        | while IFS= read -r ZKCOIN_GITIAN_SIGNER_DIR; do
            awk -v signer="$ZKCOIN_GITIAN_SIGNER_DIR" '
              /^[[:space:]]*(#|$)/ { next }
              $1 == signer && $2 ~ /^[0-9A-Fa-f]{40,}$/ { found = 1 }
              END { exit found ? 0 : 1 }
            ' "$ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" || printf '%s\n' "$ZKCOIN_GITIAN_SIGNER_DIR"
          done \
        | sort -u
    )"
    if [ -n "$ZKCOIN_GITIAN_UNAUTHORIZED_SIGNERS" ]; then
        echo "${ZKCOIN_GITIAN_RELEASE} contains unauthorized Gitian signer directories:" >&2
        printf '%s\n' "$ZKCOIN_GITIAN_UNAUTHORIZED_SIGNERS" >&2
        exit 1
    fi

    ZKCOIN_GITIAN_AUTHORIZED_SIGNER_COUNT="$(
      find "${GITIAN_SIGS_DIR}/${ZKCOIN_GITIAN_RELEASE}" \
        -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
        -exec basename {} \; \
        | while IFS= read -r ZKCOIN_GITIAN_SIGNER_DIR; do
            awk -v signer="$ZKCOIN_GITIAN_SIGNER_DIR" '
              /^[[:space:]]*(#|$)/ { next }
              $1 == signer && $2 ~ /^[0-9A-Fa-f]{40,}$/ { found = 1 }
              END { exit found ? 0 : 1 }
            ' "$ZKCOIN_GITIAN_AUTHORIZED_SIGNERS_FILE" && printf '%s\n' "$ZKCOIN_GITIAN_SIGNER_DIR"
          done \
        | sort -u \
        | wc -l \
        | tr -d '[:space:]'
    )"
    if [ "$ZKCOIN_GITIAN_AUTHORIZED_SIGNER_COUNT" -lt "$ZKCOIN_GITIAN_SIGNER_QUORUM" ]; then
        echo "${ZKCOIN_GITIAN_RELEASE} has ${ZKCOIN_GITIAN_AUTHORIZED_SIGNER_COUNT} authorized Gitian signers; require ${ZKCOIN_GITIAN_SIGNER_QUORUM}" >&2
        exit 1
    fi
done
```

- Create `SHA256SUMS.asc` for the builds, and GPG-sign it. Confirm the
  explicit binary/artifact namespace decision before writing checksums, then
  verify the release directory contains exactly the expected non-debug artifact
  set:

```bash
: "${ZKCOIN_RELEASE_BINARY_NAMESPACE:?set to litecoin-compatibility for the current retained names, or zkcoin after completing namespace migration}"

case "$ZKCOIN_RELEASE_BINARY_NAMESPACE" in
  litecoin-compatibility)
    ;;
  zkcoin)
    echo "ZKCOIN_RELEASE_BINARY_NAMESPACE=zkcoin requires binary and artifact namespace migration before signing" >&2
    exit 1
    ;;
  *)
    echo "ZKCOIN_RELEASE_BINARY_NAMESPACE must be litecoin-compatibility or zkcoin" >&2
    exit 1
    ;;
esac

ZKCOIN_RELEASE_ARTIFACTS=(
  "litecoin-${VERSION}-aarch64-linux-gnu.tar.gz"
  "litecoin-${VERSION}-arm-linux-gnueabihf.tar.gz"
  "litecoin-${VERSION}-riscv64-linux-gnu.tar.gz"
  "litecoin-${VERSION}-x86_64-linux-gnu.tar.gz"
  "litecoin-${VERSION}-osx64.tar.gz"
  "litecoin-${VERSION}-osx.dmg"
  "litecoin-${VERSION}.tar.gz"
  "litecoin-${VERSION}-win64-setup.exe"
  "litecoin-${VERSION}-win64.zip"
)

ZKCOIN_EXPECTED_ARTIFACTS="$(mktemp)"
ZKCOIN_ACTUAL_ARTIFACTS="$(mktemp)"
trap 'rm -f "$ZKCOIN_EXPECTED_ARTIFACTS" "$ZKCOIN_ACTUAL_ARTIFACTS"' EXIT

printf '%s\n' "${ZKCOIN_RELEASE_ARTIFACTS[@]}" | sort > "$ZKCOIN_EXPECTED_ARTIFACTS"
find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -exec basename {} \; | sort > "$ZKCOIN_ACTUAL_ARTIFACTS"

if ! cmp -s "$ZKCOIN_EXPECTED_ARTIFACTS" "$ZKCOIN_ACTUAL_ARTIFACTS"; then
    echo "Release artifact set does not match the expected zkCoin non-debug artifacts" >&2
    diff -u "$ZKCOIN_EXPECTED_ARTIFACTS" "$ZKCOIN_ACTUAL_ARTIFACTS" >&2 || true
    exit 1
fi

sha256sum "${ZKCOIN_RELEASE_ARTIFACTS[@]}" > SHA256SUMS
```
The `*-debug*` files generated by the gitian build contain debug symbols
for troubleshooting by developers. It is assumed that anyone that is interested
in debugging can run gitian to generate the files for themselves. To avoid
end-user confusion about which file to pick, as well as save storage
space *do not publish these to the zkCoin artifact host, checksum manifest, or
release index*.

- GPG-sign it with the published zkCoin release signing key, delete the
  unsigned file:
```
: "${ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT:?set the independently verified zkCoin release signing key fingerprint}"
: "${ZKCOIN_RELEASE_SIGNING_KEY_ID:?set the local GPG key id for the zkCoin release signing key}"
: "${ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_RECORD:?set the published zkCoin release signing key custody record}"
: "${ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_OWNER:?set the accountable zkCoin release signing key custody owner}"
: "${ZKCOIN_RELEASE_SIGNING_KEY_REVOCATION_PLAN:?set the zkCoin release signing key revocation and rotation plan}"

for ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_FIELD in \
  "$ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_RECORD" \
  "$ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_OWNER" \
  "$ZKCOIN_RELEASE_SIGNING_KEY_REVOCATION_PLAN"; do
  case "$ZKCOIN_RELEASE_SIGNING_KEY_CUSTODY_FIELD" in
    ''|TODO|TBD|todo|tbd|*'<'*|*'>'*)
      echo "ZKCOIN_RELEASE_SIGNING_KEY custody fields must not be placeholders" >&2
      exit 1
      ;;
  esac
done

ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT_NORMALIZED="$(
  printf '%s' "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" \
    | tr -d '[:space:]' \
    | tr '[:lower:]' '[:upper:]'
)"

if ! gpg --batch --with-colons --fingerprint "$ZKCOIN_RELEASE_SIGNING_KEY_ID" \
  | awk -F: '$1 == "fpr" { print $10 }' \
  | grep -Fx "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT_NORMALIZED"; then
    echo "ZKCOIN_RELEASE_SIGNING_KEY_ID does not match ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" >&2
    exit 1
fi

gpg --batch --local-user "$ZKCOIN_RELEASE_SIGNING_KEY_ID" --digest-algo sha256 --clearsign SHA256SUMS # outputs SHA256SUMS.asc
rm SHA256SUMS
```
(the digest algorithm is forced to sha256 to avoid confusion of the `Hash:` header that GPG adds with the SHA256 used for the files)
Note: check that SHA256SUMS itself doesn't end up in SHA256SUMS, which is a spurious/nonsensical entry.

- Verify the local signed checksum manifest and artifacts before uploading
  anything:

```bash
contrib/verifybinaries/verify-zkcoin-release.py \
  --checksums ./SHA256SUMS.asc \
  --trusted-fingerprint "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" \
  --artifacts-dir .
```

- Resolve the zkCoin artifact publication targets before uploading anything:

```bash
: "${ZKCOIN_RELEASE_ARTIFACT_BASE_URL:?set the resolved zkCoin artifact download base URL}"
: "${ZKCOIN_RELEASE_CHECKSUMS_URL:?set the resolved zkCoin SHA256SUMS.asc publication URL}"
: "${ZKCOIN_RELEASE_GITHUB_REPO_URL:?set the resolved zkCoin GitHub release repository URL}"
```

- Upload zips and installers, as well as `SHA256SUMS.asc` from the last step, to
  the resolved zkCoin artifact host.

- Verify the published checksums and artifacts from the resolved public URLs.
  Keep this in a clean directory so local build outputs cannot satisfy the
  post-publication check:

```bash
ZKCOIN_PUBLIC_VERIFY_DIR="./release-artifacts/public-verify"
rm -rf "$ZKCOIN_PUBLIC_VERIFY_DIR"
mkdir -p "$ZKCOIN_PUBLIC_VERIFY_DIR"

curl --fail --location --show-error --silent \
  --output "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc" \
  "$ZKCOIN_RELEASE_CHECKSUMS_URL"

cmp -s ./SHA256SUMS.asc "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc" || {
  echo "Published SHA256SUMS.asc does not match the locally signed manifest" >&2
  exit 1
}

contrib/verifybinaries/verify-zkcoin-release.py \
  --checksums "$ZKCOIN_PUBLIC_VERIFY_DIR/SHA256SUMS.asc" \
  --trusted-fingerprint "$ZKCOIN_RELEASE_SIGNING_KEY_FINGERPRINT" \
  --artifacts-dir "$ZKCOIN_PUBLIC_VERIFY_DIR" \
  --download-base "$ZKCOIN_RELEASE_ARTIFACT_BASE_URL"
```

- Resolve the zkCoin release-index and website publication targets before
  updating public metadata:

```bash
: "${ZKCOIN_RELEASE_WEBSITE_REPO_URL:?set the resolved zkCoin website repository URL}"
: "${ZKCOIN_RELEASE_WEBSITE_OWNER:?set the accountable zkCoin website publication owner}"
: "${ZKCOIN_RELEASE_INDEX_REPO_URL:?set the resolved zkCoin release index repository URL}"
: "${ZKCOIN_RELEASE_INDEX_OWNER:?set the accountable zkCoin release index publication owner}"
```

- Update the resolved zkCoin website and release index with the new version,
  artifact URLs, and checksum URL.

- Update resolved zkCoin downstream repositories, packages, and websites for
  the new version. Keep this blocked until each target repository and owner is
  explicitly documented for the release.

- Resolve the zkCoin release announcement channels before announcing:

```bash
: "${ZKCOIN_RELEASE_ANNOUNCEMENT_CHANNELS:?set the resolved zkCoin release announcement channels}"
: "${ZKCOIN_RELEASE_ANNOUNCEMENT_OWNER:?set the accountable zkCoin announcement owner}"
```

- Announce the release through the resolved zkCoin release channels.

- Resolve the zkCoin release-notes archival targets before creating the GitHub
  release:

```bash
: "${ZKCOIN_RELEASE_NOTES_PATH:?set the archived zkCoin release notes path under doc/release-notes/}"
: "${ZKCOIN_RELEASE_NOTES_BRANCH:?set the zkCoin release branch that receives archived notes}"
: "${ZKCOIN_RELEASE_NOTES_OWNER:?set the accountable zkCoin release-notes owner}"
: "${ZKCOIN_RELEASE_VERSION:?set the zkCoin release version for archived notes}"

ZKCOIN_EXPECTED_RELEASE_NOTES_PATH="doc/release-notes/release-notes-${ZKCOIN_RELEASE_VERSION}.md"
if [ "$ZKCOIN_RELEASE_NOTES_PATH" != "$ZKCOIN_EXPECTED_RELEASE_NOTES_PATH" ]; then
  echo "ZKCOIN_RELEASE_NOTES_PATH must match $ZKCOIN_EXPECTED_RELEASE_NOTES_PATH" >&2
  exit 1
fi

git check-ref-format --branch "$ZKCOIN_RELEASE_NOTES_BRANCH" >/dev/null || {
  echo "ZKCOIN_RELEASE_NOTES_BRANCH is not a valid branch name" >&2
  exit 1
}

if [ "$ZKCOIN_RELEASE_NOTES_BRANCH" = "master" ]; then
  echo "ZKCOIN_RELEASE_NOTES_BRANCH must name the release branch, not master" >&2
  exit 1
fi

git rev-parse --verify --quiet "master^{commit}" >/dev/null || {
  echo "master must resolve before verifying archived zkCoin release notes" >&2
  exit 1
}
git rev-parse --verify --quiet "$ZKCOIN_RELEASE_NOTES_BRANCH^{commit}" >/dev/null || {
  echo "ZKCOIN_RELEASE_NOTES_BRANCH must resolve before verifying archived zkCoin release notes" >&2
  exit 1
}
git cat-file -e "master:$ZKCOIN_RELEASE_NOTES_PATH" || {
  echo "Archived zkCoin release notes are missing on master" >&2
  exit 1
}
git cat-file -e "$ZKCOIN_RELEASE_NOTES_BRANCH:$ZKCOIN_RELEASE_NOTES_PATH" || {
  echo "Archived zkCoin release notes are missing on $ZKCOIN_RELEASE_NOTES_BRANCH" >&2
  exit 1
}
git diff --quiet --no-ext-diff \
  "master:$ZKCOIN_RELEASE_NOTES_PATH" \
  "$ZKCOIN_RELEASE_NOTES_BRANCH:$ZKCOIN_RELEASE_NOTES_PATH" || {
    echo "Archived zkCoin release notes differ between master and $ZKCOIN_RELEASE_NOTES_BRANCH" >&2
    exit 1
}
```

- Archive release notes to `$ZKCOIN_RELEASE_NOTES_PATH` on `master` and
  `$ZKCOIN_RELEASE_NOTES_BRANCH`. Keep this blocked until
  `$ZKCOIN_RELEASE_NOTES_OWNER` has verified both archival commits and the
  archive verification check above succeeds.

- Resolve the zkCoin GitHub release metadata before creating the GitHub release:

```bash
: "${ZKCOIN_RELEASE_GITHUB_REPO_URL:?set the resolved zkCoin GitHub release repository URL}"
: "${ZKCOIN_RELEASE_GITHUB_TAG:?set the signed zkCoin release tag for the GitHub release}"
: "${ZKCOIN_RELEASE_GITHUB_TITLE:?set the zkCoin GitHub release title}"
: "${ZKCOIN_RELEASE_GITHUB_OWNER:?set the accountable zkCoin GitHub release owner}"
: "${ZKCOIN_RELEASE_TAG:?set the signed zkCoin source tag}"

if [ "$ZKCOIN_RELEASE_GITHUB_TAG" != "$ZKCOIN_RELEASE_TAG" ]; then
  echo "ZKCOIN_RELEASE_GITHUB_TAG must match ZKCOIN_RELEASE_TAG" >&2
  exit 1
fi
```

- Create the GitHub release in `$ZKCOIN_RELEASE_GITHUB_REPO_URL` using
  `$ZKCOIN_RELEASE_GITHUB_TAG` and `$ZKCOIN_RELEASE_GITHUB_TITLE`, with a link
  to `$ZKCOIN_RELEASE_NOTES_PATH` and published `SHA256SUMS.asc`.

### Additional information

#### <a name="how-to-calculate-assumed-blockchain-and-chain-state-size"></a>How to calculate `m_assumed_blockchain_size` and `m_assumed_chain_state_size`

Both variables are used as a guideline for how much space the user needs on their drive in total, not just strictly for the blockchain.
Note that all values should be taken from a **fully synced** node and have an overhead of 5-10% added on top of its base value.

To calculate `m_assumed_blockchain_size`:
- For `mainnet` -> Take the size of the data directory, excluding `/regtest` and `/testnet4` directories.
- For `testnet` -> Take the size of the `/testnet4` directory.


To calculate `m_assumed_chain_state_size`:
- For `mainnet` -> Take the size of the `/chainstate` directory.
- For `testnet` -> Take the size of the `/testnet4/chainstate` directory.

Notes:
- When taking the size for `m_assumed_blockchain_size`, there's no need to exclude the `/chainstate` directory since it's a guideline value and an overhead will be added anyway.
- The expected overhead for growth may change over time, so it may not be the same value as last release; pay attention to that when changing the variables.
