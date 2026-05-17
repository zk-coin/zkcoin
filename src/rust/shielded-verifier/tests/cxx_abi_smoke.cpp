// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/shielded_verifier.h>

#include <algorithm>
#include <vector>

static uint256 FilledHash(unsigned char value)
{
    uint256 hash;
    std::fill(hash.begin(), hash.end(), value);
    return hash;
}

int main()
{
    static const std::vector<unsigned char> EXPECTED_PROOF{
        0x8d, 0x88, 0xec, 0x0b, 0xaa, 0x50, 0x6b, 0x9d,
        0x0a, 0xdd, 0x03, 0x36, 0x13, 0x74, 0x4b, 0x45,
        0x1f, 0x87, 0xe0, 0xd1, 0x17, 0xe7, 0x5e, 0xe5,
        0xd4, 0x8f, 0x48, 0x89, 0xa0, 0x7e, 0x59, 0x8c,
    };

    const uint256 field_hash = FilledHash(0x11);
    const uint256 tx_binding_hash = FilledHash(0x22);
    const auto built_payload = Consensus::ShieldedPool::BuildProofPayloadV1(field_hash, tx_binding_hash);
    if (built_payload != EXPECTED_PROOF) {
        return 1;
    }

    if (!Consensus::ShieldedPool::VerifyProofPayloadV1(EXPECTED_PROOF, field_hash, tx_binding_hash)) {
        return 2;
    }

    auto wrong_proof = EXPECTED_PROOF;
    wrong_proof[0] ^= 0x01;
    if (Consensus::ShieldedPool::VerifyProofPayloadV1(wrong_proof, field_hash, tx_binding_hash)) {
        return 3;
    }

    return 0;
}
