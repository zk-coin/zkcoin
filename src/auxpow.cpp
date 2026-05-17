// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <auxpow.h>

#include <consensus/merkle.h>
#include <hash.h>
#include <primitives/block.h>
#include <script/script.h>

#include <algorithm>
#include <cassert>

namespace {
constexpr size_t MIN_COINBASE_SCRIPTSIG_SIZE{2};
constexpr size_t MAX_COINBASE_SCRIPTSIG_SIZE{100};

uint32_t DecodeLE32(const unsigned char* bytes)
{
    uint32_t res = 0;
    for (int i = 0; i < 4; ++i) {
        res <<= 8;
        res |= bytes[3 - i];
    }
    return res;
}
} // namespace

bool CAuxPow::check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const
{
    if (params.auxpow.fStrictChainId && parentBlock.GetChainId() == nChainId) {
        return false;
    }

    if (!hashBlock.IsNull() && hashBlock != parentBlock.GetHash()) {
        return false;
    }

    if (vChainMerkleBranch.size() > 30) {
        return false;
    }

    const uint256 nRootHash = CheckMerkleBranch(hashAuxBlock, vChainMerkleBranch, nChainIndex);
    std::vector<unsigned char> vchRootHash(nRootHash.begin(), nRootHash.end());
    std::reverse(vchRootHash.begin(), vchRootHash.end());

    if (!coinbaseTx || !coinbaseTx->IsCoinBase()) {
        return false;
    }

    const CScript script = coinbaseTx->vin[0].scriptSig;
    if (script.size() < MIN_COINBASE_SCRIPTSIG_SIZE || script.size() > MAX_COINBASE_SCRIPTSIG_SIZE) {
        return false;
    }

    if (nIndex != 0) {
        return false;
    }

    if (CheckMerkleBranch(coinbaseTx->GetHash(), vMerkleBranch, nIndex) != parentBlock.hashMerkleRoot) {
        return false;
    }

    const unsigned char* mmHeaderBegin = PCH_MERGED_MINING_HEADER;
    const unsigned char* mmHeaderEnd = mmHeaderBegin + sizeof(PCH_MERGED_MINING_HEADER);

    CScript::const_iterator pcHead = std::search(script.begin(), script.end(), mmHeaderBegin, mmHeaderEnd);
    CScript::const_iterator pc = std::search(script.begin(), script.end(), vchRootHash.begin(), vchRootHash.end());

    if (pc == script.end()) {
        return false;
    }

    if (pcHead != script.end()) {
        if (script.end() != std::search(pcHead + 1, script.end(), mmHeaderBegin, mmHeaderEnd)) {
            return false;
        }
        if (pcHead + sizeof(PCH_MERGED_MINING_HEADER) != pc) {
            return false;
        }
    } else if (pc - script.begin() > 20) {
        return false;
    }

    pc += vchRootHash.size();
    if (script.end() - pc < 8) {
        return false;
    }

    const uint32_t nSize = DecodeLE32(&pc[0]);
    const unsigned merkleHeight = vChainMerkleBranch.size();
    if (nSize != (1u << merkleHeight)) {
        return false;
    }

    const uint32_t nNonce = DecodeLE32(&pc[4]);
    if (nChainIndex != getExpectedIndex(nNonce, nChainId, merkleHeight)) {
        return false;
    }

    return true;
}

int CAuxPow::getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h)
{
    const uint32_t mod = (1u << h);
    uint64_t rand = nNonce;
    rand = rand * 1103515245 + 12345;
    rand %= mod;
    rand += nChainId;
    rand = rand * 1103515245 + 12345;
    rand %= mod;

    return rand;
}

uint256 CAuxPow::CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex)
{
    if (nIndex == -1) {
        return uint256();
    }

    for (const uint256& branchHash : vMerkleBranch) {
        if (nIndex & 1) {
            hash = Hash(branchHash, hash);
        } else {
            hash = Hash(hash, branchHash);
        }
        nIndex >>= 1;
    }
    return hash;
}

std::unique_ptr<CAuxPow> CAuxPow::createAuxPow(const CPureBlockHeader& header)
{
    assert(header.IsAuxpow());

    const uint256 blockHash = header.GetHash();
    std::vector<unsigned char> inputData(blockHash.begin(), blockHash.end());
    std::reverse(inputData.begin(), inputData.end());
    inputData.push_back(1);
    inputData.insert(inputData.end(), 7, 0);

    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vin[0].prevout.SetNull();
    coinbase.vin[0].scriptSig = CScript() << inputData;
    CTransactionRef coinbaseRef = MakeTransactionRef(coinbase);

    CBlock parent;
    parent.nVersion = 1;
    parent.vtx.resize(1);
    parent.vtx[0] = coinbaseRef;
    parent.hashMerkleRoot = BlockMerkleRoot(parent);

    std::unique_ptr<CAuxPow> auxpow(new CAuxPow(std::move(coinbaseRef)));
    auxpow->nIndex = 0;
    auxpow->nChainIndex = 0;
    auxpow->parentBlock = parent.GetBlockHeader();

    return auxpow;
}

CPureBlockHeader& CAuxPow::initAuxPow(CBlockHeader& header)
{
    header.SetAuxpowVersion(true);

    std::unique_ptr<CAuxPow> apow = createAuxPow(header);
    CPureBlockHeader& result = apow->parentBlock;
    header.SetAuxpow(std::move(apow));

    return result;
}
