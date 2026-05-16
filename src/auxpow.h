// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_AUXPOW_H
#define BITCOIN_AUXPOW_H

#include <consensus/params.h>
#include <primitives/pureheader.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <uint256.h>

#include <memory>
#include <vector>

class CBlockHeader;

static constexpr unsigned char PCH_MERGED_MINING_HEADER[] = {0xfa, 0xbe, 'm', 'm'};

/**
 * AuxPoW proof data that commits a child-chain block header into a parent-chain
 * coinbase transaction and stores the mined parent-chain header.
 */
class CAuxPow
{
private:
    CTransactionRef coinbaseTx;
    std::vector<uint256> vMerkleBranch;
    std::vector<uint256> vChainMerkleBranch;
    int nChainIndex{0};
    CPureBlockHeader parentBlock;

    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);

public:
    explicit CAuxPow(CTransactionRef&& txIn) : coinbaseTx(std::move(txIn)) {}
    CAuxPow() = default;

    CAuxPow(CAuxPow&&) = default;
    CAuxPow& operator=(CAuxPow&&) = default;

    CAuxPow(const CAuxPow&) = delete;
    CAuxPow& operator=(const CAuxPow&) = delete;

    SERIALIZE_METHODS(CAuxPow, obj)
    {
        uint256 hashBlock;
        int nIndex = 0;

        READWRITE(obj.coinbaseTx, hashBlock, obj.vMerkleBranch, nIndex);
        READWRITE(obj.vChainMerkleBranch, obj.nChainIndex, obj.parentBlock);
    }

    bool check(const uint256& hashAuxBlock, int nChainId, const Consensus::Params& params) const;

    uint256 getParentBlockHash() const
    {
        return parentBlock.GetHash();
    }

    uint256 getParentBlockPoWHash() const
    {
        return parentBlock.GetPoWHash();
    }

    const CPureBlockHeader& getParentBlock() const
    {
        return parentBlock;
    }

    static int getExpectedIndex(uint32_t nNonce, int nChainId, unsigned h);

    static std::unique_ptr<CAuxPow> createAuxPow(const CPureBlockHeader& header);

    static CPureBlockHeader& initAuxPow(CBlockHeader& header);
};

#endif // BITCOIN_AUXPOW_H
