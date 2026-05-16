// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_PUREHEADER_H
#define BITCOIN_PRIMITIVES_PUREHEADER_H

#include <serialize.h>
#include <uint256.h>

/**
 * A block header without AuxPoW payload data.
 *
 * AuxPoW stores a parent-chain block header inside the child block header.
 * Keeping that parent header as a pure header avoids a recursive dependency.
 */
class CPureBlockHeader
{
public:
    static constexpr int32_t VERSION_AUXPOW = (1 << 8);
    static constexpr int32_t VERSION_CHAIN_START = (1 << 16);

    int32_t nVersion;
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint32_t nTime;
    uint32_t nBits;
    uint32_t nNonce;

    CPureBlockHeader()
    {
        SetNull();
    }

    SERIALIZE_METHODS(CPureBlockHeader, obj)
    {
        READWRITE(obj.nVersion, obj.hashPrevBlock, obj.hashMerkleRoot, obj.nTime, obj.nBits, obj.nNonce);
    }

    void SetNull()
    {
        nVersion = 0;
        hashPrevBlock.SetNull();
        hashMerkleRoot.SetNull();
        nTime = 0;
        nBits = 0;
        nNonce = 0;
    }

    bool IsNull() const
    {
        return nBits == 0;
    }

    uint256 GetHash() const;

    uint256 GetPoWHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }

    int32_t GetBaseVersion() const
    {
        return GetBaseVersion(nVersion);
    }

    static int32_t GetBaseVersion(int32_t ver)
    {
        return ver % VERSION_AUXPOW;
    }

    void SetBaseVersion(int32_t nBaseVersion, int32_t nChainId);

    int32_t GetChainId() const
    {
        return nVersion >> 16;
    }

    void SetChainId(int32_t chainId)
    {
        nVersion %= VERSION_CHAIN_START;
        nVersion |= chainId * VERSION_CHAIN_START;
    }

    bool IsAuxpow() const
    {
        return nVersion & VERSION_AUXPOW;
    }

    void SetAuxpowVersion(bool auxpow)
    {
        if (auxpow) {
            nVersion |= VERSION_AUXPOW;
        } else {
            nVersion &= ~VERSION_AUXPOW;
        }
    }

    bool IsLegacy() const
    {
        return nVersion == 1 || (nVersion == 2 && GetChainId() == 0);
    }
};

#endif // BITCOIN_PRIMITIVES_PUREHEADER_H
