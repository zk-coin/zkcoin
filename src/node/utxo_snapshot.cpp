// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/utxo_snapshot.h>

#include <clientversion.h>
#include <coins.h>
#include <hash.h>
#include <tinyformat.h>

#include <cstdio>
#include <exception>

namespace {
template <typename Stream, typename DoneFn>
bool DecodeSnapshotManifestImpl(Stream& stream, DoneFn done, SnapshotManifestStats& stats, std::string& error)
{
    stats = SnapshotManifestStats{};
    CHashWriter manifest_hash(SER_DISK, CLIENT_VERSION);

    try {
        stream >> stats.m_metadata;
        manifest_hash << stats.m_metadata;

        while (!done()) {
            COutPoint outpoint;
            Coin coin;
            stream >> outpoint;
            stream >> coin;

            if (coin.IsSpent()) {
                error = strprintf("snapshot contains spent coin for %s", outpoint.ToString());
                return false;
            }

            if (!MoneyRange(coin.out.nValue) || !MoneyRange(stats.m_total_amount + coin.out.nValue)) {
                error = strprintf("snapshot amount out of range at %s", outpoint.ToString());
                return false;
            }

            manifest_hash << outpoint;
            manifest_hash << coin;
            ++stats.m_coins_count;
            stats.m_total_amount += coin.out.nValue;
        }
    } catch (const std::exception& e) {
        error = strprintf("snapshot decode failed: %s", e.what());
        return false;
    }

    if (stats.m_coins_count != stats.m_metadata.m_coins_count) {
        error = strprintf("snapshot coin count mismatch: metadata=%u decoded=%u", stats.m_metadata.m_coins_count, stats.m_coins_count);
        return false;
    }

    stats.m_hash_serialized = manifest_hash.GetHash();
    return true;
}
} // namespace

bool DecodeSnapshotManifest(CDataStream& stream, SnapshotManifestStats& stats, std::string& error)
{
    return DecodeSnapshotManifestImpl(stream, [&stream]() { return stream.empty(); }, stats, error);
}

bool ReadSnapshotManifestFromFile(const fs::path& path, SnapshotManifestStats& stats, std::string& error)
{
    uintmax_t file_size{0};
    try {
        file_size = fs::file_size(path);
    } catch (const fs::filesystem_error& e) {
        error = strprintf("unable to stat snapshot file %s: %s", path.string(), e.what());
        return false;
    }

    FILE* file{fsbridge::fopen(path, "rb")};
    if (file == nullptr) {
        error = strprintf("unable to open snapshot file %s", path.string());
        return false;
    }

    CAutoFile stream{file, SER_DISK, CLIENT_VERSION};
    auto done = [&stream, file_size]() {
        const long pos = std::ftell(stream.Get());
        if (pos < 0) {
            throw std::ios_base::failure("ftell failed while reading snapshot file");
        }
        return static_cast<uintmax_t>(pos) >= file_size;
    };

    return DecodeSnapshotManifestImpl(stream, done, stats, error);
}
