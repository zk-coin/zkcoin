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
#include <memory>

namespace {
Coin NormalizeSnapshotCoinForImport(const Coin& coin)
{
    return Coin(coin.out, /*nHeightIn=*/0, /*fCoinBaseIn=*/false, /*fPegoutIn=*/false);
}

template <typename Stream, typename DoneFn>
bool DecodeSnapshotManifestImpl(
    Stream& stream,
    DoneFn done,
    SnapshotManifestStats& stats,
    std::string& error,
    CCoinsViewCache* coins_cache = nullptr,
    const uint256* expected_base_hash = nullptr,
    const uint256* expected_import_hash = nullptr,
    const std::function<void()>& interruption_point = {})
{
    stats = SnapshotManifestStats{};
    CHashWriter manifest_hash(SER_DISK, CLIENT_VERSION);
    CHashWriter import_hash(SER_DISK, CLIENT_VERSION);
    std::unique_ptr<CCoinsViewCache> import_cache;
    if (coins_cache != nullptr) {
        import_cache.reset(new CCoinsViewCache(coins_cache));
        import_cache->SetBestBlock(coins_cache->GetBestBlock());
    }

    try {
        stream >> stats.m_metadata;
        manifest_hash << stats.m_metadata;
        import_hash << stats.m_metadata;

        while (!done()) {
            if (interruption_point && stats.m_coins_count % 5000 == 0) {
                interruption_point();
            }

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
            import_hash << outpoint;
            Coin normalized_coin = NormalizeSnapshotCoinForImport(coin);
            import_hash << normalized_coin;
            if (import_cache) {
                if (import_cache->HaveCoin(outpoint)) {
                    error = strprintf("snapshot outpoint already exists in chainstate: %s", outpoint.ToString());
                    return false;
                }
                import_cache->AddCoin(outpoint, std::move(normalized_coin), /*possible_overwrite=*/false);
            }
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
    stats.m_hash_import = import_hash.GetHash();
    if (expected_base_hash != nullptr && stats.m_metadata.m_base_blockhash != *expected_base_hash) {
        error = strprintf("snapshot base hash mismatch: expected=%s actual=%s", expected_base_hash->ToString(), stats.m_metadata.m_base_blockhash.ToString());
        return false;
    }
    if (expected_import_hash != nullptr && stats.m_hash_import != *expected_import_hash) {
        error = strprintf("snapshot import hash mismatch: expected=%s actual=%s", expected_import_hash->ToString(), stats.m_hash_import.ToString());
        return false;
    }
    if (import_cache && !import_cache->Flush()) {
        error = "failed to flush snapshot import into coins cache";
        return false;
    }
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

bool ImportSnapshotManifest(CDataStream& stream, CCoinsViewCache& coins_cache, SnapshotManifestStats& stats, std::string& error, const uint256* expected_base_hash, const uint256* expected_import_hash, const std::function<void()>& interruption_point)
{
    return DecodeSnapshotManifestImpl(stream, [&stream]() { return stream.empty(); }, stats, error, &coins_cache, expected_base_hash, expected_import_hash, interruption_point);
}

bool ImportSnapshotManifestFromFile(const fs::path& path, CCoinsViewCache& coins_cache, SnapshotManifestStats& stats, std::string& error, const uint256* expected_base_hash, const uint256* expected_import_hash, const std::function<void()>& interruption_point)
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

    return DecodeSnapshotManifestImpl(stream, done, stats, error, &coins_cache, expected_base_hash, expected_import_hash, interruption_point);
}
