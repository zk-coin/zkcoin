// Copyright (c) 2026 The zkCoin developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <amount.h>
#include <clientversion.h>
#include <coins.h>
#include <node/utxo_snapshot.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <streams.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(utxo_snapshot_tests)

static Coin SnapshotCoin(CAmount value, int height, bool coinbase = false)
{
    CScript script;
    script << OP_TRUE;
    return Coin(CTxOut(value, script), height, coinbase, false);
}

static CDataStream BuildSnapshotStream(const SnapshotMetadata& metadata, const std::vector<std::pair<COutPoint, Coin>>& coins)
{
    CDataStream stream(SER_DISK, CLIENT_VERSION);
    stream << metadata;
    for (const auto& coin : coins) {
        stream << coin.first;
        stream << coin.second;
    }
    return stream;
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_decodes_and_hashes)
{
    const SnapshotMetadata metadata{100, uint256S("01"), 2, 100};
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {COutPoint(uint256S("02"), 0), SnapshotCoin(1 * COIN, 10)},
        {COutPoint(uint256S("03"), 1), SnapshotCoin(2 * COIN, 11)},
    };

    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_REQUIRE(DecodeSnapshotManifest(stream, stats, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(stats.m_metadata.m_base_height, metadata.m_base_height);
    BOOST_CHECK(stats.m_metadata.m_base_blockhash == metadata.m_base_blockhash);
    BOOST_CHECK_EQUAL(stats.m_coins_count, 2U);
    BOOST_CHECK_EQUAL(stats.m_total_amount, 3 * COIN);
    BOOST_CHECK(!stats.m_hash_serialized.IsNull());
    BOOST_CHECK(!stats.m_hash_import.IsNull());

    CDataStream stream_again = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats_again;
    BOOST_REQUIRE(DecodeSnapshotManifest(stream_again, stats_again, error));
    BOOST_CHECK(stats_again.m_hash_serialized == stats.m_hash_serialized);
    BOOST_CHECK(stats_again.m_hash_import == stats.m_hash_import);

    std::vector<std::pair<COutPoint, Coin>> remapped_metadata_coins = coins;
    remapped_metadata_coins[0].second = SnapshotCoin(1 * COIN, 900, true);
    CDataStream remapped_metadata_stream = BuildSnapshotStream(metadata, remapped_metadata_coins);
    SnapshotManifestStats remapped_metadata_stats;
    BOOST_REQUIRE(DecodeSnapshotManifest(remapped_metadata_stream, remapped_metadata_stats, error));
    BOOST_CHECK(remapped_metadata_stats.m_hash_serialized != stats.m_hash_serialized);
    BOOST_CHECK(remapped_metadata_stats.m_hash_import == stats.m_hash_import);

    std::vector<std::pair<COutPoint, Coin>> changed_coins = coins;
    changed_coins[1].second = SnapshotCoin(3 * COIN, 11);
    CDataStream changed_stream = BuildSnapshotStream(metadata, changed_coins);
    SnapshotManifestStats changed_stats;
    BOOST_REQUIRE(DecodeSnapshotManifest(changed_stream, changed_stats, error));
    BOOST_CHECK(changed_stats.m_hash_serialized != stats.m_hash_serialized);
    BOOST_CHECK(changed_stats.m_hash_import != stats.m_hash_import);
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_rejects_count_mismatch)
{
    const SnapshotMetadata metadata{100, uint256S("04"), 2, 100};
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {COutPoint(uint256S("05"), 0), SnapshotCoin(1 * COIN, 10)},
    };

    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_CHECK(!DecodeSnapshotManifest(stream, stats, error));
    BOOST_CHECK(error.find("coin count mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_normalizes_chain_metadata)
{
    const SnapshotMetadata metadata{100, uint256S("06"), 1, 100};
    const COutPoint outpoint(uint256S("07"), 0);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {outpoint, SnapshotCoin(5 * COIN, 600, true)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    const uint256 chainstate_base = uint256S("0a");
    cache.SetBestBlock(chainstate_base);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_REQUIRE(ImportSnapshotManifest(stream, cache, stats, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(stats.m_coins_count, 1U);
    BOOST_CHECK_EQUAL(stats.m_total_amount, 5 * COIN);

    Coin imported;
    BOOST_REQUIRE(cache.GetCoin(outpoint, imported));
    BOOST_CHECK_EQUAL(imported.out.nValue, 5 * COIN);
    BOOST_CHECK_EQUAL(imported.nHeight, LTC_SNAPSHOT_IMPORT_COIN_HEIGHT);
    BOOST_CHECK(!imported.IsCoinBase());
    BOOST_CHECK(!imported.IsPegout());
    BOOST_CHECK_EQUAL(cache.GetBestBlock().ToString(), chainstate_base.ToString());
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_rejects_duplicate_without_resume)
{
    const SnapshotMetadata metadata{100, uint256S("0d"), 1, 100};
    const COutPoint outpoint(uint256S("0e"), 0);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {outpoint, SnapshotCoin(5 * COIN, 600, true)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    cache.AddCoin(outpoint, SnapshotCoin(5 * COIN, 0), /*possible_overwrite=*/false);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_CHECK(!ImportSnapshotManifest(stream, cache, stats, error));
    BOOST_CHECK(error.find("snapshot outpoint already exists") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_resumes_identical_existing_coin)
{
    const SnapshotMetadata metadata{100, uint256S("0f"), 2, 100};
    const COutPoint existing_outpoint(uint256S("10"), 0);
    const COutPoint new_outpoint(uint256S("11"), 1);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {existing_outpoint, SnapshotCoin(5 * COIN, 600, true)},
        {new_outpoint, SnapshotCoin(7 * COIN, 601, true)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    cache.AddCoin(existing_outpoint, SnapshotCoin(5 * COIN, LTC_SNAPSHOT_IMPORT_COIN_HEIGHT), /*possible_overwrite=*/false);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_REQUIRE(ImportSnapshotManifest(stream, cache, stats, error, nullptr, nullptr, nullptr, {}, /*resume_import=*/true));
    BOOST_CHECK(error.empty());
    BOOST_CHECK_EQUAL(stats.m_coins_count, 2U);

    Coin existing;
    BOOST_REQUIRE(cache.GetCoin(existing_outpoint, existing));
    BOOST_CHECK_EQUAL(existing.out.nValue, 5 * COIN);
    BOOST_CHECK_EQUAL(existing.nHeight, LTC_SNAPSHOT_IMPORT_COIN_HEIGHT);
    BOOST_CHECK(!existing.IsCoinBase());

    Coin imported;
    BOOST_REQUIRE(cache.GetCoin(new_outpoint, imported));
    BOOST_CHECK_EQUAL(imported.out.nValue, 7 * COIN);
    BOOST_CHECK_EQUAL(imported.nHeight, LTC_SNAPSHOT_IMPORT_COIN_HEIGHT);
    BOOST_CHECK(!imported.IsCoinBase());
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_resume_rejects_mismatched_existing_coin)
{
    const SnapshotMetadata metadata{100, uint256S("12"), 1, 100};
    const COutPoint outpoint(uint256S("13"), 0);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {outpoint, SnapshotCoin(5 * COIN, 600, true)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    cache.AddCoin(outpoint, SnapshotCoin(6 * COIN, 0), /*possible_overwrite=*/false);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_CHECK(!ImportSnapshotManifest(stream, cache, stats, error, nullptr, nullptr, nullptr, {}, /*resume_import=*/true));
    BOOST_CHECK(error.find("snapshot outpoint already exists") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_rejects_wrong_expected_hash)
{
    const SnapshotMetadata metadata{100, uint256S("08"), 1, 100};
    const COutPoint outpoint(uint256S("09"), 0);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {outpoint, SnapshotCoin(1 * COIN, 10)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;
    const uint256 wrong_import_hash = uint256S("0a");

    BOOST_CHECK(!ImportSnapshotManifest(stream, cache, stats, error, nullptr, nullptr, &wrong_import_hash));
    BOOST_CHECK(error.find("import hash mismatch") != std::string::npos);

    Coin imported;
    BOOST_CHECK(!cache.GetCoin(outpoint, imported));
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_import_rejects_wrong_expected_height)
{
    const SnapshotMetadata metadata{100, uint256S("0b"), 1, 100};
    const COutPoint outpoint(uint256S("0c"), 0);
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {outpoint, SnapshotCoin(1 * COIN, 10)},
    };

    CCoinsView base;
    CCoinsViewCache cache(&base);
    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;
    const int wrong_height = 101;

    BOOST_CHECK(!ImportSnapshotManifest(stream, cache, stats, error, &wrong_height, &metadata.m_base_blockhash, nullptr));
    BOOST_CHECK(error.find("base height mismatch") != std::string::npos);

    Coin imported;
    BOOST_CHECK(!cache.GetCoin(outpoint, imported));
}

BOOST_AUTO_TEST_SUITE_END()
