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

static Coin SnapshotCoin(CAmount value, int height)
{
    CScript script;
    script << OP_TRUE;
    return Coin(CTxOut(value, script), height, false, false);
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
    const SnapshotMetadata metadata{uint256S("01"), 2, 100};
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {COutPoint(uint256S("02"), 0), SnapshotCoin(1 * COIN, 10)},
        {COutPoint(uint256S("03"), 1), SnapshotCoin(2 * COIN, 11)},
    };

    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_REQUIRE(DecodeSnapshotManifest(stream, stats, error));
    BOOST_CHECK(error.empty());
    BOOST_CHECK(stats.m_metadata.m_base_blockhash == metadata.m_base_blockhash);
    BOOST_CHECK_EQUAL(stats.m_coins_count, 2U);
    BOOST_CHECK_EQUAL(stats.m_total_amount, 3 * COIN);
    BOOST_CHECK(!stats.m_hash_serialized.IsNull());

    CDataStream stream_again = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats_again;
    BOOST_REQUIRE(DecodeSnapshotManifest(stream_again, stats_again, error));
    BOOST_CHECK(stats_again.m_hash_serialized == stats.m_hash_serialized);

    std::vector<std::pair<COutPoint, Coin>> changed_coins = coins;
    changed_coins[1].second = SnapshotCoin(3 * COIN, 11);
    CDataStream changed_stream = BuildSnapshotStream(metadata, changed_coins);
    SnapshotManifestStats changed_stats;
    BOOST_REQUIRE(DecodeSnapshotManifest(changed_stream, changed_stats, error));
    BOOST_CHECK(changed_stats.m_hash_serialized != stats.m_hash_serialized);
}

BOOST_AUTO_TEST_CASE(snapshot_manifest_rejects_count_mismatch)
{
    const SnapshotMetadata metadata{uint256S("04"), 2, 100};
    const std::vector<std::pair<COutPoint, Coin>> coins{
        {COutPoint(uint256S("05"), 0), SnapshotCoin(1 * COIN, 10)},
    };

    CDataStream stream = BuildSnapshotStream(metadata, coins);
    SnapshotManifestStats stats;
    std::string error;

    BOOST_CHECK(!DecodeSnapshotManifest(stream, stats, error));
    BOOST_CHECK(error.find("coin count mismatch") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
