// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash/History.hpp"

#include <stdexcept>
#include <vector>
#include <cstring> // For memcpy

#include "consensus/upgrades.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "librustzcash.h"

namespace libzcash {

void HistoryCache::Extend(const HistoryNode& leaf) {
    appends[length++] = leaf;
}

void HistoryCache::Truncate(HistoryIndex newLength) {
    if (newLength > 0) {
        for (HistoryIndex idx = length; idx >= newLength; idx--) {
            appends.erase(idx);
        }
    } else {
        appends.clear();
    }

    length = newLength;
    if (updateDepth > length) updateDepth = length;
}

HistoryNode NewNode(
    const uint256& subtreeCommitment,
    uint32_t startTime,
    uint32_t endTime,
    uint32_t startTarget,
    uint32_t endTarget,
    const uint256& startSaplingRoot,
    const uint256& endSaplingRoot,
    const std::optional<uint256>& startOrchardRoot,
    const std::optional<uint256>& endOrchardRoot,
    const uint256& subtreeTotalWork,
    uint64_t startHeight,
    uint64_t endHeight,
    uint64_t saplingTxCount,
    const std::optional<uint64_t>& orchardTxCount
) {
    std::vector<uint8_t> buffer;
    buffer.reserve(NODE_SERIALIZED_LENGTH);

    auto serialize_uint256 = [&](const uint256& value) {
        buffer.insert(buffer.end(), value.begin(), value.end());
    };

    serialize_uint256(subtreeCommitment);
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&startTime), reinterpret_cast<const uint8_t*>(&startTime) + sizeof(startTime));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&endTime), reinterpret_cast<const uint8_t*>(&endTime) + sizeof(endTime));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&startTarget), reinterpret_cast<const uint8_t*>(&startTarget) + sizeof(startTarget));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&endTarget), reinterpret_cast<const uint8_t*>(&endTarget) + sizeof(endTarget));
    serialize_uint256(startSaplingRoot);
    serialize_uint256(endSaplingRoot);
    serialize_uint256(subtreeTotalWork);

    auto serialize_compact_size = [&](uint64_t value) {
        CDataStream tempBuf(SER_DISK, 0);
        tempBuf << COMPACTSIZE(value);
        buffer.insert(buffer.end(), tempBuf.begin(), tempBuf.end());
    };

    serialize_compact_size(startHeight);
    serialize_compact_size(endHeight);
    serialize_compact_size(saplingTxCount);

    if (startOrchardRoot) {
        serialize_uint256(*startOrchardRoot);
        serialize_uint256(*endOrchardRoot);
        serialize_compact_size(*orchardTxCount);
    }

    assert(buffer.size() <= NODE_SERIALIZED_LENGTH);

    HistoryNode result{};
    std::memcpy(result.data(), buffer.data(), buffer.size());
    return result;
}

HistoryNode NewV1Leaf(
    const uint256& commitment,
    uint32_t time,
    uint32_t target,
    const uint256& saplingRoot,
    const uint256& totalWork,
    uint64_t height,
    uint64_t saplingTxCount
) {
    return NewNode(
        commitment,
        time,
        time,
        target,
        target,
        saplingRoot,
        saplingRoot,
        std::nullopt,
        std::nullopt,
        totalWork,
        height,
        height,
        saplingTxCount,
        std::nullopt
    );
}

HistoryNode NewV2Leaf(
    const uint256& commitment,
    uint32_t time,
    uint32_t target,
    const uint256& saplingRoot,
    const uint256& orchardRoot,
    const uint256& totalWork,
    uint64_t height,
    uint64_t saplingTxCount,
    uint64_t orchardTxCount
) {
    return NewNode(
        commitment,
        time,
        time,
        target,
        target,
        saplingRoot,
        saplingRoot,
        orchardRoot,
        orchardRoot,
        totalWork,
        height,
        height,
        saplingTxCount,
        orchardTxCount
    );
}

HistoryEntry NodeToEntry(const HistoryNode& node, uint32_t left, uint32_t right) {
    std::vector<uint8_t> buffer;
    buffer.reserve(ENTRY_SERIALIZED_LENGTH);

    buffer.push_back(0); // code for node entry
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&left), reinterpret_cast<const uint8_t*>(&left) + sizeof(left));
    buffer.insert(buffer.end(), reinterpret_cast<const uint8_t*>(&right), reinterpret_cast<const uint8_t*>(&right) + sizeof(right));
    buffer.insert(buffer.end(), node.begin(), node.end());

    assert(buffer.size() <= ENTRY_SERIALIZED_LENGTH);

    HistoryEntry result{};
    std::memcpy(result.data(), buffer.data(), buffer.size());
    return result;
}

HistoryEntry LeafToEntry(const HistoryNode& node) {
    std::vector<uint8_t> buffer;
    buffer.reserve(ENTRY_SERIALIZED_LENGTH);

    buffer.push_back(1); // code for leaf entry
    buffer.insert(buffer.end(), node.begin(), node.end());

    assert(buffer.size() <= ENTRY_SERIALIZED_LENGTH);

    HistoryEntry result{};
    std::memcpy(result.data(), buffer.data(), buffer.size());
    return result;
}

bool IsV1HistoryTree(uint32_t epochId) {
    static const std::unordered_set<uint32_t> v1Branches = {
        NetworkUpgradeInfo[Consensus::BASE_SPROUT].nBranchId,
        NetworkUpgradeInfo[Consensus::UPGRADE_OVERWINTER].nBranchId,
        NetworkUpgradeInfo[Consensus::UPGRADE_SAPLING].nBranchId
    };

    return v1Branches.count(epochId) > 0;
}

} // namespace libzcash


