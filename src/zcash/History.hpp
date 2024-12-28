// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .    

#ifndef ZC_HISTORY_H_
#define ZC_HISTORY_H_

#include <stdexcept>
#include <unordered_map> 
#include <boost/foreach.hpp>
#include <array>
#include <cstdint>

#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "librustzcash.h"

// Use constexpr for constants for better type safety and compile-time evaluation
constexpr size_t NODE_V1_SERIALIZED_LENGTH = 171;
constexpr size_t NODE_SERIALIZED_LENGTH = 244;
constexpr size_t ENTRY_SERIALIZED_LENGTH = NODE_SERIALIZED_LENGTH + 9;

using HistoryNode = std::array<unsigned char, NODE_SERIALIZED_LENGTH>;
using HistoryEntry = std::array<unsigned char, ENTRY_SERIALIZED_LENGTH>;

namespace libzcash {

// Renamed to CamelCase for consistency with naming conventions
using HistoryIndex = uint64_t;

class HistoryCache {
public:
    // Updates to the persistent(db) layer
    std::unordered_map<HistoryIndex, HistoryNode> appends;
    // Current length of the history
    HistoryIndex length{0};
    // Depth into the old state for current updates
    HistoryIndex updateDepth{0};
    // Current root of the history
    uint256 root{};
    // Current epoch of this history state
    uint32_t epoch{0};

    // Constructor with default initialization
    HistoryCache(HistoryIndex initialLength = 0, const uint256& initialRoot = uint256(), uint32_t initialEpoch = 0)
        : length(initialLength), updateDepth(initialLength), root(initialRoot), epoch(initialEpoch) {}

    // Extend current history update by one history node.
    void Extend(const HistoryNode& leaf);

    // Truncate history to the new length.
    void Truncate(HistoryIndex newLength);
};

// V1 history node creation with metadata based on block state
HistoryNode NewV1Leaf(
    const uint256& commitment,
    uint32_t time,
    uint32_t target,
    const uint256& saplingRoot,
    const uint256& totalWork,
    uint64_t height,
    uint64_t saplingTxCount
);

// V2 history node creation with metadata based on block state
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
);

// Convert history node to tree node (with children references)
HistoryEntry NodeToEntry(const HistoryNode& node, uint32_t left, uint32_t right);

// Convert history node to leaf node (end nodes without children)
HistoryEntry LeafToEntry(const HistoryNode& node);

// Returns true if this epoch used the V1 history tree format.
bool IsV1HistoryTree(uint32_t epochId);

} // namespace libzcash

// Type aliases for external usage
using HistoryCache = libzcash::HistoryCache;
using HistoryIndex = libzcash::HistoryIndex;

#endif /* ZC_HISTORY_H_ */
