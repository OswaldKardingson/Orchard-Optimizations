// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZC_INCREMENTALMERKLETREE_H_
#define ZC_INCREMENTALMERKLETREE_H_

#include <array>
#include <vector>
#include <optional>
#include <cassert>

#include "uint256.h"
#include "serialize.h"
#include "streams_rust.h"

#include "Zcash.h"
#include "zcash/util.h"

#include "rust/bridge.h"
#include "rust/sapling/wallet.h"
#include "primitives/sapling.h"
#include "primitives/orchard.h"

namespace libzcash {

using SubtreeIndex = uint64_t;
using SubtreeRoot = std::array<uint8_t, 32>;
constexpr uint8_t TRACKED_SUBTREE_HEIGHT = 16;

class LatestSubtree {
public:
    uint8_t leadbyte = 0x00;
    SubtreeIndex index;
    SubtreeRoot root;
    int nHeight;

    LatestSubtree() : index(0), root{}, nHeight(0) {}

    LatestSubtree(SubtreeIndex idx, SubtreeRoot rt, int height)
        : index(idx), root(rt), nHeight(height) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(leadbyte);
        READWRITE(index);
        READWRITE(root);
        READWRITE(nHeight);
    }
};

class SubtreeData {
public:
    uint8_t leadbyte = 0x00;
    SubtreeRoot root;
    int nHeight;

    SubtreeData() : root{}, nHeight(0) {}

    SubtreeData(SubtreeRoot rt, int height)
        : root(rt), nHeight(height) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(leadbyte);
        READWRITE(root);
        READWRITE(nHeight);
    }
};

class MerklePath {
public:
    std::vector<std::vector<bool>> authentication_path;
    std::vector<bool> index;

    MerklePath() = default;

    MerklePath(std::vector<std::vector<bool>> auth_path, std::vector<bool> idx)
        : authentication_path(std::move(auth_path)), index(std::move(idx)) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::vector<std::vector<unsigned char>> pathBytes;
        uint64_t indexInt;
        if (ser_action.ForRead()) {
            READWRITE(pathBytes);
            READWRITE(indexInt);
            authentication_path.clear();
            index.clear();

            for (size_t i = 0; i < pathBytes.size(); ++i) {
                authentication_path.emplace_back(convertBytesVectorToVector(pathBytes[i]));
                index.push_back((indexInt >> ((pathBytes.size() - 1) - i)) & 1);
            }
        } else {
            assert(authentication_path.size() == index.size());
            pathBytes.resize(authentication_path.size());
            for (size_t i = 0; i < authentication_path.size(); ++i) {
                auto& pathVec = authentication_path[i];
                pathBytes[i].resize((pathVec.size() + 7) / 8);
                for (size_t p = 0; p < pathVec.size(); ++p) {
                    pathBytes[i][p / 8] |= pathVec[p] << (7 - (p % 8));
                }
            }
            indexInt = convertVectorToInt(index);
            READWRITE(pathBytes);
            READWRITE(indexInt);
        }
    }

    uint64_t position() const { return convertVectorToInt(index); }
};

} // namespace libzcash

#endif // ZC_INCREMENTALMERKLETREE_H_

namespace libzcash {

template <size_t Depth, typename Hash>
class EmptyMerkleRoots {
public:
    EmptyMerkleRoots() {
        empty_roots[0] = Hash::uncommitted();
        for (size_t d = 1; d <= Depth; ++d) {
            empty_roots[d] = Hash::combine(empty_roots[d - 1], empty_roots[d - 1], d - 1);
        }
    }

    Hash empty_root(size_t depth) const {
        assert(depth <= Depth);
        return empty_roots[depth];
    }

    template <size_t D, typename H>
    friend bool operator==(const EmptyMerkleRoots<D, H>& a, const EmptyMerkleRoots<D, H>& b);

private:
    std::array<Hash, Depth + 1> empty_roots;
};

template <size_t Depth, typename Hash>
bool operator==(const EmptyMerkleRoots<Depth, Hash>& a, const EmptyMerkleRoots<Depth, Hash>& b) {
    return a.empty_roots == b.empty_roots;
}

template <size_t Depth, typename Hash>
class IncrementalWitness;

template <size_t Depth, typename Hash>
class IncrementalMerkleTree {
    friend class IncrementalWitness<Depth, Hash>;

public:
    static_assert(Depth >= 1, "Depth must be at least 1");

    IncrementalMerkleTree() = default;

    size_t DynamicMemoryUsage() const {
        return sizeof(left) + sizeof(right) + (parents.size() * sizeof(Hash));
    }

    size_t size() const;
    SubtreeIndex current_subtree_index() const;
    std::optional<Hash> complete_subtree_root() const;

    void append(const Hash& obj);
    Hash root() const {
        return root(Depth, std::deque<Hash>{});
    }
    Hash last() const;

    IncrementalWitness<Depth, Hash> witness() const {
        return IncrementalWitness<Depth, Hash>(*this);
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(left);
        READWRITE(right);
        READWRITE(parents);
        wfcheck();
    }

    static Hash empty_root() {
        return emptyroots.empty_root(Depth);
    }

    template <size_t D, typename H>
    friend bool operator==(const IncrementalMerkleTree<D, H>& a,
                           const IncrementalMerkleTree<D, H>& b);

private:
    static EmptyMerkleRoots<Depth, Hash> emptyroots;
    std::optional<Hash> left;
    std::optional<Hash> right;
    std::vector<std::optional<Hash>> parents;

    MerklePath path(std::deque<Hash> filler_hashes = {}) const;
    Hash root(size_t depth, std::deque<Hash> filler_hashes = {}) const;
    bool is_complete(size_t depth = Depth) const;
    size_t next_depth(size_t skip) const;
    void wfcheck() const;
};

template <size_t Depth, typename Hash>
bool operator==(const IncrementalMerkleTree<Depth, Hash>& a,
                const IncrementalMerkleTree<Depth, Hash>& b) {
    return (a.emptyroots == b.emptyroots &&
            a.left == b.left &&
            a.right == b.right &&
            a.parents == b.parents);
}

} // namespace libzcash

namespace libzcash {

template <size_t Depth, typename Hash>
class IncrementalWitness {
    friend class IncrementalMerkleTree<Depth, Hash>;

public:
    IncrementalWitness() = default;

    MerklePath path() const {
        return tree.path(partial_path());
    }

    Hash element() const {
        return tree.last();
    }

    uint64_t position() const {
        return tree.size() - 1;
    }

    Hash root() const {
        return tree.root(Depth, partial_path());
    }

    void append(const Hash& obj);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(tree);
        READWRITE(filled);
        READWRITE(cursor);

        cursor_depth = tree.next_depth(filled.size());
    }

    template <size_t D, typename H>
    friend bool operator==(const IncrementalWitness<D, H>& a,
                           const IncrementalWitness<D, H>& b);

private:
    IncrementalMerkleTree<Depth, Hash> tree;
    std::vector<Hash> filled;
    std::optional<IncrementalMerkleTree<Depth, Hash>> cursor;
    size_t cursor_depth = 0;

    std::deque<Hash> partial_path() const;
    IncrementalWitness(const IncrementalMerkleTree<Depth, Hash>& tree) : tree(tree) {}
};

template <size_t Depth, typename Hash>
bool operator==(const IncrementalWitness<Depth, Hash>& a,
                const IncrementalWitness<Depth, Hash>& b) {
    return (a.tree == b.tree &&
            a.filled == b.filled &&
            a.cursor == b.cursor &&
            a.cursor_depth == b.cursor_depth);
}

class SHA256Compress : public uint256 {
public:
    SHA256Compress() = default;
    explicit SHA256Compress(uint256 contents) : uint256(std::move(contents)) {}

    static SHA256Compress combine(
        const SHA256Compress& a,
        const SHA256Compress& b,
        size_t depth
    );

    static SHA256Compress uncommitted() {
        return SHA256Compress();
    }
};

class PedersenHash : public uint256 {
public:
    PedersenHash() = default;
    explicit PedersenHash(uint256 contents) : uint256(std::move(contents)) {}

    static PedersenHash combine(
        const PedersenHash& a,
        const PedersenHash& b,
        size_t depth
    );

    static PedersenHash uncommitted();
};

template <size_t Depth, typename Hash>
EmptyMerkleRoots<Depth, Hash> IncrementalMerkleTree<Depth, Hash>::emptyroots;

} // namespace libzcash

// Typedefs for specific IncrementalMerkleTree and IncrementalWitness configurations.
typedef libzcash::IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH, libzcash::SHA256Compress> SproutMerkleTree;
typedef libzcash::IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libzcash::SHA256Compress> SproutTestingMerkleTree;

typedef libzcash::IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH, libzcash::SHA256Compress> SproutWitness;
typedef libzcash::IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libzcash::SHA256Compress> SproutTestingWitness;

typedef libzcash::IncrementalMerkleTree<SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, libzcash::PedersenHash> SaplingMerkleTree;
typedef libzcash::IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libzcash::PedersenHash> SaplingTestingMerkleTree;

typedef libzcash::IncrementalWitness<SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, libzcash::PedersenHash> SaplingWitness;
typedef libzcash::IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, libzcash::PedersenHash> SaplingTestingWitness;

} // namespace libzcash

class SaplingMerkleFrontier {
private:
    rust::Box<merkle_frontier::SaplingFrontier> inner;

    friend class SaplingWallet;
    friend class SaplingMerkleFrontierLegacySer;

public:
    SaplingMerkleFrontier() : inner(merkle_frontier::new_sapling()) {}

    SaplingMerkleFrontier(SaplingMerkleFrontier&& frontier) noexcept : inner(std::move(frontier.inner)) {}

    SaplingMerkleFrontier(const SaplingMerkleFrontier& frontier)
        : inner(frontier.inner->box_clone()) {}

    SaplingMerkleFrontier& operator=(SaplingMerkleFrontier&& frontier) noexcept {
        if (this != &frontier) {
            inner = std::move(frontier.inner);
        }
        return *this;
    }

    SaplingMerkleFrontier& operator=(const SaplingMerkleFrontier& frontier) {
        if (this != &frontier) {
            inner = frontier.inner->box_clone();
        }
        return *this;
    }

    template <typename Stream>
    void Serialize(Stream& s) const {
        try {
            inner->serialize(*ToRustStream(s));
        } catch (const std::exception& e) {
            throw std::ios_base::failure(e.what());
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        try {
            inner = merkle_frontier::parse_sapling(*ToRustStream(s));
        } catch (const std::exception& e) {
            throw std::ios_base::failure(e.what());
        }
    }

    size_t DynamicMemoryUsage() const {
        return inner->dynamic_memory_usage();
    }

    merkle_frontier::SaplingAppendResult AppendBundle(const SaplingBundle& bundle) {
        return inner->append_bundle(bundle.GetDetails());
    }

    uint256 root() const {
        return uint256::FromRawBytes(inner->root());
    }

    static uint256 empty_root() {
        return uint256::FromRawBytes(merkle_frontier::sapling_empty_root());
    }

    size_t size() const {
        return inner->size();
    }

    libzcash::SubtreeIndex current_subtree_index() const {
        return (inner->size() >> libzcash::TRACKED_SUBTREE_HEIGHT);
    }
};

class OrchardMerkleFrontier {
private:
    rust::Box<merkle_frontier::OrchardFrontier> inner;

    friend class OrchardWallet;
    friend class OrchardMerkleFrontierLegacySer;

public:
    OrchardMerkleFrontier() : inner(merkle_frontier::new_orchard()) {}

    OrchardMerkleFrontier(OrchardMerkleFrontier&& frontier) noexcept : inner(std::move(frontier.inner)) {}

    OrchardMerkleFrontier(const OrchardMerkleFrontier& frontier)
        : inner(frontier.inner->box_clone()) {}

    OrchardMerkleFrontier& operator=(OrchardMerkleFrontier&& frontier) noexcept {
        if (this != &frontier) {
            inner = std::move(frontier.inner);
        }
        return *this;
    }

    OrchardMerkleFrontier& operator=(const OrchardMerkleFrontier& frontier) {
        if (this != &frontier) {
            inner = frontier.inner->box_clone();
        }
        return *this;
    }

    template <typename Stream>
    void Serialize(Stream& s) const {
        try {
            inner->serialize(*ToRustStream(s));
        } catch (const std::exception& e) {
            throw std::ios_base::failure(e.what());
        }
    }

    template <typename Stream>
    void Unserialize(Stream& s) {
        try {
            inner = merkle_frontier::parse_orchard(*ToRustStream(s));
        } catch (const std::exception& e) {
            throw std::ios_base::failure(e.what());
        }
    }

    size_t DynamicMemoryUsage() const {
        return inner->dynamic_memory_usage();
    }

    merkle_frontier::OrchardAppendResult AppendBundle(const OrchardBundle& bundle) {
        return inner->append_bundle(bundle.GetDetails());
    }

    uint256 root() const {
        return uint256::FromRawBytes(inner->root());
    }

    static uint256 empty_root() {
        return uint256::FromRawBytes(merkle_frontier::orchard_empty_root());
    }

    size_t size() const {
        return inner->size();
    }

    libzcash::SubtreeIndex current_subtree_index() const {
        return (inner->size() >> libzcash::TRACKED_SUBTREE_HEIGHT);
    }
};

} // namespace libzcash

#endif // ZC_INCREMENTALMERKLETREE_H_
