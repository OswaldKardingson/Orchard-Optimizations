// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include <stdexcept>
#include <vector>  // Replacing deque where sequential access is required
#include "zcash/IncrementalMerkleTree.hpp"
#include "crypto/sha256.h"
#include "zcash/util.h"
#include "librustzcash.h"

namespace libzcash {

PedersenHash PedersenHash::combine(
    const PedersenHash& a,
    const PedersenHash& b,
    size_t depth
)
{
    PedersenHash res;
    librustzcash_merkle_hash(
        depth,
        a.begin(),
        b.begin(),
        res.begin()
    );
    return res;
}

PedersenHash PedersenHash::uncommitted() {
    PedersenHash res;
    librustzcash_tree_uncommitted(res.begin());
    return res;
}

SHA256Compress SHA256Compress::combine(
    const SHA256Compress& a,
    const SHA256Compress& b,
    size_t depth
)
{
    SHA256Compress res;
    CSHA256 hasher;
    hasher.Write(a.begin(), 32);
    hasher.Write(b.begin(), 32);
    hasher.FinalizeNoPadding(res.begin());
    return res;
}

template <size_t Depth, typename Hash>
class PathFiller {
private:
    std::vector<Hash> queue;  // Changed to vector for better cache locality
    static EmptyMerkleRoots<Depth, Hash> emptyroots;
public:
    PathFiller() = default;
    explicit PathFiller(std::vector<Hash> queue) : queue(std::move(queue)) {}

    Hash next(size_t depth) {
        if (!queue.empty()) {
            Hash h = queue.front();
            queue.erase(queue.begin());
            return h;
        } else {
            return emptyroots.empty_root(depth);
        }
    }
};

template <size_t Depth, typename Hash>
EmptyMerkleRoots<Depth, Hash> PathFiller<Depth, Hash>::emptyroots;

template<size_t Depth, typename Hash>
void IncrementalMerkleTree<Depth, Hash>::wfcheck() const {
    if (parents.size() >= Depth) {
        throw std::ios_base::failure("tree has too many parents");
    }

    // Ensure the last parent is not null
    if (!parents.empty() && !parents.back()) {
        throw std::ios_base::failure("tree has non-canonical representation of parent");
    }

    // Left cannot be empty when right exists
    if (!left && right) {
        throw std::ios_base::failure("tree has non-canonical representation; right should not exist");
    }

    // Left cannot be empty when parents are nonempty
    if (!left && !parents.empty()) {
        throw std::ios_base::failure("tree has non-canonical representation; parents should not be empty");
    }
}

template<size_t Depth, typename Hash>
Hash IncrementalMerkleTree<Depth, Hash>::last() const {
    if (right) {
        return *right;
    } else if (left) {
        return *left;
    } else {
        throw std::runtime_error("tree has no cursor");
    }
}

template<size_t Depth, typename Hash>
size_t IncrementalMerkleTree<Depth, Hash>::size() const {
    size_t ret = left.has_value() + right.has_value();
    for (size_t i = 0; i < parents.size(); i++) {
        if (parents[i]) {
            ret += (1U << (i + 1));  // Binary representation as tree size
        }
    }
    return ret;
}

template<size_t Depth, typename Hash>
SubtreeIndex IncrementalMerkleTree<Depth, Hash>::current_subtree_index() const {
    return size() >> TRACKED_SUBTREE_HEIGHT;
}

template<size_t Depth, typename Hash>
Hash IncrementalMerkleTree<Depth, Hash>::complete_subtree_root() const {
    auto treeSize = size();

    if (treeSize && ((treeSize % (1U << TRACKED_SUBTREE_HEIGHT)) == 0)) {
        assert(left && right);
        assert(parents.size() >= (TRACKED_SUBTREE_HEIGHT - 1));

        for (size_t i = 0; i < TRACKED_SUBTREE_HEIGHT - 1; i++) {
            assert(parents[i]);
        }

        Hash root = Hash::combine(*left, *right, 0);
        for (size_t d = 1; d < TRACKED_SUBTREE_HEIGHT; d++) {
            root = Hash::combine(*parents[d - 1], root, d);
        }

        return root;
    } else {
        throw std::runtime_error("tree has no root");
    }
}

template<size_t Depth, typename Hash>
void IncrementalMerkleTree<Depth, Hash>::append(Hash obj) {
    if (is_complete(Depth)) {
        throw std::runtime_error("tree is full");
    }

    if (!left) {
        left = obj; // Set the left leaf
    } else if (!right) {
        right = obj; // Set the right leaf
    } else {
        // Combine the leaves and propagate up the tree
        auto combined = Hash::combine(*left, *right, 0);

        left = obj; // Reset left leaf
        right.reset(); // Clear right leaf

        for (size_t i = 0; i < Depth; ++i) {
            if (i < parents.size()) {
                if (parents[i]) {
                    combined = Hash::combine(*parents[i], combined, i + 1);
                    parents[i].reset();
                } else {
                    parents[i] = combined;
                    break;
                }
            } else {
                parents.push_back(combined);
                break;
            }
        }
    }
}

template<size_t Depth, typename Hash>
bool IncrementalMerkleTree<Depth, Hash>::is_complete(size_t depth) const {
    if (!left || !right) {
        return false;
    }

    if (parents.size() != (depth - 1)) {
        return false;
    }

    return std::all_of(parents.begin(), parents.end(), [](const auto& parent) { return parent.has_value(); });
}

template<size_t Depth, typename Hash>
size_t IncrementalMerkleTree<Depth, Hash>::next_depth(size_t skip) const {
    if (!left) {
        if (skip > 0) {
            skip--;
        } else {
            return 0;
        }
    }

    if (!right) {
        if (skip > 0) {
            skip--;
        } else {
            return 0;
        }
    }

    size_t depth = 1;
    for (const auto& parent : parents) {
        if (!parent) {
            if (skip > 0) {
                skip--;
            } else {
                return depth;
            }
        }
        depth++;
    }

    return depth + skip;
}

template<size_t Depth, typename Hash>
Hash IncrementalMerkleTree<Depth, Hash>::root(size_t depth, std::deque<Hash> filler_hashes) const {
    PathFiller<Depth, Hash> filler(std::move(filler_hashes));

    Hash combine_left = left.value_or(filler.next(0));
    Hash combine_right = right.value_or(filler.next(0));
    Hash root = Hash::combine(combine_left, combine_right, 0);

    size_t d = 1;
    for (const auto& parent : parents) {
        if (parent) {
            root = Hash::combine(*parent, root, d);
        } else {
            root = Hash::combine(root, filler.next(d), d);
        }
        d++;
    }

    while (d < depth) {
        root = Hash::combine(root, filler.next(d), d);
        d++;
    }

    return root;
}

template<size_t Depth, typename Hash>
MerklePath IncrementalMerkleTree<Depth, Hash>::path(std::deque<Hash> filler_hashes) const {
    if (!left) {
        throw std::runtime_error("Cannot create an authentication path for an empty tree");
    }

    PathFiller<Depth, Hash> filler(std::move(filler_hashes));

    std::vector<Hash> path;
    std::vector<bool> index;

    if (right) {
        index.push_back(true);
        path.push_back(*left);
    } else {
        index.push_back(false);
        path.push_back(filler.next(0));
    }

    size_t depth = 1;
    for (const auto& parent : parents) {
        if (parent) {
            index.push_back(true);
            path.push_back(*parent);
        } else {
            index.push_back(false);
            path.push_back(filler.next(depth));
        }
        depth++;
    }

    while (depth < Depth) {
        index.push_back(false);
        path.push_back(filler.next(depth));
        depth++;
    }

    std::vector<std::vector<bool>> merkle_path;
    for (const auto& hash : path) {
        std::vector<unsigned char> hash_bytes(hash.begin(), hash.end());
        merkle_path.push_back(convertBytesVectorToVector(hash_bytes));
    }

    std::reverse(merkle_path.begin(), merkle_path.end());
    std::reverse(index.begin(), index.end());

    return MerklePath(merkle_path, index);
}

template<size_t Depth, typename Hash>
std::deque<Hash> IncrementalWitness<Depth, Hash>::partial_path() const {
    std::deque<Hash> uncles(filled.begin(), filled.end());

    if (cursor) {
        uncles.push_back(cursor->root(cursor_depth));
    }

    return uncles;
}

template<size_t Depth, typename Hash>
void IncrementalWitness<Depth, Hash>::append(Hash obj) {
    if (cursor) {
        cursor->append(obj);

        if (cursor->is_complete(cursor_depth)) {
            filled.push_back(cursor->root(cursor_depth));
            cursor.reset();
        }
    } else {
        cursor_depth = tree.next_depth(filled.size());

        if (cursor_depth >= Depth) {
            throw std::runtime_error("Tree is full");
        }

        if (cursor_depth == 0) {
            filled.push_back(obj);
        } else {
            cursor.emplace();
            cursor->append(obj);
        }
    }
}

// Specialize templates for supported tree depths and hash types
template class IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH, SHA256Compress>;
template class IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, SHA256Compress>;

template class IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH, SHA256Compress>;
template class IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, SHA256Compress>;

template class IncrementalMerkleTree<SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, PedersenHash>;
template class IncrementalMerkleTree<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, PedersenHash>;

template class IncrementalWitness<SAPLING_INCREMENTAL_MERKLE_TREE_DEPTH, PedersenHash>;
template class IncrementalWitness<INCREMENTAL_MERKLE_TREE_DEPTH_TESTING, PedersenHash>;

} // namespace libzcash
