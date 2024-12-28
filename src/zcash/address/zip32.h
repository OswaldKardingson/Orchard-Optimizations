// Copyright (c) 2018 The Zcash developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCASH_ZIP32_H
#define ZCASH_ZIP32_H

#include "serialize.h"
#include "uint256.h"
#include "zcash/address/sapling.hpp"
#include "zcash/address/pirate_orchard.hpp"

#include <optional>
#include <array>

constexpr uint32_t HARDENED_KEY_LIMIT = 0x80000000;
constexpr size_t SAPLING_ZIP32_XFVK_SIZE = 169;
constexpr size_t SAPLING_ZIP32_XSK_SIZE = 169;
constexpr size_t SAPLING_ZIP32_DXFVK_SIZE = 180;
constexpr size_t SAPLING_ZIP32_DXSK_SIZE = 180;

typedef std::vector<unsigned char, secure_allocator<unsigned char>> RawHDSeed;

class HDSeed {
private:
    RawHDSeed seed;

public:
    HDSeed() = default;
    explicit HDSeed(const RawHDSeed& seedIn) : seed(seedIn) {}
    explicit HDSeed(RawHDSeed&& seedIn) noexcept : seed(std::move(seedIn)) {}

    static HDSeed Random(size_t len = 32);
    static HDSeed RestoreFromPhrase(const std::string& phrase);
    bool IsValidPhrase(const std::string& phrase) const;
    bool IsNull() const { return seed.empty(); }
    void GetPhrase(std::string& phrase) const;
    uint256 Fingerprint() const;
    uint256 EncryptionFingerprint() const;
    const RawHDSeed& RawSeed() const { return seed; }

    friend bool operator==(const HDSeed& a, const HDSeed& b) {
        return a.seed == b.seed;
    }

    friend bool operator!=(const HDSeed& a, const HDSeed& b) {
        return !(a == b);
    }
};

// This is not part of ZIP 32 but is linked to the HD seed.
uint256 ovkForShieldingFromTaddr(const HDSeed& seed);

namespace libzcash {

typedef uint32_t AccountId;

constexpr AccountId ZCASH_LEGACY_ACCOUNT = HARDENED_KEY_LIMIT - 1;

class diversifier_index_t : public base_blob<88> {
public:
    diversifier_index_t() = default;
    explicit diversifier_index_t(const base_blob<88>& b) : base_blob<88>(b) {}
    explicit diversifier_index_t(uint64_t i) : base_blob<88>() {
        std::fill(data.begin(), data.end(), 0);
        data[0] = i & 0xFF;
        data[1] = (i >> 8) & 0xFF;
        data[2] = (i >> 16) & 0xFF;
        data[3] = (i >> 24) & 0xFF;
        data[4] = (i >> 32) & 0xFF;
        data[5] = (i >> 40) & 0xFF;
        data[6] = (i >> 48) & 0xFF;
        data[7] = (i >> 56) & 0xFF;
    }
    explicit diversifier_index_t(const std::vector<unsigned char>& vch) : base_blob<88>(vch) {}

    static diversifier_index_t FromRawBytes(const std::array<uint8_t, 11>& bytes) {
        diversifier_index_t buf;
        std::copy(bytes.begin(), bytes.end(), buf.begin());
        return buf;
    }

    bool increment() {
        for (int i = 0; i < 11; i++) {
            this->data[i] += 1;
            if (this->data[i] != 0) {
                return true; // no overflow
            }
        }
        return false; // overflow
    }

    std::optional<diversifier_index_t> succ() const {
        diversifier_index_t next(*this);
        if (next.increment()) {
            return next;
        } else {
            return std::nullopt;
        }
    }

    std::optional<uint32_t> ToTransparentChildIndex() const;

    friend bool operator<(const diversifier_index_t& a, const diversifier_index_t& b) {
        return std::lexicographical_compare(a.data.rbegin(), a.data.rend(), b.data.rbegin(), b.data.rend());
    }
};

struct SaplingExtendedFullViewingKey {
    uint8_t depth = 0;
    uint32_t parentFVKTag = 0;
    uint32_t childIndex = 0;
    uint256 chaincode;
    libzcash::SaplingFullViewingKey fvk;
    uint256 dk;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(depth);
        READWRITE(parentFVKTag);
        READWRITE(childIndex);
        READWRITE(chaincode);
        READWRITE(fvk);
        READWRITE(dk);
    }

    std::optional<SaplingExtendedFullViewingKey> Derive(uint32_t i) const;

    std::optional<std::pair<diversifier_index_t, libzcash::SaplingPaymentAddress>>
        Address(diversifier_index_t j) const;

    libzcash::SaplingPaymentAddress DefaultAddress() const;

    friend inline bool operator==(const SaplingExtendedFullViewingKey& a, const SaplingExtendedFullViewingKey& b) {
        return std::tie(a.depth, a.parentFVKTag, a.childIndex, a.chaincode, a.fvk, a.dk) ==
               std::tie(b.depth, b.parentFVKTag, b.childIndex, b.chaincode, b.fvk, b.dk);
    }

    friend inline bool operator<(const SaplingExtendedFullViewingKey& a, const SaplingExtendedFullViewingKey& b) {
        return std::tie(a.depth, a.childIndex, a.fvk) < std::tie(b.depth, b.childIndex, b.fvk);
    }
};

struct SaplingDiversifiedExtendedFullViewingKey {
    SaplingExtendedFullViewingKey extfvk;
    diversifier_t d;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(extfvk);
        READWRITE(d);
    }
};

struct SaplingExtendedSpendingKey {
    uint8_t depth = 0;
    uint32_t parentFVKTag = 0;
    uint32_t childIndex = 0;
    uint256 chaincode;
    libzcash::SaplingExpandedSpendingKey expsk;
    uint256 dk;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(depth);
        READWRITE(parentFVKTag);
        READWRITE(childIndex);
        READWRITE(chaincode);
        READWRITE(expsk);
        READWRITE(dk);
    }

    static SaplingExtendedSpendingKey Master(const HDSeed& seed, bool bip39Enabled = true);

    SaplingExtendedSpendingKey Derive(uint32_t i) const;

    SaplingExtendedFullViewingKey ToXFVK() const;

    libzcash::SaplingPaymentAddress DefaultAddress() const;

    friend bool operator==(const SaplingExtendedSpendingKey& a, const SaplingExtendedSpendingKey& b) {
        return std::tie(a.depth, a.parentFVKTag, a.childIndex, a.chaincode, a.expsk, a.dk) ==
               std::tie(b.depth, b.parentFVKTag, b.childIndex, b.chaincode, b.expsk, b.dk);
    }

    friend inline bool operator<(const SaplingExtendedSpendingKey& a, const SaplingExtendedSpendingKey& b) {
        return std::tie(a.depth, a.childIndex, a.expsk) < std::tie(b.depth, b.childIndex, b.expsk);
    }
};

struct SaplingDiversifiedExtendedSpendingKey {
    SaplingExtendedSpendingKey extsk;
    diversifier_t d;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(extsk);
        READWRITE(d);
    }
};

struct OrchardExtendedFullViewingKeyPirate {
    uint8_t depth = 0;
    uint32_t parentFVKTag = 0;
    uint32_t childIndex = 0;
    uint256 chaincode;
    libzcash::OrchardFullViewingKeyPirate fvk;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(depth);
        READWRITE(parentFVKTag);
        READWRITE(childIndex);
        READWRITE(chaincode);
        READWRITE(fvk);
    }

    friend inline bool operator==(const OrchardExtendedFullViewingKeyPirate& a, const OrchardExtendedFullViewingKeyPirate& b) {
        return std::tie(a.depth, a.parentFVKTag, a.childIndex, a.chaincode, a.fvk) ==
               std::tie(b.depth, b.parentFVKTag, b.childIndex, b.chaincode, b.fvk);
    }

    friend inline bool operator<(const OrchardExtendedFullViewingKeyPirate& a, const OrchardExtendedFullViewingKeyPirate& b) {
        return std::tie(a.depth, a.childIndex, a.fvk) < std::tie(b.depth, b.childIndex, b.fvk);
    }
};

struct OrchardExtendedSpendingKeyPirate {
    uint8_t depth = 0;
    uint32_t parentFVKTag = 0;
    uint32_t childIndex = 0;
    uint256 chaincode;
    libzcash::OrchardSpendingKeyPirate sk;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(depth);
        READWRITE(parentFVKTag);
        READWRITE(childIndex);
        READWRITE(chaincode);
        READWRITE(sk);
    }

    static OrchardExtendedSpendingKeyPirate Master(const HDSeed& seed, bool bip39Enabled = true);

    std::optional<OrchardExtendedSpendingKeyPirate> DeriveChild(uint32_t bip44CoinType, uint32_t account) const;

    std::optional<OrchardExtendedFullViewingKeyPirate> GetXFVK() const;

    friend bool operator==(const OrchardExtendedSpendingKeyPirate& a, const OrchardExtendedSpendingKeyPirate& b) {
        return std::tie(a.depth, a.parentFVKTag, a.childIndex, a.chaincode, a.sk) ==
               std::tie(b.depth, b.parentFVKTag, b.childIndex, b.chaincode, b.sk);
    }

    friend inline bool operator<(const OrchardExtendedSpendingKeyPirate& a, const OrchardExtendedSpendingKeyPirate& b) {
        return std::tie(a.depth, a.childIndex, a.sk) < std::tie(b.depth, b.childIndex, b.sk);
    }
};

} // namespace libzcash

#endif // ZCASH_ZIP32_H
