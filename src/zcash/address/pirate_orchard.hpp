// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZC_ADDRESS_PIRATE_ORCHARD_H_
#define ZC_ADDRESS_PIRATE_ORCHARD_H_

#include "serialize.h"
#include "uint256.h"
#include "zcash/Zcash.h"
#include <rust/orchard/pirate_keys.h>

namespace libzcash
{

// Define serialized sizes for Orchard keys and addresses.
const size_t SerializedOrchardPaymentAddressSize = 43;
const size_t SerializedOrchardOutgoingKeySize = 32;
const size_t SerializedOrchardIncomingViewingKeySize = 64;
const size_t SerializedOrchardFullViewingKeySize = 96;
const size_t SerializedOrchardExtendedFullViewingKeySize = 137;
const size_t SerializedOrchardSpendingKeySize = 32;
const size_t SerializedOrchardExtendedSpendingKeySize = 73;

// Define data types for Orchard keys and addresses.
typedef std::array<unsigned char, SerializedOrchardPaymentAddressSize> OrchardPaymentAddress_t;
typedef std::array<unsigned char, SerializedOrchardIncomingViewingKeySize> OrchardIncomingViewingKey_t;
typedef std::array<unsigned char, SerializedOrchardFullViewingKeySize> OrchardFullViewingKey_t;
typedef std::array<unsigned char, SerializedOrchardSpendingKeySize> OrchardSpendingKey_t;
typedef std::array<unsigned char, SerializedOrchardExtendedSpendingKeySize> OrchardExtendedSpendingKey_t;
typedef std::array<unsigned char, ZC_DIVERSIFIER_SIZE> diversifier_t;

// Add secure memory cleansing utility.
template <typename T>
void secure_cleanse(T& obj) {
    memory_cleanse(reinterpret_cast<void*>(obj.data()), obj.size());
}

//! Orchard functions and classes.
class OrchardPaymentAddressPirate
{
public:
    diversifier_t d;
    uint256 pk_d;

    OrchardPaymentAddressPirate() : d(), pk_d() {
        secure_cleanse(d);
        secure_cleanse(pk_d);
    }
    OrchardPaymentAddressPirate(diversifier_t d, uint256 pk_d) : d(d), pk_d(pk_d) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(d);
        READWRITE(pk_d);
    }

    //! Get the 256-bit SHA256d hash of this payment address.
    uint256 GetHash() const;

    //! Get serialized bytes of an Orchard Address.
    OrchardPaymentAddress_t ToBytes() const;

    friend inline bool operator==(const OrchardPaymentAddressPirate& a, const OrchardPaymentAddressPirate& b)
    {
        return a.d == b.d && a.pk_d == b.pk_d;
    }
    friend inline bool operator<(const OrchardPaymentAddressPirate& a, const OrchardPaymentAddressPirate& b)
    {
        return (a.d < b.d ||
                (a.d == b.d && a.pk_d < b.pk_d));
    }
};

class OrchardOutgoingViewingKey
{
public:
    uint256 ovk;

    OrchardOutgoingViewingKey() : ovk() {
        secure_cleanse(ovk);
    }
    OrchardOutgoingViewingKey(uint256 ovk) : ovk(ovk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ovk);
    }

    friend inline bool operator==(const OrchardOutgoingViewingKey& a, const OrchardOutgoingViewingKey& b)
    {
        return a.ovk == b.ovk;
    }
    friend inline bool operator<(const OrchardOutgoingViewingKey& a, const OrchardOutgoingViewingKey& b)
    {
        return (a.ovk < b.ovk);
    }
};

class OrchardIncomingViewingKeyPirate
{
public:
    uint256 dk;
    uint256 ivk;

    OrchardIncomingViewingKeyPirate() : dk(), ivk() {
        secure_cleanse(dk);
        secure_cleanse(ivk);
    }
    OrchardIncomingViewingKeyPirate(uint256 dk, uint256 ivk) : dk(dk), ivk(ivk) {}

    // Returns the payment address for a given diversifier.
    std::optional<OrchardPaymentAddressPirate> address(diversifier_t d) const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(dk);
        READWRITE(ivk);
    }

    friend inline bool operator==(const OrchardIncomingViewingKeyPirate& a, const OrchardIncomingViewingKeyPirate& b)
    {
        return a.dk == b.dk && a.ivk == b.ivk;
    }
    friend inline bool operator<(const OrchardIncomingViewingKeyPirate& a, const OrchardIncomingViewingKeyPirate& b)
    {
        return (a.dk < b.dk || (a.dk == b.dk && a.ivk < b.ivk));
    }
};

class OrchardFullViewingKeyPirate
{
public:
    uint256 ak;
    uint256 nk;
    uint256 rivk;
    bool internal; // key scope

    OrchardFullViewingKeyPirate() : ak(), nk(), rivk() {
        secure_cleanse(ak);
        secure_cleanse(nk);
        secure_cleanse(rivk);
    }
    OrchardFullViewingKeyPirate(uint256 ak, uint256 nk, uint256 rivk)
        : ak(ak), nk(nk), rivk(rivk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(ak);
        READWRITE(nk);
        READWRITE(rivk);
    }

    //! Get the fingerprint of the Full Viewing Key.
    uint256 GetFingerprint() const;

    //! Retrieve the outgoing viewing key associated with this full viewing key.
    std::optional<OrchardOutgoingViewingKey> GetOVK() const;

    //! Retrieve the outgoing viewing key for internal purposes.
    std::optional<OrchardOutgoingViewingKey> GetOVKinternal() const;

    //! Retrieve the incoming viewing key associated with this full viewing key.
    std::optional<OrchardIncomingViewingKeyPirate> GetIVK() const;

    //! Retrieve the incoming viewing key for internal purposes.
    std::optional<OrchardIncomingViewingKeyPirate> GetIVKinternal() const;

    //! Retrieve the default payment address associated with this full viewing key.
    std::optional<OrchardPaymentAddressPirate> GetDefaultAddress() const;

    //! Retrieve the default payment address for internal purposes.
    std::optional<OrchardPaymentAddressPirate> GetDefaultAddressInternal() const;

    //! Retrieve the payment address for a given diversifier associated with this full viewing key.
    std::optional<OrchardPaymentAddressPirate> GetAddress(blob88 diversifier) const;

    //! Retrieve the payment address for internal purposes for a given diversifier.
    std::optional<OrchardPaymentAddressPirate> GetAddressInternal(blob88 diversifier) const;

    friend inline bool operator==(const OrchardFullViewingKeyPirate& a, const OrchardFullViewingKeyPirate& b)
    {
        return a.ak == b.ak && a.nk == b.nk && a.rivk == b.rivk;
    }
    friend inline bool operator<(const OrchardFullViewingKeyPirate& a, const OrchardFullViewingKeyPirate& b)
    {
        return (a.ak < b.ak ||
                (a.ak == b.ak && a.nk < b.nk) ||
                (a.ak == b.ak && a.nk == b.nk && a.rivk < b.rivk));
    }
};

class OrchardSpendingKeyPirate
{
public:
    uint256 sk;

    OrchardSpendingKeyPirate() : sk() {
        secure_cleanse(sk);
    }
    OrchardSpendingKeyPirate(uint256 sk) : sk(sk) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(sk);
    }

    //! Generate a random spending key.
    std::optional<OrchardSpendingKeyPirate> random();

    //! Validate the spending key bytes.
    bool IsValid();

    //! Retrieve the Full Viewing Key associated with this spending key.
    std::optional<OrchardFullViewingKeyPirate> GetFVK() const;

    //! Retrieve the default payment address associated with this spending key.
    std::optional<OrchardPaymentAddressPirate> GetDefaultAddress() const;

    //! Retrieve the default payment address for internal purposes.
    std::optional<OrchardPaymentAddressPirate> GetDefaultAddressInternal() const;

    friend inline bool operator==(const OrchardSpendingKeyPirate& a, const OrchardSpendingKeyPirate& b)
    {
        return a.sk == b.sk;
    }
    friend inline bool operator<(const OrchardSpendingKeyPirate& a, const OrchardSpendingKeyPirate& b)
    {
        return (a.sk < b.sk);
    }
};

} // namespace libzcash

#endif // ZC_ADDRESS_PIRATE_ORCHARD_H_
