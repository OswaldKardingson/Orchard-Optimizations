// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "zcash/address/pirate_orchard.hpp"

#include "hash.h"
#include "streams.h"
#include "zcash/NoteEncryption.hpp"

namespace libzcash
{

const unsigned char ZCASH_ORCHARH_FVFP_PERSONALIZATION[crypto_generichash_blake2b_PERSONALBYTES] =
    {'Z', 'c', 'a', 's', 'h', 'O', 'r', 'c', 'h', 'a', 'r', 'd', 'F', 'V', 'F', 'P'};

// Utility function for secure memory cleansing.
template <typename T>
void secure_cleanse(T& obj) {
    memory_cleanse(reinterpret_cast<void*>(obj.data()), obj.size());
}

//! Orchard
uint256 OrchardPaymentAddressPirate::GetHash() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;
    return Hash(ss.begin(), ss.end());
}

OrchardPaymentAddress_t OrchardPaymentAddressPirate::ToBytes() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    OrchardPaymentAddress_t address_t;

    ss << *this;
    std::copy(ss.begin(), ss.end(), address_t.begin());

    return address_t;
}

std::optional<OrchardPaymentAddressPirate> OrchardIncomingViewingKeyPirate::address(diversifier_t d) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardIncomingViewingKey_t ivk_t;
    OrchardPaymentAddress_t address_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), ivk_t.begin());

    rustCompleted = orchard_ivk_to_address(ivk_t.data(), d.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(ivk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

uint256 OrchardFullViewingKeyPirate::GetFingerprint() const
{
    CBLAKE2bWriter ss(SER_GETHASH, 0, ZCASH_ORCHARH_FVFP_PERSONALIZATION);
    ss << *this;
    return ss.GetHash();
}

std::optional<OrchardOutgoingViewingKey> OrchardFullViewingKeyPirate::GetOVK() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardOutgoingViewingKey ovk;
    OrchardIncomingViewingKey_t ovk_t;
    OrchardFullViewingKey_t fvk_t;

    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), fvk_t.begin());

    rustCompleted = orchard_fvk_to_ovk(fvk_t.data(), ovk_t.data());

    if (rustCompleted) {
        std::copy(ovk_t.begin(), ovk_t.end(), rs.begin());
        rs >> ovk;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(fvk_t);
    secure_cleanse(ovk_t);

    if (rustCompleted) {
        return ovk;
    }

    return std::nullopt;
}

std::optional<OrchardIncomingViewingKeyPirate> OrchardFullViewingKeyPirate::GetIVK() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardIncomingViewingKey_t ivk_t;
    OrchardFullViewingKey_t fvk_t;

    OrchardIncomingViewingKeyPirate ivk;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), fvk_t.begin());

    rustCompleted = orchard_fvk_to_ivk(fvk_t.data(), ivk_t.data());

    if (rustCompleted) {
        std::copy(ivk_t.begin(), ivk_t.end(), rs.begin());
        rs >> ivk;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(fvk_t);
    secure_cleanse(ivk_t);

    if (rustCompleted) {
        return ivk;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardFullViewingKeyPirate::GetDefaultAddress() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardFullViewingKey_t fvk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), fvk_t.begin());

    rustCompleted = orchard_fvk_to_default_address(fvk_t.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(fvk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardSpendingKeyPirate> OrchardSpendingKeyPirate::random()
{
    while (true) {
        auto bytes = random_uint256();
        if (orchard_sk_is_valid(bytes.data())) {
            return OrchardSpendingKeyPirate(bytes);
        }
    }
}

bool OrchardSpendingKeyPirate::IsValid()
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    OrchardSpendingKey_t sk_t;
    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    bool rustCompleted = orchard_sk_is_valid(sk_t.data());

    secure_cleanse(ss);
    secure_cleanse(sk_t);

    return rustCompleted;
}

std::optional<OrchardFullViewingKeyPirate> OrchardSpendingKeyPirate::GetFVK() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardFullViewingKey_t fvk_t;
    OrchardSpendingKey_t sk_t;

    OrchardFullViewingKeyPirate fvk;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_fvk(sk_t.data(), fvk_t.data());

    if (rustCompleted) {
        std::copy(fvk_t.begin(), fvk_t.end(), rs.begin());
        rs >> fvk;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(fvk_t);

    if (rustCompleted) {
        return fvk;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetDefaultAddress() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_default_address(sk_t.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetDefaultAddressInternal() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_default_address_internal(sk_t.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetAddress(blob88 diversifier) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_address(sk_t.data(), diversifier.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetAddressInternal(blob88 diversifier) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_address_internal(sk_t.data(), diversifier.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardSpendingKeyPirate> OrchardSpendingKeyPirate::random()
{
    while (true) {
        auto bytes = random_uint256();
        if (orchard_sk_is_valid(bytes.data())) {
            return OrchardSpendingKeyPirate(bytes);
        }
    }
}

bool OrchardSpendingKeyPirate::IsValid()
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);

    OrchardSpendingKey_t sk_t;
    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    bool rustCompleted = orchard_sk_is_valid(sk_t.data());

    secure_cleanse(ss);
    secure_cleanse(sk_t);

    return rustCompleted;
}

std::optional<OrchardFullViewingKeyPirate> OrchardSpendingKeyPirate::GetFVK() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardFullViewingKey_t fvk_t;
    OrchardSpendingKey_t sk_t;

    OrchardFullViewingKeyPirate fvk;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_fvk(sk_t.data(), fvk_t.data());

    if (rustCompleted) {
        std::copy(fvk_t.begin(), fvk_t.end(), rs.begin());
        rs >> fvk;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(fvk_t);

    if (rustCompleted) {
        return fvk;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetDefaultAddress() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_default_address(sk_t.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetDefaultAddressInternal() const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_default_address_internal(sk_t.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetAddress(blob88 diversifier) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_address(sk_t.data(), diversifier.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

std::optional<OrchardPaymentAddressPirate> OrchardSpendingKeyPirate::GetAddressInternal(blob88 diversifier) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION);

    OrchardPaymentAddress_t address_t;
    OrchardSpendingKey_t sk_t;

    OrchardPaymentAddressPirate address;
    bool rustCompleted;

    ss << *this;
    std::copy(ss.begin(), ss.end(), sk_t.begin());

    rustCompleted = orchard_sk_to_address_internal(sk_t.data(), diversifier.data(), address_t.data());

    if (rustCompleted) {
        std::copy(address_t.begin(), address_t.end(), rs.begin());
        rs >> address;
    }

    secure_cleanse(ss);
    secure_cleanse(rs);
    secure_cleanse(sk_t);
    secure_cleanse(address_t);

    if (rustCompleted) {
        return address;
    }

    return std::nullopt;
}

} // namespace libzcash
