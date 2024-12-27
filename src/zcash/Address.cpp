// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "Address.hpp"
#include "NoteEncryption.hpp"
#include "hash.h"
#include "prf.h"
#include "streams.h"

#include <librustzcash.h>

const uint32_t SAPLING_BRANCH_ID = 0x76b809bb;

namespace libzcash {

// Spending Keys
std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const SproutSpendingKey &sk) const {
    return std::make_pair("z-sprout", sk.address());
}
std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const SaplingExtendedSpendingKey &sk) const {
    return std::make_pair("z-sapling", sk.DefaultAddress());
}
std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const OrchardExtendedSpendingKeyPirate &extsk) const {
    auto addressOpt = extsk.sk.GetDefaultAddress();
    if (!addressOpt.has_value()) {
        throw std::runtime_error("Cannot derive default address from invalid Orchard spending key.");
    }
    return std::make_pair("z-orchard", addressOpt.value());
}
std::pair<std::string, PaymentAddress> AddressInfoFromSpendingKey::operator()(const InvalidEncoding&) const {
    throw std::runtime_error("Cannot derive default address from invalid spending key.");
}

// Diversified Spending Keys
std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedSpendingKey::operator()(const SaplingDiversifiedExtendedSpendingKey &dsk) const {
    auto addrOpt = dsk.extsk.ToXFVK().fvk.in_viewing_key().address(dsk.d);
    if (!addrOpt.has_value()) {
        throw std::runtime_error("Cannot derive diversified address from invalid Sapling key.");
    }
    return std::make_pair("z-sapling", addrOpt.value());
}
std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedSpendingKey::operator()(const InvalidEncoding&) const {
    throw std::runtime_error("Cannot derive default address from invalid diversified spending key.");
}

// Viewing Keys
std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const SproutViewingKey &sk) const {
    return std::make_pair("z-sprout", sk.address());
}
std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const SaplingExtendedFullViewingKey &sk) const {
    return std::make_pair("z-sapling", sk.DefaultAddress());
}
std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const OrchardExtendedFullViewingKeyPirate &sk) const {
    auto addressOpt = sk.fvk.GetDefaultAddress();
    if (!addressOpt.has_value()) {
        throw std::runtime_error("Cannot derive default address from invalid Orchard viewing key.");
    }
    return std::make_pair("z-orchard", addressOpt.value());
}
std::pair<std::string, PaymentAddress> AddressInfoFromViewingKey::operator()(const InvalidEncoding&) const {
    throw std::runtime_error("Cannot derive default address from invalid viewing key.");
}

// Diversified Viewing Keys
std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedViewingKey::operator()(const SaplingDiversifiedExtendedFullViewingKey &dvk) const {
    auto addrOpt = dvk.extfvk.fvk.in_viewing_key().address(dvk.d);
    if (!addrOpt.has_value()) {
        throw std::runtime_error("Cannot derive diversified address from invalid Sapling key.");
    }
    return std::make_pair("z-sapling", addrOpt.value());
}
std::pair<std::string, PaymentAddress> AddressInfoFromDiversifiedViewingKey::operator()(const InvalidEncoding&) const {
    throw std::runtime_error("Cannot derive address from invalid diversified viewing key.");
}

// Validation for Address Types
class IsValidAddressForNetwork : public boost::static_visitor<bool> {
public:
    bool operator()(const libzcash::SproutPaymentAddress &addr) const {
        return false;
    }

    bool operator()(const libzcash::SaplingPaymentAddress &addr) const {
        return true;
    }

    bool operator()(const libzcash::OrchardPaymentAddressPirate &addr) const {
        return true;
    }

    bool operator()(const libzcash::InvalidEncoding &addr) const {
        return false;
    }
};

// Validity Checks
bool IsValidPaymentAddress(const libzcash::PaymentAddress& zaddr) {
    return std::visit(IsValidAddressForNetwork(), zaddr);
}

bool IsValidViewingKey(const libzcash::ViewingKey& vk) {
    return vk.index() != 0;
}

bool IsValidDiversifiedViewingKey(const libzcash::DiversifiedViewingKey& vk) {
    return vk.index() != 0;
}

bool IsValidSpendingKey(const libzcash::SpendingKey& zkey) {
    return zkey.index() != 0;
}

bool IsValidDiversifiedSpendingKey(const libzcash::DiversifiedSpendingKey& zkey) {
    return zkey.index() != 0;
}
