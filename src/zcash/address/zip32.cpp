// Copyright (c) 2018 The Zcash developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "zip32.h"

#include "hash.h"
#include "random.h"
#include "streams.h"
#include "version.h"
#include "zcash/prf.h"

#include <librustzcash.h>
#include <sodium.h>
#include <stdexcept> // Improved exception handling

const unsigned char ZCASH_HD_SEED_FP_ENCRYTION[crypto_generichash_blake2b_PERSONALBYTES] =
    {'P', 'i', 'r', 'a', 't', 'e', 'E', 'n', 'c', 'r', 'y', 'p', 't','_','F', 'P'};

const unsigned char ZCASH_HD_SEED_FP_PERSONAL[crypto_generichash_blake2b_PERSONALBYTES] =
    {'Z', 'c', 'a', 's', 'h', '_', 'H', 'D', '_', 'S', 'e', 'e', 'd', '_', 'F', 'P'};

const unsigned char ZCASH_TADDR_OVK_PERSONAL[crypto_generichash_blake2b_PERSONALBYTES] =
    {'Z', 'c', 'T', 'a', 'd', 'd', 'r', 'T', 'o', 'S', 'a', 'p', 'l', 'i', 'n', 'g'};

HDSeed HDSeed::Random(size_t len)
{
    if (len != 32) {
        throw std::invalid_argument("HDSeed::Random requires length to be 32 bytes.");
    }

    RawHDSeed rawSeed(len, 0);
    librustzcash_getrandom(rawSeed.data(), len);
    return HDSeed(rawSeed);
}

HDSeed HDSeed::RestoreFromPhrase(std::string &phrase)
{
    std::stringstream stream(phrase);
    unsigned int wordCount = std::distance(
        std::istream_iterator<std::string>(stream), 
        std::istream_iterator<std::string>()
    );

    RawHDSeed restoredSeed;
    size_t entropySize;

    switch (wordCount) {
        case 12: entropySize = 16; break;
        case 18: entropySize = 24; break;
        case 24: entropySize = 32; break;
        default:
            throw std::invalid_argument("HDSeed::RestoreFromPhrase invalid number of words.");
    }

    restoredSeed.resize(entropySize);
    if (!librustzcash_restore_seed_from_phase(restoredSeed.data(), entropySize, phrase.c_str())) {
        throw std::runtime_error("Failed to restore seed from phrase.");
    }

    return HDSeed(restoredSeed);
}

bool HDSeed::IsValidPhrase(std::string &phrase)
{
    std::stringstream stream(phrase);
    unsigned int wordCount = std::distance(
        std::istream_iterator<std::string>(stream), 
        std::istream_iterator<std::string>()
    );

    RawHDSeed restoredSeed;
    size_t entropySize;

    switch (wordCount) {
        case 12: entropySize = 16; break;
        case 18: entropySize = 24; break;
        case 24: entropySize = 32; break;
        default:
            return false; // Invalid word count
    }

    restoredSeed.resize(entropySize);
    return librustzcash_restore_seed_from_phase(restoredSeed.data(), entropySize, phrase.c_str());
}

void HDSeed::GetPhrase(std::string &phrase)
{
    auto rawSeed = this->RawSeed();
    char *rustPhrase = librustzcash_get_seed_phrase(rawSeed.data(), rawSeed.size());
    if (!rustPhrase) {
        throw std::runtime_error("Failed to retrieve phrase from seed.");
    }

    phrase.assign(rustPhrase);
    sodium_memzero(rustPhrase, strlen(rustPhrase)); // Securely clear the memory
    free(rustPhrase); // Free the dynamically allocated memory
}

uint256 HDSeed::Fingerprint() const
{
    CBLAKE2bWriter h(SER_GETHASH, 0, ZCASH_HD_SEED_FP_PERSONAL);
    h << seed;
    return h.GetHash();
}

uint256 HDSeed::EncryptionFingerprint() const
{
    CBLAKE2bWriter h(SER_GETHASH, 0, ZCASH_HD_SEED_FP_ENCRYTION);
    h << seed;
    return h.GetHash();
}

uint256 ovkForShieldingFromTaddr(HDSeed& seed) {
    auto rawSeed = seed.RawSeed();

    crypto_generichash_blake2b_state state;
    if (crypto_generichash_blake2b_init_salt_personal(
        &state,
        nullptr, 0, // No key
        64,
        nullptr,    // No salt
        ZCASH_TADDR_OVK_PERSONAL) != 0) {
        throw std::runtime_error("Failed to initialize Blake2b hash state.");
    }

    crypto_generichash_blake2b_update(&state, rawSeed.data(), rawSeed.size());
    auto intermediate = std::array<unsigned char, 64>();
    crypto_generichash_blake2b_final(&state, intermediate.data(), 64);

    uint256 intermediate_L;
    memcpy(intermediate_L.begin(), intermediate.data(), 32);

    return PRF_ovk(intermediate_L);
}

namespace libzcash {

std::optional<SaplingExtendedFullViewingKey> SaplingExtendedFullViewingKey::Derive(uint32_t i) const
{
    CDataStream ss_p(SER_NETWORK, PROTOCOL_VERSION);
    ss_p << *this;
    CSerializeData p_bytes(ss_p.begin(), ss_p.end());

    CSerializeData i_bytes(SAPLING_ZIP32_XFVK_SIZE);
    if (librustzcash_zip32_xfvk_derive(
        reinterpret_cast<unsigned char*>(p_bytes.data()),
        i,
        reinterpret_cast<unsigned char*>(i_bytes.data())
    )) {
        CDataStream ss_i(i_bytes, SER_NETWORK, PROTOCOL_VERSION);
        SaplingExtendedFullViewingKey xfvk_i;
        ss_i >> xfvk_i;
        return xfvk_i;
    } else {
        return std::nullopt;
    }
}

std::optional<std::pair<diversifier_index_t, libzcash::SaplingPaymentAddress>>
SaplingExtendedFullViewingKey::Address(diversifier_index_t j) const
{
    CDataStream ss_xfvk(SER_NETWORK, PROTOCOL_VERSION);
    ss_xfvk << *this;
    CSerializeData xfvk_bytes(ss_xfvk.begin(), ss_xfvk.end());

    diversifier_index_t j_ret;
    CSerializeData addr_bytes(libzcash::SerializedSaplingPaymentAddressSize);
    if (librustzcash_zip32_xfvk_address(
        reinterpret_cast<unsigned char*>(xfvk_bytes.data()),
        j.begin(), j_ret.begin(),
        reinterpret_cast<unsigned char*>(addr_bytes.data()))) {
        CDataStream ss_addr(addr_bytes, SER_NETWORK, PROTOCOL_VERSION);
        libzcash::SaplingPaymentAddress addr;
        ss_addr >> addr;
        return std::make_pair(j_ret, addr);
    } else {
        return std::nullopt;
    }
}

libzcash::SaplingPaymentAddress SaplingExtendedFullViewingKey::DefaultAddress() const
{
    diversifier_index_t j0;
    auto addr = Address(j0);
    if (!addr) {
        throw std::runtime_error("Failed to derive default address: No valid diversifiers available.");
    }
    return addr.value().second;
}

SaplingExtendedSpendingKey SaplingExtendedSpendingKey::Master(const HDSeed& seed, bool bip39Enabled)
{
    auto rawSeed = seed.RawSeed();
    CSerializeData m_bytes(SAPLING_ZIP32_XSK_SIZE);

    unsigned char* bip39_seed = librustzcash_get_bip39_seed(rawSeed.data(), rawSeed.size());

    if (bip39Enabled) {
        librustzcash_zip32_xsk_master(
            bip39_seed,
            64,
            reinterpret_cast<unsigned char*>(m_bytes.data()));
    } else {
        librustzcash_zip32_xsk_master(
            rawSeed.data(),
            rawSeed.size(),
            reinterpret_cast<unsigned char*>(m_bytes.data()));
    }

    CDataStream ss(m_bytes, SER_NETWORK, PROTOCOL_VERSION);
    SaplingExtendedSpendingKey xsk_m;
    ss >> xsk_m;

    sodium_memzero(bip39_seed, sizeof(bip39_seed));
    free(bip39_seed);

    return xsk_m;
}

SaplingExtendedSpendingKey SaplingExtendedSpendingKey::Derive(uint32_t i) const
{
    CDataStream ss_p(SER_NETWORK, PROTOCOL_VERSION);
    ss_p << *this;
    CSerializeData p_bytes(ss_p.begin(), ss_p.end());

    CSerializeData i_bytes(SAPLING_ZIP32_XSK_SIZE);
    librustzcash_zip32_xsk_derive(
        reinterpret_cast<unsigned char*>(p_bytes.data()),
        i,
        reinterpret_cast<unsigned char*>(i_bytes.data()));

    CDataStream ss_i(i_bytes, SER_NETWORK, PROTOCOL_VERSION);
    SaplingExtendedSpendingKey xsk_i;
    ss_i >> xsk_i;
    return xsk_i;
}

SaplingExtendedFullViewingKey SaplingExtendedSpendingKey::ToXFVK() const
{
    SaplingExtendedFullViewingKey ret;
    ret.depth = depth;
    ret.parentFVKTag = parentFVKTag;
    ret.childIndex = childIndex;
    ret.chaincode = chaincode;
    ret.fvk = expsk.full_viewing_key();
    ret.dk = dk;
    return ret;
}

libzcash::SaplingPaymentAddress SaplingExtendedSpendingKey::DefaultAddress() const
{
    return ToXFVK().DefaultAddress();
}

OrchardExtendedSpendingKeyPirate OrchardExtendedSpendingKeyPirate::Master(const HDSeed& seed, bool bip39Enabled)
{
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION); // Returning stream
    OrchardExtendedSpendingKey_t xsk_t_out;

    auto rawSeed = seed.RawSeed();
    unsigned char* bip39_seed = librustzcash_get_bip39_seed(rawSeed.data(), rawSeed.size());

    if (bip39Enabled) {
        orchard_derive_master_key(bip39_seed, 64, xsk_t_out.begin());
    } else {
        orchard_derive_master_key(rawSeed.data(), rawSeed.size(), xsk_t_out.begin());
    }

    OrchardExtendedSpendingKeyPirate xsk;
    rs << xsk_t_out;
    rs >> xsk;

    sodium_memzero(bip39_seed, sizeof(bip39_seed));
    free(bip39_seed);

    return xsk;
}

std::optional<OrchardExtendedSpendingKeyPirate> OrchardExtendedSpendingKeyPirate::DeriveChild(uint32_t bip44CoinType, uint32_t account) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION); // Sending stream
    CDataStream rs(SER_NETWORK, PROTOCOL_VERSION); // Returning stream

    OrchardExtendedSpendingKey_t xsk_t_out;
    OrchardExtendedSpendingKey_t xsk_t_in;

    ss << *this;
    ss >> xsk_t_in;

    if (orchard_derive_child_key(xsk_t_in.begin(), bip44CoinType, account, xsk_t_out.begin())) {
        OrchardExtendedSpendingKeyPirate xsk;
        rs << xsk_t_out;
        rs >> xsk;
        return xsk;
    }

    return std::nullopt;
}

std::optional<OrchardExtendedFullViewingKeyPirate> OrchardExtendedSpendingKeyPirate::GetXFVK() const
{
    auto fvkOpt = sk.GetFVK();
    if (fvkOpt) {
        OrchardExtendedFullViewingKeyPirate ret;
        ret.depth = depth;
        ret.parentFVKTag = parentFVKTag;
        ret.childIndex = childIndex;
        ret.chaincode = chaincode;
        ret.fvk = fvkOpt.value();
        return ret;
    }
    return std::nullopt;
}

} // namespace libzcash
