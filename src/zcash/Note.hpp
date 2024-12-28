// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#ifndef ZC_NOTE_H_
#define ZC_NOTE_H_

#include "uint256.h"
#include "Zcash.h"
#include "Address.hpp"
#include "NoteEncryption.hpp"
#include "consensus/params.h"
#include "consensus/consensus.h"
#include "primitives/orchard.h"

#include "rust/orchard/orchard_actions.h"

#include <array>
#include <optional>
#include <type_traits> // For std::is_trivially_copyable

namespace libzcash {

// Helper function for secure memory handling
template <typename T>
void SecureZeroMemory(T& obj) {
    static_assert(std::is_trivially_copyable<T>::value, "Type must be trivially copyable");
    std::memset(&obj, 0, sizeof(T));
}

class BaseNote {
protected:
    uint64_t value_ = 0;

public:
    BaseNote() = default;
    explicit BaseNote(uint64_t value) : value_(value) {}
    virtual ~BaseNote() = default;

    inline uint64_t value() const { return value_; }
};

class SproutNote : public BaseNote {
public:
    uint256 a_pk;
    uint256 rho;
    uint256 r;

    SproutNote() = default;
    SproutNote(uint256 a_pk, uint64_t value, uint256 rho, uint256 r)
        : BaseNote(value), a_pk(std::move(a_pk)), rho(std::move(rho)), r(std::move(r)) {}

    virtual ~SproutNote() = default;

    uint256 cm() const;
    uint256 nullifier(const SproutSpendingKey& a_sk) const;
};

inline bool plaintext_version_is_valid(const Consensus::Params& params, int height, unsigned char leadbyte) {
    int orchardActivationHeight = params.vUpgrades[Consensus::UPGRADE_ORCHARD].nActivationHeight;

    if (height < orchardActivationHeight && leadbyte != 0x01) {
        return false;
    }
    if (height >= orchardActivationHeight
        && height < orchardActivationHeight + ZIP212_GRACE_PERIOD
        && leadbyte != 0x01
        && leadbyte != 0x02) {
        return false;
    }
    if (orchardActivationHeight > 0 && height >= orchardActivationHeight + ZIP212_GRACE_PERIOD && leadbyte != 0x02) {
        return false;
    }
    return true;
}

enum class Zip212Enabled { BeforeZip212, AfterZip212 };

class SaplingNote : public BaseNote {
private:
    uint256 rseed;
    friend class SaplingNotePlaintext;
    Zip212Enabled zip_212_enabled;

public:
    diversifier_t d;
    uint256 pk_d;

    SaplingNote() = default;
    SaplingNote(diversifier_t d, uint256 pk_d, uint64_t value, uint256 rseed, Zip212Enabled zip_212_enabled)
        : BaseNote(value), d(std::move(d)), pk_d(std::move(pk_d)), rseed(std::move(rseed)), zip_212_enabled(zip_212_enabled) {}

    SaplingNote(const SaplingPaymentAddress& address, uint64_t value, Zip212Enabled zip_212_enabled);

    virtual ~SaplingNote() = default;

    std::optional<uint256> cmu() const;
    std::optional<uint256> nullifier(const SaplingFullViewingKey& vk, uint64_t position) const;
    uint256 rcm() const;

    Zip212Enabled get_zip_212_enabled() const { return zip_212_enabled; }
};

class OrchardNote : public BaseNote {
private:
    uint256 rho_;
    uint256 rseed_;
    uint256 cmx_;

public:
    OrchardPaymentAddressPirate address;

    OrchardNote() = default;
    OrchardNote(OrchardPaymentAddressPirate address, uint64_t value, uint256 rho, uint256 rseed, uint256 cmx)
        : BaseNote(value), address(std::move(address)), rho_(std::move(rho)), rseed_(std::move(rseed)), cmx_(std::move(cmx)) {}

    virtual ~OrchardNote() = default;

    uint256 rho() const { return rho_; }
    uint256 rseed() const { return rseed_; }
    uint256 cmx() const { return cmx_; }

    std::optional<uint256> GetNullifier(const libzcash::OrchardFullViewingKeyPirate& fvk) const;
};

class BaseNotePlaintext {
protected:
    uint64_t value_ = 0;
    std::array<unsigned char, ZC_MEMO_SIZE> memo_ = {};

public:
    BaseNotePlaintext() = default;
    BaseNotePlaintext(const BaseNote& note, std::array<unsigned char, ZC_MEMO_SIZE> memo)
        : value_(note.value()), memo_(std::move(memo)) {}

    BaseNotePlaintext(uint64_t value, std::array<unsigned char, ZC_MEMO_SIZE> memo)
        : value_(value), memo_(std::move(memo)) {}

    virtual ~BaseNotePlaintext() = default;

    inline uint64_t value() const { return value_; }
    inline const std::array<unsigned char, ZC_MEMO_SIZE>& memo() const { return memo_; }
};

class SproutNotePlaintext : public BaseNotePlaintext {
public:
    uint256 rho;
    uint256 r;

    SproutNotePlaintext() = default;
    SproutNotePlaintext(const SproutNote& note, std::array<unsigned char, ZC_MEMO_SIZE> memo);

    SproutNote note(const SproutPaymentAddress& addr) const;

    virtual ~SproutNotePlaintext() = default;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        unsigned char leadbyte = 0x00;
        READWRITE(leadbyte);

        if (leadbyte != 0x00) {
            throw std::ios_base::failure("lead byte of SproutNotePlaintext is not recognized");
        }

        READWRITE(value_);
        READWRITE(rho);
        READWRITE(r);
        READWRITE(memo_);
    }

    static SproutNotePlaintext decrypt(const ZCNoteDecryption& decryptor,
                                       const ZCNoteDecryption::Ciphertext& ciphertext,
                                       const uint256& ephemeralKey,
                                       const uint256& h_sig,
                                       unsigned char nonce);

    ZCNoteEncryption::Ciphertext encrypt(ZCNoteEncryption& encryptor, const uint256& pk_enc) const;
};

typedef std::pair<SaplingEncCiphertext, SaplingNoteEncryption> SaplingNotePlaintextEncryptionResult;

class SaplingNotePlaintext : public BaseNotePlaintext {
private:
    uint256 rseed;
    unsigned char leadbyte;

public:
    diversifier_t d;

    SaplingNotePlaintext() = default;

    SaplingNotePlaintext(const SaplingNote& note, std::array<unsigned char, ZC_MEMO_SIZE> memo);

    static std::optional<SaplingNotePlaintext> decrypt(
        const Consensus::Params& params,
        int height,
        const SaplingEncCiphertext& ciphertext,
        const uint256& ivk,
        const uint256& epk,
        const uint256& cmu);

    static std::optional<SaplingNotePlaintext> plaintext_checks_without_height(
        const SaplingNotePlaintext& plaintext,
        const uint256& ivk,
        const uint256& epk,
        const uint256& cmu);

    static std::optional<SaplingNotePlaintext> attempt_sapling_enc_decryption_deserialization(
        const SaplingEncCiphertext& ciphertext,
        const uint256& ivk,
        const uint256& epk);

    static std::optional<SaplingNotePlaintext> decrypt(
        const Consensus::Params& params,
        int height,
        const SaplingEncCiphertext& ciphertext,
        const uint256& epk,
        const uint256& esk,
        const uint256& pk_d,
        const uint256& cmu);

    static std::optional<SaplingNotePlaintext> plaintext_checks_without_height(
        const SaplingNotePlaintext& plaintext,
        const uint256& epk,
        const uint256& esk,
        const uint256& pk_d,
        const uint256& cmu);

    static std::optional<SaplingNotePlaintext> attempt_sapling_enc_decryption_deserialization(
        const SaplingEncCiphertext& ciphertext,
        const uint256& epk,
        const uint256& esk,
        const uint256& pk_d);

    std::optional<SaplingNote> note(const SaplingIncomingViewingKey& ivk) const;

    virtual ~SaplingNotePlaintext() = default;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(leadbyte);

        if (leadbyte != 0x01 && leadbyte != 0x02) {
            throw std::ios_base::failure("lead byte of SaplingNotePlaintext is not recognized");
        }

        READWRITE(d);           // 11 bytes
        READWRITE(value_);      // 8 bytes
        READWRITE(rseed);       // 32 bytes
        READWRITE(memo_);       // 512 bytes
    }

    std::optional<SaplingNotePlaintextEncryptionResult> encrypt(const uint256& pk_d) const;

    uint256 rcm() const;
    uint256 generate_or_derive_esk() const;

    unsigned char get_leadbyte() const { return leadbyte; }
};

class OrchardNotePlaintext : public BaseNotePlaintext {
private:
    libzcash::OrchardPaymentAddressPirate address;
    uint256 rho;
    uint256 rseed;
    std::optional<uint256> nullifier;
    uint256 cmx;

public:
    OrchardNotePlaintext() = default;

    OrchardNotePlaintext(
        const CAmount value,
        const libzcash::OrchardPaymentAddressPirate address,
        const std::array<unsigned char, ZC_MEMO_SIZE> memo,
        const uint256 rho,
        const uint256 rseed,
        const std::optional<uint256> nullifier,
        const uint256 cmx)
        : BaseNotePlaintext(value, memo), address(address), rho(rho), rseed(rseed), nullifier(nullifier), cmx(cmx) {}

    virtual ~OrchardNotePlaintext() = default;

    libzcash::OrchardPaymentAddressPirate GetAddress() const { return address; }

    static std::optional<OrchardNotePlaintext> AttemptDecryptOrchardAction(
        const orchard_bundle::Action* action,
        const libzcash::OrchardIncomingViewingKeyPirate& ivk);

    static std::optional<OrchardNotePlaintext> AttemptDecryptOrchardAction(
        const orchard_bundle::Action* action,
        const libzcash::OrchardOutgoingViewingKey& ovk);

    std::optional<OrchardNote> note() const;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(value_);      // 8 bytes
        READWRITE(address);     // 43 bytes
        READWRITE(memo_);       // 512 bytes
        READWRITE(rho);         // 32 bytes
        READWRITE(rseed);       // 32 bytes
        READWRITE(nullifier);   // 32 bytes
    }
};

class SaplingOutgoingPlaintext {
public:
    uint256 pk_d;
    uint256 esk;

    SaplingOutgoingPlaintext() = default;

    SaplingOutgoingPlaintext(uint256 pk_d, uint256 esk) : pk_d(pk_d), esk(esk) {}

    virtual ~SaplingOutgoingPlaintext() = default;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(pk_d);        // 32 bytes
        READWRITE(esk);         // 32 bytes
    }

    static std::optional<SaplingOutgoingPlaintext> decrypt(
        const SaplingOutCiphertext& ciphertext,
        const uint256& ovk,
        const uint256& cv,
        const uint256& cm,
        const uint256& epk);

    SaplingOutCiphertext encrypt(
        const uint256& ovk,
        const uint256& cv,
        const uint256& cm,
        SaplingNoteEncryption& enc) const;
};

// Definitions for helper functions
template <typename Stream>
inline void SerializeOrchardBundle(Stream& s, const orchard_bundle::Bundle& bundle) {
    s << bundle;
}

template <typename Stream>
inline void UnserializeOrchardBundle(Stream& s, orchard_bundle::Bundle& bundle) {
    s >> bundle;
}

template <typename Stream>
inline void SerializeOrchardAction(Stream& s, const orchard_bundle::Action& action) {
    s << action;
}

template <typename Stream>
inline void UnserializeOrchardAction(Stream& s, orchard_bundle::Action& action) {
    s >> action;
}

// Memory management utility for zeroing sensitive data
template <typename T>
void ZeroSecureMemory(T& obj) {
    std::memset(&obj, 0, sizeof(T));
}

// Orchard note plaintext encryption/decryption utilities
class OrchardNoteEncryption {
public:
    static std::optional<OrchardNotePlaintext> AttemptDecryptAction(
        const orchard_bundle::Action* action,
        const libzcash::OrchardIncomingViewingKeyPirate& ivk);

    static std::optional<OrchardNotePlaintext> AttemptDecryptAction(
        const orchard_bundle::Action* action,
        const libzcash::OrchardOutgoingViewingKey& ovk);

    static std::optional<OrchardNotePlaintext> DecryptNotePlaintext(
        const orchard_bundle::Action* action,
        const uint256& key_material);
};

// Placeholder for Sapling and Orchard constants
namespace Constants {
    constexpr size_t SaplingCiphertextSize = 512; // Example constant
    constexpr size_t OrchardCiphertextSize = 512;
}

// Utility functions for note management
namespace NoteUtils {
    template <typename Note>
    bool IsValid(const Note& note) {
        // Add validation logic for notes
        return true;
    }

    template <typename Plaintext>
    bool IsPlaintextValid(const Plaintext& plaintext) {
        // Add validation logic for note plaintexts
        return true;
    }
}

} // namespace libzcash

#endif // ZC_NOTE_H_
