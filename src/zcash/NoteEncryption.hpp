// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

/*
See the Zcash protocol specification for more information.
https://github.com/zcash/zips/blob/master/protocol/protocol.pdf
*/

#ifndef ZC_NOTE_ENCRYPTION_H_
#define ZC_NOTE_ENCRYPTION_H_

#include "uint256.h"
#include "uint252.h"

#include "zcash/Zcash.h"
#include "zcash/Address.hpp"

#include <array>

namespace libzcash {

// Ciphertext for the recipient to decrypt
typedef std::array<unsigned char, ZC_SAPLING_ENCCIPHERTEXT_SIZE> SaplingEncCiphertext;
typedef std::array<unsigned char, ZC_SAPLING_ENCPLAINTEXT_SIZE> SaplingEncPlaintext;

// Ciphertext for outgoing viewing key to decrypt
typedef std::array<unsigned char, ZC_SAPLING_OUTCIPHERTEXT_SIZE> SaplingOutCiphertext;
typedef std::array<unsigned char, ZC_SAPLING_OUTPLAINTEXT_SIZE> SaplingOutPlaintext;

//! This is not a thread-safe API.
class SaplingNoteEncryption {
protected:
    // Ephemeral public key
    uint256 epk;

    // Ephemeral secret key
    uint256 esk;

    // Flags to prevent multiple encryptions
    bool already_encrypted_enc;
    bool already_encrypted_out;

    // Constructor to initialize encryption keys
    SaplingNoteEncryption(uint256 epk, uint256 esk)
        : epk(epk), esk(esk), already_encrypted_enc(false), already_encrypted_out(false) {}

    // Destructor to securely cleanse keys
    ~SaplingNoteEncryption() {
        memory_cleanse(epk.begin(), epk.size());
        memory_cleanse(esk.begin(), esk.size());
    }

public:
    // Initialize note encryption from a diversifier
    static std::optional<SaplingNoteEncryption> FromDiversifier(diversifier_t d, uint256 esk);

    // Encrypts plaintext for the recipient using their public key
    std::optional<SaplingEncCiphertext> encrypt_to_recipient(
        const uint256 &pk_d,
        const SaplingEncPlaintext &message
    );

    // Encrypts plaintext for the sender's own viewing key
    SaplingOutCiphertext encrypt_to_ourselves(
        const uint256 &ovk,
        const uint256 &cv,
        const uint256 &cm,
        const SaplingOutPlaintext &message
    );

    // Returns the ephemeral public key
    uint256 get_epk() const {
        return epk;
    }

    // Returns the ephemeral secret key
    uint256 get_esk() const {
        return esk;
    }
};

// Attempts to decrypt a Sapling note. This will not check that the contents
// of the ciphertext are correct.
std::optional<SaplingEncPlaintext> AttemptSaplingEncDecryption(
    const SaplingEncCiphertext &ciphertext,
    const uint256 &ivk,
    const uint256 &epk
);

// Attempts to decrypt a Sapling note using outgoing plaintext.
// This will not check that the contents of the ciphertext are correct.
std::optional<SaplingEncPlaintext> AttemptSaplingEncDecryption(
    const SaplingEncCiphertext &ciphertext,
    const uint256 &epk,
    const uint256 &esk,
    const uint256 &pk_d
);

// Attempts to decrypt a Sapling note. This will not check that the contents
// of the ciphertext are correct.
std::optional<SaplingOutPlaintext> AttemptSaplingOutDecryption(
    const SaplingOutCiphertext &ciphertext,
    const uint256 &ovk,
    const uint256 &cv,
    const uint256 &cm,
    const uint256 &epk
);

template <size_t MLEN>
class NoteEncryption {
protected:
    enum { CLEN = MLEN + NOTEENCRYPTION_AUTH_BYTES };
    uint256 epk;
    uint256 esk;
    unsigned char nonce;
    uint256 hSig;

public:
    typedef std::array<unsigned char, CLEN> Ciphertext;
    typedef std::array<unsigned char, MLEN> Plaintext;

    // Constructor to initialize NoteEncryption
    NoteEncryption(uint256 hSig);

    // Destructor to securely cleanse keys
    ~NoteEncryption() {
        memory_cleanse(epk.begin(), epk.size());
        memory_cleanse(esk.begin(), esk.size());
    }

    // Gets the ephemeral secret key
    uint256 get_esk() {
        return esk;
    }

    // Gets the ephemeral public key
    uint256 get_epk() {
        return epk;
    }

    // Encrypts `message` with `pk_enc` and returns the ciphertext.
    // This is only called ZC_NUM_JS_OUTPUTS times for a given instantiation; 
    // but can be called 255 times before the nonce-space runs out.
    Ciphertext encrypt(const uint256 &pk_enc,
                       const Plaintext &message);

    // Creates a NoteEncryption private key
    static uint256 generate_privkey(const uint252 &a_sk);

    // Creates a NoteEncryption public key from a private key
    static uint256 generate_pubkey(const uint256 &sk_enc);
};

template <size_t MLEN>
class NoteDecryption {
protected:
    enum { CLEN = MLEN + NOTEENCRYPTION_AUTH_BYTES };
    uint256 sk_enc;
    uint256 pk_enc;

public:
    typedef std::array<unsigned char, CLEN> Ciphertext;
    typedef std::array<unsigned char, MLEN> Plaintext;

    NoteDecryption() {}
    NoteDecryption(uint256 sk_enc);

    // Decrypts the given ciphertext
    Plaintext decrypt(const Ciphertext &ciphertext,
                      const uint256 &epk,
                      const uint256 &hSig,
                      unsigned char nonce) const;

    // Compare NoteDecryption objects
    friend inline bool operator==(const NoteDecryption &a, const NoteDecryption &b) {
        return a.sk_enc == b.sk_enc && a.pk_enc == b.pk_enc;
    }
    friend inline bool operator<(const NoteDecryption &a, const NoteDecryption &b) {
        return (a.sk_enc < b.sk_enc ||
                (a.sk_enc == b.sk_enc && a.pk_enc < b.pk_enc));
    }
};

// Generate a random 256-bit number
uint256 random_uint256();

// Generate a random 252-bit number
uint252 random_uint252();

class note_decryption_failed : public std::runtime_error {
public:
    note_decryption_failed() : std::runtime_error("Could not decrypt message") {}
};

// Subclass PaymentDisclosureNoteDecryption provides a method to decrypt a note with esk.
template <size_t MLEN>
class PaymentDisclosureNoteDecryption : public NoteDecryption<MLEN> {
protected:
public:
    enum { CLEN = MLEN + NOTEENCRYPTION_AUTH_BYTES };
    typedef std::array<unsigned char, CLEN> Ciphertext;
    typedef std::array<unsigned char, MLEN> Plaintext;

    PaymentDisclosureNoteDecryption() : NoteDecryption<MLEN>() {}
    PaymentDisclosureNoteDecryption(uint256 sk_enc) : NoteDecryption<MLEN>(sk_enc) {}

    // Decrypts with esk
    Plaintext decryptWithEsk(
        const Ciphertext &ciphertext,
        const uint256 &pk_enc,
        const uint256 &esk,
        const uint256 &hSig,
        unsigned char nonce) const;
};

} // namespace libzcash

// Typedefs for Zcash-specific encryption and decryption
typedef libzcash::NoteEncryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteEncryption;
typedef libzcash::NoteDecryption<ZC_NOTEPLAINTEXT_SIZE> ZCNoteDecryption;

typedef libzcash::PaymentDisclosureNoteDecryption<ZC_NOTEPLAINTEXT_SIZE> ZCPaymentDisclosureNoteDecryption;

#endif /* ZC_NOTE_ENCRYPTION_H_ */

