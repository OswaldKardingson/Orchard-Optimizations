// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php .

#include "Note.hpp"
#include "prf.h"
#include "crypto/sha256.h"
#include "consensus/consensus.h"

#include "random.h"
#include "version.h"
#include "streams.h"

#include "zcash/util.h"
#include "librustzcash.h"

using namespace libzcash;

// Default constructor for SproutNote initializes random values for fields.
SproutNote::SproutNote()
{
    a_pk = random_uint256();
    rho = random_uint256();
    r = random_uint256();
}

// Compute the commitment for SproutNote using SHA256.
uint256 SproutNote::cm() const
{
    constexpr unsigned char discriminant = 0xb0;

    CSHA256 hasher;
    hasher.Write(&discriminant, 1);
    hasher.Write(a_pk.begin(), a_pk.size());

    auto value_vec = convertIntToVectorLE(value_);
    hasher.Write(value_vec.data(), value_vec.size());
    hasher.Write(rho.begin(), rho.size());
    hasher.Write(r.begin(), r.size());

    uint256 result;
    hasher.Finalize(result.begin());

    return result;
}

// Compute the nullifier for SproutNote using the spending key and rho.
uint256 SproutNote::nullifier(const SproutSpendingKey& a_sk) const
{
    return PRF_nf(a_sk, rho);
}

// Construct a SaplingNote with the specified payment address and value.
SaplingNote::SaplingNote(
    const SaplingPaymentAddress& address,
    const uint64_t value,
    Zip212Enabled zip212Enabled
) : BaseNote(value)
{
    d = address.d;
    pk_d = address.pk_d;
    zip_212_enabled = zip212Enabled;

    // Initialize rseed based on ZIP 212 rules.
    if (zip_212_enabled == Zip212Enabled::AfterZip212) {
        rseed = random_uint256();
    } else {
        librustzcash_sapling_generate_r(rseed.begin());
    }
}

// Compute the commitment for SaplingNote using librustzcash.
std::optional<uint256> SaplingNote::cmu() const
{
    uint256 result;
    uint256 rcm_tmp = rcm();
    if (!librustzcash_sapling_compute_cmu(
            d.data(),
            pk_d.begin(),
            value(),
            rcm_tmp.begin(),
            result.begin()))
    {
        return std::nullopt;
    }
    return result;
}

// Compute the nullifier for SaplingNote using librustzcash.
std::optional<uint256> SaplingNote::nullifier(const SaplingFullViewingKey& vk, const uint64_t position) const
{
    uint256 result;
    uint256 rcm_tmp = rcm();

    if (!librustzcash_sapling_compute_nf(
            d.data(),
            pk_d.begin(),
            value(),
            rcm_tmp.begin(),
            vk.ak.begin(),
            vk.nk.begin(),
            position,
            result.begin()))
    {
        return std::nullopt;
    }
    return result;
}

// Construct a SproutNotePlaintext from a SproutNote and memo.
SproutNotePlaintext::SproutNotePlaintext(
    const SproutNote& note,
    std::array<unsigned char, ZC_MEMO_SIZE> memo) 
    : BaseNotePlaintext(note, memo)
{
    rho = note.rho;
    r = note.r;
}

// Convert a SproutNotePlaintext into a SproutNote for the given payment address.
SproutNote SproutNotePlaintext::note(const SproutPaymentAddress& addr) const
{
    return SproutNote(addr.a_pk, value_, rho, r);
}

// Decrypt a SproutNotePlaintext using the provided decryptor and ciphertext.
SproutNotePlaintext SproutNotePlaintext::decrypt(
    const ZCNoteDecryption& decryptor,
    const ZCNoteDecryption::Ciphertext& ciphertext,
    const uint256& ephemeralKey,
    const uint256& h_sig,
    unsigned char nonce)
{
    auto plaintext = decryptor.decrypt(ciphertext, ephemeralKey, h_sig, nonce);

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << plaintext;

    SproutNotePlaintext ret;
    ss >> ret;

    // Ensure no residual data remains after deserialization.
    assert(ss.size() == 0);

    return ret;
}

// Encrypt a SproutNotePlaintext using the provided encryptor and encryption key.
ZCNoteEncryption::Ciphertext SproutNotePlaintext::encrypt(
    ZCNoteEncryption& encryptor,
    const uint256& pk_enc) const
{
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    ZCNoteEncryption::Plaintext pt;

    // Ensure plaintext size matches the serialized size.
    assert(pt.size() == ss.size());

    // Use std::copy for memory safety.
    std::copy(ss.begin(), ss.end(), pt.begin());

    return encryptor.encrypt(pk_enc, pt);
}

// Construct a SaplingNotePlaintext from a SaplingNote and memo.
SaplingNotePlaintext::SaplingNotePlaintext(
    const SaplingNote& note,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
    : BaseNotePlaintext(note, memo)
{
    d = note.d;
    rseed = note.rseed;

    // Set the lead byte based on ZIP 212 compatibility.
    leadbyte = (note.get_zip_212_enabled() == libzcash::Zip212Enabled::AfterZip212) ? 0x02 : 0x01;
}

// Convert a SaplingNotePlaintext into a SaplingNote for the given viewing key.
std::optional<SaplingNote> SaplingNotePlaintext::note(
    const SaplingIncomingViewingKey& ivk) const
{
    auto addr = ivk.address(d);
    if (addr) {
        Zip212Enabled zip_212_enabled = (leadbyte == 0x01) ? Zip212Enabled::BeforeZip212 : Zip212Enabled::AfterZip212;
        return SaplingNote{d, addr.value().pk_d, value_, rseed, zip_212_enabled};
    }
    return std::nullopt;
}

// Decrypt a SaplingOutgoingPlaintext from ciphertext using the given parameters.
std::optional<SaplingOutgoingPlaintext> SaplingOutgoingPlaintext::decrypt(
    const SaplingOutCiphertext& ciphertext,
    const uint256& ovk,
    const uint256& cv,
    const uint256& cm,
    const uint256& epk)
{
    auto pt = AttemptSaplingOutDecryption(ciphertext, ovk, cv, cm, epk);
    if (!pt) {
        return std::nullopt;
    }

    try {
        // Deserialize from plaintext.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << pt.value();
        SaplingOutgoingPlaintext ret;
        ss >> ret;

        // Ensure no residual data remains after deserialization.
        assert(ss.size() == 0);
        return ret;
    } catch (const boost::thread_interrupted&) {
        throw;
    } catch (...) {
        return std::nullopt;
    }
}

// Decrypt a SaplingNotePlaintext from ciphertext using the given parameters.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::decrypt(
    const Consensus::Params& params,
    int height,
    const SaplingEncCiphertext& ciphertext,
    const uint256& ivk,
    const uint256& epk,
    const uint256& cmu)
{
    auto ret = attempt_sapling_enc_decryption_deserialization(ciphertext, ivk, epk);

    if (!ret) {
        return std::nullopt;
    }

    const SaplingNotePlaintext& plaintext = *ret;

    // Check that the lead byte is allowed at the given block height.
    if (!plaintext_version_is_valid(params, height, plaintext.get_leadbyte())) {
        return std::nullopt;
    }

    return plaintext_checks_without_height(plaintext, ivk, epk, cmu);
}

// Attempt decryption and deserialization of a SaplingNotePlaintext.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::attempt_sapling_enc_decryption_deserialization(
    const SaplingEncCiphertext& ciphertext,
    const uint256& ivk,
    const uint256& epk)
{
    auto encPlaintext = AttemptSaplingEncDecryption(ciphertext, ivk, epk);

    if (!encPlaintext) {
        return std::nullopt;
    }

    try {
        // Deserialize from plaintext.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << encPlaintext.value();
        SaplingNotePlaintext ret;
        ss >> ret;

        // Ensure no extra data remains in the stream.
        assert(ss.size() == 0);
        return ret;
    } catch (const boost::thread_interrupted&) {
        throw;
    } catch (...) {
        return std::nullopt;
    }
}

// Validate a SaplingNotePlaintext without considering block height.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::plaintext_checks_without_height(
    const SaplingNotePlaintext& plaintext,
    const uint256& ivk,
    const uint256& epk,
    const uint256& cmu)
{
    uint256 pk_d;
    if (!librustzcash_ivk_to_pkd(ivk.begin(), plaintext.d.data(), pk_d.begin())) {
        return std::nullopt;
    }

    uint256 cmu_expected;
    uint256 rcm = plaintext.rcm();
    if (!librustzcash_sapling_compute_cmu(
            plaintext.d.data(),
            pk_d.begin(),
            plaintext.value(),
            rcm.begin(),
            cmu_expected.begin()))
    {
        return std::nullopt;
    }

    if (cmu_expected != cmu) {
        return std::nullopt;
    }

    if (plaintext.get_leadbyte() != 0x01) {
        // ZIP 212: Check consistency of epk to prevent linkability attacks.
        uint256 expected_epk;
        uint256 esk = plaintext.generate_or_derive_esk();
        if (!librustzcash_sapling_ka_derivepublic(plaintext.d.data(), esk.begin(), expected_epk.begin())) {
            return std::nullopt;
        }
        if (expected_epk != epk) {
            return std::nullopt;
        }
    }

    return plaintext;
}

// Decrypt a SaplingNotePlaintext with explicit Esk and PK_D parameters.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::decrypt(
    const Consensus::Params& params,
    int height,
    const SaplingEncCiphertext& ciphertext,
    const uint256& epk,
    const uint256& esk,
    const uint256& pk_d,
    const uint256& cmu)
{
    auto ret = attempt_sapling_enc_decryption_deserialization(ciphertext, epk, esk, pk_d);

    if (!ret) {
        return std::nullopt;
    }

    SaplingNotePlaintext plaintext = *ret;

    // Validate the lead byte for the given block height.
    if (!plaintext_version_is_valid(params, height, plaintext.get_leadbyte())) {
        return std::nullopt;
    }

    return plaintext_checks_without_height(plaintext, epk, esk, pk_d, cmu);
}

// Attempt decryption and deserialization of a SaplingNotePlaintext with Esk and PK_D.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::attempt_sapling_enc_decryption_deserialization(
    const SaplingEncCiphertext& ciphertext,
    const uint256& epk,
    const uint256& esk,
    const uint256& pk_d)
{
    auto encPlaintext = AttemptSaplingEncDecryption(ciphertext, epk, esk, pk_d);

    if (!encPlaintext) {
        return std::nullopt;
    }

    try {
        // Deserialize from plaintext.
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << encPlaintext.value();
        SaplingNotePlaintext ret;
        ss >> ret;

        // Ensure no extra data remains in the stream.
        assert(ss.size() == 0);
        return ret;
    } catch (const boost::thread_interrupted&) {
        throw;
    } catch (...) {
        return std::nullopt;
    }
}

// Validate a SaplingNotePlaintext without considering block height.
std::optional<SaplingNotePlaintext> SaplingNotePlaintext::plaintext_checks_without_height(
    const SaplingNotePlaintext& plaintext,
    const uint256& epk,
    const uint256& esk,
    const uint256& pk_d,
    const uint256& cmu)
{
    // Verify that epk is consistent with esk.
    uint256 expected_epk;
    if (!librustzcash_sapling_ka_derivepublic(plaintext.d.data(), esk.begin(), expected_epk.begin())) {
        return std::nullopt;
    }
    if (expected_epk != epk) {
        return std::nullopt;
    }

    // Compute and validate the expected commitment.
    uint256 cmu_expected;
    uint256 rcm = plaintext.rcm();
    if (!librustzcash_sapling_compute_cmu(
            plaintext.d.data(),
            pk_d.begin(),
            plaintext.value(),
            rcm.begin(),
            cmu_expected.begin()))
    {
        return std::nullopt;
    }

    if (cmu_expected != cmu) {
        return std::nullopt;
    }

    // For ZIP 212: Check if esk is consistent with the derived value.
    if (plaintext.get_leadbyte() != 0x01) {
        if (esk != plaintext.generate_or_derive_esk()) {
            return std::nullopt;
        }
    }

    return plaintext;
}

// Encrypt a SaplingNotePlaintext and return the result.
std::optional<SaplingNotePlaintextEncryptionResult> SaplingNotePlaintext::encrypt(const uint256& pk_d) const
{
    // Get the encryptor.
    auto sne = SaplingNoteEncryption::FromDiversifier(d, generate_or_derive_esk());
    if (!sne) {
        return std::nullopt;
    }
    auto enc = sne.value();

    // Create the plaintext.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    SaplingEncPlaintext pt;
    assert(pt.size() == ss.size());
    std::copy(ss.begin(), ss.end(), pt.begin());

    // Encrypt the plaintext.
    auto encciphertext = enc.encrypt_to_recipient(pk_d, pt);
    if (!encciphertext) {
        return std::nullopt;
    }

    return SaplingNotePlaintextEncryptionResult(encciphertext.value(), enc);
}

// Encrypt a SaplingOutgoingPlaintext.
SaplingOutCiphertext SaplingOutgoingPlaintext::encrypt(
    const uint256& ovk,
    const uint256& cv,
    const uint256& cm,
    SaplingNoteEncryption& enc) const
{
    // Create the plaintext.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    SaplingOutPlaintext pt;
    assert(pt.size() == ss.size());
    std::copy(ss.begin(), ss.end(), pt.begin());

    // Encrypt using the provided encryption parameters.
    return enc.encrypt_to_ourselves(ovk, cv, cm, pt);
}

// Compute the random commitment (rcm) for a SaplingNotePlaintext.
uint256 SaplingNotePlaintext::rcm() const
{
    if (leadbyte != 0x01) {
        return PRF_rcm(rseed);
    } else {
        return rseed;
    }
}

// Compute the random commitment (rcm) for a SaplingNote.
uint256 SaplingNote::rcm() const
{
    if (SaplingNote::get_zip_212_enabled() == libzcash::Zip212Enabled::AfterZip212) {
        return PRF_rcm(rseed);
    } else {
        return rseed;
    }
}

// Generate or derive the encryption secret key (esk) for a SaplingNotePlaintext.
uint256 SaplingNotePlaintext::generate_or_derive_esk() const
{
    if (leadbyte != 0x01) {
        return PRF_esk(rseed);
    } else {
        uint256 esk;
        // Generate a random esk value.
        librustzcash_sapling_generate_r(esk.begin());
        return esk;
    }
}

// Convert an OrchardNotePlaintext into an OrchardNote.
std::optional<OrchardNote> OrchardNotePlaintext::note() const
{
    return OrchardNote(address, value_, rho, rseed, cmx);
}

// SaplingOutCiphertext encryption implementation.
SaplingOutCiphertext SaplingOutgoingPlaintext::encrypt(
    const uint256& ovk,
    const uint256& cv,
    const uint256& cm,
    SaplingNoteEncryption& enc) const
{
    // Create the plaintext for encryption.
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << (*this);

    SaplingOutPlaintext pt;
    assert(pt.size() == ss.size());
    std::copy(ss.begin(), ss.end(), pt.begin());

    // Encrypt using the provided SaplingNoteEncryption object.
    return enc.encrypt_to_ourselves(ovk, cv, cm, pt);
}

// Generate or derive the encryption secret key (esk) for a SaplingNote.
uint256 SaplingNote::generate_or_derive_esk() const
{
    if (get_zip_212_enabled() == libzcash::Zip212Enabled::AfterZip212) {
        // Derive esk using PRF_esk.
        return PRF_esk(rseed);
    } else {
        // Generate a random esk for pre-ZIP 212 notes.
        uint256 esk;
        librustzcash_sapling_generate_r(esk.begin());
        return esk;
    }
}

// OrchardNotePlaintext: Convert the plaintext into an OrchardNote.
std::optional<OrchardNote> OrchardNotePlaintext::note() const
{
    // Create and return the OrchardNote.
    return OrchardNote(address, value_, rho, rseed, cmx);
}
