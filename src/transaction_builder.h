// Copyright (c) 2018 The Zcash developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Copyright (c) 2018 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRANSACTION_BUILDER_H
#define TRANSACTION_BUILDER_H

#include "consensus/params.h"
#include "keystore.h"
#include "primitives/transaction.h"
#include "script/script.h"
#include "script/standard.h"
#include "serialize.h"
#include "streams.h"
#include "uint256.h"
#include "zcash/Address.hpp"
#include "zcash/IncrementalMerkleTree.hpp"
#include "zcash/Note.hpp"
#include "zcash/NoteEncryption.hpp"
#include "zcash/memo.h"

#include <optional>

uint256 ProduceShieldedSignatureHash(
    uint32_t consensusBranchId,
    const CTransaction& tx,
    const std::vector<CTxOut>& allPrevOutputs,
    const sapling::UnauthorizedBundle& saplingBundle,
    const std::optional<orchard::UnauthorizedBundle>& orchardBundle);

namespace orchard
{

/// Constructs an `UnauthorizedBundle` from notes to be spent and recipients to receive funds.
class Builder
{
private:
    /// Pointer to the Orchard builder allocated by Rust.
    std::unique_ptr<OrchardBuilderPtr, decltype(&orchard_builder_free)> inner;
    bool hasActions{false};

    /// Private constructor for internal usage.
    Builder() : inner(nullptr, orchard_builder_free), hasActions(false) {}

public:
    /// Initializes the Orchard builder with the specified anchor and flags.
    Builder(bool spendsEnabled, bool outputsEnabled, uint256 anchor);

    // Disable copy operations to prevent accidental duplication.
    Builder(const Builder&) = delete;
    Builder& operator=(const Builder&) = delete;

    // Move constructor and assignment.
    Builder(Builder&& builder) : inner(std::move(builder.inner)) {}
    Builder& operator=(Builder&& builder)
    {
        if (this != &builder) {
            inner = std::move(builder.inner);
        }
        return *this;
    }

    /// Destructor to cleanse sensitive data and release Rust memory.
    ~Builder() {
        inner.reset();
        hasActions = false; // Explicitly reset flags
    }

    /// Adds a note's serialized parts to be spent in this bundle.
    ///
    /// - Returns `false` if deserialization or note construction fails.
    /// - Validates the Merkle path against the provided anchor.
    /// - Ensures no sensitive data is leaked on failure.
    bool AddSpendFromParts(
        const libzcash::OrchardFullViewingKeyPirate fvk,
        const libzcash::OrchardPaymentAddressPirate addr,
        const CAmount value,
        const uint256 rho,
        const uint256 rseed,
        const libzcash::MerklePath orchardMerklePath);

    /// Adds an address which will receive funds in this bundle.
    ///
    /// - Accepts an optional outgoing viewing key (`ovk`) for recipient tracing.
    /// - Ensures memo data is securely serialized and handled.
    bool AddOutput(
        const std::optional<uint256>& ovk,
        const libzcash::OrchardPaymentAddressPirate& to,
        CAmount value,
        const std::array<unsigned char, ZC_MEMO_SIZE> memo);

    /// Returns `true` if any spends or outputs have been added to this builder.
    /// Prevents unnecessary `Build()` calls for empty bundles.
    bool HasActions() const {
        return hasActions;
    }

    /// Builds a bundle containing the given spent notes and recipients.
    ///
    /// - Invalidates this object on success or failure.
    /// - Returns `std::nullopt` if an error occurs.
    /// - Ensures secure cleanup of any intermediate state on failure.
    std::optional<UnauthorizedBundle> Build();
};

/// Represents an unauthorized Orchard bundle, ready for proof generation and signing.
class UnauthorizedBundle
{
private:
    /// Pointer to the Orchard bundle allocated by Rust.
    std::unique_ptr<OrchardUnauthorizedBundlePtr, decltype(&orchard_unauthorized_bundle_free)> inner;

    /// Private constructor for internal usage.
    UnauthorizedBundle() : inner(nullptr, orchard_unauthorized_bundle_free) {}
    UnauthorizedBundle(OrchardUnauthorizedBundlePtr* bundle) : inner(bundle, orchard_unauthorized_bundle_free) {}

    // Grant `Builder` access to internal members.
    friend class Builder;

    // Grant `ProduceShieldedSignatureHash` access to internal members.
    friend uint256(::ProduceShieldedSignatureHash(
        uint32_t consensusBranchId,
        const CTransaction& tx,
        const std::vector<CTxOut>& allPrevOutputs,
        const sapling::UnauthorizedBundle& saplingBundle,
        const std::optional<orchard::UnauthorizedBundle>& orchardBundle));

public:
    // Disable copy operations to prevent accidental duplication.
    UnauthorizedBundle(const UnauthorizedBundle&) = delete;
    UnauthorizedBundle& operator=(const UnauthorizedBundle&) = delete;

    // Move constructor and assignment.
    UnauthorizedBundle(UnauthorizedBundle&& bundle) : inner(std::move(bundle.inner)) {}
    UnauthorizedBundle& operator=(UnauthorizedBundle&& bundle)
    {
        if (this != &bundle) {
            inner = std::move(bundle.inner);
        }
        return *this;
    }

    /// Destructor to cleanse sensitive data and release Rust memory.
    ~UnauthorizedBundle() {
        inner.reset();
    }

    /// Adds proofs and signatures to the bundle.
    ///
    /// - Invalidates this object on success or failure.
    /// - Returns `std::nullopt` if an error occurs.
    /// - Ensures secure handling of sensitive data during proof generation.
    std::optional<OrchardBundle> ProveAndSign(
        libzcash::OrchardSpendingKeyPirate keys,
        uint256 sighash);
};

class SaplingSpendDescriptionInfo
{
public:
    SaplingOutPoint op;
    libzcash::SaplingPaymentAddress addr;
    CAmount value;
    uint256 rcm;
    libzcash::MerklePath saplingMerklePath;
    uint256 anchor;

    SaplingSpendDescriptionInfo() {}

    SaplingSpendDescriptionInfo(
        SaplingOutPoint opIn,
        libzcash::SaplingPaymentAddress addrIn,
        CAmount valueIn,
        uint256 rcmIn,
        libzcash::MerklePath saplingMerklePathIn,
        uint256 anchorIn)
        : op(opIn), addr(addrIn), value(valueIn), rcm(rcmIn), saplingMerklePath(saplingMerklePathIn), anchor(anchorIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(op);
        READWRITE(addr);
        READWRITE(value);
        READWRITE(rcm);
        READWRITE(saplingMerklePath);
        READWRITE(anchor);
    }
};

class OrchardSpendDescriptionInfo
{
public:
    OrchardOutPoint op;
    libzcash::OrchardPaymentAddressPirate addr;
    CAmount value;
    uint256 rho;
    uint256 rseed;
    libzcash::MerklePath orchardMerklePath;
    uint256 anchor;

    OrchardSpendDescriptionInfo() {}

    OrchardSpendDescriptionInfo(
        OrchardOutPoint opIn,
        libzcash::OrchardPaymentAddressPirate addrIn,
        CAmount valueIn,
        uint256 rhoIn,
        uint256 rseedIn,
        libzcash::MerklePath orchardMerklePathIn,
        uint256 anchorIn)
        : op(opIn), addr(addrIn), value(valueIn), rho(rhoIn), rseed(rseedIn), orchardMerklePath(orchardMerklePathIn), anchor(anchorIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(op);
        READWRITE(addr);
        READWRITE(value);
        READWRITE(rho);
        READWRITE(rseed);
        READWRITE(orchardMerklePath);
        READWRITE(anchor);
    }
};

class SaplingOutputDescriptionInfo
{
public:
    libzcash::SaplingPaymentAddress addr;
    CAmount value;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;

    SaplingOutputDescriptionInfo() {}
    SaplingOutputDescriptionInfo(
        libzcash::SaplingPaymentAddress addrIn,
        CAmount valueIn,
        std::array<unsigned char, ZC_MEMO_SIZE> memoIn)
        : addr(addrIn), value(valueIn), memo(memoIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(addr);
        READWRITE(value);
        READWRITE(memo);
    }
};

class OrchardOutputDescriptionInfo
{
public:
    libzcash::OrchardPaymentAddressPirate addr;
    CAmount value;
    std::array<unsigned char, ZC_MEMO_SIZE> memo;

    OrchardOutputDescriptionInfo() {}
    OrchardOutputDescriptionInfo(
        libzcash::OrchardPaymentAddressPirate addrIn,
        CAmount valueIn,
        std::array<unsigned char, ZC_MEMO_SIZE> memoIn)
        : addr(addrIn), value(valueIn), memo(memoIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(addr);
        READWRITE(value);
        READWRITE(memo);
    }
};

struct TransparentInputInfo {
    CScript scriptPubKey;
    CAmount value;

    TransparentInputInfo(
        CScript scriptPubKey,
        CAmount value)
        : scriptPubKey(scriptPubKey), value(value) {}
};

class TransactionBuilderResult
{
private:
    std::optional<CTransaction> maybeTx;
    std::optional<std::string> maybeError;

public:
    TransactionBuilderResult() = delete;
    TransactionBuilderResult(const CTransaction& tx) : maybeTx(tx), maybeError(std::nullopt) {}
    TransactionBuilderResult(const std::string& error) : maybeTx(std::nullopt), maybeError(error) {}

    bool IsTx() const {
        return maybeTx.has_value();
    }

    bool IsError() const {
        return maybeError.has_value();
    }

    CTransaction GetTxOrThrow() const {
        if (!maybeTx.has_value()) {
            throw std::runtime_error("No transaction available: " + maybeError.value_or("Unknown error"));
        }
        return maybeTx.value();
    }

    std::string GetError() const {
        if (!maybeError.has_value()) {
            throw std::runtime_error("No error present.");
        }
        return maybeError.value();
    }
};

class TransactionBuilder
{
private:
    Consensus::Params consensusParams;
    int nHeight = 0;
    const CKeyStore* keystore;
    CMutableTransaction mtx;
    CAmount fee = 10000;
    int iMinConf = 1;
    uint32_t consensusBranchId;
    std::string strNetworkID = "main";
    uint16_t checksum = 0xFFFF;

    std::vector<CTxOut> tIns;

    std::optional<SaplingBundle> saplingBundle;
    std::optional<OrchardBundle> orchardBundle;

    std::optional<orchard::Builder> orchardBuilder;
    CAmount valueBalanceSapling = 0;
    rust::Box<sapling::Builder> saplingBuilder;
    CAmount valueBalanceOrchard = 0;

    std::optional<std::pair<uint256, libzcash::SaplingPaymentAddress>> firstSaplingSpendAddr;
    std::optional<std::pair<uint256, libzcash::SaplingPaymentAddress>> saplingChangeAddr;

    std::vector<libzcash::OrchardSpendingKeyPirate> orchardSpendingKeys;
    std::optional<std::pair<uint256, libzcash::OrchardPaymentAddressPirate>> firstOrchardSpendAddr;
    std::optional<std::pair<uint256, libzcash::OrchardPaymentAddressPirate>> orchardChangeAddr;

    std::optional<CTxDestination> tChangeAddr;
    std::optional<CScript> opReturn;

    bool AddOpRetLast(CScript& s);

    const rust::Box<consensus::Network> RustNetwork() const
    {
        return consensus::network(
            strNetworkID,
            consensusParams.vUpgrades[Consensus::UPGRADE_OVERWINTER].nActivationHeight,
            consensusParams.vUpgrades[Consensus::UPGRADE_SAPLING].nActivationHeight,
            consensusParams.vUpgrades[Consensus::UPGRADE_ORCHARD].nActivationHeight);
    }

public:
    std::vector<SaplingSpendDescriptionInfo> vSaplingSpends;
    std::vector<SaplingOutputDescriptionInfo> vSaplingOutputs;

    std::vector<OrchardSpendDescriptionInfo> vOrchardSpends;
    std::vector<OrchardOutputDescriptionInfo> vOrchardOutputs;

    TransactionBuilder();
    TransactionBuilder(const Consensus::Params& consensusParams, int nHeight, CKeyStore* keyStore = nullptr);

    // TransactionBuilder should never be copied
    TransactionBuilder(const TransactionBuilder&) = delete;
    TransactionBuilder& operator=(const TransactionBuilder&) = delete;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(consensusParams);
        READWRITE(consensusBranchId);
        READWRITE(strNetworkID);
        READWRITE(nHeight);
        READWRITE(mtx);
        READWRITE(vSaplingSpends);
        READWRITE(vSaplingOutputs);
        READWRITE(vOrchardSpends);
        READWRITE(vOrchardOutputs);
        READWRITE(fee);
        READWRITE(checksum);
    }
};

    // Transaction Builder initialization functions
    void InitializeTransactionBuilder(const Consensus::Params& consensusParams, int nHeight);
    void SetFee(CAmount fee);
    void SetMinConfirmations(int iMinConf);
    void SetExpiryHeight(int expHeight);
    void SetLockTime(uint32_t time) { this->mtx.nLockTime = time; }

    // Validate datastream with crc16 Checksum
    uint16_t CalculateChecksum();
    void SetChecksum();
    uint16_t GetChecksum();
    bool ValidateChecksum();

    // Return the underlying mutable transaction
    CTransaction getTransaction() { return mtx; }

    // Sapling
    void InitializeSapling();

    bool AddSaplingSpendRaw(
        SaplingOutPoint op,
        libzcash::SaplingPaymentAddress addr,
        CAmount value,
        uint256 rcm,
        libzcash::MerklePath saplingMerklePath,
        uint256 anchor);

    bool ConvertRawSaplingSpend(libzcash::SaplingExtendedSpendingKey extsk);

    bool AddSaplingOutputRaw(
        libzcash::SaplingPaymentAddress to,
        CAmount value,
        std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0}});

    bool ConvertRawSaplingOutput(uint256 ovk);

    // Orchard
    void InitializeOrchard(
        bool spendsEnabled,
        bool outputsEnabled,
        uint256 anchor);

    bool AddOrchardSpendRaw(
        OrchardOutPoint op,
        libzcash::OrchardPaymentAddressPirate addr,
        CAmount value,
        uint256 rho,
        uint256 rseed,
        libzcash::MerklePath orchardMerklePath,
        uint256 anchor);

    bool ConvertRawOrchardSpend(libzcash::OrchardExtendedSpendingKeyPirate extsk);

    bool AddOrchardOutputRaw(
        libzcash::OrchardPaymentAddressPirate to,
        CAmount value,
        std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0}});

    bool ConvertRawOrchardOutput(uint256 ovk);

    // Transparent Addresses
    void AddTransparentInput(COutPoint utxo, CScript scriptPubKey, CAmount value, uint32_t nSequence = 0xffffffff);

    bool AddTransparentOutput(CTxDestination& to, CAmount value);

    void AddOpRet(CScript& s);

    bool AddOpRetLast();

    // Change
    void SendChangeTo(libzcash::OrchardPaymentAddressPirate changeAddr, uint256 ovk);

    void SendChangeTo(libzcash::SaplingPaymentAddress changeAddr, uint256 ovk);

    bool SendChangeTo(CTxDestination& changeAddr);

    TransactionBuilderResult Build();
};

#endif /* TRANSACTION_BUILDER_H */

