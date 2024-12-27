// Copyright (c) 2018 The Zcash developers
// Copyright (c) 2021-2024 The Pirate developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transaction_builder.h"

#include "core_io.h" //for EncodeHexTx
#include "key_io.h"
#include "main.h"
#include "pubkey.h"
#include "rpc/protocol.h"
#include "script/sign.h"
#include "utilmoneystr.h"
#include "zcash/Note.hpp"

#include <librustzcash.h>

uint256 ProduceShieldedSignatureHash(
    uint32_t consensusBranchId,
    const CTransaction& tx,
    const std::vector<CTxOut>& allPrevOutputs,
    const sapling::UnauthorizedBundle& saplingBundle,
    const std::optional<orchard::UnauthorizedBundle>& orchardBundle)
{
    CDataStream sTx(SER_NETWORK, PROTOCOL_VERSION);
    sTx << tx;

    CDataStream sAllPrevOutputs(SER_NETWORK, PROTOCOL_VERSION);
    sAllPrevOutputs << allPrevOutputs;

    if (sTx.empty() || sAllPrevOutputs.empty()) {
        throw std::logic_error("ProduceShieldedSignatureHash: Empty data streams detected");
    }

    const OrchardUnauthorizedBundlePtr* orchardBundlePtr;
    if (orchardBundle.has_value()) {
        orchardBundlePtr = orchardBundle->inner.get();
    } else {
        orchardBundlePtr = nullptr;
    }

    auto dataToBeSigned = builder::shielded_signature_digest(
        consensusBranchId,
        {reinterpret_cast<const unsigned char*>(sTx.data()), sTx.size()},
        {reinterpret_cast<const unsigned char*>(sAllPrevOutputs.data()), sAllPrevOutputs.size()},
        saplingBundle,
        orchardBundlePtr);

    if (dataToBeSigned.empty()) {
        throw std::runtime_error("ProduceShieldedSignatureHash: Failed to generate signature hash");
    }

    return uint256::FromRawBytes(dataToBeSigned);
}

bool Builder::AddSpendFromParts(
    const libzcash::OrchardFullViewingKeyPirate fvk,
    const libzcash::OrchardPaymentAddressPirate addr,
    const CAmount value,
    const uint256 rho,
    const uint256 rseed,
    const libzcash::MerklePath orchardMerklePath)
{
    if (!inner) {
        throw std::logic_error("orchard::Builder has already been used");
    }

    // Serialize Full Viewing Key
    CDataStream ssfvk(SER_NETWORK, PROTOCOL_VERSION);
    ssfvk << fvk;
    if (ssfvk.empty()) {
        throw std::runtime_error("AddSpendFromParts: Failed to serialize FullViewingKey");
    }
    std::array<unsigned char, 96> fvk_t;
    std::move(ssfvk.begin(), ssfvk.end(), fvk_t.begin());

    // Serialize Payment Address
    CDataStream ssaddr(SER_NETWORK, PROTOCOL_VERSION);
    ssaddr << addr;
    if (ssaddr.empty()) {
        throw std::runtime_error("AddSpendFromParts: Failed to serialize PaymentAddress");
    }
    std::array<unsigned char, 43> addr_t;
    std::move(ssaddr.begin(), ssaddr.end(), addr_t.begin());

    // Serialize Merkle Path
    CDataStream ssMerklePath(SER_NETWORK, PROTOCOL_VERSION);
    ssMerklePath << orchardMerklePath;
    if (ssMerklePath.empty()) {
        throw std::runtime_error("AddSpendFromParts: Failed to serialize MerklePath");
    }
    std::array<unsigned char, 1065> merklepath_t;
    std::move(ssMerklePath.begin(), ssMerklePath.end(), merklepath_t.begin());

    if (orchard_builder_add_spend_from_parts(
            inner.get(),
            fvk_t.begin(),
            addr_t.begin(),
            value,
            rho.begin(),
            rseed.begin(),
            merklepath_t.begin())) {
        hasActions = true;

        // Clear sensitive memory
        memory_cleanse(fvk_t.data(), fvk_t.size());
        memory_cleanse(addr_t.data(), addr_t.size());
        memory_cleanse(merklepath_t.data(), merklepath_t.size());

        return true;
    } else {
        // Clear sensitive memory on failure
        memory_cleanse(fvk_t.data(), fvk_t.size());
        memory_cleanse(addr_t.data(), addr_t.size());
        memory_cleanse(merklepath_t.data(), merklepath_t.size());

        return false;
    }
}

bool Builder::AddOutput(
    const std::optional<uint256>& ovk,
    const libzcash::OrchardPaymentAddressPirate& to,
    CAmount value,
    const std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    if (!inner) {
        throw std::logic_error("orchard::Builder has already been used");
    }

    // Check for valid output value
    if (value <= 0) {
        throw std::invalid_argument("AddOutput: Output value must be greater than zero");
    }

    // Ensure memo size is valid
    if (memo.size() != ZC_MEMO_SIZE) {
        throw std::runtime_error("AddOutput: Invalid memo size");
    }

    // Call Rust FFI to add recipient
    if (!orchard_builder_add_recipient(
            inner.get(),
            ovk.has_value() ? ovk->begin() : nullptr,
            to.ToBytes().data(),
            value,
            memo.begin())) {
        return false;
    }

    hasActions = true;
    return true;
}

std::optional<UnauthorizedBundle> Builder::Build()
{
    if (!inner) {
        throw std::logic_error("orchard::Builder has already been used");
    }

    auto bundle = orchard_builder_build(inner.release());
    if (bundle == nullptr) {
        return std::nullopt;
    }

    // Validate the resulting bundle
    if (!bundle->is_valid()) {
        throw std::runtime_error("Build: Invalid Orchard bundle created");
    }

    return UnauthorizedBundle(bundle);
}

std::optional<OrchardBundle> UnauthorizedBundle::ProveAndSign(
    libzcash::OrchardSpendingKeyPirate key,
    uint256 sighash)
{
    if (!inner) {
        throw std::logic_error("orchard::UnauthorizedBundle has already been used");
    }

    // Validate Spending Key
    if (!key.IsValid()) {
        throw std::invalid_argument("ProveAndSign: Invalid Orchard Spending Key provided");
    }

    // Validate Signature Hash
    if (sighash.IsNull()) {
        throw std::invalid_argument("ProveAndSign: Signature hash is null");
    }

    auto authorizedBundle = orchard_unauthorized_bundle_prove_and_sign(
        inner.release(),
        key.sk.begin(),
        sighash.begin());

    if (authorizedBundle == nullptr) {
        throw std::runtime_error("ProveAndSign: Failed to create Orchard proof or signatures");
    }

    return OrchardBundle(authorizedBundle);
}

TransactionBuilderResult::TransactionBuilderResult(const CTransaction& tx) : maybeTx(tx)
{
    if (!tx.IsValid()) {
        throw std::invalid_argument("TransactionBuilderResult: Invalid transaction provided");
    }
}

TransactionBuilderResult::TransactionBuilderResult(const std::string& error) : maybeError(error)
{
    if (error.empty()) {
        throw std::invalid_argument("TransactionBuilderResult: Error message cannot be empty");
    }
}

bool TransactionBuilderResult::IsTx()
{
    return maybeTx != std::nullopt;
}

bool TransactionBuilderResult::IsError()
{
    return maybeError != std::nullopt;
}

CTransaction TransactionBuilderResult::GetTxOrThrow()
{
    if (maybeTx) {
        return maybeTx.value();
    } else {
        throw JSONRPCError(RPC_WALLET_ERROR, "Failed to build transaction: " + GetError());
    }
}

std::string TransactionBuilderResult::GetError()
{
    if (maybeError) {
        return maybeError.value();
    } else {
        throw std::runtime_error("TransactionBuilderResult: No error message available");
    }
}

TransactionBuilder::TransactionBuilder() : saplingBuilder(sapling::new_builder(*RustNetwork(), 1))
{
    // Set the network the transactions will be submitted to (main, test, or regtest)
    strNetworkID = Params().NetworkIDString();
    if (strNetworkID.empty()) {
        throw std::runtime_error("TransactionBuilder: Failed to determine network ID");
    }
}

TransactionBuilder::TransactionBuilder(
    const Consensus::Params& consensusParams,
    int nHeight,
    CKeyStore* keystore) : consensusParams(consensusParams),
                           nHeight(nHeight),
                           keystore(keystore),
                           saplingBuilder(sapling::new_builder(*RustNetwork(), nHeight))
{
    // Ensure valid network height
    if (nHeight < 0) {
        throw std::invalid_argument("TransactionBuilder: Height must be non-negative");
    }

    // Create a new mutable transaction to build on
    mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);

    // Set the consensus ID of the chain
    consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Set the network the transactions will be submitted to
    strNetworkID = Params().NetworkIDString();
    if (strNetworkID.empty()) {
        throw std::runtime_error("TransactionBuilder: Failed to determine network ID");
    }

    // Initialize the Sapling builder for Sapling-compatible transactions
    if (mtx.nVersion >= SAPLING_MIN_TX_VERSION) {
        saplingBuilder = std::move(sapling::new_builder(*RustNetwork(), nHeight));
    }
}

void TransactionBuilder::InitializeTransactionBuilder(const Consensus::Params& consensusParams, int nHeight)
{
    this->consensusParams = consensusParams;
    this->nHeight = nHeight;

    // Ensure valid network height
    if (nHeight < 0) {
        throw std::invalid_argument("InitializeTransactionBuilder: Height must be non-negative");
    }

    // Create a new mutable transaction to build on
    mtx = CreateNewContextualCMutableTransaction(consensusParams, nHeight);

    // Set the consensus ID of the chain
    consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Set the network the transactions will be submitted to
    strNetworkID = Params().NetworkIDString();
    if (strNetworkID.empty()) {
        throw std::runtime_error("InitializeTransactionBuilder: Failed to determine network ID");
    }

    // Initialize the Sapling builder for Sapling-compatible transactions
    if (mtx.nVersion >= SAPLING_MIN_TX_VERSION) {
        saplingBuilder = std::move(sapling::new_builder(*RustNetwork(), nHeight));
    }
}

void TransactionBuilder::SetFee(CAmount fee)
{
    if (fee <= 0) {
        throw std::invalid_argument("SetFee: Fee must be greater than zero");
    }
    this->fee = fee;
}

void TransactionBuilder::SetMinConfirmations(int iMinConf)
{
    if (iMinConf < 0) {
        throw std::invalid_argument("SetMinConfirmations: Minimum confirmations must be non-negative");
    }
    this->iMinConf = iMinConf;
}

void TransactionBuilder::SetExpiryHeight(int expHeight)
{
    if (expHeight < 0) {
        throw std::invalid_argument("SetExpiryHeight: Expiry height must be non-negative");
    }
    this->mtx.nExpiryHeight = expHeight;
}

uint16_t TransactionBuilder::CalculateChecksum()
{
    // Serialize the current state of the transaction builder
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *this;

    if (ss.empty()) {
        throw std::runtime_error("CalculateChecksum: Serialization failed, data stream is empty");
    }

    // Determine size of the unsigned char* array
    size_t s = ss.size();

    // Set initial value for CRC calculation
    uint16_t crc = 0xFFFF;

    // Calculate the checksum without the bytes allocated for the checksum
    for (size_t i = 0; i < s - 2; ++i) {
        crc ^= ss[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 0x0001) {
                crc = (crc >> 1) ^ 0x8408; // CCITT polynomial
            } else {
                crc >>= 1;
            }
        }
    }

    return crc;
}

void TransactionBuilder::SetChecksum()
{
    // Validate checksum calculation
    if (this->checksum != 0xFFFF) {
        throw std::runtime_error("SetChecksum: Checksum already set");
    }

    // Set the checksum on the transaction builder
    this->checksum = CalculateChecksum();
}

uint16_t TransactionBuilder::GetChecksum()
{
    // Ensure the checksum has been calculated
    if (this->checksum == 0xFFFF) {
        throw std::runtime_error("GetChecksum: Checksum has not been set");
    }

    return this->checksum;
}

bool TransactionBuilder::ValidateChecksum()
{
    // Compare the stored checksum with the calculated checksum
    if (this->checksum == CalculateChecksum()) {
        return true;
    } else {
        LogPrintf("ValidateChecksum: Stored checksum does not match calculated checksum\n");
        return false;
    }
}

void TransactionBuilder::InitializeSapling()
{
    // Create a fresh Sapling builder with the correct info
    if (mtx.nVersion >= SAPLING_MIN_TX_VERSION) {
        saplingBuilder = std::move(sapling::new_builder(*RustNetwork(), nHeight));
    } else {
        throw std::runtime_error("InitializeSapling: Sapling is not supported for the current transaction version");
    }
}

bool TransactionBuilder::AddSaplingSpendRaw(
    SaplingOutPoint op,
    libzcash::SaplingPaymentAddress addr,
    CAmount value,
    uint256 rcm,
    libzcash::MerklePath saplingMerklePath,
    uint256 anchor)
{
    // Ensure value is positive
    if (value <= 0) {
        throw std::invalid_argument("AddSaplingSpendRaw: Spend value must be greater than zero");
    }

    // Consistency check: all from addresses must equal the first one
    if (!vSaplingSpends.empty() && !(vSaplingSpends[0].addr == addr)) {
        throw std::invalid_argument("AddSaplingSpendRaw: Inconsistent Sapling payment address in spends");
    }

    // Consistency check: all anchors must equal the first one
    if (!vSaplingSpends.empty() && !(vSaplingSpends[0].anchor == anchor)) {
        throw std::invalid_argument("AddSaplingSpendRaw: Inconsistent anchor in Sapling spends");
    }

    vSaplingSpends.emplace_back(op, addr, value, rcm, saplingMerklePath, anchor);

    return true;
}

bool TransactionBuilder::ConvertRawSaplingSpend(libzcash::SaplingExtendedSpendingKey extsk)
{
    // Ensure transaction supports Sapling
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("ConvertRawSaplingSpend: Cannot add Sapling spend to pre-Sapling transaction");
    }

    // Serialize extended spending key
    CDataStream ssExtSk(SER_NETWORK, PROTOCOL_VERSION);
    ssExtSk << extsk;

    for (const auto& spend : vSaplingSpends) {
        // Consistency check: all anchors must equal the first one
        if (spend.anchor != vSaplingSpends[0].anchor) {
            throw std::invalid_argument("ConvertRawSaplingSpend: Inconsistent anchor in Sapling spends");
        }

        // Serialize Merkle Path
        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
        ss << spend.saplingMerklePath;
        std::array<unsigned char, 1065> merkle_path;
        std::move(ss.begin(), ss.end(), merkle_path.begin());

        saplingBuilder->add_spend(
            {reinterpret_cast<uint8_t*>(ssExtSk.data()), ssExtSk.size()},
            spend.addr.d,
            spend.addr.GetRawBytes(),
            spend.value,
            spend.rcm.GetRawBytes(),
            merkle_path);

        if (!firstSaplingSpendAddr.has_value()) {
            firstSaplingSpendAddr = std::make_pair(extsk.ToXFVK().fvk.ovk, spend.addr);
        }

        valueBalanceSapling += spend.value;
        LogPrintf("ConvertRawSaplingSpend: Adding Sapling spend value %i\n", spend.value);
    }

    // Reset spend vector
    vSaplingSpends.clear();

    return true;
}

bool TransactionBuilder::AddSaplingOutputRaw(
    libzcash::SaplingPaymentAddress to,
    CAmount value,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    // Ensure value is positive
    if (value <= 0) {
        throw std::invalid_argument("AddSaplingOutputRaw: Output value must be greater than zero");
    }

    // Ensure memo size is valid
    if (memo.size() != ZC_MEMO_SIZE) {
        throw std::invalid_argument("AddSaplingOutputRaw: Memo size is invalid");
    }

    // Ensure transaction supports Sapling
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("AddSaplingOutputRaw: Cannot add Sapling output to pre-Sapling transaction");
    }

    vSaplingOutputs.emplace_back(to, value, memo);

    return true;
}

bool TransactionBuilder::ConvertRawSaplingOutput(uint256 ovk)
{
    // Ensure transaction supports Sapling
    if (mtx.nVersion < SAPLING_TX_VERSION) {
        throw std::runtime_error("ConvertRawSaplingOutput: Cannot add Sapling output to pre-Sapling transaction");
    }

    for (const auto& output : vSaplingOutputs) {
        saplingBuilder->add_recipient(
            ovk.GetRawBytes(),
            output.addr.GetRawBytes(),
            output.value,
            output.memo);

        valueBalanceSapling -= output.value;
        LogPrintf("ConvertRawSaplingOutput: Adding Sapling output value %i\n", output.value);
    }

    // Reset output vector
    vSaplingOutputs.clear();

    return true;
}

void TransactionBuilder::InitializeOrchard(
    bool spendsEnabled,
    bool outputsEnabled,
    uint256 anchor)
{
    // Ensure transaction supports Orchard
    if (mtx.nVersion < ORCHARD_MIN_TX_VERSION) {
        throw std::runtime_error("InitializeOrchard: Cannot initialize Orchard before activation");
    }

    // Ensure valid anchor
    if (anchor.IsNull()) {
        throw std::invalid_argument("InitializeOrchard: Anchor cannot be null");
    }

    orchardBuilder = orchard::Builder(spendsEnabled, outputsEnabled, anchor);
}

bool TransactionBuilder::AddOrchardSpendRaw(
    OrchardOutPoint op,
    libzcash::OrchardPaymentAddressPirate addr,
    CAmount value,
    uint256 rho,
    uint256 rseed,
    libzcash::MerklePath orchardMerklePath,
    uint256 anchor)
{
    // Ensure transaction supports Orchard
    if (mtx.nVersion < ORCHARD_MIN_TX_VERSION) {
        throw std::runtime_error("AddOrchardSpendRaw: Cannot add Orchard spend to pre-Orchard transaction");
    }

    // Ensure value is positive
    if (value <= 0) {
        throw std::invalid_argument("AddOrchardSpendRaw: Spend value must be greater than zero");
    }

    // Consistency check: all addresses must equal the first one
    if (!vOrchardSpends.empty() && !(vOrchardSpends[0].addr == addr)) {
        throw std::invalid_argument("AddOrchardSpendRaw: Inconsistent Orchard payment address in spends");
    }

    // Consistency check: all anchors must equal the first one
    if (!vOrchardSpends.empty() && !(vOrchardSpends[0].anchor == anchor)) {
        throw std::invalid_argument("AddOrchardSpendRaw: Inconsistent anchor in Orchard spends");
    }

    vOrchardSpends.emplace_back(op, addr, value, rho, rseed, orchardMerklePath, anchor);

    return true;
}

bool TransactionBuilder::ConvertRawOrchardSpend(libzcash::OrchardExtendedSpendingKeyPirate extsk)
{
    // Ensure transaction supports Orchard
    if (!orchardBuilder.has_value()) {
        if (mtx.nVersion < ORCHARD_MIN_TX_VERSION) {
            throw std::runtime_error("ConvertRawOrchardSpend: Cannot add Orchard spend to pre-Orchard transaction");
        } else {
            throw std::runtime_error("ConvertRawOrchardSpend: Orchard builder not initialized");
        }
    }

    // Retrieve full viewing key from extended spending key
    auto fvkOpt = extsk.GetXFVK();
    if (fvkOpt == std::nullopt) {
        throw std::runtime_error("ConvertRawOrchardSpend: Failed to retrieve XFVK from EXTSK");
    }
    auto fvk = fvkOpt.value().fvk;

    // Initialize change address if necessary
    if (!firstOrchardSpendAddr.has_value()) {
        auto ovkOpt = fvk.GetOVK();
        auto changeAddrOpt = fvk.GetDefaultAddress();

        if (ovkOpt == std::nullopt || changeAddrOpt == std::nullopt) {
            throw std::runtime_error("ConvertRawOrchardSpend: Failed to retrieve OVK or default address from FVK");
        }

        firstOrchardSpendAddr = std::make_pair(ovkOpt.value().ovk, changeAddrOpt.value());
    }

    for (const auto& spend : vOrchardSpends) {
        // Ensure anchors are consistent
        if (spend.anchor != vOrchardSpends[0].anchor) {
            throw std::invalid_argument("ConvertRawOrchardSpend: Inconsistent anchor in Orchard spends");
        }

        orchardBuilder->AddSpendFromParts(
            fvk,
            spend.addr,
            spend.value,
            spend.rho,
            spend.rseed,
            spend.orchardMerklePath);

        valueBalanceOrchard += spend.value;
        LogPrintf("ConvertRawOrchardSpend: Adding Orchard spend value %i\n", spend.value);
    }

    // Add to list of keys for bundle signing
    orchardSpendingKeys.push_back(extsk.sk);

    // Reset spend vector
    vOrchardSpends.clear();

    return true;
}

bool TransactionBuilder::AddOrchardOutputRaw(
    libzcash::OrchardPaymentAddressPirate to,
    CAmount value,
    std::array<unsigned char, ZC_MEMO_SIZE> memo)
{
    // Ensure transaction supports Orchard
    if (mtx.nVersion < ORCHARD_MIN_TX_VERSION) {
        throw std::runtime_error("AddOrchardOutputRaw: Cannot add Orchard output to pre-Orchard transaction");
    }

    // Ensure value is positive
    if (value <= 0) {
        throw std::invalid_argument("AddOrchardOutputRaw: Output value must be greater than zero");
    }

    // Ensure memo size is valid
    if (memo.size() != ZC_MEMO_SIZE) {
        throw std::invalid_argument("AddOrchardOutputRaw: Memo size is invalid");
    }

    vOrchardOutputs.emplace_back(to, value, memo);

    return true;
}

bool TransactionBuilder::ConvertRawOrchardOutput(uint256 ovk)
{
    // Ensure transaction supports Orchard
    if (!orchardBuilder.has_value()) {
        if (mtx.nVersion < ORCHARD_MIN_TX_VERSION) {
            throw std::runtime_error("ConvertRawOrchardOutput: Cannot add Orchard output to pre-Orchard transaction");
        } else {
            throw std::runtime_error("ConvertRawOrchardOutput: Orchard builder not initialized");
        }
    }

    for (const auto& output : vOrchardOutputs) {
        if (!orchardBuilder->AddOutput(ovk, output.addr, output.value, output.memo)) {
            throw std::runtime_error("ConvertRawOrchardOutput: Failed to add Orchard output");
        }

        valueBalanceOrchard -= output.value;
        LogPrintf("ConvertRawOrchardOutput: Adding Orchard output value %i\n", output.value);
    }

    // Reset output vector
    vOrchardOutputs.clear();

    return true;
}

void TransactionBuilder::AddTransparentInput(COutPoint utxo, CScript scriptPubKey, CAmount value, uint32_t _nSequence)
{
    // Ensure valid value
    if (value <= 0) {
        throw std::invalid_argument("AddTransparentInput: Input value must be greater than zero");
    }

    // Ensure valid scriptPubKey
    if (!scriptPubKey.IsPayToCryptoCondition() && keystore == nullptr) {
        throw std::runtime_error("AddTransparentInput: Cannot add transparent inputs without a keystore unless using crypto conditions");
    }

    mtx.vin.emplace_back(utxo);
    mtx.vin.back().nSequence = _nSequence;
    tIns.emplace_back(value, scriptPubKey);
}

bool TransactionBuilder::AddTransparentOutput(CTxDestination& to, CAmount value)
{
    // Validate destination
    if (!IsValidDestination(to)) {
        return false;
    }

    // Ensure positive output value
    if (value <= 0) {
        throw std::invalid_argument("AddTransparentOutput: Output value must be greater than zero");
    }

    CScript scriptPubKey = GetScriptForDestination(to);
    CTxOut out(value, scriptPubKey);
    mtx.vout.push_back(out);

    return true;
}

bool TransactionBuilder::AddOpRetLast()
{
    // Check if there's an OP_RETURN to add
    if (opReturn.has_value()) {
        CScript s = opReturn.value();
        CTxOut out(0, s);
        mtx.vout.push_back(out);
    }
    return true;
}

void TransactionBuilder::AddOpRet(CScript& s)
{
    // Store OP_RETURN for later addition
    opReturn = CScript(s);
}

void TransactionBuilder::SendChangeTo(libzcash::OrchardPaymentAddressPirate changeAddr, uint256 ovk)
{
    // Set Orchard change address
    orchardChangeAddr = std::make_pair(ovk, changeAddr);

    // Clear other change addresses
    tChangeAddr = std::nullopt;
    saplingChangeAddr = std::nullopt;
}

void TransactionBuilder::SendChangeTo(libzcash::SaplingPaymentAddress changeAddr, uint256 ovk)
{
    // Set Sapling change address
    saplingChangeAddr = std::make_pair(ovk, changeAddr);

    // Clear other change addresses
    tChangeAddr = std::nullopt;
    orchardChangeAddr = std::nullopt;
}

bool TransactionBuilder::SendChangeTo(CTxDestination& changeAddr)
{
    // Validate change address
    if (!IsValidDestination(changeAddr)) {
        return false;
    }

    // Set transparent change address
    tChangeAddr = changeAddr;

    // Clear other change addresses
    saplingChangeAddr = std::nullopt;
    orchardChangeAddr = std::nullopt;

    return true;
}

TransactionBuilderResult TransactionBuilder::Build()
{
    // Begin transaction construction
    std::optional<CTransaction> maybe_tx = CTransaction(mtx);
    auto tx_result = maybe_tx.value();
    auto signedtxn = EncodeHexTx(tx_result);

    //
    // Consistency checks
    //

    // Reset pending inputs and outputs
    vSaplingSpends.clear();
    vSaplingOutputs.clear();
    vOrchardSpends.clear();
    vOrchardOutputs.clear();

    // Validate change
    CAmount change = valueBalanceSapling + valueBalanceOrchard - fee;

    for (const auto& tIn : tIns) {
        change += tIn.nValue;
    }

    for (const auto& tOut : mtx.vout) {
        change -= tOut.nValue;
    }

    if (change < 0) {
        return TransactionBuilderResult("Build: Change cannot be negative");
    }

    //
    // Handle change output
    //

    if (change > 0) {
        try {
            // Send change to the appropriate address type
            if (orchardChangeAddr) {
                AddOrchardOutputRaw(orchardChangeAddr->second, change, {{0}});
                ConvertRawOrchardOutput(orchardChangeAddr->first);
            } else if (firstOrchardSpendAddr) {
                AddOrchardOutputRaw(firstOrchardSpendAddr->second, change, {{0}});
                ConvertRawOrchardOutput(firstOrchardSpendAddr->first);
            } else if (saplingChangeAddr) {
                AddSaplingOutputRaw(saplingChangeAddr->second, change, {{0}});
                ConvertRawSaplingOutput(saplingChangeAddr->first);
            } else if (firstSaplingSpendAddr) {
                AddSaplingOutputRaw(firstSaplingSpendAddr->second, change, {{0}});
                ConvertRawSaplingOutput(firstSaplingSpendAddr->first);
            } else if (tChangeAddr) {
                assert(AddTransparentOutput(tChangeAddr.value(), change));
            } else {
                return TransactionBuilderResult("Build: Could not determine change address");
            }
        } catch (const std::exception& ex) {
            return TransactionBuilderResult(std::string("Build: Failed to handle change - ") + ex.what());
        }
    }

    //
    // Sapling spends and outputs
    //
    std::optional<rust::Box<sapling::UnauthorizedBundle>> maybeSaplingBundle;
    try {
        maybeSaplingBundle = sapling::build_bundle(std::move(saplingBuilder), nHeight);
    } catch (const rust::Error& e) {
        return TransactionBuilderResult("Build: Failed to build Sapling bundle: " + std::string(e.what()));
    }

    auto saplingBundle = std::move(maybeSaplingBundle.value());

    //
    // Orchard
    //
    std::optional<orchard::UnauthorizedBundle> orchardBundle;
    if (orchardBuilder.has_value() && orchardBuilder->HasActions()) {
        auto bundle = orchardBuilder->Build();
        if (bundle.has_value()) {
            orchardBundle = std::move(bundle);
        } else {
            return TransactionBuilderResult("Build: Failed to build Orchard bundle");
        }
    }

    // Add OP_RETURN if present
    AddOpRetLast();

    //
    // Signatures
    //
    auto consensusBranchId = CurrentEpochBranchId(nHeight, consensusParams);

    // Construct signature hash
    uint256 dataToBeSigned;
    try {
        if (mtx.fOverwintered) {
            dataToBeSigned = ProduceShieldedSignatureHash(
                consensusBranchId,
                mtx,
                tIns,
                *saplingBundle,
                orchardBundle);
        } else {
            CScript scriptCode;
            const PrecomputedTransactionData txdata(mtx, tIns);
            dataToBeSigned = SignatureHash(scriptCode, mtx, NOT_AN_INPUT, SIGHASH_ALL, 0, consensusBranchId, txdata);
        }
    } catch (const std::exception& ex) {
        return TransactionBuilderResult(std::string("Build: Failed to construct signature hash - ") + ex.what());
    }

    //
    // Orchard bundle signing
    //
    if (orchardBundle.has_value()) {
        if (orchardSpendingKeys.empty()) {
            auto randomKey = libzcash::OrchardSpendingKeyPirate().random();
            if (randomKey) {
                orchardSpendingKeys.push_back(randomKey.value());
            }
        }

        auto authorizedBundle = orchardBundle.value().ProveAndSign(
            orchardSpendingKeys[0],
            dataToBeSigned);

        if (authorizedBundle.has_value()) {
            mtx.orchardBundle = authorizedBundle.value();
        } else {
            return TransactionBuilderResult("Build: Failed to create Orchard proof or signatures");
        }
    }

    return CTransaction(mtx);
}

    //
    // Sapling bundle signing
    //
    try {
        mtx.saplingBundle = sapling::apply_bundle_signatures(
            std::move(saplingBundle), dataToBeSigned.GetRawBytes());
    } catch (const rust::Error& e) {
        return TransactionBuilderResult("Build: Failed to sign Sapling bundle: " + std::string(e.what()));
    }

    //
    // Transparent input signatures
    //
    CTransaction txNewConst(mtx);
    const PrecomputedTransactionData txdata(txNewConst, tIns);
    for (size_t nIn = 0; nIn < mtx.vin.size(); nIn++) {
        const auto& tIn = tIns[nIn];
        SignatureData sigdata;

        bool signSuccess = ProduceSignature(
            TransactionSignatureCreator(
                keystore, &txNewConst, txdata, nIn, tIn.nValue, SIGHASH_ALL),
            tIn.scriptPubKey, sigdata, consensusBranchId);

        if (!signSuccess) {
            return TransactionBuilderResult("Build: Failed to sign transparent input at index " + std::to_string(nIn));
        } else {
            UpdateTransaction(mtx, nIn, sigdata);
        }
    }

    //
    // Finalize transaction
    //
    try {
        maybe_tx = CTransaction(mtx);
        tx_result = maybe_tx.value();
        signedtxn = EncodeHexTx(tx_result);
    } catch (const std::exception& ex) {
        return TransactionBuilderResult(std::string("Build: Failed to finalize transaction - ") + ex.what());
    }

    return TransactionBuilderResult(tx_result);
}
