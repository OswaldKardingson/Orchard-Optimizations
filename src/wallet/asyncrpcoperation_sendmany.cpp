// Copyright (c) 2016 The Zcash developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/******************************************************************************
 * Copyright © 2014-2019 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "asyncrpcoperation_sendmany.h"
#include "amount.h"
#include "asyncrpcqueue.h"
#include "consensus/upgrades.h"
#include "core_io.h"
#include "init.h"
#include "key_io.h"
#include "komodo_bitcoind.h"
#include "komodo_notary.h"
#include "main.h"
#include "miner.h"
#include "net.h"
#include "netbase.h"
#include "rpc/protocol.h"
#include "rpc/rawtransaction.h"
#include "rpc/server.h"
#include "script/interpreter.h"
#include "sodium.h"
#include "timedata.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utiltime.h"
#include "wallet.h"
#include "walletdb.h"
#include "zcash/IncrementalMerkleTree.hpp"

#include <stdint.h>

#include <array>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "paymentdisclosuredb.h"

using namespace libzcash;

int find_output(UniValue obj, int n)
{
    UniValue outputMapValue = find_value(obj, "outputmap");
    if (!outputMapValue.isArray()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Missing outputmap for JoinSplit operation");
    }

    UniValue outputMap = outputMapValue.get_array();
    assert(outputMap.size() == ZC_NUM_JS_OUTPUTS);
    for (size_t i = 0; i < outputMap.size(); i++) {
        if (outputMap[i].get_int() == n) {
            return i;
        }
    }

    throw std::logic_error("n is not present in outputmap");
}

AsyncRPCOperation_sendmany::AsyncRPCOperation_sendmany(
    const Consensus::Params& consensusParams,
    const int nHeight,
    std::string fromAddress,
    std::vector<SendManyRecipient> saplingOutputs,
    std::vector<SendManyRecipient> orchardOutputs,
    int minDepth,
    CAmount fee,
    UniValue contextInfo) : fromaddress_(fromAddress), sapling_outputs_(saplingOutputs), orchard_outputs_(orchardOutputs), mindepth_(minDepth), fee_(fee), contextinfo_(contextInfo),
                            builder_(TransactionBuilder(consensusParams, nHeight, pwalletMain))
{
    assert(fee_ >= 0);

    if (minDepth < 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be negative");
    }

    if (fromAddress.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "From address parameter missing");
    }

    if (saplingOutputs.size() == 0 && orchardOutputs.size() == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "No recipients");
    }

    fromtaddr_ = DecodeDestination(fromAddress);
    isfromtaddr_ = IsValidDestination(fromtaddr_);
    isfromzaddr_ = false;

    int ivOUT = (int)saplingOutputs.size();

    bOfflineSpendingKey = false;
    if (!isfromtaddr_) {
        fromAddress_ = fromAddress; // Initialise private, persistant Address for the object.
        auto address = DecodePaymentAddress(fromAddress);
        if (IsValidPaymentAddress(address)) {
            isfromzaddr_ = true;
            frompaymentaddress_ = address;
            // We don't need to lock on the wallet as spending key related methods are thread-safe
            if (!std::visit(HaveSpendingKeyForPaymentAddress(pwalletMain), address)) {
                // TBD: confirm if the from addr is in our wallet. From the GUI is will be, but maybe not from CLI.
                // Leave spendingkey_ uninitialised
                bOfflineSpendingKey = true;
            } else {
                spendingkey_ = std::visit(GetSpendingKeyForPaymentAddress(pwalletMain), address).value();
                bOfflineSpendingKey = false;
            }
        } else {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid from address");
        }
    }

    if (isfromzaddr_ && minDepth == 0) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Minconf cannot be zero when sending from zaddr");
    }

    // Log the context info i.e. the call parameters to z_sendmany
    if (LogAcceptCategory("zrpcunsafe")) {
        LogPrint("zrpcunsafe", "%s: z_sendmany initialized (params=%s)\n", getId(), contextInfo.write());
    } else {
        LogPrint("zrpc", "%s: z_sendmany initialized\n", getId());
    }

    // Enable payment disclosure if requested
    paymentDisclosureMode = fExperimentalMode && GetBoolArg("-paymentdisclosure", true);
}

AsyncRPCOperation_sendmany::~AsyncRPCOperation_sendmany()
{
}

void AsyncRPCOperation_sendmany::main()
{
    if (isCancelled())
        return;

    set_state(OperationStatus::EXECUTING);
    start_execution_clock();

    bool success = false;

#ifdef ENABLE_MINING
#ifdef ENABLE_WALLET
    GenerateBitcoins(false, NULL, 0);
#else
    GenerateBitcoins(false, 0);
#endif
#endif

    try {
        success = main_impl();
    } catch (const UniValue& objError) {
        int code = find_value(objError, "code").get_int();
        std::string message = find_value(objError, "message").get_str();
        set_error_code(code);
        set_error_message(message);
    } catch (const runtime_error& e) {
        set_error_code(-1);
        set_error_message("runtime error: " + string(e.what()));
    } catch (const logic_error& e) {
        set_error_code(-1);
        set_error_message("logic error: " + string(e.what()));
    } catch (const exception& e) {
        set_error_code(-1);
        set_error_message("general exception: " + string(e.what()));
    } catch (...) {
        set_error_code(-2);
        set_error_message("unknown error");
    }

#ifdef ENABLE_MINING
#ifdef ENABLE_WALLET
    GenerateBitcoins(GetBoolArg("-gen", false), pwalletMain, GetArg("-genproclimit", 1));
#else
    GenerateBitcoins(GetBoolArg("-gen", false), GetArg("-genproclimit", 1));
#endif
#endif

    stop_execution_clock();

    if (success) {
        set_state(OperationStatus::SUCCESS);
    } else {
        set_state(OperationStatus::FAILED);
    }

    std::string s = strprintf("%s: z_sendmany finished (status=%s", getId(), getStateAsString());
    if (success) {
        s += strprintf(", txid=%s)\n", tx_.GetHash().ToString());
    } else {
        s += strprintf(", error=%s)\n", getErrorMessage());
    }
    LogPrintf("%s", s);

    // !!! Payment disclosure START
    if (success && paymentDisclosureMode && paymentDisclosureData_.size() > 0) {
        uint256 txidhash = tx_.GetHash();
        std::shared_ptr<PaymentDisclosureDB> db = PaymentDisclosureDB::sharedInstance();
        for (PaymentDisclosureKeyInfo p : paymentDisclosureData_) {
            p.first.hash = txidhash;
            if (!db->Put(p.first, p.second)) {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Error writing entry to database for key %s\n", getId(), p.first.ToString());
            } else {
                LogPrint("paymentdisclosure", "%s: Payment Disclosure: Successfully added entry to database for key %s\n", getId(), p.first.ToString());
            }
        }
    }
    // !!! Payment disclosure END
}

// Notes:
// 1. #1159 Currently there is no limit set on the number of joinsplits, so size of tx could be invalid.
// 2. #1360 Note selection is not optimal
// 3. #1277 Spendable notes are not locked, so an operation running in parallel could also try to use them
bool AsyncRPCOperation_sendmany::main_impl()
{
    assert(isfromtaddr_ != isfromzaddr_);

    bool isSingleZaddrOutput = (sapling_outputs_.size() + orchard_outputs_.size() == 1);
    bool isMultipleZaddrOutput = (sapling_outputs_.size() + orchard_outputs_.size() >= 1);
    bool isPureTaddrOnlyTx = (isfromtaddr_ && sapling_outputs_.size() == 0 & orchard_outputs_.size() == 0);
    CAmount minersFee = fee_;

    // When spending coinbase utxos, you can only specify a single zaddr as the change must go somewhere
    // and if there are multiple zaddrs, we don't know where to send it.
    if (isfromtaddr_) {
        if (isSingleZaddrOutput) {
            bool b = find_utxos(true);
            if (!b) {
                throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no UTXOs found for taddr from address.");
            }
        } else {
            bool b = find_utxos(false);
            if (!b) {
                if (isMultipleZaddrOutput) {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any non-coinbase UTXOs to spend. Coinbase UTXOs can only be sent to a single zaddr recipient.");
                } else {
                    throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Could not find any non-coinbase UTXOs to spend.");
                }
            }
        }
    }

    if (isfromzaddr_ && !find_unspent_notes()) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, "Insufficient funds, no unspent notes found for zaddr from address.");
    }

    CAmount t_inputs_total = 0;
    for (SendManyInputUTXO& t : t_inputs_) {
        t_inputs_total += std::get<2>(t);
    }

    CAmount z_inputs_total = 0;
    for (auto t : z_sapling_inputs_) {
        z_inputs_total += t.note.value();
    }

    CAmount sapling_outputs_total = 0;
    for (SendManyRecipient& t : sapling_outputs_) {
        sapling_outputs_total += std::get<1>(t);
    }

    CAmount orchard_outputs_total = 0;
    for (SendManyRecipient& t : orchard_outputs_) {
        orchard_outputs_total += std::get<1>(t);
    }

    CAmount sendAmount = sapling_outputs_total + orchard_outputs_total;
    CAmount targetAmount = sendAmount + minersFee;

    assert(!isfromtaddr_ || z_inputs_total == 0);
    assert(!isfromzaddr_ || t_inputs_total == 0);

    if (isfromtaddr_ && (t_inputs_total < targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           strprintf("Insufficient transparent funds, have %s, need %s",
                                     FormatMoney(t_inputs_total), FormatMoney(targetAmount)));
    }

    if (isfromzaddr_ && (z_inputs_total < targetAmount)) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                           strprintf("Insufficient shielded funds, have %s, need %s",
                                     FormatMoney(z_inputs_total), FormatMoney(targetAmount)));
    }

    // If from address is a taddr, select UTXOs to spend
    CAmount selectedUTXOAmount = 0;
    bool selectedUTXOCoinbase = false;
    if (isfromtaddr_) {
        // Get dust threshold
        CKey secret;
        secret.MakeNewKey(true);
        CScript scriptPubKey = GetScriptForDestination(secret.GetPubKey().GetID());
        CTxOut out(CAmount(1), scriptPubKey);
        CAmount dustThreshold = out.GetDustThreshold(minRelayTxFee);
        CAmount dustChange = -1;

        std::vector<SendManyInputUTXO> selectedTInputs;
        for (SendManyInputUTXO& t : t_inputs_) {
            bool b = std::get<3>(t);
            if (b) {
                selectedUTXOCoinbase = true;
            }
            selectedUTXOAmount += std::get<2>(t);
            selectedTInputs.push_back(t);
            if (selectedUTXOAmount >= targetAmount) {
                // Select another utxo if there is change less than the dust threshold.
                dustChange = selectedUTXOAmount - targetAmount;
                if (dustChange == 0 || dustChange >= dustThreshold) {
                    break;
                }
            }
        }

        // If there is transparent change, is it valid or is it dust?
        if (dustChange < dustThreshold && dustChange != 0) {
            throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS,
                               strprintf("Insufficient transparent funds, have %s, need %s more to avoid creating invalid change output %s (dust threshold is %s)",
                                         FormatMoney(t_inputs_total), FormatMoney(dustThreshold - dustChange), FormatMoney(dustChange), FormatMoney(dustThreshold)));
        }

        t_inputs_ = selectedTInputs;
        t_inputs_total = selectedUTXOAmount;

        // Check mempooltxinputlimit to avoid creating a transaction which the local mempool rejects
        size_t limit = (size_t)GetArg("-mempooltxinputlimit", 0);
        {
            LOCK(cs_main);
            if (NetworkUpgradeActive(chainActive.Height() + 1, Params().GetConsensus(), Consensus::UPGRADE_OVERWINTER)) {
                limit = 0;
            }
        }
        if (limit > 0) {
            size_t n = t_inputs_.size();
            if (n > limit) {
                throw JSONRPCError(RPC_WALLET_ERROR, strprintf("Too many transparent inputs %zu > limit %zu", n, limit));
            }
        }

        // update the transaction with these inputs
        CScript scriptPubKeyInputs;
        for (auto t : t_inputs_) {
            scriptPubKeyInputs = GetScriptForDestination(std::get<4>(t));
            // printf("Checking new script: %s\n", scriptPubKey.ToString().c_str());
            uint256 txid = std::get<0>(t);
            int vout = std::get<1>(t);
            CAmount amount = std::get<2>(t);
            builder_.AddTransparentInput(COutPoint(txid, vout), scriptPubKeyInputs, amount);
        }
        // for Komodo, set lock time to accure interest, for other chains, set
        // locktime to spend time locked coinbases
        if (chainName.isKMD()) {
            // if ((uint32_t)chainActive.Tip()->nTime < ASSETCHAINS_STAKED_HF_TIMESTAMP)
            if (!komodo_hardfork_active((uint32_t)chainActive.Tip()->nTime))
                builder_.SetLockTime((uint32_t)time(NULL) - 60); // set lock time for Komodo interest
            else
                builder_.SetLockTime((uint32_t)chainActive.Tip()->GetMedianTimePast());
        }
    }

    LogPrint((isfromtaddr_) ? "zrpc" : "zrpcunsafe", "%s: spending %s to send %s with fee %s\n",
             getId(), FormatMoney(targetAmount), FormatMoney(sendAmount), FormatMoney(minersFee));
    LogPrint("zrpc", "%s: transparent input: %s (to choose from)\n", getId(), FormatMoney(t_inputs_total));
    LogPrint("zrpcunsafe", "%s: private input: %s (to choose from)\n", getId(), FormatMoney(z_inputs_total));
    LogPrint("zrpcunsafe", "%s: private output: %s\n", getId(), FormatMoney(sapling_outputs_total));
    LogPrint("zrpc", "%s: fee: %s\n", getId(), FormatMoney(minersFee));

    // Offline Signing
    if (bOfflineSpendingKey == true) {
        /* Format the necessary data to construct a transaction that can
         * be signed with an off-line wallet
         */

        builder_.SetFee(minersFee);
        builder_.SetMinConfirmations(1);

        // Select Sapling notes that makes up the total amount to send:
        std::vector<SaplingOutPoint> ops;
        std::vector<SaplingNote> notes;
        CAmount sum = 0;
        int iI = 0;
        for (auto t : z_sapling_inputs_) {
            ops.push_back(t.op);
            notes.push_back(t.note);
            sum += t.note.value();

            // printf("asyncrpcoperation_sendmany.cpp main_impl() Process z_sapling_inputs_ #%d Value=%ld, Sum=%ld\n",iI, t.note.value(), sum); fflush(stdout);
            // iI+=1;
            if (sum >= targetAmount) {
                // printf("asyncrpcoperation_sendmany.cpp main_impl() Notes exceed targetAmount: %ld>%ld\n",sum,targetAmount);
                break;
            }
        }

        // Fetch Sapling anchor and witnesses
        // printf("asyncrpcoperation_sendmany.cpp main_impl() Fetch Sapling anchor and witnesses\n"); fflush(stdout);
        uint256 anchor;
        std::vector<libzcash::MerklePath> saplingMerklePaths;
        {
            // printf("asyncrpcoperation_sendmany.cpp main_impl() Fetch Sapling anchor and witnesses - start\n"); fflush(stdout);
            LOCK2(cs_main, pwalletMain->cs_wallet);
            if (!pwalletMain->GetSaplingNoteMerklePaths(ops, saplingMerklePaths, anchor)) {
                throw JSONRPCError(RPC_WALLET_ERROR, "Missing merkle path for Sapling note");
            }
            // printf("asyncrpcoperation_sendmany.cpp main_impl() Fetch Sapling anchor and witnesses - done\n"); fflush(stdout);
        }

        // Add Sapling spends to the transaction builder:
        // printf("asyncrpcoperation_sendmany.cpp main_impl() Add sapling spends: #%ld\n",notes.size() ); fflush(stdout);

        // Note: expsk is uninitialised - we do not have the spending key!
        //     : fvk also garbage?
        SaplingExpandedSpendingKey expsk;
        auto fvk = expsk.full_viewing_key();
        auto ovk = fvk.ovk;
        for (size_t i = 0; i < notes.size(); i++) {
            // printf("asyncrpcoperation_sendmany.cpp main_impl() Add sapling spend: %ld of %ld - start\n",i+1,notes.size() ); fflush(stdout);
            // Convert witness to a char array:
            CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
            ss << saplingMerklePaths[i];
            std::vector<unsigned char> local_witness(ss.begin(), ss.end());
            myCharArray_s sWitness;
            memcpy(&sWitness.cArray[0], reinterpret_cast<unsigned char*>(local_witness.data()), sizeof(sWitness.cArray));
            assert(builder_.AddSaplingSpend_prepare_offline_transaction(fromAddress_, notes[i], anchor, saplingMerklePaths[i].position(), &sWitness.cArray[0]));
            // printf("asyncrpcoperation_sendmany.cpp main_impl() Add sapling spend: %ld of %ld - done\n",i+1,notes.size() ); fflush(stdout);
        }

        // Add Sapling outputs to the transaction builder
        // printf("asyncrpcoperation_sendmany.cpp main_impl() Add sapling outputs\n" ); fflush(stdout);
        iI = 0;
        for (auto r : sapling_outputs_) {
            auto address = std::get<0>(r);
            auto value = std::get<1>(r);
            auto strMemo = std::get<2>(r);


            // Note: transaction builder expectes memo in
            //       ASCII encoding, not as a hex string.
            std::array<unsigned char, ZC_MEMO_SIZE> caMemo = {0x00};
            if (IsHex(strMemo)) {
                if (strMemo.length() > (ZC_MEMO_SIZE * 2)) {
                    printf("asyncrpcoperation_sendmany.cpp main_impl() Hex encoded memo is larger than maximum allowed %d\n", (ZC_MEMO_SIZE * 2));

                    UniValue o(UniValue::VOBJ);
                    o.push_back(Pair("Failure", "Memo is too long"));
                    set_result(o);

                    return false;
                }
                caMemo = get_memo_from_hex_string(strMemo);
            } else {
                int iLength = strMemo.length();

                if (strMemo.length() > ZC_MEMO_SIZE) {
                    printf("asyncrpcoperation_sendmany.cpp main_impl() Memo is larger than maximum allowed %d\n", ZC_MEMO_SIZE);

                    UniValue o(UniValue::VOBJ);
                    o.push_back(Pair("Failure", "Memo is too long"));
                    set_result(o);

                    return false;
                }

                unsigned char cByte;
                for (int iI = 0; iI < iLength; iI++) {
                    cByte = (unsigned char)strMemo[iI];
                    caMemo[iI] = cByte;
                }
            }

            // printf("asyncrpcoperation_sendmany.cpp main_impl() Output #%d:\n  addr=%s, ",iI+1,address.c_str() );
            // printf("value=%ld\n",value);
            // printf("memo=%s\n"  , strMemo.c_str() );
            // fflush(stdout);
            iI += 1;
            // builder_.AddSaplingOutput_offline_transaction(ovk, address, value, memo);
            builder_.AddSaplingOutput_offline_transaction(address, value, caMemo);
        }

        // Build the off-line transaction
        std::string sResult = builder_.Build_offline_transaction();
        // printf("AsyncRPCOperation_sendmany::main_impl() %s\n",sResult.c_str() );

        // Send result upstream
        // printf("AsyncRPCOperation_sendmany::main_impl() Result available\n");
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("Success", sResult));
        set_result(o);

        // printf("AsyncRPCOperation_sendmany::main_impl() Pushed result OBJ back. return true\n");
        return true;
    }

    /**
     * SCENARIO #0
     *
     * Sprout not involved, so we just use the TransactionBuilder and we're done.
     * We added the transparent inputs to the builder earlier.
     */

    builder_.SetFee(minersFee);

    // Get various necessary keys
    SaplingExtendedSpendingKey extsk;
    uint256 ovk;
    if (isfromzaddr_) {
        extsk = *(std::get_if<libzcash::SaplingExtendedSpendingKey>(&spendingkey_));
        ovk = extsk.expsk.full_viewing_key().ovk;
    } else {
        // Sending from a t-address, which we don't have an ovk for. Instead,
        // generate a common one from the HD seed. This ensures the data is
        // recoverable, while keeping it logically separate from the ZIP 32
        // Sapling key hierarchy, which the user might not be using.
        HDSeed seed;
        if (!pwalletMain->GetHDSeed(seed)) {
            throw JSONRPCError(
                RPC_WALLET_ERROR,
                "AsyncRPCOperation_sendmany::main_impl(): HD seed not found");
        }
        ovk = ovkForShieldingFromTaddr(seed);
    }

    // Set change address if we are using transparent funds
    // TODO: Should we just use fromtaddr_ as the change address?
    if (isfromtaddr_) {
        LOCK2(cs_main, pwalletMain->cs_wallet);

        EnsureWalletIsUnlocked();
        CReserveKey keyChange(pwalletMain);
        CPubKey vchPubKey;
        bool ret = keyChange.GetReservedKey(vchPubKey);
        if (!ret) {
            // should never fail, as we just unlocked
            throw JSONRPCError(
                RPC_WALLET_KEYPOOL_RAN_OUT,
                "Could not generate a taddr to use as a change address");
        }

        CTxDestination changeAddr = vchPubKey.GetID();
        assert(builder_.SendChangeTo(changeAddr));
    }

    // Select Sapling notes
    std::vector<SaplingOutPoint> ops;
    std::vector<SaplingNote> notes;
    CAmount sum = 0;
    for (auto t : z_sapling_inputs_) {
        ops.push_back(t.op);
        notes.push_back(t.note);
        sum += t.note.value();
        if (sum >= targetAmount) {
            break;
        }
    }

    // Fetch Sapling anchor and merkle paths
    uint256 anchor;
    std::vector<libzcash::MerklePath> saplingMerklePaths;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (!pwalletMain->GetSaplingNoteMerklePaths(ops, saplingMerklePaths, anchor)) {
            LogPrint("zrpcunsafe", "%s: Merkle Path not found for Sapling note. Stopping.\n", getId());
        }
    }

    // Add Sapling spends
    for (size_t i = 0; i < notes.size(); i++) {
        assert(builder_.AddSaplingSpend(extsk, notes[i], anchor, saplingMerklePaths[i]));
    }

    // Add Sapling outputs
    for (auto r : sapling_outputs_) {
        auto address = std::get<0>(r);
        auto value = std::get<1>(r);
        auto hexMemo = std::get<2>(r);

        auto addr = DecodePaymentAddress(address);
        assert(std::get_if<libzcash::SaplingPaymentAddress>(&addr) != nullptr);
        auto to = *(std::get_if<libzcash::SaplingPaymentAddress>(&addr));

        auto memo = get_memo_from_hex_string(hexMemo);

        builder_.AddSaplingOutput(ovk, to, value, memo);
    }

    // Add Sapling outputs
    for (auto r : orchard_outputs_) {
        auto address = std::get<0>(r);
        auto value = std::get<1>(r);
        auto hexMemo = std::get<2>(r);

        auto addr = DecodePaymentAddress(address);
        assert(std::get_if<libzcash::OrchardPaymentAddressPirate>(&addr) != nullptr);
        auto to = *(std::get_if<libzcash::OrchardPaymentAddressPirate>(&addr));

        auto memo = get_memo_from_hex_string(hexMemo);

        builder_.AddOrchardOutput(ovk, to, value, memo);
    }

    // Build the transaction
    tx_ = builder_.Build().GetTxOrThrow();

    // Send the transaction
    // TODO: Use CWallet::CommitTransaction instead of sendrawtransaction
    auto signedtxn = EncodeHexTx(tx_);
    if (!testmode) {
        UniValue params = UniValue(UniValue::VARR);
        params.push_back(signedtxn);
        UniValue sendResultValue = sendrawtransaction(params, false, CPubKey());
        if (sendResultValue.isNull()) {
            throw JSONRPCError(RPC_WALLET_ERROR, "sendrawtransaction did not return an error or a txid.");
        }

        auto txid = sendResultValue.get_str();

        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("txid", txid));
        set_result(o);
    } else {
        // Test mode does not send the transaction to the network.
        UniValue o(UniValue::VOBJ);
        o.push_back(Pair("test", 1));
        o.push_back(Pair("txid", tx_.GetHash().ToString()));
        o.push_back(Pair("hex", signedtxn));
        set_result(o);
    }

    return true;
}

bool AsyncRPCOperation_sendmany::find_utxos(bool fAcceptCoinbase = false)
{
    std::set<CTxDestination> destinations;
    destinations.insert(fromtaddr_);

    vector<COutput> vecOutputs;

    LOCK2(cs_main, pwalletMain->cs_wallet);
    pwalletMain->AvailableCoins(vecOutputs, false, NULL, true, fAcceptCoinbase);

    BOOST_FOREACH (const COutput& out, vecOutputs) {
        CTxDestination dest;

        if (!out.fSpendable) {
            continue;
        }

        if (mindepth_ > 1) {
            int nHeight = tx_height(out.tx->GetHash());
            int dpowconfs = komodo_dpowconfs(nHeight, out.nDepth);
            if (dpowconfs < mindepth_) {
                continue;
            }
        } else {
            if (out.nDepth < mindepth_) {
                continue;
            }
        }

        const CScript& scriptPubKey = out.tx->vout[out.i].scriptPubKey;

        if (destinations.size()) {
            if (!ExtractDestination(scriptPubKey, dest)) {
                continue;
            }

            if (!destinations.count(dest)) {
                continue;
            }
        }

        // By default we ignore coinbase outputs
        bool isCoinbase = out.tx->IsCoinBase();
        if (isCoinbase && fAcceptCoinbase == false) {
            continue;
        }

        if (!ExtractDestination(scriptPubKey, dest, true))
            continue;

        CAmount nValue = out.tx->vout[out.i].nValue;

        SendManyInputUTXO utxo(out.tx->GetHash(), out.i, nValue, isCoinbase, dest);
        t_inputs_.push_back(utxo);
    }

    // sort in ascending order, so smaller utxos appear first
    std::sort(t_inputs_.begin(), t_inputs_.end(), [](SendManyInputUTXO i, SendManyInputUTXO j) -> bool {
        return (std::get<2>(i) < std::get<2>(j));
    });

    return t_inputs_.size() > 0;
}


bool AsyncRPCOperation_sendmany::find_unspent_notes()
{
    std::vector<CSproutNotePlaintextEntry> sproutEntries;
    std::vector<SaplingNoteEntry> saplingEntries;
    {
        LOCK2(cs_main, pwalletMain->cs_wallet);
        if (bOfflineSpendingKey == true) {
            // Offline transaction, Does not require the spending key in this wallet
            pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, fromaddress_, mindepth_, true, false);
        } else {
            // Local transaction: Require the spending key
            pwalletMain->GetFilteredNotes(sproutEntries, saplingEntries, fromaddress_, mindepth_, true, true);
        }
    }

    for (auto entry : saplingEntries) {
        z_sapling_inputs_.push_back(entry);
        std::string data(entry.memo.begin(), entry.memo.end());
        LogPrint("zrpcunsafe", "%s: found unspent Sapling note (txid=%s, vShieldedSpend=%d, amount=%s, memo=%s)\n",
                 getId(),
                 entry.op.hash.ToString().substr(0, 10),
                 entry.op.n,
                 FormatMoney(entry.note.value()),
                 HexStr(data).substr(0, 10));
    }

    if (z_sapling_inputs_.empty()) {
        return false;
    }

    // sort in descending order, so big notes appear first
    std::sort(z_sapling_inputs_.begin(), z_sapling_inputs_.end(),
              [](SaplingNoteEntry i, SaplingNoteEntry j) -> bool {
                  return i.note.value() > j.note.value();
              });

    return true;
}

std::array<unsigned char, ZC_MEMO_SIZE> AsyncRPCOperation_sendmany::get_memo_from_hex_string(std::string s)
{
    // initialize to default memo (no_memo), see section 5.5 of the protocol spec
    std::array<unsigned char, ZC_MEMO_SIZE> memo = {{0xF6}};

    std::vector<unsigned char> rawMemo = ParseHex(s.c_str());

    // If ParseHex comes across a non-hex char, it will stop but still return results so far.
    size_t slen = s.length();
    if (slen % 2 != 0 || (slen > 0 && rawMemo.size() != slen / 2)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Memo must be in hexadecimal format");
    }

    if (rawMemo.size() > ZC_MEMO_SIZE) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Memo size of %d is too big, maximum allowed is %d", rawMemo.size(), ZC_MEMO_SIZE));
    }

    // copy vector into boost array
    int lenMemo = rawMemo.size();
    for (int i = 0; i < ZC_MEMO_SIZE && i < lenMemo; i++) {
        memo[i] = rawMemo[i];
    }
    return memo;
}

/**
 * Override getStatus() to append the operation's input parameters to the default status object.
 */
UniValue AsyncRPCOperation_sendmany::getStatus() const
{
    UniValue v = AsyncRPCOperation::getStatus();
    if (contextinfo_.isNull()) {
        return v;
    }

    UniValue obj = v.get_obj();
    obj.push_back(Pair("method", "z_sendmany"));
    obj.push_back(Pair("params", contextinfo_));
    return obj;
}
