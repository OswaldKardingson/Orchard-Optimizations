// Copyright (c) 2019 Cryptoforge
// Copyright (c) 2019 The Zero developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "key_io.h"
#include "rpc/server.h"
#include "wallet.h"
#include "rpcpiratewallet.h"
#include "utilmoneystr.h"

#include "komodo_defs.h"

#include <utf8cpp/utf8.h>

using namespace std;
using namespace libzcash;

bool EnsureWalletIsAvailable(bool avoidException);
int32_t komodo_dpowconfs(int32_t height, int32_t numconfs);

template <typename RpcTx>
void getTransparentSpends(RpcTx& tx, vector<TransactionSpendT>& vSpend, CAmount& transparentValue, bool fIncludeWatchonly)
{
    // Transparent Inputs belonging to the wallet
    for (int i = 0; i < tx.vin.size(); i++) {
        const CTxIn& txin = tx.vin[i];
        TransactionSpendT spend;

        // Get Tx from files
        CTxOut parentOut = CTxOut();
        const CWalletTx* parentwtx = pwalletMain->GetWalletTx(txin.prevout.hash);
        if (parentwtx != NULL) {
            parentOut = parentwtx->vout[txin.prevout.n];
        } else {
            map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.find(txin.prevout.hash);
            if (it != pwalletMain->mapArcTxs.end()) {
                CTransaction parentctx;
                uint256 hashBlock;

                // Find the block it claims to be in
                BlockMap::iterator mi = mapBlockIndex.find(it->second.hashBlock);
                if (mi == mapBlockIndex.end()) {
                    return;
                }
                CBlockIndex* pindex = (*mi).second;
                if (!pindex || !chainActive.Contains(pindex)) {
                    return;
                }

                // Get Tx from block
                CBlock block;
                ReadBlockFromDisk(block, pindex, 1);

                // Get Tx
                for (int j = 0; j < block.vtx.size(); j++) {
                    if (txin.prevout.hash == block.vtx[j].GetHash()) {
                        parentctx = block.vtx[j];
                        parentOut = parentctx.vout[txin.prevout.n];
                    }
                }
            }
        }

        if (!parentOut.IsNull()) {
            transparentValue -= parentOut.nValue;
            CTxDestination address;
            ExtractDestination(parentOut.scriptPubKey, address);

            spend.encodedAddress = EncodeDestination(address);
            spend.encodedScriptPubKey = HexStr(parentOut.scriptPubKey.begin(), parentOut.scriptPubKey.end());
            spend.amount = parentOut.nValue;
            spend.spendTxid = txin.prevout.hash.ToString();
            spend.spendVout = (int)txin.prevout.n;

            if (IsMine(*pwalletMain, address) == ISMINE_SPENDABLE) {
                spend.spendable = true;
            } else {
                spend.spendable = false;
            }

            if (IsMine(*pwalletMain, address) == ISMINE_SPENDABLE || (IsMine(*pwalletMain, address) == ISMINE_WATCH_ONLY && fIncludeWatchonly))
                vSpend.push_back(spend);
        }
    }
}

template <typename RpcTx>
void getTransparentSends(RpcTx& tx, vector<TransactionSendT>& vSend, CAmount& transparentValue)
{
    // All Transparent Sends in the transaction
    for (int i = 0; i < tx.vout.size(); i++) {
        const CTxOut& txout = tx.vout[i];
        TransactionSendT send;
        CTxDestination address;
        ExtractDestination(txout.scriptPubKey, address);

        send.encodedAddress = EncodeDestination(address);
        send.encodedScriptPubKey = HexStr(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
        send.amount = txout.nValue;
        transparentValue += txout.nValue;
        send.vout = i;
        send.mine = IsMine(*pwalletMain, address);
        vSend.push_back(send);
    }
}

template <typename RpcTx>
void getTransparentRecieves(RpcTx& tx, vector<TransactionReceivedT>& vReceived, bool fIncludeWatchonly)
{
    // Transparent Received txos belonging to the wallet
    for (int i = 0; i < tx.vout.size(); i++) {
        TransactionReceivedT received;
        const CTxOut& txout = tx.vout[i];
        CTxDestination address;
        ExtractDestination(txout.scriptPubKey, address);

        received.encodedAddress = EncodeDestination(address);
        received.encodedScriptPubKey = HexStr(txout.scriptPubKey.begin(), txout.scriptPubKey.end());
        received.amount = txout.nValue;
        received.vout = i;

        if (IsMine(*pwalletMain, address) == ISMINE_SPENDABLE) {
            received.spendable = true;
        } else {
            received.spendable = false;
        }

        if (IsMine(*pwalletMain, address) == ISMINE_SPENDABLE || (IsMine(*pwalletMain, address) == ISMINE_WATCH_ONLY && fIncludeWatchonly))
            vReceived.push_back(received);
    }
}

template <typename RpcTx>
void getSaplingSpends(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<uint256>& ivks, std::set<uint256>& ivksOut, vector<TransactionSpendZS>& vSpend, bool fIncludeWatchonly)
{
    // Sapling Inputs belonging to the wallet
    for (const auto& rustSpend : tx.GetSaplingSpends()) {
        uint256 nullifier = uint256::FromRawBytes(rustSpend.nullifier());

        TransactionSpendZS spend;

        // Find the op of the nullifier
        map<uint256, SaplingOutPoint>::iterator opit = pwalletMain->mapArcSaplingOutPoints.find(nullifier);
        if (opit == pwalletMain->mapArcSaplingOutPoints.end()) {
            continue;
        }
        SaplingOutPoint op = (*opit).second;

        // Get Tx from files
        sapling::Output* output;
        const CWalletTx* parentwtx = pwalletMain->GetWalletTx(op.hash);
        if (parentwtx != NULL) {
            auto vOutputs = parentwtx->GetSaplingOutputs();
            output = &vOutputs[op.n];
        } else {
            map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.find(op.hash);
            if (it != pwalletMain->mapArcTxs.end()) {
                CTransaction parentctx;
                uint256 hashBlock;

                // Find the block it claims to be in
                BlockMap::iterator mi = mapBlockIndex.find(it->second.hashBlock);
                if (mi == mapBlockIndex.end()) {
                    return;
                }
                CBlockIndex* pindex = (*mi).second;
                if (!pindex || !chainActive.Contains(pindex)) {
                    return;
                }

                // Get Tx from block
                CBlock block;
                ReadBlockFromDisk(block, pindex, 1);

                // Get Tx
                for (int j = 0; j < block.vtx.size(); j++) {
                    if (op.hash == block.vtx[j].GetHash()) {
                        parentctx = block.vtx[j];
                        continue;
                    }
                }

                // Get Output
                auto vOutputs = parentctx.GetSaplingOutputs();
                output = &vOutputs[op.n];
            }
        }

        for (std::set<uint256>::iterator it = ivks.begin(); it != ivks.end(); it++) {
            auto ivk = SaplingIncomingViewingKey(*it);

            // Cipher Text
            libzcash::SaplingEncCiphertext encCiphertext;
            auto rustEncCiphertext = output->enc_ciphertext();
            std::memcpy(&encCiphertext, &rustEncCiphertext, 580);

            auto ephemeralKey = uint256::FromRawBytes(output->ephemeral_key());
            auto cmu = uint256::FromRawBytes(output->cmu());

            auto pt = libzcash::SaplingNotePlaintext::decrypt(params, nHeight,
                                                              encCiphertext, ivk, ephemeralKey, cmu);

            if (pt) {
                ivksOut.insert(ivk);
                auto note = pt.value();
                auto pa = ivk.address(note.d);
                auto address = pa.value();
                spend.encodedAddress = EncodePaymentAddress(address);
                spend.amount = note.value();
                spend.spendShieldedOutputIndex = (int)op.n;
                spend.spendTxid = op.hash.ToString();

                libzcash::SaplingExtendedFullViewingKey extfvk;
                pwalletMain->GetSaplingFullViewingKey(ivk, extfvk);
                spend.spendable = pwalletMain->HaveSaplingSpendingKey(extfvk);

                if (spend.spendable || fIncludeWatchonly)
                    vSpend.push_back(spend);
                // ivk found no need ot try anymore
                break;
            }
        }
    }
}


template <typename RpcTx>
void getSaplingSends(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<uint256>& ovks, std::set<uint256>& ovksOut, vector<TransactionSendZS>& vSend)
{
    // Outgoing Sapling Spends
    int shieldedOutputIndex = 0;
    for (const auto& rustOutput : tx.GetSaplingOutputs()) {
        auto cmu = uint256::FromRawBytes(rustOutput.cmu());
        auto ephemeralKey = uint256::FromRawBytes(rustOutput.ephemeral_key());
        auto cv = uint256::FromRawBytes(rustOutput.cv());
        auto encCiphertext = rustOutput.enc_ciphertext();
        auto outCiphertext = rustOutput.out_ciphertext();

        for (std::set<uint256>::iterator it = ovks.begin(); it != ovks.end(); it++) {
            auto ovk = *it;
            TransactionSendZS send;
            auto opt = libzcash::SaplingOutgoingPlaintext::decrypt(outCiphertext, ovk, cv, cmu, ephemeralKey);

            if (opt) {
                auto opt_unwrapped = opt.value();
                auto pt = libzcash::SaplingNotePlaintext::decrypt(params, nHeight, encCiphertext, ephemeralKey, opt_unwrapped.esk, opt_unwrapped.pk_d, cmu);

                if (pt) {
                    ovksOut.insert(ovk);
                    auto pt_unwrapped = pt.value();
                    auto memo = pt_unwrapped.memo();
                    libzcash::SaplingPaymentAddress sentAddr(pt_unwrapped.d, opt_unwrapped.pk_d);

                    libzcash::SaplingExtendedSpendingKey extsk;
                    bool addrIsMine = pwalletMain->GetSaplingExtendedSpendingKey(sentAddr, extsk);

                    send.encodedAddress = EncodePaymentAddress(sentAddr);
                    send.amount = pt_unwrapped.value();
                    send.shieldedOutputIndex = shieldedOutputIndex;
                    send.memo = HexStr(memo);

                    // If the leading byte is 0xF4 or lower, the memo field should be interpreted as a
                    // UTF-8-encoded text string.
                    if (memo[0] <= 0xf4) {
                        // Trim off trailing zeroes
                        auto end = std::find_if(
                            memo.rbegin(),
                            memo.rend(),
                            [](unsigned char v) { return v != 0; });
                        std::string memoStr(memo.begin(), end.base());
                        if (utf8::is_valid(memoStr)) {
                            send.memoStr = memoStr;
                        }
                    }

                    send.mine = addrIsMine;
                    vSend.push_back(send);
                }
                // ovk found no need ot try anymore
                break;
            }
        }
        shieldedOutputIndex++;
    }
}

template <typename RpcTx>
void getSaplingReceives(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<uint256>& ivks, std::set<uint256>& ivksOut, vector<TransactionReceivedZS>& vReceived, bool fIncludeWatchonly)
{
    int shieldedOutputIndex = 0;
    for (const auto& rustOutput : tx.GetSaplingOutputs()) {
        TransactionReceivedZS received;
        auto cmu = uint256::FromRawBytes(rustOutput.cmu());
        auto ephemeralKey = uint256::FromRawBytes(rustOutput.ephemeral_key());
        auto encCiphertext = rustOutput.enc_ciphertext();

        for (std::set<uint256>::iterator it = ivks.begin(); it != ivks.end(); it++) {
            auto ivk = SaplingIncomingViewingKey(*it);
            auto pt = libzcash::SaplingNotePlaintext::decrypt(params, nHeight, encCiphertext, ivk, ephemeralKey, cmu);

            if (pt) {
                ivksOut.insert(ivk);
                auto note = pt.value();
                auto pa = ivk.address(note.d);
                auto address = pa.value();
                auto memo = note.memo();
                received.encodedAddress = EncodePaymentAddress(address);
                received.amount = note.value();
                received.shieldedOutputIndex = shieldedOutputIndex;
                received.memo = HexStr(memo);

                libzcash::SaplingExtendedFullViewingKey extfvk;
                pwalletMain->GetSaplingFullViewingKey(ivk, extfvk);
                received.spendable = pwalletMain->HaveSaplingSpendingKey(extfvk);

                // If the leading byte is 0xF4 or lower, the memo field should be interpreted as a
                // UTF-8-encoded text string.
                if (memo[0] <= 0xf4) {
                    // Trim off trailing zeroes
                    auto end = std::find_if(
                        memo.rbegin(),
                        memo.rend(),
                        [](unsigned char v) { return v != 0; });
                    std::string memoStr(memo.begin(), end.base());
                    if (utf8::is_valid(memoStr)) {
                        received.memoStr = memoStr;
                    }
                }

                if (received.spendable || fIncludeWatchonly)
                    vReceived.push_back(received);
                // ivk found no need to try anymore
                break;
            }
        }
        shieldedOutputIndex++;
    }
}

template <typename RpcTx>
void getOrchardSends(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<libzcash::OrchardOutgoingViewingKey>& ovks, std::set<libzcash::OrchardOutgoingViewingKey>& ovksOut, vector<TransactionSendZO>& vSend)
{
    // Outgoing Sapling Spends
    int shieldedActionIndex = 0;
    for (const auto& rustAction : tx.GetOrchardActions()) {
        for (std::set<libzcash::OrchardOutgoingViewingKey>::iterator it = ovks.begin(); it != ovks.end(); it++) {
            auto ovk = *it;
            TransactionSendZO send;
            auto pt = OrchardNotePlaintext::AttemptDecryptOrchardAction(&rustAction, ovk);

            if (pt) {
                auto note = pt.value();
                auto memo = note.memo();
                auto addr = note.GetAddress();

                ovksOut.insert(ovk);

                send.encodedAddress = EncodePaymentAddress(addr);
                send.amount = note.value();
                send.shieldedActionIndex = shieldedActionIndex;
                send.memo = HexStr(memo);

                libzcash::OrchardExtendedSpendingKeyPirate extsk;
                bool addrIsMine = pwalletMain->GetOrchardExtendedSpendingKey(addr, extsk);

                // If the leading byte is 0xF4 or lower, the memo field should be interpreted as a
                // UTF-8-encoded text string.
                if (memo[0] <= 0xf4) {
                    // Trim off trailing zeroes
                    auto end = std::find_if(
                        memo.rbegin(),
                        memo.rend(),
                        [](unsigned char v) { return v != 0; });
                    std::string memoStr(memo.begin(), end.base());
                    if (utf8::is_valid(memoStr)) {
                        send.memoStr = memoStr;
                    }
                }

                send.mine = addrIsMine;
                vSend.push_back(send);
                // ovk found no need to try anymore
                break;
            }
        }
        shieldedActionIndex++;
    }
}

template <typename RpcTx>
void getOrchardSpends(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<libzcash::OrchardIncomingViewingKeyPirate>& ivks, std::set<libzcash::OrchardIncomingViewingKeyPirate>& ivksOut, vector<TransactionSpendZO>& vSpend, bool fIncludeWatchonly)
{
    // Sapling Inputs belonging to the wallet
    for (const auto& rustSpend : tx.GetOrchardActions()) {
        uint256 nullifier = uint256::FromRawBytes(rustSpend.nullifier());

        TransactionSpendZO spend;

        // Find the op of the nullifier
        map<uint256, OrchardOutPoint>::iterator opit = pwalletMain->mapArcOrchardOutPoints.find(nullifier);
        if (opit == pwalletMain->mapArcOrchardOutPoints.end()) {
            continue;
        }
        OrchardOutPoint op = (*opit).second;

        // Get Tx from files
        orchard_bundle::Action* rustAction;
        const CWalletTx* parentwtx = pwalletMain->GetWalletTx(op.hash);
        if (parentwtx != NULL) {
            auto vActions = parentwtx->GetOrchardActions();
            rustAction = &vActions[op.n];
        } else {
            map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.find(op.hash);
            if (it != pwalletMain->mapArcTxs.end()) {
                CTransaction parentctx;
                uint256 hashBlock;

                // Find the block it claims to be in
                BlockMap::iterator mi = mapBlockIndex.find(it->second.hashBlock);
                if (mi == mapBlockIndex.end()) {
                    return;
                }
                CBlockIndex* pindex = (*mi).second;
                if (!pindex || !chainActive.Contains(pindex)) {
                    return;
                }

                // Get Tx from block
                CBlock block;
                ReadBlockFromDisk(block, pindex, 1);

                // Get Tx
                for (int j = 0; j < block.vtx.size(); j++) {
                    if (op.hash == block.vtx[j].GetHash()) {
                        parentctx = block.vtx[j];
                        continue;
                    }
                }

                // Get Output
                auto vActions = parentctx.GetOrchardActions();
                rustAction = &vActions[op.n];
            }
        }

        for (std::set<OrchardIncomingViewingKeyPirate>::iterator it = ivks.begin(); it != ivks.end(); it++) {
            auto ivk = *it;
            auto pt = OrchardNotePlaintext::AttemptDecryptOrchardAction(rustAction, ivk);

            if (pt) {
                auto note = pt.value();
                auto memo = note.memo();

                ivksOut.insert(ivk);
                spend.encodedAddress = EncodePaymentAddress(note.GetAddress());
                spend.amount = note.value();
                spend.spendShieldedActionIndex = (int)op.n;
                spend.spendTxid = op.hash.ToString();

                libzcash::OrchardExtendedFullViewingKeyPirate extfvk;
                pwalletMain->GetOrchardFullViewingKey(ivk, extfvk);
                spend.spendable = pwalletMain->HaveOrchardSpendingKey(extfvk);

                if (spend.spendable || fIncludeWatchonly)
                    vSpend.push_back(spend);
                // ivk found no need ot try anymore
                break;
            }
        }
    }
}

template <typename RpcTx>
void getOrchardReceives(const Consensus::Params& params, int nHeight, RpcTx& tx, std::set<libzcash::OrchardIncomingViewingKeyPirate>& ivks, std::set<libzcash::OrchardIncomingViewingKeyPirate>& ivksOut, vector<TransactionReceivedZO>& vReceived, bool fIncludeWatchonly)
{
    int shieldedActionIndex = 0;
    for (const auto& rustAction : tx.GetOrchardActions()) {
        TransactionReceivedZO received;

        for (std::set<libzcash::OrchardIncomingViewingKeyPirate>::iterator it = ivks.begin(); it != ivks.end(); it++) {
            auto ivk = *it;
            auto pt = OrchardNotePlaintext::AttemptDecryptOrchardAction(&rustAction, ivk);

            if (pt) {
                auto note = pt.value();
                auto memo = note.memo();

                ivksOut.insert(ivk);
                received.encodedAddress = EncodePaymentAddress(note.GetAddress());
                received.amount = note.value();
                received.shieldedActionIndex = shieldedActionIndex;
                received.memo = HexStr(memo);

                libzcash::OrchardExtendedFullViewingKeyPirate extfvk;
                pwalletMain->GetOrchardFullViewingKey(ivk, extfvk);
                received.spendable = pwalletMain->HaveOrchardSpendingKey(extfvk);

                // If the leading byte is 0xF4 or lower, the memo field should be interpreted as a
                // UTF-8-encoded text string.
                if (memo[0] <= 0xf4) {
                    // Trim off trailing zeroes
                    auto end = std::find_if(
                        memo.rbegin(),
                        memo.rend(),
                        [](unsigned char v) { return v != 0; });
                    std::string memoStr(memo.begin(), end.base());
                    if (utf8::is_valid(memoStr)) {
                        received.memoStr = memoStr;
                    }
                }

                if (received.spendable || fIncludeWatchonly)
                    vReceived.push_back(received);
                // ivk found no need to try anymore
                break;
            }
        }
        shieldedActionIndex++;
    }
}

void getAllSaplingOVKs(std::set<uint256>& ovks, bool fIncludeWatchonly)
{
    // exit if pwalletMain is not set
    if (pwalletMain == nullptr)
        return;

    // get ovks for all sapling spending keys
    if (fIncludeWatchonly) {
        pwalletMain->GetSaplingOutgoingViewingKeySet(ovks);
    } else {
        std::set<libzcash::SaplingIncomingViewingKey> setIvks;
        pwalletMain->GetSaplingIncomingViewingKeySet(setIvks);
        for (std::set<libzcash::SaplingIncomingViewingKey>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
            libzcash::SaplingIncomingViewingKey ivk = (*it);
            libzcash::SaplingExtendedFullViewingKey extfvk;

            if (pwalletMain->GetSaplingFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveSaplingSpendingKey(extfvk) || fIncludeWatchonly) {
                    ovks.insert(extfvk.fvk.ovk);
                }
            }
        }
    }

    // get ovks for all orchard spending keys (Orcharch OVKs can be used when the source is a Orchard note)
    std::set<libzcash::OrchardOutgoingViewingKey> ovksOrchard;
    if (fIncludeWatchonly) {
        pwalletMain->GetOrchardOutgoingViewingKeySet(ovksOrchard);
    } else {
        std::set<libzcash::OrchardIncomingViewingKeyPirate> setIvks;
        pwalletMain->GetOrchardIncomingViewingKeySet(setIvks);
        for (std::set<libzcash::OrchardIncomingViewingKeyPirate>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
            libzcash::OrchardIncomingViewingKeyPirate ivk = (*it);
            libzcash::OrchardExtendedFullViewingKeyPirate extfvk;

            if (pwalletMain->GetOrchardFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveOrchardSpendingKey(extfvk) || fIncludeWatchonly) {
                    // External OVK
                    auto ovkOpt_e = extfvk.fvk.GetOVK();
                    if (ovkOpt_e != std::nullopt) {
                        ovksOrchard.insert(ovkOpt_e.value());
                    }
                    // Internal OVK
                    auto ovkOpt_i = extfvk.fvk.GetOVKinternal();
                    if (ovkOpt_i != std::nullopt) {
                        ovksOrchard.insert(ovkOpt_i.value());
                    }
                }
            }
        }
    }

    for (std::set<libzcash::OrchardOutgoingViewingKey>::iterator it = ovksOrchard.begin(); it != ovksOrchard.end(); it++) {
        ovks.insert(it->ovk);
    }

    // ovk used of t addresses
    HDSeed seed;
    if (pwalletMain->GetHDSeed(seed)) {
        ovks.insert(ovkForShieldingFromTaddr(seed));
    }
}

void getAllSaplingIVKs(std::set<uint256>& ivks, bool fIncludeWatchonly)
{
    // exit if pwalletMain is not set
    if (pwalletMain == nullptr)
        return;

    std::set<libzcash::SaplingIncomingViewingKey> setIvks;
    pwalletMain->GetSaplingIncomingViewingKeySet(setIvks);
    // get ivks for all spending keys
    for (std::set<libzcash::SaplingIncomingViewingKey>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
        libzcash::SaplingIncomingViewingKey ivk = (*it);


        if (fIncludeWatchonly) {
            ivks.insert(ivk);
        } else {
            libzcash::SaplingExtendedFullViewingKey extfvk;
            if (pwalletMain->GetSaplingFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveSaplingSpendingKey(extfvk)) {
                    ivks.insert(ivk);
                }
            }
        }
    }
}

void getRpcArcTxSaplingKeys(const CWalletTx& tx, int txHeight, RpcArcTransaction& arcTx, bool fIncludeWatchonly)
{
    AssertLockHeld(pwalletMain->cs_wallet);

    std::set<uint256> ivks;
    std::set<uint256> ovks;

    getAllSaplingOVKs(ovks, fIncludeWatchonly);
    getAllSaplingIVKs(ivks, fIncludeWatchonly);

    auto params = Params().GetConsensus();
    getSaplingSpends(params, txHeight, tx, ivks, arcTx.saplingIvks, arcTx.vZsSpend, fIncludeWatchonly);
    getSaplingSends(params, txHeight, tx, ovks, arcTx.saplingOvks, arcTx.vZsSend);
    getSaplingReceives(params, txHeight, tx, ivks, arcTx.saplingIvks, arcTx.vZsReceived, fIncludeWatchonly);

    // Create Set of wallet address the belong to the wallet for this tx and have been spent from
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZsSpend[i].encodedAddress);
    }

    // Create Set of wallet address the belong to the wallet for this tx
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsReceived[i].encodedAddress);
    }
}

void getAllOrchardOVKs(std::set<libzcash::OrchardOutgoingViewingKey>& ovks, bool fIncludeWatchonly)
{
    // exit if pwalletMain is not set
    if (pwalletMain == nullptr)
        return;

    // get ovks for all spending keys
    if (fIncludeWatchonly) {
        pwalletMain->GetOrchardOutgoingViewingKeySet(ovks);
    } else {
        std::set<libzcash::OrchardIncomingViewingKeyPirate> setIvks;
        pwalletMain->GetOrchardIncomingViewingKeySet(setIvks);
        for (std::set<libzcash::OrchardIncomingViewingKeyPirate>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
            libzcash::OrchardIncomingViewingKeyPirate ivk = (*it);
            libzcash::OrchardExtendedFullViewingKeyPirate extfvk;

            if (pwalletMain->GetOrchardFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveOrchardSpendingKey(extfvk) || fIncludeWatchonly) {
                    // External OVK
                    auto ovkOpt_e = extfvk.fvk.GetOVK();
                    if (ovkOpt_e != std::nullopt) {
                        ovks.insert(ovkOpt_e.value());
                    }
                    // Internal OVK
                    auto ovkOpt_i = extfvk.fvk.GetOVKinternal();
                    if (ovkOpt_i != std::nullopt) {
                        ovks.insert(ovkOpt_i.value());
                    }
                }
            }
        }
    }

    // get ovks for all sapling spending keys (Sapling OVKs can be used for Orchard when the source is a Sapling note)
    std::set<uint256> ovksSapling;
    if (fIncludeWatchonly) {
        pwalletMain->GetSaplingOutgoingViewingKeySet(ovksSapling);
    } else {
        std::set<libzcash::SaplingIncomingViewingKey> setIvks;
        pwalletMain->GetSaplingIncomingViewingKeySet(setIvks);
        for (std::set<libzcash::SaplingIncomingViewingKey>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
            libzcash::SaplingIncomingViewingKey ivk = (*it);
            libzcash::SaplingExtendedFullViewingKey extfvk;

            if (pwalletMain->GetSaplingFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveSaplingSpendingKey(extfvk) || fIncludeWatchonly) {
                    ovksSapling.insert(extfvk.fvk.ovk);
                }
            }
        }
    }

    for (std::set<uint256>::iterator it = ovksSapling.begin(); it != ovksSapling.end(); it++) {
        ovks.insert(libzcash::OrchardOutgoingViewingKey(*it));
    }

    // ovk used of t addresses
    HDSeed seed;
    if (pwalletMain->GetHDSeed(seed)) {
        ovks.insert(libzcash::OrchardOutgoingViewingKey(ovkForShieldingFromTaddr(seed)));
    }
}

void getAllOrchardIVKs(std::set<libzcash::OrchardIncomingViewingKeyPirate>& ivks, bool fIncludeWatchonly)
{
    // exit if pwalletMain is not set
    if (pwalletMain == nullptr)
        return;

    std::set<libzcash::OrchardIncomingViewingKeyPirate> setIvks;
    pwalletMain->GetOrchardIncomingViewingKeySet(setIvks);
    // get ivks for all spending keys
    for (std::set<libzcash::OrchardIncomingViewingKeyPirate>::iterator it = setIvks.begin(); it != setIvks.end(); it++) {
        libzcash::OrchardIncomingViewingKeyPirate ivk = (*it);


        if (fIncludeWatchonly) {
            ivks.insert(ivk);
        } else {
            libzcash::OrchardExtendedFullViewingKeyPirate extfvk;
            if (pwalletMain->GetOrchardFullViewingKey(ivk, extfvk)) {
                if (pwalletMain->HaveOrchardSpendingKey(extfvk)) {
                    ivks.insert(ivk);
                }
            }
        }
    }
}

void getRpcArcTxOrchardKeys(const CWalletTx& tx, int txHeight, RpcArcTransaction& arcTx, bool fIncludeWatchonly)
{
    AssertLockHeld(pwalletMain->cs_wallet);

    std::set<libzcash::OrchardIncomingViewingKeyPirate> ivks;
    std::set<libzcash::OrchardOutgoingViewingKey> ovks;

    getAllOrchardOVKs(ovks, fIncludeWatchonly);
    getAllOrchardIVKs(ivks, fIncludeWatchonly);

    auto params = Params().GetConsensus();
    getOrchardSpends(params, txHeight, tx, ivks, arcTx.orchardIvks, arcTx.vZoSpend, fIncludeWatchonly);
    getOrchardSends(params, txHeight, tx, ovks, arcTx.orchardOvks, arcTx.vZoSend);
    getOrchardReceives(params, txHeight, tx, ivks, arcTx.orchardIvks, arcTx.vZoReceived, fIncludeWatchonly);

    // Create Set of wallet address the belong to the wallet for this tx and have been spent from
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZoSpend[i].encodedAddress);
    }

    // Create Set of wallet address the belong to the wallet for this tx
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoReceived[i].encodedAddress);
    }
}

void getRpcArcTx(uint256& txid, RpcArcTransaction& arcTx, bool fIncludeWatchonly, bool rescan)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);

    // set defaults
    arcTx.archiveType = ARCHIVED;
    arcTx.txid = txid;
    arcTx.coinbase = false;
    arcTx.category = "not found";
    arcTx.blockHash = uint256();
    arcTx.blockHeight = 0;
    arcTx.blockIndex = 0;
    arcTx.nBlockTime = 0;
    arcTx.rawconfirmations = 0;
    arcTx.confirmations = 0;

    CTransaction tx;
    uint256 hashBlock;
    int nIndex;
    ArchiveTxPoint arcTxPt;
    std::set<uint256> saplingIvks;
    std::set<uint256> saplingOvks;
    std::set<libzcash::OrchardIncomingViewingKeyPirate> orchardIvks;
    std::set<libzcash::OrchardOutgoingViewingKey> orchardOvks;

    // try to find the transaction to pull the hashblock
    std::map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.find(txid);
    if (it != pwalletMain->mapArcTxs.end()) {
        // Get Location of tx in blockchain
        arcTxPt = it->second;
        hashBlock = arcTxPt.hashBlock;
        nIndex = arcTxPt.nIndex;

        // Get Ivks and Ovks saved in ArchiveTxPoint
        if ((arcTxPt.saplingIvks.size() == 0 && arcTxPt.saplingOvks.size() == 0 && arcTxPt.orchardIvks.size() == 0 && arcTxPt.orchardOvks.size() == 0) || rescan) {
            getAllSaplingOVKs(saplingOvks, fIncludeWatchonly);
            getAllSaplingIVKs(saplingIvks, fIncludeWatchonly);
            getAllOrchardOVKs(orchardOvks, fIncludeWatchonly);
            getAllOrchardIVKs(orchardIvks, fIncludeWatchonly);
        } else {
            saplingIvks = arcTxPt.saplingIvks;
            saplingOvks = arcTxPt.saplingOvks;
            orchardIvks = arcTxPt.orchardIvks;
            orchardOvks = arcTxPt.orchardOvks;
        }

        // Find the block it claims to be in
        BlockMap::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi == mapBlockIndex.end()) {
            return;
        }
        CBlockIndex* pindex = (*mi).second;
        if (!pindex || !chainActive.Contains(pindex)) {
            return;
        }

        // Get Tx from block
        CBlock block;
        ReadBlockFromDisk(block, pindex, 1);

        if (nIndex > block.vtx.size() - 1) {
            return; // Tx nIndex is invalid;
        }

        // Get Tx
        tx = block.vtx[nIndex];

        if (tx.GetHash() != txid) {
            return; // Tx Hash doesn't match;
        }
    } else {
        return;
    }

    arcTx.blockHash = hashBlock;

    int nHeight = chainActive.Tip()->nHeight;
    int txHeight = mapBlockIndex[hashBlock]->nHeight;
    arcTx.blockHeight = txHeight;
    arcTx.rawconfirmations = nHeight - txHeight + 1;
    arcTx.confirmations = komodo_dpowconfs(txHeight, nHeight - txHeight + 1);

    arcTx.nBlockTime = mapBlockIndex[hashBlock]->GetBlockTime();

    if (tx.IsCoinBase()) {
        arcTx.coinbase = true;
        arcTx.category = "generate";
    } else {
        arcTx.coinbase = false;
        arcTx.category = "standard";
    }

    arcTx.blockIndex = nIndex;
    arcTx.nTime = arcTx.nBlockTime;
    arcTx.expiryHeight = 0;
    arcTx.size = static_cast<uint64_t>(GetSerializeSize(static_cast<CTransaction>(tx), SER_NETWORK, PROTOCOL_VERSION));

    auto params = Params().GetConsensus();
    // Spends must be located to determine if outputs are change
    getTransparentSpends(tx, arcTx.vTSpend, arcTx.transparentValue, fIncludeWatchonly);
    getSaplingSpends(params, txHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsSpend, fIncludeWatchonly);
    getOrchardSpends(params, txHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoSpend, fIncludeWatchonly);

    getTransparentSends(tx, arcTx.vTSend, arcTx.transparentValue);
    getSaplingSends(params, txHeight, tx, saplingOvks, arcTx.saplingOvks, arcTx.vZsSend);
    getOrchardSends(params, txHeight, tx, orchardOvks, arcTx.orchardOvks, arcTx.vZoSend);

    getTransparentRecieves(tx, arcTx.vTReceived, fIncludeWatchonly);
    getSaplingReceives(params, txHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsReceived, fIncludeWatchonly);
    getOrchardReceives(params, txHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoReceived, fIncludeWatchonly);

    arcTx.saplingValue = -tx.GetValueBalanceSapling();
    arcTx.orchardValue = -tx.GetValueBalanceOrchard();

    // Create Set of wallet address the belong to the wallet for this tx and have been spent from
    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vTSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZsSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZoSpend[i].encodedAddress);
    }

    // Create Set of wallet address the belong to the wallet for this tx
    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vTSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSpend[i].encodedAddress);
    }


    for (int i = 0; i < arcTx.vTSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vTSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSend[i].encodedAddress);
    }


    for (int i = 0; i < arcTx.vTReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vTReceived[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsReceived[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoReceived[i].encodedAddress);
    }
}

void getRpcArcTx(CWalletTx& tx, RpcArcTransaction& arcTx, bool fIncludeWatchonly, bool rescan)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(pwalletMain->cs_wallet);

    std::set<uint256> saplingIvks;
    std::set<uint256> saplingOvks;
    std::set<libzcash::OrchardIncomingViewingKeyPirate> orchardIvks;
    std::set<libzcash::OrchardOutgoingViewingKey> orchardOvks;
    ArchiveTxPoint arcTxPt;
    std::map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.find(tx.GetHash());
    if (it != pwalletMain->mapArcTxs.end()) {
        arcTxPt = it->second;
        // Get Ivks and Ovks saved in ArchiveTxPoint
        if ((arcTxPt.saplingIvks.size() == 0 && arcTxPt.saplingOvks.size() == 0 && arcTxPt.orchardIvks.size() == 0 && arcTxPt.orchardOvks.size() == 0) || rescan) {
            getAllSaplingOVKs(saplingOvks, fIncludeWatchonly);
            getAllSaplingIVKs(saplingIvks, fIncludeWatchonly);
            getAllOrchardOVKs(orchardOvks, fIncludeWatchonly);
            getAllOrchardIVKs(orchardIvks, fIncludeWatchonly);
        } else {
            saplingIvks = arcTxPt.saplingIvks;
            saplingOvks = arcTxPt.saplingOvks;
            orchardIvks = arcTxPt.orchardIvks;
            orchardOvks = arcTxPt.orchardOvks;
        }
    } else {
        getAllSaplingOVKs(saplingOvks, fIncludeWatchonly);
        getAllSaplingIVKs(saplingIvks, fIncludeWatchonly);
        getAllOrchardOVKs(orchardOvks, fIncludeWatchonly);
        getAllOrchardIVKs(orchardIvks, fIncludeWatchonly);
    }


    arcTx.archiveType = ACTIVE;
    arcTx.txid = tx.GetHash();
    arcTx.blockIndex = tx.nIndex;
    arcTx.blockHash = tx.hashBlock;
    arcTx.rawconfirmations = tx.GetDepthInMainChain();
    int txHeight = chainActive.Tip()->nHeight + 1;

    if (!tx.hashBlock.IsNull() && mapBlockIndex.count(tx.hashBlock) > 0) {
        arcTx.nBlockTime = mapBlockIndex[tx.hashBlock]->GetBlockTime();
        arcTx.nTime = arcTx.nBlockTime;
        arcTx.confirmations = komodo_dpowconfs(mapBlockIndex[tx.hashBlock]->nHeight, tx.GetDepthInMainChain());
        txHeight = mapBlockIndex[tx.hashBlock]->nHeight;
        arcTx.blockHeight = txHeight;
    } else {
        arcTx.blockHeight = 0;
        arcTx.nBlockTime = 0;
        arcTx.confirmations = 0;
        arcTx.nTime = tx.GetTxTime();
    }

    if (tx.IsCoinBase()) {
        arcTx.coinbase = true;
        if (tx.GetDepthInMainChain() < 1) {
            arcTx.category = "orphan";
        } else if (tx.GetBlocksToMaturity() > 0) {
            arcTx.category = "immature";
        } else {
            arcTx.category = "generate";
        }
    } else {
        arcTx.coinbase = false;
        if (tx.GetDepthInMainChain() < 1) {
            arcTx.category = "orphan";
        } else if (tx.GetBlocksToMaturity() > 0) {
            arcTx.category = "immature";
        } else {
            arcTx.category = "standard";
        }
    }

    arcTx.expiryHeight = (int64_t)tx.nExpiryHeight;
    arcTx.size = static_cast<uint64_t>(GetSerializeSize(static_cast<CTransaction>(tx), SER_NETWORK, PROTOCOL_VERSION));

    auto params = Params().GetConsensus();
    // Spends must be located to determine if outputs are change
    getTransparentSpends(tx, arcTx.vTSpend, arcTx.transparentValue, fIncludeWatchonly);
    getSaplingSpends(params, txHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsSpend, fIncludeWatchonly);
    getOrchardSpends(params, txHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoSpend, fIncludeWatchonly);

    getTransparentSends(tx, arcTx.vTSend, arcTx.transparentValue);
    getSaplingSends(params, txHeight, tx, saplingOvks, arcTx.saplingOvks, arcTx.vZsSend);
    getOrchardSends(params, txHeight, tx, orchardOvks, arcTx.orchardOvks, arcTx.vZoSend);

    getTransparentRecieves(tx, arcTx.vTReceived, fIncludeWatchonly);
    getSaplingReceives(params, txHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsReceived, fIncludeWatchonly);
    getOrchardReceives(params, txHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoReceived, fIncludeWatchonly);

    arcTx.saplingValue = -tx.GetValueBalanceSapling();
    arcTx.orchardValue = -tx.GetValueBalanceOrchard();

    // Create Set of wallet address the belong to the wallet for this tx and have been spent from
    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vTSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZsSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZoSpend[i].encodedAddress);
    }

    // Create Set of wallet address the belong to the wallet for this tx
    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vTSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSpend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSpend[i].encodedAddress);
    }


    for (int i = 0; i < arcTx.vTSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vTSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsSend[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoSend.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoSend[i].encodedAddress);
    }


    for (int i = 0; i < arcTx.vTReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vTReceived[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZsReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZsReceived[i].encodedAddress);
    }
    for (int i = 0; i < arcTx.vZoReceived.size(); i++) {
        arcTx.addresses.insert(arcTx.vZoReceived[i].encodedAddress);
    }
}


void getRpcArcTxJSONHeader(RpcArcTransaction& arcTx, UniValue& ArcTxJSON)
{
    CAmount txFee = 0;
    if (!arcTx.coinbase)
        txFee = arcTx.transparentValue + arcTx.saplingValue + arcTx.orchardValue;

    ArcTxJSON.push_back(Pair("txid", arcTx.txid.ToString()));
    ArcTxJSON.push_back(Pair("coinbase", arcTx.coinbase));
    ArcTxJSON.push_back(Pair("category", arcTx.category));
    ArcTxJSON.push_back(Pair("blockHeight", arcTx.blockHeight));
    ArcTxJSON.push_back(Pair("blockhash", arcTx.blockHash.ToString()));
    ArcTxJSON.push_back(Pair("blockindex", arcTx.blockIndex));
    ArcTxJSON.push_back(Pair("blocktime", arcTx.nBlockTime));
    ArcTxJSON.push_back(Pair("rawconfirmations", arcTx.rawconfirmations));
    ArcTxJSON.push_back(Pair("confirmations", arcTx.confirmations));
    ArcTxJSON.push_back(Pair("time", arcTx.nTime));
    ArcTxJSON.push_back(Pair("expiryHeight", arcTx.expiryHeight));
    ArcTxJSON.push_back(Pair("size", arcTx.size));
    ArcTxJSON.push_back(Pair("transparentValue", arcTx.transparentValue));
    ArcTxJSON.push_back(Pair("saplingValue", arcTx.saplingValue));
    ArcTxJSON.push_back(Pair("orchardValue", arcTx.orchardValue));
    ArcTxJSON.push_back(Pair("fee", -txFee));
}

void getRpcArcTxJSONSpends(RpcArcTransaction& arcTx, UniValue& ArcTxJSON, bool filterAddress, string encodedAddress)
{
    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "transparent"));
        obj.push_back(Pair("spend", i));
        obj.push_back(Pair("txidPrev", arcTx.vTSpend[i].spendTxid));
        obj.push_back(Pair("outputPrev", arcTx.vTSpend[i].spendVout));
        obj.push_back(Pair("address", arcTx.vTSpend[i].encodedAddress));
        obj.push_back(Pair("scriptPubKey", arcTx.vTSpend[i].encodedScriptPubKey));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vTSpend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vTSpend[i].amount));
        obj.push_back(Pair("spendable", arcTx.vTSpend[i].spendable));
        if (!filterAddress || arcTx.vTSpend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "sapling"));
        obj.push_back(Pair("spend", i));
        obj.push_back(Pair("txidPrev", arcTx.vZsSpend[i].spendTxid));
        obj.push_back(Pair("outputPrev", arcTx.vZsSpend[i].spendShieldedOutputIndex));
        obj.push_back(Pair("address", arcTx.vZsSpend[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZsSpend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZsSpend[i].amount));
        obj.push_back(Pair("spendable", arcTx.vZsSpend[i].spendable));
        if (!filterAddress || arcTx.vZsSpend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("type", "orchard"));
        obj.push_back(Pair("spend", i));
        obj.push_back(Pair("txidPrev", arcTx.vZoSpend[i].spendTxid));
        obj.push_back(Pair("outputPrev", arcTx.vZoSpend[i].spendShieldedActionIndex));
        obj.push_back(Pair("address", arcTx.vZoSpend[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZoSpend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZoSpend[i].amount));
        obj.push_back(Pair("spendable", arcTx.vZoSpend[i].spendable));
        if (!filterAddress || arcTx.vZoSpend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }
}

void getRpcArcTxJSONSends(RpcArcTransaction& arcTx, UniValue& ArcTxJSON, bool filterAddress, string encodedAddress)
{
    for (int i = 0; i < arcTx.vTSend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vTSend[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "transparent"));
        obj.push_back(Pair("output", arcTx.vTSend[i].vout));
        obj.push_back(Pair("outgoing", !arcTx.vTSend[i].mine ? true : false));
        obj.push_back(Pair("address", arcTx.vTSend[i].encodedAddress));
        obj.push_back(Pair("scriptPubKey", arcTx.vTSend[i].encodedScriptPubKey));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vTSend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vTSend[i].amount));
        obj.push_back(Pair("change", change));
        if (!filterAddress || arcTx.vTSend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZsSend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vZsSend[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "sapling"));
        obj.push_back(Pair("output", arcTx.vZsSend[i].shieldedOutputIndex));
        obj.push_back(Pair("outgoing", !arcTx.vZsSend[i].mine ? true : false));
        obj.push_back(Pair("address", arcTx.vZsSend[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZsSend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZsSend[i].amount));
        obj.push_back(Pair("change", change));
        obj.push_back(Pair("memo", arcTx.vZsSend[i].memo));
        obj.push_back(Pair("memoStr", arcTx.vZsSend[i].memoStr));
        if (!filterAddress || arcTx.vZsSend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZoSend.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vZoSend[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "orchard"));
        obj.push_back(Pair("output", arcTx.vZoSend[i].shieldedActionIndex));
        obj.push_back(Pair("outgoing", !arcTx.vZoSend[i].mine ? true : false));
        obj.push_back(Pair("address", arcTx.vZoSend[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZoSend[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZoSend[i].amount));
        obj.push_back(Pair("change", change));
        obj.push_back(Pair("memo", arcTx.vZoSend[i].memo));
        obj.push_back(Pair("memoStr", arcTx.vZoSend[i].memoStr));
        if (!filterAddress || arcTx.vZoSend[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }
}

void getRpcArcTxJSONReceives(RpcArcTransaction& arcTx, UniValue& ArcTxJSON, bool filterAddress, string encodedAddress)
{
    for (int i = 0; i < arcTx.vTReceived.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vTReceived[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "transparent"));
        obj.push_back(Pair("output", arcTx.vTReceived[i].vout));
        obj.push_back(Pair("outgoing", false));
        obj.push_back(Pair("address", arcTx.vTReceived[i].encodedAddress));
        obj.push_back(Pair("scriptPubKey", arcTx.vTReceived[i].encodedScriptPubKey));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vTReceived[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vTReceived[i].amount));
        obj.push_back(Pair("change", change));
        obj.push_back(Pair("spendable", arcTx.vTReceived[i].spendable));
        if (!filterAddress || arcTx.vTReceived[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZsReceived.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vZsReceived[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "sapling"));
        obj.push_back(Pair("output", arcTx.vZsReceived[i].shieldedOutputIndex));
        obj.push_back(Pair("outgoing", false));
        obj.push_back(Pair("address", arcTx.vZsReceived[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZsReceived[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZsReceived[i].amount));
        obj.push_back(Pair("change", change));
        obj.push_back(Pair("spendable", arcTx.vZsReceived[i].spendable));
        obj.push_back(Pair("memo", arcTx.vZsReceived[i].memo));
        obj.push_back(Pair("memoStr", arcTx.vZsReceived[i].memoStr));
        if (!filterAddress || arcTx.vZsReceived[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }

    for (int i = 0; i < arcTx.vZoReceived.size(); i++) {
        UniValue obj(UniValue::VOBJ);
        bool change = arcTx.spentFrom.size() > 0 && arcTx.spentFrom.find(arcTx.vZoReceived[i].encodedAddress) != arcTx.spentFrom.end();
        obj.push_back(Pair("type", "orchard"));
        obj.push_back(Pair("output", arcTx.vZoReceived[i].shieldedActionIndex));
        obj.push_back(Pair("outgoing", false));
        obj.push_back(Pair("address", arcTx.vZoReceived[i].encodedAddress));
        obj.push_back(Pair("value", ValueFromAmount(CAmount(arcTx.vZoReceived[i].amount))));
        obj.push_back(Pair("valueZat", arcTx.vZoReceived[i].amount));
        obj.push_back(Pair("change", change));
        obj.push_back(Pair("spendable", arcTx.vZoReceived[i].spendable));
        obj.push_back(Pair("memo", arcTx.vZoReceived[i].memo));
        obj.push_back(Pair("memoStr", arcTx.vZoReceived[i].memoStr));
        if (!filterAddress || arcTx.vZoReceived[i].encodedAddress == encodedAddress)
            ArcTxJSON.push_back(obj);
    }
}

UniValue zs_listtransactions(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 5 || params.size() == 2)
        throw runtime_error(
            "zs_listtransactions\n"
            "\nReturns an array of decrypted Pirate transactions.\n"
            "\n"
            "This function only returns information on addresses with full spending keys."
            "\n"
            "\nArguments:\n"
            "1. \"Minimum Confimations:\"   (numeric, optional, default=0) \n"
            "\n"
            "2. \"Filter Type:\"            (numeric, optional, default=0) \n"
            "                               Value of 0: Returns all transactions in the wallet\n"
            "                               Value of 1: Returns the last x days of transactions\n"
            "                               Value of 2: Returns transactions with confimations less than x\n"
            "                               Value of 3: Returns transactions with a minimum block height of x\n"
            "\n"
            "3. \"Filter:\"                 (numeric, optional, default=0) \n"
            "                               Filter Type equal 0: paramater ignored\n"
            "                               Filter Type equal 1: number represents the number of days returned\n"
            "                               Filter Type equal 2: number represents the max confirmations for transaction to be returned\n"
            "                               Filter Type equal 3: number represents the minimum block height of the transactions returned\n"
            "\n"
            "4. \"Count:\"                 (numeric, optional, default=100000) \n"
            "                               Last n number of transactions returned\n"
            "\n"
            "5. \"Include Watch Only\"   (bool, optional, Default = false) \n"
            "\n"
            "Default Parameters:\n"
            "1. 0 - O confimations required\n"
            "2. 0 - Returns all transactions\n"
            "3. 0 - Ignored\n"
            "4. 100000 - Return the last 100,000 transactions.\n"
            "5. false - exclude watch only\n"
            "\n"
            "\nResult:\n"
            "[{\n                                     An Array of Transactions\n"
            "   \"txid\":  \"transactionid\",           (string)  The transaction id.\n"
            "   \"coinbase\": \"coinbase\",             (string)  Coinbase transaction, true or false\n"
            "   \"category\": \"category\",             (string)  orphan (coinbase), immature (coinbase), generate (coinbase), regular\n"
            "   \"blockhash\": \"hashvalue\",           (string)  The block hash containing the transaction\n"
            "   \"blockindex\": n,                    (numeric) The block index containing the transaction\n"
            "   \"blocktime\": n,                     (numeric) The block time in seconds of the block containing the transaction, 0 for unconfirmed transactions\n"
            "   \"expiryHeight\": n,                  (numeric) The expiry height of the transaction\n"
            "   \"confirmations\": n,                 (numeric) The number of confirmations for the transaction\n"
            "   \"time\": xxx,                        (numeric) The transaction time in seconds of the transaction\n"
            "   \"size\": xxx,                        (numeric) The transaction size\n"
            "   \"spends\": {                       A list of the spends used as inputs in the transaction\n"
            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
            "      \"spend\": n,                      (numeric) spend index\n"
            "      \"txidPrev\":  \"transactionid\",    (string)  The transaction id of the output being spent\n"
            "      \"outputPrev\": n,                 (numeric) vout, shieledoutput or jsindex of output being spent \n"
            "      \"spendJsOutIndex\": n,            (numeric) Joinsplit Output index of the output being spent (sprout address type only)\n"
            "      \"address\": \"address\",            (string)  Pirate address\n"
            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      },\n"
                            "   \"sent\": {                        A list of outputs of where funds were sent to in the transaction,\n"
                            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
                            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
                            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
                            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
                            "      \"address\": \"address\",            (string)  Pirate address\n"
                            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
                            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (string)  The note is change. This can result from sending funds\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   }\n"
                            "   \"recieved\": {                     A list of receives from the transaction\n"
                            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
                            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
                            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
                            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
                            "      \"address\": \"address\",            (string)  Pirate address\n"
                            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
                            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (string)  The note is change. This can result from sending funds\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   },\n"
                            "}]\n"
                            "\nExamples:\n" +
            HelpExampleCli("zs_listtransactions", "") + HelpExampleCli("zs_listtransactions", "1") + HelpExampleCli("zs_listtransactions", "1 1 30 200") + HelpExampleRpc("zs_listtransactions", "") + HelpExampleRpc("zs_listtransactions", "1") + HelpExampleRpc("zs_listtransactions", "1 1 30 200"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlockedForReporting();

    UniValue ret(UniValue::VARR);

    // param values`
    int64_t nMinConfirms = 0;
    int64_t nFilterType = 0;
    int64_t nFilter = 0;
    int64_t nCount = 100000;

    if (params.size() >= 1)
        nMinConfirms = params[0].get_int64();

    if (params.size() >= 3) {
        nFilterType = params[1].get_int64();
        nFilter = params[2].get_int64();
    }

    if (params.size() == 4) {
        nCount = params[3].get_int64();
    }

    bool fIncludeWatchonly = false;
    if (params.size() == 5) {
        fIncludeWatchonly = params[4].get_bool();
    }

    if (nMinConfirms < 0)
        throw runtime_error("Minimum confimations must be greater that 0");

    if (nFilterType < 0 || nFilterType > 3)
        throw runtime_error("Filter type must be 0, 1, 2 or 3.");

    if (nFilter < 0)
        throw runtime_error("Filter must be equal or greater than 0.");

    // get Sorted Archived Transactions
    std::map<std::pair<int, int>, uint256> sortedArchive;
    for (map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.begin(); it != pwalletMain->mapArcTxs.end(); ++it) {
        uint256 txid = (*it).first;
        ArchiveTxPoint arcTxPt = (*it).second;
        std::pair<int, int> key;

        if (!arcTxPt.hashBlock.IsNull() && mapBlockIndex.count(arcTxPt.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[arcTxPt.hashBlock]->nHeight, arcTxPt.nIndex);
            sortedArchive[key] = txid;
        }
    }

    // add any missing wallet transactions - unconfimred & conflicted
    int nPosUnconfirmed = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        CWalletTx wtx = (*it).second;
        std::pair<int, int> key;

        if (wtx.GetDepthInMainChain() == 0) {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        } else if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.nIndex);
            sortedArchive[key] = wtx.GetHash();
        } else {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        }
    }

    uint64_t t = GetTime();
    int chainHeight = chainActive.Tip()->nHeight;
    // Reverse Iterate thru transactions
    for (map<std::pair<int, int>, uint256>::reverse_iterator it = sortedArchive.rbegin(); it != sortedArchive.rend(); ++it) {
        uint256 txid = (*it).second;
        RpcArcTransaction arcTx;

        // Exclude transactions with block height lower the type 3 filter minimum
        if (nFilterType == 3 && (*it).first.first < nFilter)
            continue;

        if (pwalletMain->mapWallet.count(txid)) {
            CWalletTx& wtx = pwalletMain->mapWallet[txid];

            if (!CheckFinalTx(wtx))
                continue;

            if (wtx.GetDepthInMainChain() < 0)
                continue;

            if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
                continue;

            // Excude transactions with less confirmations than required
            if (wtx.GetDepthInMainChain() < nMinConfirms)
                continue;

            // Exclude Transactions older that max days old
            if (mapBlockIndex.count(wtx.hashBlock) > 0) {
                if (wtx.GetDepthInMainChain() > 0 && nFilterType == 1 && mapBlockIndex[wtx.hashBlock]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24))) {
                    continue;
                }
            }

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && wtx.GetDepthInMainChain() > nFilter)
                continue;

            getRpcArcTx(wtx, arcTx, fIncludeWatchonly, false);

        } else {
            int confirms = chainHeight - (*it).first.first + 1;

            // Excude transactions with less confirmations than required
            if (confirms < nMinConfirms)
                continue;

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && confirms > nFilter)
                continue;

            // Archived Transactions
            getRpcArcTx(txid, arcTx, fIncludeWatchonly, false);

            if (arcTx.blockHash.IsNull() || mapBlockIndex.count(arcTx.blockHash) == 0)
                continue;

            // Exclude Transactions older that max days old
            if (confirms > 0 && nFilterType == 1 && mapBlockIndex[arcTx.blockHash]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24)))
                continue;
        }

        UniValue txObj(UniValue::VOBJ);
        getRpcArcTxJSONHeader(arcTx, txObj);

        UniValue spends(UniValue::VARR);
        getRpcArcTxJSONSpends(arcTx, spends);
        txObj.push_back(Pair("spends", spends));

        UniValue sends(UniValue::VARR);
        if (arcTx.spentFrom.size() > 0)
            getRpcArcTxJSONSends(arcTx, sends);
        txObj.push_back(Pair("sent", sends));

        UniValue received(UniValue::VARR);
        getRpcArcTxJSONReceives(arcTx, received);
        txObj.push_back(Pair("received", received));

        ret.push_back(txObj);

        if (ret.size() >= nCount)
            break;
    }

    vector<UniValue> arrTmp = ret.getValues();

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue zs_gettransaction(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() != 1)
        throw runtime_error(
            "zs_gettransaction\n"
            "\nReturns a decrypted Pirate transaction.\n"
            "\n"
            "\nArguments:\n"
            "1. \"txid:\"   (string, required) \n"
            "\n"
            "\nResult:\n"
            "   \"txid\":  \"transactionid\",           (string)  The transaction id.\n"
            "   \"coinbase\": \"coinbase\",             (string)  Coinbase transaction, true or false\n"
            "   \"category\": \"category\",             (string)  orphan (coinbase), immature (coinbase), generate (coinbase), regular\n"
            "   \"blockhash\": \"hashvalue\",           (string)  The block hash containing the transaction\n"
            "   \"blockindex\": n,                    (numeric) The block index containing the transaction\n"
            "   \"blocktime\": n,                     (numeric) The block time in seconds of the block containing the transaction, 0 for unconfirmed transactions\n"
            "   \"rawconfirmations\": n,              (numeric) The number of onchain confirmations for the transaction\n"
            "   \"confirmations\": n,                 (numeric) The number of dpow confirmations for the transaction\n"
            "   \"time\": xxx,                        (numeric) The transaction time in seconds of the transaction\n"
            "   \"expiryHeight\": n,                  (numeric) The expiry height of the transaction\n"
            "   \"size\": xxx,                        (numeric) The transaction size\n"
            "   \"fee\": n,                           (numeric) Transaction fee in Zatoshis\n"
            "   \"spends\": {                       A list of the spends used as inputs in the transaction\n"
            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
            "      \"spend\": n,                      (numeric) spend index\n"
            "      \"txidPrev\":  \"transactionid\",    (string)  The transaction id of the output being spent\n"
            "      \"outputPrev\": n,                 (numeric) vout, shieledoutput or jsindex of output being spent \n"
            "      \"spendJsOutIndex\": n,            (numeric) Joinsplit Output index of the output being spent (sprout address type only)\n"
            "      \"address\": \"address\",            (string)  Pirate address\n"
            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      },\n"
                            "   \"sent\": {                        A list of outputs of where funds were sent to in the transaction,\n"
                            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
                            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
                            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
                            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
                            "      \"address\": \"address\",            (string)  Pirate address\n"
                            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
                            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (string)  The note is change. This can result from sending funds\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   }\n"
                            "   \"recieved\": {                     A list of receives from the transaction\n"
                            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
                            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
                            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
                            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
                            "      \"address\": \"address\",            (string)  Pirate address\n"
                            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
                            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (string)  The note is change. This can result from sending funds\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   },\n"
                            "\nExamples:\n" +
            HelpExampleCli("zs_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\"") + HelpExampleRpc("zs_gettransaction", "\"1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d\""));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    uint256 hash;
    hash.SetHex(params[0].get_str());

    if (!pwalletMain->mapWallet.count(hash) && !pwalletMain->mapArcTxs.count(hash))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid or non-wallet transaction id");

    UniValue txObj(UniValue::VOBJ);
    RpcArcTransaction arcTx;
    if (pwalletMain->mapWallet.count(hash)) {
        CWalletTx& wtx = pwalletMain->mapWallet[hash];
        getRpcArcTx(wtx, arcTx, true, false);
    } else {
        getRpcArcTx(hash, arcTx, true, false);
        if (arcTx.blockHash.IsNull() || mapBlockIndex.count(arcTx.blockHash) == 0) {
            return txObj;
        }
    }

    getRpcArcTxJSONHeader(arcTx, txObj);

    UniValue spends(UniValue::VARR);
    getRpcArcTxJSONSpends(arcTx, spends);
    txObj.push_back(Pair("spends", spends));

    UniValue sends(UniValue::VARR);
    if (arcTx.spentFrom.size() > 0)
        getRpcArcTxJSONSends(arcTx, sends);
    txObj.push_back(Pair("sent", sends));

    UniValue received(UniValue::VARR);
    getRpcArcTxJSONReceives(arcTx, received);
    txObj.push_back(Pair("received", received));

    return txObj;
}

UniValue zs_listspentbyaddress(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 5 || params.size() == 3 || params.size() < 1)
        throw runtime_error(
            "zs_listspentbyaddress\n"
            "\nReturns decrypted Pirate spent inputs for a single address.\n"
            "\n"
            "This function only returns information on addresses with full spending keys."
            "\n"
            "\nArguments:\n"
            "1. \"address:\"                (string, required) \n"
            "\n"
            "2. \"Minimum Confimations:\"   (numeric, optional, default=0) \n"
            "\n"
            "3. \"Filter Type:\"            (numeric, optional, default=0) \n"
            "                               Value of 0: Returns all transactions in the wallet\n"
            "                               Value of 1: Returns the last x days of transactions\n"
            "                               Value of 2: Returns transactions with confimations less than x\n"
            "                               Value of 3: Returns transactions with a minimum block height of x\n"
            "\n"
            "4. \"Filter:\"                 (numeric, optional, default=0) \n"
            "                               Filter Type equal 0: paramater ignored\n"
            "                               Filter Type equal 1: number represents the number of days returned\n"
            "                               Filter Type equal 2: number represents the max confirmations for transaction to be returned\n"
            "                               Filter Type equal 3: number represents the minimum block height of the transactions returned\n"
            "\n"
            "5. \"Count:\"                 (numeric, optional, default=100000) \n"
            "                               Last n number of transactions returned\n"
            "\n"
            "Default Parameters:\n"
            "1. Pirate Address\n"
            "2. 0 - O confimations required\n"
            "3. 0 - Returns all transactions\n"
            "4. 0 - Ignored\n"
            "5. 100000 - Return the last 9,999,999 transactions.\n"
            "\n"
            "\nResult:\n"
            "   \"txid\":  \"transactionid\",           (string)  The transaction id.\n"
            "   \"coinbase\": \"coinbase\",             (string)  Coinbase transaction, true or false\n"
            "   \"category\": \"category\",             (string)  orphan (coinbase), immature (coinbase), generate (coinbase), regular\n"
            "   \"blockhash\": \"hashvalue\",           (string)  The block hash containing the transaction\n"
            "   \"blockindex\": n,                    (numeric) The block index containing the transaction\n"
            "   \"blocktime\": n,                     (numeric) The block time in seconds of the block containing the transaction, 0 for unconfirmed transactions\n"
            "   \"rawconfirmations\": n,              (numeric) The number of onchain confirmations for the transaction\n"
            "   \"confirmations\": n,                 (numeric) The number of dpow confirmations for the transaction\n"
            "   \"time\": xxx,                        (numeric) The transaction time in seconds of the transaction\n"
            "   \"expiryHeight\": n,                  (numeric) The expiry height of the transaction\n"
            "   \"size\": xxx,                        (numeric) The transaction size\n"
            "   \"fee\": n,                           (numeric) Transaction fee in Zatoshis\n"
            "   \"spends\": {                       A list of the spends used as inputs in the transaction\n"
            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
            "      \"spend\": n,                      (numeric) spend index\n"
            "      \"txidPrev\":  \"transactionid\",    (string)  The transaction id of the output being spent\n"
            "      \"outputPrev\": n,                 (numeric) vout, shieledoutput or jsindex of output being spent \n"
            "      \"spendJsOutIndex\": n,            (numeric) Joinsplit Output index of the output being spent (sprout address type only)\n"
            "      \"address\": \"address\",            (string)  Pirate address\n"
            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      },\n"
                            "\nExamples:\n" +
            HelpExampleCli("zs_listspentbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL") + HelpExampleRpc("zs_listspentbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VARR);

    // param values`
    int64_t nMinConfirms = 0;
    int64_t nFilterType = 0;
    int64_t nFilter = 0;
    int64_t nCount = 100000;

    if (params.size() >= 2)
        nMinConfirms = params[1].get_int64();

    if (params.size() >= 4) {
        nFilterType = params[2].get_int64();
        nFilter = params[3].get_int64();
    }

    if (params.size() == 5) {
        nCount = params[4].get_int64();
    }

    bool fIncludeWatchonly = true;

    if (nMinConfirms < 0)
        throw runtime_error("Minimum confimations must be greater that 0");

    if (nFilterType < 0 || nFilterType > 3)
        throw runtime_error("Filter type must be 0, 1, 2 or 3.");

    if (nFilter < 0)
        throw runtime_error("Filter must be equal or greater than 0.");

    // Check address
    bool isTAddress = false;
    bool isZsAddress = false;
    bool isZoAddress = false;
    string encodedAddress = params[0].get_str();

    CTxDestination tAddress = DecodeDestination(encodedAddress);
    auto zAddress = DecodePaymentAddress(encodedAddress);
    SaplingPaymentAddress zsAddress;
    OrchardPaymentAddressPirate zoAddress;

    if (IsValidDestination(tAddress))
        isTAddress = true;

    if (IsValidPaymentAddress(zAddress)) {
        if (std::get_if<libzcash::SaplingPaymentAddress>(&zAddress) != nullptr) {
            zsAddress = *(std::get_if<libzcash::SaplingPaymentAddress>(&zAddress));
            isZsAddress = true;
        }
        if (std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress) != nullptr) {
            zoAddress = *(std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress));
            isZoAddress = true;
        }
    }

    if (!isTAddress && !isZsAddress && !isZoAddress)
        return ret;

    // Get set of txids that the encoded address was used in
    std::map<std::string, std::set<uint256>>::iterator ait;
    ait = pwalletMain->mapAddressTxids.find(encodedAddress);
    std::set<uint256> txids;

    if (ait != pwalletMain->mapAddressTxids.end()) {
        txids = ait->second;
    }

    // get Sorted Archived Transactions
    std::map<std::pair<int, int>, uint256> sortedArchive;
    for (map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.begin(); it != pwalletMain->mapArcTxs.end(); ++it) {
        uint256 txid = (*it).first;
        ArchiveTxPoint arcTxPt = (*it).second;
        std::pair<int, int> key;

        std::set<uint256>::iterator txit;
        txit = txids.find(txid);
        if (txit == txids.end()) {
            continue;
        }

        if (!arcTxPt.hashBlock.IsNull() && mapBlockIndex.count(arcTxPt.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[arcTxPt.hashBlock]->nHeight, arcTxPt.nIndex);
            sortedArchive[key] = txid;
        }
    }

    // add any missing wallet transactions - unconfimred & conflicted
    int nPosUnconfirmed = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        CWalletTx wtx = (*it).second;
        std::pair<int, int> key;

        if (wtx.GetDepthInMainChain() == 0) {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        } else if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.nIndex);
            sortedArchive[key] = wtx.GetHash();
        } else {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        }
    }

    uint64_t t = GetTime();
    int chainHeight = chainActive.Tip()->nHeight;
    // Reverse Iterate thru transactions
    for (map<std::pair<int, int>, uint256>::reverse_iterator it = sortedArchive.rbegin(); it != sortedArchive.rend(); ++it) {
        uint256 txid = (*it).second;
        RpcArcTransaction arcTx;

        // Exclude transactions with block height lower the type 3 filter minimum
        if (nFilterType == 3 && (*it).first.first < nFilter)
            continue;

        if (pwalletMain->mapWallet.count(txid)) {
            CWalletTx& wtx = pwalletMain->mapWallet[txid];

            if (!CheckFinalTx(wtx))
                continue;

            if (wtx.GetDepthInMainChain() < 0)
                continue;

            if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
                continue;

            // Excude transactions with less confirmations than required
            if (wtx.GetDepthInMainChain() < nMinConfirms)
                continue;

            // Exclude Transactions older that max days old
            if (mapBlockIndex.count(wtx.hashBlock) > 0) {
                if (wtx.GetDepthInMainChain() > 0 && nFilterType == 1 && mapBlockIndex[wtx.hashBlock]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24))) {
                    continue;
                }
            }

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && wtx.GetDepthInMainChain() > nFilter)
                continue;

            getRpcArcTx(wtx, arcTx, fIncludeWatchonly, false);

        } else {
            int confirms = chainHeight - (*it).first.first + 1;

            // Excude transactions with less confirmations than required
            if (confirms < nMinConfirms)
                continue;

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && confirms > nFilter)
                continue;

            // Archived Transactions
            getRpcArcTx(txid, arcTx, fIncludeWatchonly, false);

            if (arcTx.blockHash.IsNull() || mapBlockIndex.count(arcTx.blockHash) == 0)
                continue;

            // Exclude Transactions older that max days old
            if (confirms > 0 && nFilterType == 1 && mapBlockIndex[arcTx.blockHash]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24)))
                continue;
        }

        bool containsAddress = false;
        UniValue txObj(UniValue::VOBJ);
        getRpcArcTxJSONHeader(arcTx, txObj);
        UniValue spends(UniValue::VARR);
        if (isTAddress) {
            for (int i = 0; i < arcTx.vTSpend.size(); i++) {
                if (arcTx.vTSpend[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        } else if (isZsAddress) {
            for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
                if (arcTx.vZsSpend[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        } else if (isZoAddress) {
            for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
                if (arcTx.vZoSpend[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        }

        if (containsAddress) {
            getRpcArcTxJSONSpends(arcTx, spends, true, encodedAddress);
            txObj.push_back(Pair("spends", spends));
            ret.push_back(txObj);
        }

        if (ret.size() >= nCount)
            break;
    }

    vector<UniValue> arrTmp = ret.getValues();

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue zs_listreceivedbyaddress(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 5 || params.size() == 3 || params.size() < 1)
        throw runtime_error(
            "zs_listreceivedbyaddress\n"
            "\nReturns decrypted Pirate received outputs for a single address.\n"
            "\n"
            "This function only returns information on addresses with full spending keys."
            "\n"
            "\nArguments:\n"
            "1. \"address:\"                (string, required) \n"
            "\n"
            "2. \"Minimum Confimations:\"   (numeric, optional, default=0) \n"
            "\n"
            "3. \"Filter Type:\"            (numeric, optional, default=0) \n"
            "                               Value of 0: Returns all transactions in the wallet\n"
            "                               Value of 1: Returns the last x days of transactions\n"
            "                               Value of 2: Returns transactions with confimations less than x\n"
            "                               Value of 3: Returns transactions with a minimum block height of x\n"
            "\n"
            "4. \"Filter:\"                 (numeric, optional, default=0) \n"
            "                               Filter Type equal 0: paramater ignored\n"
            "                               Filter Type equal 1: number represents the number of days returned\n"
            "                               Filter Type equal 2: number represents the max confirmations for transaction to be returned\n"
            "                               Filter Type equal 3: number represents the minimum block height of the transactions returned\n"
            "\n"
            "5. \"Count:\"                 (numeric, optional, default=100000) \n"
            "                               Last n number of transactions returned\n"
            "\n"
            "Default Parameters:\n"
            "2. 0 - O confimations required\n"
            "3. 0 - Returns all transactions\n"
            "4. 0 - Ignored\n"
            "5. 100000 - Return the last 9,999,999 transactions.\n"
            "\n"
            "\nResult:\n"
            "   \"txid\":  \"transactionid\",           (string)  The transaction id.\n"
            "   \"coinbase\": \"coinbase\",             (string)  Coinbase transaction, true or false\n"
            "   \"category\": \"category\",             (string)  orphan (coinbase), immature (coinbase), generate (coinbase), regular\n"
            "   \"blockhash\": \"hashvalue\",           (string)  The block hash containing the transaction\n"
            "   \"blockindex\": n,                    (numeric) The block index containing the transaction\n"
            "   \"blocktime\": n,                     (numeric) The block time in seconds of the block containing the transaction, 0 for unconfirmed transactions\n"
            "   \"rawconfirmations\": n,              (numeric) The number of onchain confirmations for the transaction\n"
            "   \"confirmations\": n,                 (numeric) The number of dpow confirmations for the transaction\n"
            "   \"time\": xxx,                        (numeric) The transaction time in seconds of the transaction\n"
            "   \"expiryHeight\": n,                  (numeric) The expiry height of the transaction\n"
            "   \"size\": xxx,                        (numeric) The transaction size\n"
            "   \"fee\": n,                           (numeric) Transaction fee in Zatoshis\n"
            "   \"recieved\": {                     A list of receives from the transaction\n"
            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
            "      \"address\": \"address\",            (string)  Pirate address\n"
            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (bool)  The note is change. This can result from sending funds\n"
                            "      \"spendable\": true/false          (bool)  Is this output spendable by this wallet\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   },\n"
                            "\nExamples:\n" +
            HelpExampleCli("zs_listreceivedbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL") + HelpExampleRpc("zs_listreceivedbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VARR);

    // param values`
    int64_t nMinConfirms = 0;
    int64_t nFilterType = 0;
    int64_t nFilter = 0;
    int64_t nCount = 100000;

    if (params.size() >= 2)
        nMinConfirms = params[1].get_int64();

    if (params.size() >= 4) {
        nFilterType = params[2].get_int64();
        nFilter = params[3].get_int64();
    }

    if (params.size() == 5) {
        nCount = params[4].get_int64();
    }

    bool fIncludeWatchonly = true;

    if (nMinConfirms < 0)
        throw runtime_error("Minimum confimations must be greater that 0");

    if (nFilterType < 0 || nFilterType > 3)
        throw runtime_error("Filter type must be 0, 1, 2 or 3.");

    if (nFilter < 0)
        throw runtime_error("Filter must be equal or greater than 0.");

    // Check address
    bool isTAddress = false;
    bool isZsAddress = false;
    bool isZoAddress = false;
    string encodedAddress = params[0].get_str();

    CTxDestination tAddress = DecodeDestination(encodedAddress);
    auto zAddress = DecodePaymentAddress(encodedAddress);
    SaplingPaymentAddress zsAddress;
    OrchardPaymentAddressPirate zoAddress;

    if (IsValidDestination(tAddress))
        isTAddress = true;

    if (IsValidPaymentAddress(zAddress)) {
        if (std::get_if<libzcash::SaplingPaymentAddress>(&zAddress) != nullptr) {
            zsAddress = *(std::get_if<libzcash::SaplingPaymentAddress>(&zAddress));
            isZsAddress = true;
        }
        if (std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress) != nullptr) {
            zoAddress = *(std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress));
            isZoAddress = true;
        }
    }

    if (!isTAddress && !isZsAddress && !isZoAddress)
        return ret;

    // Get set of txids that the encoded address was used in
    std::map<std::string, std::set<uint256>>::iterator ait;
    ait = pwalletMain->mapAddressTxids.find(encodedAddress);
    std::set<uint256> txids;
    if (ait != pwalletMain->mapAddressTxids.end()) {
        txids = ait->second;
    }

    // get Sorted Archived Transactions
    std::map<std::pair<int, int>, uint256> sortedArchive;
    for (map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.begin(); it != pwalletMain->mapArcTxs.end(); ++it) {
        uint256 txid = (*it).first;
        ArchiveTxPoint arcTxPt = (*it).second;
        std::pair<int, int> key;

        std::set<uint256>::iterator txit;
        txit = txids.find(txid);
        if (txit == txids.end()) {
            continue;
        }

        if (!arcTxPt.hashBlock.IsNull() && mapBlockIndex.count(arcTxPt.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[arcTxPt.hashBlock]->nHeight, arcTxPt.nIndex);
            sortedArchive[key] = txid;
        }
    }

    // add any missing wallet transactions - unconfimred & conflicted
    int nPosUnconfirmed = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        CWalletTx wtx = (*it).second;
        std::pair<int, int> key;

        if (wtx.GetDepthInMainChain() == 0) {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        } else if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.nIndex);
            sortedArchive[key] = wtx.GetHash();
        } else {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        }
    }

    uint64_t t = GetTime();
    int chainHeight = chainActive.Tip()->nHeight;
    // Reverse Iterate thru transactions
    for (map<std::pair<int, int>, uint256>::reverse_iterator it = sortedArchive.rbegin(); it != sortedArchive.rend(); ++it) {
        uint256 txid = (*it).second;
        RpcArcTransaction arcTx;

        // Exclude transactions with block height lower the type 3 filter minimum
        if (nFilterType == 3 && (*it).first.first < nFilter)
            continue;

        if (pwalletMain->mapWallet.count(txid)) {
            CWalletTx& wtx = pwalletMain->mapWallet[txid];

            if (!CheckFinalTx(wtx))
                continue;

            if (wtx.GetDepthInMainChain() < 0)
                continue;

            if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
                continue;

            // Excude transactions with less confirmations than required
            if (wtx.GetDepthInMainChain() < nMinConfirms)
                continue;

            // Exclude Transactions older that max days old
            if (mapBlockIndex.count(wtx.hashBlock) > 0) {
                if (wtx.GetDepthInMainChain() > 0 && nFilterType == 1 && mapBlockIndex[wtx.hashBlock]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24))) {
                    continue;
                }
            }

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && wtx.GetDepthInMainChain() > nFilter)
                continue;

            getRpcArcTx(wtx, arcTx, fIncludeWatchonly, false);

        } else {
            int confirms = chainHeight - (*it).first.first + 1;

            // Excude transactions with less confirmations than required
            if (confirms < nMinConfirms)
                continue;

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && confirms > nFilter)
                continue;

            // Archived Transactions
            getRpcArcTx(txid, arcTx, fIncludeWatchonly, false);

            if (arcTx.blockHash.IsNull() || mapBlockIndex.count(arcTx.blockHash) == 0)
                continue;

            // Exclude Transactions older that max days old
            if (confirms > 0 && nFilterType == 1 && mapBlockIndex[arcTx.blockHash]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24)))
                continue;
        }

        bool containsAddress = false;
        UniValue txObj(UniValue::VOBJ);
        getRpcArcTxJSONHeader(arcTx, txObj);
        UniValue received(UniValue::VARR);
        if (isTAddress) {
            for (int i = 0; i < arcTx.vTReceived.size(); i++) {
                if (arcTx.vTReceived[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        } else if (isZsAddress) {
            for (int i = 0; i < arcTx.vZsReceived.size(); i++) {
                if (arcTx.vZsReceived[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        } else if (isZoAddress) {
            for (int i = 0; i < arcTx.vZoReceived.size(); i++) {
                if (arcTx.vZoReceived[i].encodedAddress == encodedAddress) {
                    containsAddress = true;
                    break;
                }
            }
        }

        if (containsAddress) {
            getRpcArcTxJSONReceives(arcTx, received, true, encodedAddress);
            txObj.push_back(Pair("received", received));
            ret.push_back(txObj);
        }

        if (ret.size() >= nCount)
            break;
    }

    vector<UniValue> arrTmp = ret.getValues();

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}

UniValue zs_listsentbyaddress(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (!EnsureWalletIsAvailable(fHelp))
        return NullUniValue;

    if (fHelp || params.size() > 5 || params.size() == 3 || params.size() < 1)
        throw runtime_error(
            "zs_listsentbyaddress\n"
            "\nReturns decrypted Pirate outputs sent to a single address.\n"
            "\n"
            "This function only returns information on addresses sent from wallet addresses with full spending keys."
            "\n"
            "\nArguments:\n"
            "1. \"address:\"                (string, required) \n"
            "\n"
            "2. \"Minimum Confimations:\"   (numeric, optional, default=0) \n"
            "\n"
            "3. \"Filter Type:\"            (numeric, optional, default=0) \n"
            "                               Value of 0: Returns all transactions in the wallet\n"
            "                               Value of 1: Returns the last x days of transactions\n"
            "                               Value of 2: Returns transactions with confimations less than x\n"
            "                               Value of 3: Returns transactions with a minimum block height of x\n"
            "\n"
            "4. \"Filter:\"                 (numeric, optional, default=0) \n"
            "                               Filter Type equal 0: paramater ignored\n"
            "                               Filter Type equal 1: number represents the number of days returned\n"
            "                               Filter Type equal 2: number represents the max confirmations for transaction to be returned\n"
            "                               Filter Type equal 3: number represents the minimum block height of the transactions returned\n"
            "\n"
            "5. \"Count:\"                 (numeric, optional, default=100000) \n"
            "                               Last n number of transactions returned\n"
            "\n"
            "Default Parameters:\n"
            "2. 0 - O confimations required\n"
            "3. 0 - Returns all transactions\n"
            "4. 0 - Ignored\n"
            "5. 100000 - Return the last 9,999,999 transactions.\n"
            "\n"
            "\nResult:\n"
            "   \"txid\":  \"transactionid\",           (string)  The transaction id.\n"
            "   \"coinbase\": \"coinbase\",             (string)  Coinbase transaction, true or false\n"
            "   \"category\": \"category\",             (string)  orphan (coinbase), immature (coinbase), generate (coinbase), regular\n"
            "   \"blockhash\": \"hashvalue\",           (string)  The block hash containing the transaction\n"
            "   \"blockindex\": n,                    (numeric) The block index containing the transaction\n"
            "   \"blocktime\": n,                     (numeric) The block time in seconds of the block containing the transaction, 0 for unconfirmed transactions\n"
            "   \"rawconfirmations\": n,              (numeric) The number of onchain confirmations for the transaction\n"
            "   \"confirmations\": n,                 (numeric) The number of dpow confirmations for the transaction\n"
            "   \"time\": xxx,                        (numeric) The transaction time in seconds of the transaction\n"
            "   \"expiryHeight\": n,                  (numeric) The expiry height of the transaction\n"
            "   \"size\": xxx,                        (numeric) The transaction size\n"
            "   \"fee\": n,                           (numeric) Transaction fee in Zatoshis\n"
            "   \"sent\": {                        A list of outputs of where funds were sent to in the transaction,\n"
            "      \"type\": \"address type\",          (string)  transparent, sprout, sapling\n"
            "      \"output\": n,                     (numeric) vout, shieledoutput or jsindex\n"
            "      \"outIndex\": n,                   (numeric) Joinsplit Output index (sprout address type only)\n"
            "      \"outgoing\": true or false,       (bool)    funds leaving the wallet\n"
            "      \"address\": \"address\",            (string)  Pirate address\n"
            "      \"scriptPubKey\": \"script\",        (string)  Script for the Pirate transparent address (transparent address type only)\n"
            "      \"value\": x.xxxx,                 (numeric) Value of output being spent " +
            CURRENCY_UNIT + "\n"
                            "      \"valueZat\": xxxxx,               (numeric) Value of output being spent in Zatoshis " +
            CURRENCY_UNIT + "\n"
                            "      \"change\": true/false             (string)  The note is change. This can result from sending funds\n"
                            "      \"memo\": \"hex string\",            (string)  Hex encoded memo (sprout and sapling address types only)\n"
                            "      \"memoStr\": \"memo\",               (string)  UTF-8 encoded memo (sprout and sapling address types only)\n"
                            "   }\n"
                            "\nExamples:\n" +
            HelpExampleCli("zs_listsentbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL") + HelpExampleRpc("zs_listsentbyaddress", "t1KzZ5n2TPEGYXTZ3WYGL1AYEumEQaRoHaL"));

    LOCK2(cs_main, pwalletMain->cs_wallet);

    UniValue ret(UniValue::VARR);

    // param values`
    int64_t nMinConfirms = 0;
    int64_t nFilterType = 0;
    int64_t nFilter = 0;
    int64_t nCount = 100000;

    if (params.size() >= 2)
        nMinConfirms = params[1].get_int64();

    if (params.size() >= 4) {
        nFilterType = params[2].get_int64();
        nFilter = params[3].get_int64();
    }

    if (params.size() == 5) {
        nCount = params[4].get_int64();
    }

    bool fIncludeWatchonly = true;

    if (nMinConfirms < 0)
        throw runtime_error("Minimum confimations must be greater that 0");

    if (nFilterType < 0 || nFilterType > 3)
        throw runtime_error("Filter type must be 0, 1, 2 or 3.");

    if (nFilter < 0)
        throw runtime_error("Filter must be equal or greater than 0.");


    // Check address
    bool isTAddress = false;
    bool isZsAddress = false;
    bool isZoAddress = false;
    string encodedAddress = params[0].get_str();

    CTxDestination tAddress = DecodeDestination(encodedAddress);
    auto zAddress = DecodePaymentAddress(encodedAddress);
    SaplingPaymentAddress zsAddress;
    OrchardPaymentAddressPirate zoAddress;

    if (IsValidDestination(tAddress))
        isTAddress = true;

    if (IsValidPaymentAddress(zAddress)) {
        if (std::get_if<libzcash::SaplingPaymentAddress>(&zAddress) != nullptr) {
            zsAddress = *(std::get_if<libzcash::SaplingPaymentAddress>(&zAddress));
            isZsAddress = true;
        }
        if (std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress) != nullptr) {
            zoAddress = *(std::get_if<libzcash::OrchardPaymentAddressPirate>(&zAddress));
            isZoAddress = true;
        }
    }

    if (!isTAddress && !isZsAddress && !isZoAddress)
        return ret;

    // Get set of txids that the encoded address was used in
    std::map<std::string, std::set<uint256>>::iterator ait;
    ait = pwalletMain->mapAddressTxids.find(encodedAddress);
    std::set<uint256> txids;

    if (ait != pwalletMain->mapAddressTxids.end()) {
        txids = ait->second;
    }

    // get Sorted Archived Transactions
    std::map<std::pair<int, int>, uint256> sortedArchive;
    for (map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.begin(); it != pwalletMain->mapArcTxs.end(); ++it) {
        uint256 txid = (*it).first;
        ArchiveTxPoint arcTxPt = (*it).second;
        std::pair<int, int> key;

        std::set<uint256>::iterator txit;
        txit = txids.find(txid);
        if (txit == txids.end()) {
            continue;
        }

        if (!arcTxPt.hashBlock.IsNull() && mapBlockIndex.count(arcTxPt.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[arcTxPt.hashBlock]->nHeight, arcTxPt.nIndex);
            sortedArchive[key] = txid;
        }
    }

    // add any missing wallet transactions - unconfimred & conflicted
    int nPosUnconfirmed = 0;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        CWalletTx wtx = (*it).second;
        std::pair<int, int> key;

        if (wtx.GetDepthInMainChain() == 0) {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        } else if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
            key = make_pair(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.nIndex);
            sortedArchive[key] = wtx.GetHash();
        } else {
            key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
            sortedArchive[key] = wtx.GetHash();
            nPosUnconfirmed++;
        }
    }

    uint64_t t = GetTime();
    int chainHeight = chainActive.Tip()->nHeight;
    // Reverse Iterate thru transactions
    for (map<std::pair<int, int>, uint256>::reverse_iterator it = sortedArchive.rbegin(); it != sortedArchive.rend(); ++it) {
        uint256 txid = (*it).second;
        RpcArcTransaction arcTx;

        // Exclude transactions with block height lower the type 3 filter minimum
        if (nFilterType == 3 && (*it).first.first < nFilter)
            continue;

        if (pwalletMain->mapWallet.count(txid)) {
            CWalletTx& wtx = pwalletMain->mapWallet[txid];

            if (!CheckFinalTx(wtx))
                continue;

            if (wtx.GetDepthInMainChain() < 0)
                continue;

            if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
                continue;

            // Excude transactions with less confirmations than required
            if (wtx.GetDepthInMainChain() < nMinConfirms)
                continue;

            // Exclude Transactions older that max days old
            if (mapBlockIndex.count(wtx.hashBlock) > 0) {
                if (wtx.GetDepthInMainChain() > 0 && nFilterType == 1 && mapBlockIndex[wtx.hashBlock]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24))) {
                    continue;
                }
            }

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && wtx.GetDepthInMainChain() > nFilter)
                continue;

            getRpcArcTx(wtx, arcTx, fIncludeWatchonly, false);

        } else {
            int confirms = chainHeight - (*it).first.first + 1;

            // Excude transactions with less confirmations than required
            if (confirms < nMinConfirms)
                continue;

            // Exclude transactions with greater than max confirmations
            if (nFilterType == 2 && confirms > nFilter)
                continue;

            // Archived Transactions
            getRpcArcTx(txid, arcTx, fIncludeWatchonly, false);

            if (arcTx.blockHash.IsNull() || mapBlockIndex.count(arcTx.blockHash) == 0)
                continue;

            // Exclude Transactions older that max days old
            if (confirms > 0 && nFilterType == 1 && mapBlockIndex[arcTx.blockHash]->GetBlockTime() < (t - (nFilter * 60 * 60 * 24)))
                continue;
        }

        if (arcTx.spentFrom.size() > 0) {
            bool containsAddress = false;
            UniValue txObj(UniValue::VOBJ);
            getRpcArcTxJSONHeader(arcTx, txObj);
            UniValue sends(UniValue::VARR);
            if (isTAddress) {
                for (int i = 0; i < arcTx.vTSend.size(); i++) {
                    if (arcTx.vTSend[i].encodedAddress == encodedAddress) {
                        containsAddress = true;
                        break;
                    }
                }
            } else if (isZsAddress) {
                for (int i = 0; i < arcTx.vZsSend.size(); i++) {
                    if (arcTx.vZsSend[i].encodedAddress == encodedAddress) {
                        containsAddress = true;
                        break;
                    }
                }
            } else if (isZoAddress) {
                for (int i = 0; i < arcTx.vZoSend.size(); i++) {
                    if (arcTx.vZoSend[i].encodedAddress == encodedAddress) {
                        containsAddress = true;
                        break;
                    }
                }
            }

            if (containsAddress) {
                getRpcArcTxJSONSends(arcTx, sends, true, encodedAddress);
                txObj.push_back(Pair("sent", sends));
                ret.push_back(txObj);
            }
        }

        if (ret.size() >= nCount)
            break;
    }

    vector<UniValue> arrTmp = ret.getValues();

    std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

    ret.clear();
    ret.setArray();
    ret.push_backV(arrTmp);

    return ret;
}


/**
 *Return current blockchain status, wallet balance, address balance and the last 200 transactions
 **/
UniValue getalldata(const UniValue& params, bool fHelp, const CPubKey& mypk)
{
    if (fHelp || params.size() > 4)
        throw runtime_error(
            "getalldata \"datatype transactiontype \"\n"
            "\n"
            "This function only returns information on wallet addresses with full spending keys."
            "\n"
            "\nArguments:\n"
            "1. \"datatype\"     (integer, required) \n"
            "                    Value of 0: Return address, balance, transactions and blockchain info\n"
            "                    Value of 1: Return address, balance, blockchain info\n"
            "                    Value of 2: Return transactions and blockchain info\n"
            "2. \"transactiontype\"     (integer, optional) \n"
            "                    Value of 0: Return all transactions\n"
            "                    Value of 1: Return all transactions in the last 24 hours\n"
            "                    Value of 2: Return all transactions in the last 7 days\n"
            "                    Value of 3: Return all transactions in the last 30 days\n"
            "                    Value of 4: Return all transactions in the last 90 days\n"
            "                    Value of 5: Return all transactions in the last 365 days\n"
            "                    Other number: Return all transactions\n"
            "3. \"transactioncount\"     (integer, optional) \n"
            "4. \"Include Watch Only\"   (bool, optional, Default = false) \n"
            "\nResult:\n"
            "\nExamples:\n" +
            HelpExampleCli("getalldata", "0") + HelpExampleRpc("getalldata", "0"));

    LOCK(cs_main);

    bool fIncludeWatchonly = false;
    if (params.size() == 4) {
        fIncludeWatchonly = params[3].get_bool();
    }

    UniValue returnObj(UniValue::VOBJ);
    int connectionCount = 0;
    {
        LOCK2(cs_main, cs_vNodes);
        connectionCount = (int)vNodes.size();
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    EnsureWalletIsUnlockedForReporting();

    int nMinDepth = 1;

    CAmount confirmed = 0;
    CAmount unconfirmed = 0;
    CAmount locked = 0;
    CAmount immature = 0;

    CAmount privateConfirmed = 0;
    CAmount privateUnconfirmed = 0;
    CAmount privateLocked = 0;
    CAmount privateImmature = 0;

    balancestruct txAmounts;
    txAmounts.confirmed = 0;
    txAmounts.unconfirmed = 0;
    txAmounts.locked = 0;
    txAmounts.immature = 0;

    // //get Ovks for sapling decryption
    // std::set<uint256> ovks;
    // getAllSaplingOVKs(ovks, fIncludeWatchonly);
    //
    // //get Ivks for sapling decryption
    // std::set<uint256> ivks;
    // getAllSaplingIVKs(ivks, fIncludeWatchonly);


    // Create map of addresses
    // Add all Transaparent addresses to list
    map<string, balancestruct> addressBalances;
    BOOST_FOREACH (const PAIRTYPE(CTxDestination, CAddressBookData) & item, pwalletMain->mapAddressBook) {
        string addressString = EncodeDestination(item.first);
        isminetype mine = IsMine(*pwalletMain, item.first);

        if (mine == ISMINE_SPENDABLE || (mine == ISMINE_WATCH_ONLY && fIncludeWatchonly)) {
            if (addressBalances.count(addressString) == 0)
                addressBalances.insert(make_pair(addressString, txAmounts));

            if (mine == ISMINE_SPENDABLE) {
                addressBalances.at(addressString).spendable = true;
            } else {
                addressBalances.at(addressString).spendable = false;
            }
        }
    }

    // Create Ordered List
    map<int64_t, CWalletTx> orderedTxs;
    for (map<uint256, CWalletTx>::iterator it = pwalletMain->mapWallet.begin(); it != pwalletMain->mapWallet.end(); ++it) {
        const uint256& wtxid = it->first;
        const CWalletTx& wtx = (*it).second;
        orderedTxs.insert(std::pair<int64_t, CWalletTx>(wtx.nOrderPos, wtx));

        unsigned int txType = 0;
        // 0 Unassigend
        // 1 Immature
        // 2 Unconfirmed
        // 3 Locked

        if (!CheckFinalTx(wtx))
            continue;

        if (wtx.GetDepthInMainChain() < 0)
            continue;

        if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
            continue;

        // Get Block height of transaction
        int txHeight = chainActive.Tip()->nHeight + 1;
        if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
            txHeight = mapBlockIndex[wtx.hashBlock]->nHeight;
        }

        // Assign Immature
        if (txType == 0 && wtx.IsCoinBase() && wtx.GetBlocksToMaturity() > 0)
            txType = 1;

        // Assign Unconfirmed
        if (txType == 0 && wtx.GetDepthInMainChain() == 0)
            txType = 2;

        for (unsigned int i = 0; i < wtx.vout.size(); i++) {
            CTxDestination address;
            if (!ExtractDestination(wtx.vout[i].scriptPubKey, address))
                continue;

            // excluded coins that we dont have the spending or watchonly keys for
            isminetype mine = IsMine(*pwalletMain, address);
            if (mine != ISMINE_SPENDABLE && !(mine == ISMINE_WATCH_ONLY && fIncludeWatchonly))
                continue;

            // Exclude spent coins
            if (pwalletMain->IsSpent(wtxid, i))
                continue;

            // Assign locked
            if (txType == 0 && pwalletMain->IsLockedCoin((*it).first, i))
                txType = 3;

            string addressString = EncodeDestination(address);
            if (addressBalances.count(addressString) == 0)
                addressBalances.insert(make_pair(addressString, txAmounts));

            if (txType == 0) {
                addressBalances.at(addressString).confirmed += wtx.vout[i].nValue;
                confirmed += wtx.vout[i].nValue;
            } else if (txType == 1) {
                addressBalances.at(addressString).immature += wtx.vout[i].nValue;
                immature += wtx.vout[i].nValue;
            } else if (txType == 2) {
                addressBalances.at(addressString).unconfirmed += wtx.vout[i].nValue;
                unconfirmed += wtx.vout[i].nValue;
            } else if (txType == 3) {
                addressBalances.at(addressString).locked += wtx.vout[i].nValue;
                locked += wtx.vout[i].nValue;
            }
            if (mine == ISMINE_SPENDABLE) {
                addressBalances.at(addressString).spendable = true;
            } else {
                addressBalances.at(addressString).spendable = false;
            }
        }

        // Get Outputs to decrypt
        auto vOutputs = wtx.GetSaplingOutputs();

        for (auto& pair : wtx.mapSaplingNoteData) {
            SaplingOutPoint op = pair.first;
            SaplingNoteData nd = pair.second;

            // Skip Spent
            if (nd.nullifier && pwalletMain->IsSaplingSpent(*nd.nullifier))
                continue;

            // Decrypt sapling incoming commitments using IVK
            auto ivk = nd.ivk;
            libzcash::SaplingExtendedFullViewingKey extfvk;
            if (pwalletMain->GetSaplingFullViewingKey(ivk, extfvk)) {
                bool haveSpendingKey = pwalletMain->HaveSaplingSpendingKey(extfvk);
                if (haveSpendingKey || fIncludeWatchonly) {
                    auto cmu = uint256::FromRawBytes(vOutputs[op.n].cmu());
                    auto ephemeralKey = uint256::FromRawBytes(vOutputs[op.n].ephemeral_key());
                    auto encCiphertext = vOutputs[op.n].enc_ciphertext();

                    auto pt = libzcash::SaplingNotePlaintext::decrypt(Params().GetConsensus(), txHeight, encCiphertext, ivk, ephemeralKey, cmu);

                    if (txType == 0 && pwalletMain->IsLockedNote(op))
                        txType = 3;

                    auto note = pt.value();
                    auto pa = ivk.address(note.d);
                    auto addr = pa.value();
                    string addressString = EncodePaymentAddress(addr);
                    if (addressBalances.count(addressString) == 0)
                        addressBalances.insert(make_pair(addressString, txAmounts));

                    if (txType == 0) {
                        addressBalances.at(addressString).confirmed += note.value();
                        privateConfirmed += note.value();
                    } else if (txType == 1) {
                        addressBalances.at(addressString).immature += note.value();
                        privateImmature += note.value();
                    } else if (txType == 2) {
                        addressBalances.at(addressString).unconfirmed += note.value();
                        privateUnconfirmed += note.value();
                    } else if (txType == 3) {
                        addressBalances.at(addressString).locked += note.value();
                        privateLocked += note.value();
                    }
                    addressBalances.at(addressString).spendable = haveSpendingKey;
                }
            }
        }

        // Get Actions to decrypt
        auto vActions = wtx.GetOrchardActions();

        for (auto& pair : wtx.mapOrchardNoteData) {
            OrchardOutPoint op = pair.first;
            OrchardNoteData nd = pair.second;

            // Skip Spent
            if (nd.nullifier && pwalletMain->IsOrchardSpent(*nd.nullifier))
                continue;

            // Decrypt orchard action
            auto ivk = nd.ivk;
            libzcash::OrchardExtendedFullViewingKeyPirate extfvk;
            if (pwalletMain->GetOrchardFullViewingKey(ivk, extfvk)) {
                bool haveSpendingKey = pwalletMain->HaveOrchardSpendingKey(extfvk);
                if (haveSpendingKey || fIncludeWatchonly) {
                    auto pt = OrchardNotePlaintext::AttemptDecryptOrchardAction(&vActions[op.n], ivk);

                    if (txType == 0 && pwalletMain->IsLockedNote(op))
                        txType = 3;

                    if (pt) {
                        auto note = pt.value();
                        auto addr = note.GetAddress();
                        string addressString = EncodePaymentAddress(addr);
                        if (addressBalances.count(addressString) == 0)
                            addressBalances.insert(make_pair(addressString, txAmounts));

                        if (txType == 0) {
                            addressBalances.at(addressString).confirmed += note.value();
                            privateConfirmed += note.value();
                        } else if (txType == 1) {
                            addressBalances.at(addressString).immature += note.value();
                            privateImmature += note.value();
                        } else if (txType == 2) {
                            addressBalances.at(addressString).unconfirmed += note.value();
                            privateUnconfirmed += note.value();
                        } else if (txType == 3) {
                            addressBalances.at(addressString).locked += note.value();
                            privateLocked += note.value();
                        }
                        addressBalances.at(addressString).spendable = haveSpendingKey;
                    }
                }
            }
        }
    }


    CAmount nBalance = 0;
    CAmount nBalanceUnconfirmed = 0;
    CAmount nBalanceTotal = 0;
    CAmount totalBalance = confirmed + privateConfirmed;
    CAmount totalUnconfirmed = unconfirmed + privateUnconfirmed;


    returnObj.push_back(Pair("connectionCount", connectionCount));
    returnObj.push_back(Pair("besttime", chainActive.Tip()->GetBlockTime()));
    returnObj.push_back(Pair("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex()));
    returnObj.push_back(Pair("transparentbalance", FormatMoney(confirmed)));
    returnObj.push_back(Pair("transparentbalanceunconfirmed", FormatMoney(unconfirmed)));
    returnObj.push_back(Pair("privatebalance", FormatMoney(privateConfirmed)));
    returnObj.push_back(Pair("privatebalanceunconfirmed", FormatMoney(privateUnconfirmed)));
    returnObj.push_back(Pair("totalbalance", FormatMoney(totalBalance)));
    returnObj.push_back(Pair("totalunconfirmed", FormatMoney(totalUnconfirmed)));
    returnObj.push_back(Pair("lockedbalance", FormatMoney(locked)));
    returnObj.push_back(Pair("immaturebalance", FormatMoney(immature)));

    // get all t address
    UniValue addressbalance(UniValue::VARR);
    UniValue addrlist(UniValue::VOBJ);

    if (params.size() > 0 && (params[0].get_int() == 1 || params[0].get_int() == 0)) {
        for (map<string, balancestruct>::iterator it = addressBalances.begin(); it != addressBalances.end(); ++it) {
            UniValue addr(UniValue::VOBJ);
            addr.push_back(Pair("amount", ValueFromAmount(it->second.confirmed)));
            addr.push_back(Pair("unconfirmed", ValueFromAmount(it->second.unconfirmed)));
            addr.push_back(Pair("locked", ValueFromAmount(it->second.locked)));
            addr.push_back(Pair("immature", ValueFromAmount(it->second.immature)));
            addr.push_back(Pair("spendable", it->second.spendable));
            addrlist.push_back(Pair(it->first, addr));
        }
    }

    addressbalance.push_back(addrlist);
    returnObj.push_back(Pair("addressbalance", addressbalance));


    // get transactions
    uint64_t t = GetTime();
    int nCount = 200;
    UniValue trans(UniValue::VARR);
    UniValue transTime(UniValue::VARR);

    if (params.size() == 3) {
        nCount = params[2].get_int();
    }

    if (params.size() > 0 && (params[0].get_int() == 2 || params[0].get_int() == 0)) {
        int day = 365 * 30; // 30 Years
        if (params.size() > 1) {
            if (params[1].get_int() == 1) {
                day = 1;
            } else if (params[1].get_int() == 2) {
                day = 7;
            } else if (params[1].get_int() == 3) {
                day = 30;
            } else if (params[1].get_int() == 4) {
                day = 90;
            } else if (params[1].get_int() == 5) {
                day = 365;
            }
        }

        uint256 ut;
        // get Sorted Archived Transactions
        std::map<std::pair<int, int>, uint256> sortedArchive;
        for (map<uint256, ArchiveTxPoint>::iterator it = pwalletMain->mapArcTxs.begin(); it != pwalletMain->mapArcTxs.end(); ++it) {
            uint256 txid = (*it).first;
            ArchiveTxPoint arcTxPt = (*it).second;
            std::pair<int, int> key;

            if (!arcTxPt.hashBlock.IsNull() && mapBlockIndex.count(arcTxPt.hashBlock) > 0) {
                // Exclude Transactions older that max days old
                if (mapBlockIndex[arcTxPt.hashBlock]->GetBlockTime() < (t - (day * 60 * 60 * 24))) {
                    continue;
                }

                key = make_pair(mapBlockIndex[arcTxPt.hashBlock]->nHeight, arcTxPt.nIndex);
                sortedArchive[key] = txid;
            }
        }

        // add any missing wallet transactions - unconfimred & conflicted
        int nPosUnconfirmed = 0;
        for (map<int64_t, CWalletTx>::reverse_iterator it = orderedTxs.rbegin(); it != orderedTxs.rend(); ++it) {
            CWalletTx wtx = (*it).second;
            std::pair<int, int> key;

            if (!CheckFinalTx(wtx))
                continue;

            if (wtx.mapSaplingNoteData.size() == 0 && wtx.mapOrchardNoteData.size() == 0 && !wtx.IsTrusted())
                continue;

            // Excude transactions with less confirmations than required
            if (wtx.GetDepthInMainChain() < 0)
                continue;

            // Exclude Transactions older that max days old
            if (mapBlockIndex.count(wtx.hashBlock) > 0) {
                if (wtx.GetDepthInMainChain() > 0 && mapBlockIndex[wtx.hashBlock]->GetBlockTime() < (t - (day * 60 * 60 * 24))) {
                    continue;
                }
            }

            if (wtx.GetDepthInMainChain() == 0) {
                ut = wtx.GetHash();
                key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
                sortedArchive[key] = wtx.GetHash();
                nPosUnconfirmed++;
            } else if (!wtx.hashBlock.IsNull() && mapBlockIndex.count(wtx.hashBlock) > 0) {
                key = make_pair(mapBlockIndex[wtx.hashBlock]->nHeight, wtx.nIndex);
                sortedArchive[key] = wtx.GetHash();
            } else {
                key = make_pair(chainActive.Tip()->nHeight + 1, nPosUnconfirmed);
                sortedArchive[key] = wtx.GetHash();
                nPosUnconfirmed++;
            }
        }

        for (map<std::pair<int, int>, uint256>::reverse_iterator it = sortedArchive.rbegin(); it != sortedArchive.rend(); ++it) {
            uint256 txid = (*it).second;
            RpcArcTransaction arcTx;

            if (pwalletMain->mapWallet.count(txid)) {
                CWalletTx& wtx = pwalletMain->mapWallet[txid];

                getRpcArcTx(wtx, arcTx, fIncludeWatchonly, false);

            } else {
                // Archived Transactions
                getRpcArcTx(txid, arcTx, fIncludeWatchonly, false);
            }

            UniValue txObj(UniValue::VOBJ);
            getRpcArcTxJSONHeader(arcTx, txObj);

            if (arcTx.spentFrom.size() > 0) {
                UniValue sends(UniValue::VARR);
                getRpcArcTxJSONSends(arcTx, sends);
                txObj.push_back(Pair("sent", sends));
            }

            UniValue receive(UniValue::VARR);
            getRpcArcTxJSONReceives(arcTx, receive);
            txObj.push_back(Pair("received", receive));

            if (arcTx.vTReceived.size() + arcTx.spentFrom.size() > 0)
                trans.push_back(txObj);

            if (trans.size() >= nCount)
                break;
        }

        vector<UniValue> arrTmp = trans.getValues();

        std::reverse(arrTmp.begin(), arrTmp.end()); // Return oldest to newest

        trans.clear();
        trans.setArray();
        trans.push_backV(arrTmp);
    }

    returnObj.push_back(Pair("listtransactions", trans));
    return returnObj;
}

void decrypttransaction(CTransaction& tx, RpcArcTransaction& arcTx, int nHeight)
{
    // get Ovks for sapling decryption
    std::set<uint256> saplingOvks;
    getAllSaplingOVKs(saplingOvks, true);

    // get Ivks for sapling decryption
    std::set<uint256> saplingIvks;
    getAllSaplingIVKs(saplingIvks, true);

    // get Ovks for sapling decryption
    std::set<libzcash::OrchardOutgoingViewingKey> orchardOvks;
    getAllOrchardOVKs(orchardOvks, true);

    // get Ivks for sapling decryption
    std::set<libzcash::OrchardIncomingViewingKeyPirate> orchardIvks;
    getAllOrchardIVKs(orchardIvks, true);

    auto params = Params().GetConsensus();
    // Spends must be located to determine if outputs are change
    getTransparentSpends(tx, arcTx.vTSpend, arcTx.transparentValue, true);
    getSaplingSpends(params, nHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsSpend, true);
    getOrchardSpends(params, nHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoSpend, true);

    getTransparentSends(tx, arcTx.vTSend, arcTx.transparentValue);
    getSaplingSends(params, nHeight, tx, saplingOvks, arcTx.saplingOvks, arcTx.vZsSend);
    getOrchardSends(params, nHeight, tx, orchardOvks, arcTx.orchardOvks, arcTx.vZoSend);

    getTransparentRecieves(tx, arcTx.vTReceived, true);
    getSaplingReceives(params, nHeight, tx, saplingIvks, arcTx.saplingIvks, arcTx.vZsReceived, true);
    getOrchardReceives(params, nHeight, tx, orchardIvks, arcTx.orchardIvks, arcTx.vZoReceived, true);

    arcTx.saplingValue = -tx.GetValueBalanceSapling();
    arcTx.orchardValue = -tx.GetValueBalanceOrchard();

    for (int i = 0; i < arcTx.vTSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vTSpend[i].encodedAddress);
    }

    for (int i = 0; i < arcTx.vZsSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZsSpend[i].encodedAddress);
    }

    for (int i = 0; i < arcTx.vZoSpend.size(); i++) {
        arcTx.spentFrom.insert(arcTx.vZoSpend[i].encodedAddress);
    }
}


static const CRPCCommand commands[] =
{   //  category              name                          actor (function)              okSafeMode
    //  --------------------- ------------------------      -----------------------       ----------
    {   "pirate Exclusive",     "zs_listtransactions",       &zs_listtransactions,          true },
    {   "pirate Exclusive",     "zs_gettransaction",         &zs_gettransaction,            true },
    {   "pirate Exclusive",     "zs_listspentbyaddress",     &zs_listspentbyaddress,        true },
    {   "pirate Exclusive",     "zs_listreceivedbyaddress",  &zs_listreceivedbyaddress,     true },
    {   "pirate Exclusive",     "zs_listsentbyaddress",      &zs_listsentbyaddress,         true },
    {   "pirate Exclusive",     "getalldata",                &getalldata,                   true },
};

void RegisterPirateExclusiveRPCCommands(CRPCTable& tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
