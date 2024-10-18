// Copyright (c) 2011-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef KOMODO_QT_WALLETMODELZTRANSACTION_H
#define KOMODO_QT_WALLETMODELZTRANSACTION_H

#include "walletmodel.h"
#include "transaction_builder.h"
#include "wallet/asyncrpcoperation_sendmany.h"

#include <QObject>

class SendCoinsRecipient;

class CWallet;

/** Data model for a walletmodel transaction. */
class WalletModelZTransaction
{
public:
    explicit WalletModelZTransaction(const QString &fromaddress, const QList<SendCoinsRecipient> &recipients, const CAmount& fee, const bool &bIsMine);
    ~WalletModelZTransaction();

    QString getFromAddress() const;
    bool    getIsMine() const;
    QList<SendCoinsRecipient> getRecipients() const;

    void setTransactionFee(const CAmount& newFee);
    CAmount getTransactionFee() const;

    void setTxHeight(const int& newTxHeight);
    int getTxHeight() const;

    void setOaddrRecipients(const std::vector<SendManyRecipient>& newOaddrRecipients);
    std::vector<SendManyRecipient> getOaddrRecipients() const;

    void setZaddrRecipients(const std::vector<SendManyRecipient>& newZaddrRecipients);
    std::vector<SendManyRecipient> getZaddrRecipients() const;

    void setContextInfo(const UniValue& newContextInfo);
    UniValue getContextInfo() const;

    CAmount getTotalTransactionAmount() const;

    void setOperationId(const AsyncRPCOperationId& newOperationId);
    AsyncRPCOperationId getOperationId() const;

    void setZSignOfflineTransaction(const string& sTransaction);
    string getZSignOfflineTransaction() const;

private:
    QString fromaddress;
    bool    bIsMine;     //True: Spending key must be in the local adres book. False: Prepare an offline transaction signing (Off-line PC wallet || h/w wallet)
    QList<SendCoinsRecipient> recipients;
    CAmount fee;
    int txHeight;
    std::vector<SendManyRecipient> oaddrRecipients;
    std::vector<SendManyRecipient> zaddrRecipients;
    UniValue contextInfo;

    AsyncRPCOperationId operationId;
    string sZSignOfflineTransaction;
};

#endif // KOMODO_QT_WALLETMODELZTRANSACTION_H
