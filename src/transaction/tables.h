#pragma once

#include "../app/tables.h"
#include "kv/map.h"
#include "kv/store.h"
#include "ethereum_transaction.h"
#include "../queue/workertransaction.h"
#include "../app/utils.h"
#include "signature_abstract.h"
#include "../app/tables.h"
namespace evm4ccf
{ 
    struct TxTables
    {
        static constexpr auto PRIVACYS = "eth.transaction.privacys";
        static constexpr auto PRIVACY_DIGESTS = "eth.transaction.privacy_digests";
        static constexpr auto CLOAKPOLICYS = "eth.transaction.cloak_policys";
        static constexpr auto CLOAK_DIGESTS = "eth.transaction.cloak_digests";
        static constexpr auto MULTI_PARTYS = "eth.transaction.multi_partys";
        static constexpr auto NONCES = "eth.account.nonce";
    };
    
    struct AccTables
    {
        static constexpr auto BALANCES = "eth.account.balance";
        static constexpr auto CODERS = "eth.account.code";
        static constexpr auto NONCES = "eth.account.nonce";     
    };
    

    struct TransactionTables
    {
        const kv::Store& store;
        Privacys privacys;     // 存储隐私模型
        PrivacyDigests privacy_digests;

        CloakPolicys cloak_policys;
        CloakDigests cloak_digests;
        MultiPartys  multi_partys;
        tables::Accounts::Nonces nonces;
        TransactionTables(const kv::Store& _store) :
            store(_store),
            privacys(TxTables::PRIVACYS),
            privacy_digests(TxTables::PRIVACY_DIGESTS),
            cloak_policys(TxTables::CLOAKPOLICYS),
            cloak_digests(TxTables::CLOAK_DIGESTS),
            multi_partys(TxTables::MULTI_PARTYS),
            nonces(TxTables::NONCES)
        {}
    };
    
    
} // namespace evm4ccf
