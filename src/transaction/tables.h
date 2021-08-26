// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
        Privacys privacys;
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
