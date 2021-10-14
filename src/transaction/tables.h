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

#include "app/utils.h"
#include "ethereum/tables.h"
#include "ethereum_transaction.h"
#include "kv/map.h"
#include "kv/store.h"
#include "queue/workertransaction.h"
#include "signature_abstract.h"

namespace cloak4ccf {

namespace transaction {
struct Tables {
    static constexpr auto PRIVACYS = "eth.transaction.privacys";
    static constexpr auto PRIVACY_DIGESTS = "eth.transaction.privacy_digests";
    static constexpr auto CLOAKPOLICYS = "eth.transaction.cloak_policys";
    static constexpr auto CLOAK_DIGESTS = "eth.transaction.cloak_digests";
    static constexpr auto MULTI_PARTYS = "eth.transaction.multi_partys";
    static constexpr auto STATES_DIGEST = "eth.transaction.states_digest";
};

} // namespace transaction

namespace accounts {
struct Tables {};

} // namespace accounts

struct TransactionTables {
    evm4ccf::Privacys privacys;
    evm4ccf::PrivacyDigests privacy_digests;

    evm4ccf::CloakPolicys cloak_policys;
    evm4ccf::CloakDigests cloak_digests;
    evm4ccf::MultiPartys multi_partys;
    evm4ccf::StatesDigests states_digests;
    TransactionTables() :
        privacys(transaction::Tables::PRIVACYS),
        privacy_digests(transaction::Tables::PRIVACY_DIGESTS),
        cloak_policys(transaction::Tables::CLOAKPOLICYS),
        cloak_digests(transaction::Tables::CLOAK_DIGESTS),
        multi_partys(transaction::Tables::MULTI_PARTYS),
        states_digests(transaction::Tables::STATES_DIGEST) {}
};

} // namespace cloak4ccf
