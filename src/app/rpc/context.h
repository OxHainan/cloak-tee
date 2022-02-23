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
#include "ccf/tx.h"
#include "ethereum/tables.h"
#include "ethereum/tee_account.h"
#include "pop/tables.h"
#include "transaction/tables.h"

namespace cloak4ccf
{
    using SeqNo = int64_t;
    struct CloakTables
    {
        TransactionTables txTables;
        Ethereum::tables::AccountsState acc_state;
        Ethereum::tables::Results tx_results;
        TeeManager::tables::Table tee_table;
        Pop::Tables popTables;
        CloakTables() :
          txTables(),
          acc_state(),
          tx_results("eth.txresults"),
          tee_table(),
          popTables()
        {}
    };

    template <typename TX>
    struct CloakContextT
    {
        TX& tx;
        CloakTables& cloakTables;
        SeqNo seqno;
        CloakContextT(TX& tx_, CloakTables& cloakTables_) :
          tx(tx_),
          cloakTables(cloakTables_)
        {}
    };

    using CloakContext = CloakContextT<kv::Tx>;
    using ReadOnlyCloakContext = CloakContextT<kv::ReadOnlyTx>;
} // namespace cloak4ccf
