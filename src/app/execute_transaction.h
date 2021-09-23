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
#include "execute_transaction.h"
#include "rpc_types.h"

#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/processor.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>

namespace eevm {

using MessageCall = evm4ccf::rpcparams::MessageCall;
using EthereumState = evm4ccf::EthereumState;
using namespace evm4ccf;

class AbstractEVM {
 protected:
    AbstractEVM(const MessageCall& _call_data, EthereumState& _es, LogHandler& _log_handler)
        : call_data(_call_data), es(_es), log_handler(_log_handler) {}

    std::tuple<ExecResult, evm4ccf::TxHash, Address> run_in_evm() {
        Address to;
        if (call_data.to.has_value()) {
            to = call_data.to.value();
        } else {
            // If there's no to field, create a new account to deploy this to
            const auto from_state = es.get(call_data.from);
            to = generate_address(from_state.acc.get_address(), from_state.acc.get_nonce());
            es.create(to, call_data.gas, to_bytes(call_data.data));
        }

        auto [exec_result, account_state] = run(to);
        if (exec_result.er == ExitReason::threw) {
            return std::make_tuple(exec_result, 0, 0);
        }

        if (!call_data.to.has_value()) {
            account_state.acc.set_code(std::move(exec_result.output));
        }

        auto from_state = es.get(call_data.from);
        auto tx_nonce = from_state.acc.get_nonce();
        from_state.acc.increment_nonce();

        evm4ccf::EthereumTransaction eth_tx(tx_nonce, call_data);
        const auto tx_hash = eth_tx.to_be_signed();
        const auto hash = from_big_endian(tx_hash.data());
        return std::make_tuple(exec_result, hash, account_state.acc.get_address());
    }

    const MessageCall& call_data;

 private:
    std::pair<ExecResult, AccountState> run(Address& to) {
        Transaction eth_tx(call_data.from, log_handler);
        auto account_state = es.get(to);
        CLOAK_DEBUG_FMT("code: {}", account_state.acc.get_code());
        CLOAK_DEBUG_FMT("call_data: {}", nlohmann::json(call_data).dump());
#ifdef RECORD_TRACE
        Trace tr;
#endif  // RECORD_TRACE
        Processor proc(es);
        const auto result = proc.run(eth_tx,
                                     call_data.from,
                                     account_state,
                                     to_bytes(call_data.data),
                                     call_data.value
#ifdef RECORD_TRACE
                                     ,
                                     &tr
#endif      // RECORD_TRACE
        );  // NOLINT
#ifdef RECORD_TRACE
        if (result.er == ExitReason::threw) {
            LOG_INFO_FMT("--- Trace of failing evm execution ---\n{}", tr);
        }
#endif  // RECORD_TRACE
        return std::make_pair(result, account_state);
    }

    EthereumState& es;
    LogHandler& log_handler;
};

class EVMC : public AbstractEVM {
 private:
    // kv::Tx tx;
    evm4ccf::tables::Results::TxView* results_view;

 public:
    EVMC(const MessageCall& call_data, EthereumState& es, evm4ccf::tables::Results::TxView* views)
        : AbstractEVM(call_data, es, vlh), results_view(views) {}
    VectorLogHandler vlh;
    evm4ccf::TxHash run() {
        const auto [exec_result, tx_hash, to_address] = run_in_evm();
        if (exec_result.er == ExitReason::threw) {
            throw std::logic_error(exec_result.exmsg);
        }

        evm4ccf::TxResult tx_result;
        if (!call_data.to.has_value()) {
            tx_result.contract_address = to_address;
        }

        tx_result.logs = vlh.logs;

        results_view->put(tx_hash, tx_result);
        return tx_hash;
    }

    ExecResult run_with_result() {
        const auto [exec_result, tx_hash, to_address] = run_in_evm();

        if (exec_result.er == ExitReason::threw) {
            throw std::logic_error(exec_result.exmsg);
        }

        return exec_result;
    }
};

}  // namespace eevm
