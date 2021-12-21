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
#include "app/rpc/context.h"
#include "ethereum/state.h"
#include "ethereum/tee_manager.h"
#include "ethereum/types.h"

#include <eEVM/address.h>
#include <eEVM/processor.h>
#include <eEVM/util.h>

namespace Ethereum {

using MessageCall = Ethereum::MessageCall;
using Address = eevm::Address;
class AbstractEVM {
 protected:
    AbstractEVM(const MessageCall& _call_data,
                EthereumState& _es,
                eevm::LogHandler& _log_handler,
                const std::string& _mpt_id,
                const std::map<int, std::string>& _slot_mapping) :
        call_data(_call_data),
        es(_es), log_handler(_log_handler), mpt_id(_mpt_id), slot_mapping(_slot_mapping) {}

    std::tuple<eevm::ExecResult, evm4ccf::TxHash, Address> run_in_evm() {
        Address to;
        if (call_data.to.has_value()) {
            to = call_data.to.value();
        } else {
            // If there's no to field, create a new account to deploy this to
            const auto from_state = es.get(call_data.from);
            to = eevm::generate_address(from_state.acc.get_address(), from_state.acc.get_nonce());
            es.create(to, call_data.gas, eevm::to_bytes(call_data.data));
        }

        auto [exec_result, account_state] = run(to);
        if (exec_result.er == eevm::ExitReason::threw) {
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
        const auto hash = eevm::from_big_endian(tx_hash.data());
        return std::make_tuple(exec_result, hash, account_state.acc.get_address());
    }

    const MessageCall& call_data;

 private:
    std::pair<eevm::ExecResult, eevm::AccountState> run(Address& to) {
        eevm::Transaction eth_tx(call_data.from, log_handler);
        auto account_state = es.get(to);
        if (!account_state.acc.has_code()) {
            throw Exception(
                fmt::format("this address [{}] is a common address", eevm::to_hex_string(to)));
        }
#ifdef RECORD_TRACE
        Trace tr;
#endif // RECORD_TRACE
        eevm::Processor proc(es);
        const auto result = proc.run(eth_tx,
                                     call_data.from,
                                     account_state,
                                     eevm::to_bytes(call_data.data),
                                     call_data.value,
                                     mpt_id,
                                     slot_mapping
#ifdef RECORD_TRACE
                                     ,
                                     &tr
#endif // RECORD_TRACE
        ); // NOLINT
#ifdef RECORD_TRACE
        if (result.er == eevm::ExitReason::threw) {
            LOG_INFO_FMT("--- Trace of failing evm execution ---\n{}", tr);
        }
#endif // RECORD_TRACE
        return std::make_pair(result, account_state);
    }

    EthereumState& es;
    eevm::LogHandler& log_handler;
    std::string mpt_id;
    std::map<int, std::string> slot_mapping;
};

class EVMC : public AbstractEVM {
 private:
    // kv::Tx tx;
    tables::Results::TxView* results_view;

 public:
    EVMC(const MessageCall& call_data,
         EthereumState& es,
         tables::Results::TxView* views,
         const std::string& mpt_id,
         const std::map<int, std::string>& slot_mapping) :
        AbstractEVM(call_data, es, vlh, mpt_id, slot_mapping),
        results_view(views) {}
    eevm::VectorLogHandler vlh;
    evm4ccf::TxHash run() {
        const auto [exec_result, tx_hash, to_address] = run_in_evm();
        if (exec_result.er == eevm::ExitReason::threw) {
            throw std::logic_error(exec_result.exmsg);
        }

        TxResult tx_result;
        if (!call_data.to.has_value()) {
            tx_result.contract_address = to_address;
        }

        tx_result.logs = vlh.logs;

        results_view->put(tx_hash, tx_result);
        return tx_hash;
    }

    eevm::ExecResult run_with_result() {
        const auto [exec_result, tx_hash, to_address] = run_in_evm();

        if (exec_result.er == eevm::ExitReason::threw) {
            throw std::logic_error(exec_result.exmsg);
        }

        return exec_result;
    }
};

void policy_states_to_slot_mapping(const std::vector<policy::Params>& policy_states,
                                   std::map<int, std::string>& slot_mapping) {
    for (auto state : policy_states) {
        slot_mapping[state.slot] = state.name;
    }
}

std::vector<uint8_t> execute_mpt(cloak4ccf::CloakContext& ctx,
                                 evm4ccf::CloakPolicyTransaction& ct,
                                 const Address& tee_addr,
                                 const std::vector<std::string>& decryped_states,
                                 const std::string& mpt_id) {
    kv::Tx& tx = ctx.tx;
    auto encoder = abicoder::Encoder("set_states");
    encoder.add_inputs("data", "bytes[]", decryped_states, abicoder::make_bytes_array());
    auto set_states_call_data = encoder.encodeWithSignatrue();

    CLOAK_DEBUG_FMT("splited decryped_states_packed:\n{}",
                    fmt::join(abicoder::split_abi_data(encoder.encode()), "\n"));

    MessageCall set_states_mc(tee_addr, ct.to, set_states_call_data);
    CLOAK_DEBUG_FMT("call_data:{}", eevm::to_hex_string(set_states_call_data));
    auto es = EthereumState::make_state(tx, ctx.cloakTables.acc_state);
    std::map<int, std::string> slot_mapping;
    policy_states_to_slot_mapping(ct.states, slot_mapping);
    auto set_states_res =
        EVMC(set_states_mc, es, tx.get_view(ctx.cloakTables.tx_results), mpt_id, slot_mapping)
            .run_with_result();

    // run in evm
    auto data = ct.function.packed_to_data();
    MessageCall mc(ct.from, ct.to, data);

    CLOAK_DEBUG_FMT("ct function data: {}", mc.data);
    const auto res = EVMC(mc, es, tx.get_view(ctx.cloakTables.tx_results), mpt_id, slot_mapping)
                         .run_with_result();
    ct.function.raw_outputs = res.output;

    // == get new states ==
    auto get_new_states_call_data = ct.get_states_call_data(false);
    CLOAK_DEBUG_FMT("get_new_states_call_data:{}", eevm::to_hex_string(get_new_states_call_data));
    MessageCall get_new_states_mc(tee_addr, ct.to, get_new_states_call_data);

    auto get_new_states_res =
        EVMC(get_new_states_mc, es, tx.get_view(ctx.cloakTables.tx_results), mpt_id, slot_mapping)
            .run_with_result();
    CLOAK_DEBUG_FMT("get_new_states res:{}, {}, {}, {}",
                    get_new_states_res.er,
                    get_new_states_res.ex,
                    eevm::to_hex_string(get_new_states_res.output),
                    get_new_states_res.exmsg);

    CLOAK_DEBUG_FMT("splited output:{}\n",
                    abicoder::split_abi_data_to_str(get_new_states_res.output));
    return get_new_states_res.output;
}

} // namespace Ethereum
