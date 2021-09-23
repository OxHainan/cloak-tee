// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// STL/3rd-party
#include <iostream>
#include <stdexcept>
#include <unistd.h>

// CCF
#include "ds/hash.h"
#include "enclave/app_interface.h"
#include "node/quote.h"
#include "node/rpc/user_frontend.h"
#include "rpc_types.h"

#include <msgpack/msgpack.hpp>

// eEVM
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/processor.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>

// EVM-for-CCF
#include "abi/abicoder.h"
#include "account_proxy.h"
#include "app/execute_transaction.h"
#include "app/json_hander.h"
#include "ds/logger.h"
#include "ethereum_state.h"
#include "ethereum_transaction.h"
#include "http/http_status.h"
#include "jsonrpc.h"
#include "nlohmann/json.hpp"
#include "tables.h"
#include "tee_manager.h"
#include "tls/key_pair.h"
#include "transaction/generator.h"
#include "utils.h"

namespace evm4ccf {
using namespace std;
using namespace eevm;
using namespace ccf;
using namespace ccfapp;

//
// RPC handler class
//
class EVMHandlers : public UserEndpointRegistry {
    tables::Accounts accounts;
    tables::Storage storage;
    tables::Results tx_results;
    TransactionTables txTables;

    Tables table;
    EthereumState make_state(kv::Tx& tx) { return EthereumState(accounts.get_views(tx), tx.get_view(storage)); }
    void install_standard_rpcs() {
        auto get_chainId = [](CloakContext&) {
            // return nlohmann::json(to_hex_string(evm4ccf::current_chain_id));
            return evm4ccf::current_chain_id;
        };

        auto get_gasPrice = [](CloakContext&) {
            auto result = nlohmann::json(to_hex_string(0));
            return result;
        };

        auto get_balance = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto gb = params.get<rpcparams::AddressWithBlock>();
            if (gb.block_id != "latest") {
                auto error = nlohmann::json("Can only request latest block");
                return ccf::make_error(HTTP_STATUS_BAD_REQUEST, error);
            }

            auto es = make_state(ctx.tx);
            const auto account_state = es.get(gb.address);
            const auto result = account_state.acc.get_balance();
            return ccf::make_success(to_hex_string(result));
        };

        auto get_code = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto gc = params.get<rpcparams::AddressWithBlock>();
            if (gc.block_id != "latest") {
                auto error = nlohmann::json("Can only request latest block");
                return ccf::make_error(HTTP_STATUS_BAD_REQUEST, error);
            }

            auto es = make_state(ctx.tx);
            const auto account_state = es.get(gc.address);
            const auto result = account_state.acc.get_code();
            return ccf::make_success(to_hex_string(result));
        };

        auto get_transaction_count = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto gtc = params.get<rpcparams::GetTransactionCount>();
            if (gtc.block_id != "latest") {
                auto error = nlohmann::json("Can only request latest block");
                return ccf::make_error(HTTP_STATUS_BAD_REQUEST, error);
            }

            auto es = make_state(ctx.tx);
            auto account_state = es.get(gtc.address);

            const auto result = account_state.acc.get_nonce();
            return ccf::make_success(to_hex_string(result));
        };

        auto send_raw_transaction = [this](CloakContext& ctx, const nlohmann::json& params) {
            CLOAK_DEBUG_FMT("SEND RAW {}", params.dump());
            auto srtp = params.get<rpcparams::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srtp.raw_transaction);
            EthereumTransactionWithSignature eth_tx(in);

            rpcparams::MessageCall tc;
            eth_tx.to_transaction_call(tc);
            auto es = make_state(ctx.tx);
            auto tx_result = eevm::EVMC(tc, es, ctx.tx.get_view(tx_results)).run();

            return to_hex_string(tx_result);
        };

        auto send_raw_privacy_policy_transaction = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto srpp = params.get<rpcparams::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srpp.raw_transaction);

            TransactionGenerator gen(txTables, ctx.tx);
            auto policy_digest = gen.add_privacy(in);

            return to_hex_string(policy_digest);
        };

        auto send_raw_multiPartyTransaction = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto srmp = params.get<rpcparams::SendRawTransaction>();
            eevm::rlp::ByteString in = eevm::to_bytes(srmp.raw_transaction);
            TransactionGenerator gen(txTables, ctx.tx);
            auto ct_digest = gen.add_cloakTransaction(in);
            return to_hex_string(ct_digest);
        };

        auto get_transaction_receipt = [this](ReadOnlyCloakContext& ctx, const nlohmann::json& params) {
            auto gtrp = params.get<rpcparams::GetTransactionReceipt>();

            const TxHash& tx_hash = gtrp.tx_hash;

            auto results_view = ctx.tx.get_read_only_view(tx_results);
            const auto r = results_view->get(tx_hash);

            // "or null when no receipt was found"
            rpcresults::ReceiptResponse response = nullopt;
            if (r.has_value()) {
                const auto& tx_result = r.value();

                response.emplace();
                response->transaction_hash = tx_hash;
                if (tx_result.contract_address.has_value()) {
                    response->contract_address = tx_result.contract_address;
                } else {
                    response->to = 0x0;
                }
                response->logs = tx_result.logs;
                response->status = 1;
            }
            return response;
        };

        auto get_transaction_count_test = [this](kv::Tx& tx, const nlohmann::json& params) {
            auto gtcp = params.get<ethrpc::GetTransactionCountTest::In>();

            if (gtcp.block_id != "latest") {
                return ccf::make_error(HTTP_STATUS_BAD_REQUEST, "Can only request latest block");
            }

            auto es = make_state(tx);
            auto account_state = es.get(gtcp.address);

            return ccf::make_success(ethrpc::GetTransactionCountTest::Out{account_state.acc.get_nonce()});
        };

        auto prepare = [](CloakContext& ctx, const nlohmann::json& params) {
            auto addr = params.get<TeePrepare>();
            TeeManager::prepare(ctx.tx, addr.cloak_service_addr, addr.pki_addr);
            return true;
        };

        auto sync_old_states = [this](CloakContext& ctx, const nlohmann::json& params) {
            kv::Tx& tx = ctx.tx;
            h256 tx_hash = Utils::to_KeccakHash(params["tx_hash"].get<std::string>());
            CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, ctx.tx, tx_hash);
            if (!ct.function.complete()) {
                LOG_AND_THROW("function is not ready");
                return false;
            }

            auto data = to_bytes(params["data"].get<std::string>());
            auto old_states = abicoder::decode_uint256_array(data);
            auto old_states_hash = eevm::keccak_256(data);
            ct.old_states = old_states;
            ct.old_states_hash = old_states_hash;
            CLOAK_DEBUG_FMT("old_states:{}", fmt::join(ct.old_states, ", "));

            if (!ct.request_public_keys(tx)) {
                execute_mpt(ct.old_states, ct, ctx.tx);
            }
            ct.save(tx, txTables.cloak_policys);
            return true;
        };

        auto sync_report = [this](CloakContext& ctx, const nlohmann::json& params) {
            kv::Tx& tx = ctx.tx;
            h256 tx_hash = Utils::to_KeccakHash(params["id"].get<std::string>());
            auto result = params["result"].get<std::string>();
            CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, ctx.tx, tx_hash);
            if (result == "SYNCED") {
                ct.set_status(Status::SYNCED);
            } else {
                ct.set_status(Status::SYNC_FAILED);
            }
            ct.save(tx, txTables.cloak_policys);
            return true;
        };

        auto sync_public_keys = [this](CloakContext& ctx, const nlohmann::json& params) {
            kv::Tx& tx = ctx.tx;
            auto tx_hash = Utils::to_KeccakHash(params["tx_hash"].get<std::string>());
            CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, tx, tx_hash);
            std::map<std::string, std::string> public_keys;
            auto public_keys_str = params["data"].get<std::string>();
            CLOAK_DEBUG_FMT("public_keys_str:{}", public_keys_str);
            auto public_keys_vec = to_bytes(public_keys_str);
            auto public_key_list = abicoder::decode_string_array({public_keys_vec.begin() + 32, public_keys_vec.end()});
            CLOAK_DEBUG_FMT("public_keys_list:{}", fmt::join(public_key_list, ", "));
            for (size_t i = 0; i < ct.requested_addresses.size(); i++) {
                public_keys[ct.requested_addresses[i]] = public_key_list[i];
            }
            ct.public_keys = public_keys;
            std::vector<std::string> decrypted = ct.decrypt_states(tx);
            auto eth_state = make_state(tx);
            execute_mpt(decrypted, ct, tx);
            ct.save(tx, txTables.cloak_policys);
            return true;
        };

        auto get_mpt = [this](ReadOnlyCloakContext& ctx, const nlohmann::json& params) {
            auto mpc = params.get<MPT_CALL::In>();
            auto tx_hash = Utils::to_KeccakHash(mpc.id);
            auto [cp_handler, pd_handler] = ctx.tx.get_read_only_view(txTables.cloak_policys, txTables.privacy_digests);
            auto cpt_opt = cp_handler->get(tx_hash);
            if (!cpt_opt.has_value()) {
                throw std::logic_error(fmt::format("tx_hash:{} not found", tx_hash));
            }

            return MPT_CALL::Out{cpt_opt->get_status(), to_hex_string(cpt_opt->function.raw_outputs)};
        };

        // Because CCF OpenAPI json module do not support uint256, thus do not use
        // ccf::json_adapter(call) or add_auto_schema(...)

        make_endpoint(ethrpc::GetBalance::name, HTTP_GET, evm4ccf::cloak_json_adapter(get_balance, table)).install();

        make_endpoint(ethrpc::GetChainId::name, HTTP_GET, evm4ccf::cloak_json_adapter(get_chainId, table)).install();
        make_endpoint(ethrpc::GetGasPrice::name, HTTP_GET, evm4ccf::cloak_json_adapter(get_gasPrice, table)).install();
        make_endpoint(ethrpc::GetCode::name, HTTP_GET, evm4ccf::cloak_json_adapter(get_code, table)).install();
        make_endpoint(
            ethrpc::GetTransactionCount::name, HTTP_GET, evm4ccf::cloak_json_adapter(get_transaction_count, table))
            .install();

        make_read_only_endpoint(ethrpc::GetTransactionReceipt::name,
                                HTTP_GET,
                                evm4ccf::cloak_json_read_only_adapter(get_transaction_receipt, table))
            .install();

        make_endpoint(
            ethrpc::SendRawTransaction::name, HTTP_POST, evm4ccf::cloak_json_adapter(send_raw_transaction, table))
            .install();

        make_endpoint(ethrpc::SendRawPrivacyTransaction::name,
                      HTTP_POST,
                      evm4ccf::cloak_json_adapter(send_raw_privacy_policy_transaction, table))
            .install();

        make_endpoint(ethrpc::SendRawMultiPartyTransaction::name,
                      HTTP_POST,
                      evm4ccf::cloak_json_adapter(send_raw_multiPartyTransaction, table))
            .install();

        make_endpoint("eth_getTransactionCount_Test", HTTP_GET, ccf::json_adapter(get_transaction_count_test))
            .set_auto_schema<ethrpc::GetTransactionCountTest>()
            .install();

        make_endpoint("eth_sync_old_states", HTTP_POST, evm4ccf::cloak_json_adapter(sync_old_states, table)).install();

        make_endpoint("eth_sync_public_keys", HTTP_POST, evm4ccf::cloak_json_adapter(sync_public_keys, table))
            .install();

        make_endpoint("cloak_prepare", HTTP_POST, evm4ccf::cloak_json_adapter(prepare, table)).install();

        make_read_only_endpoint("cloak_get_mpt", HTTP_GET, evm4ccf::cloak_json_read_only_adapter(get_mpt, table))
            .set_auto_schema<MPT_CALL>()
            .install();

        make_endpoint("cloak_sync_report", HTTP_POST, evm4ccf::cloak_json_adapter(sync_report, table)).install();
    }

 public:
    // SNIPPET_START: initialization

    EVMHandlers(ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
        : UserEndpointRegistry(nwt),
          accounts{
              tables::Accounts::Balances("eth.account.balance"),
              tables::Accounts::Codes("eth.account.code"),
              tables::Accounts::Nonces("eth.account.nonce"),
          },
          storage("eth.storage"),
          tx_results("eth.txresults"),
          txTables(*nwt.tables),
          table{txTables, accounts, storage, tx_results} {
        // SNIPPET_END: initialization
        context.get_historical_state();
        install_standard_rpcs();
    }

 private:
    void execute_mpt(const std::vector<std::string>& decryped_states, CloakPolicyTransaction& ct, kv::Tx& tx) {
        auto tee_addr = TeeManager::tee_addr(tx);
        MessageCall set_states_mc;

        auto encoder = abicoder::Encoder();
        encoder.add_inputs("set_states", "uint[]", decryped_states);
        auto decryped_states_packed = encoder.encode();
        // function selector
        auto set_states_call_data = Utils::make_function_selector("set_states(uint256[])");
        CLOAK_DEBUG_FMT("decryped_states:{}", fmt::join(decryped_states, ", "));
        set_states_call_data.insert(
            set_states_call_data.end(), decryped_states_packed.begin(), decryped_states_packed.end());
        set_states_mc.from = tee_addr;
        set_states_mc.to = ct.to;
        CLOAK_DEBUG_FMT("call_data:{}", eevm::to_hex_string(set_states_call_data));
        set_states_mc.data = eevm::to_hex_string(set_states_call_data);
        auto es = make_state(tx);

        auto set_states_res = eevm::EVMC(set_states_mc, es, tx.get_view(tx_results)).run_with_result();
        if (set_states_res.er == ExitReason::threw) {
            CLOAK_DEBUG_FMT("set_states execution error: {}", set_states_res.exmsg);
            return;
        }

        // run in evm
        auto data = ct.function.packed_to_data();
        MessageCall mc;
        mc.from = ct.from;
        mc.to = ct.to;
        mc.data = to_hex_string(data);
        CLOAK_DEBUG_FMT("ct function data: {}", mc.data);
        const auto res = eevm::EVMC(mc, es, tx.get_view(tx_results)).run_with_result();
        CLOAK_DEBUG_FMT("run in evm, res: {}, msg: {}\n", res.output, res.exmsg);

        ct.function.raw_outputs = res.output;

        // == get new states ==
        MessageCall get_new_states_mc;
        auto get_new_states_call_data = ct.get_states_call_data(false);
        CLOAK_DEBUG_FMT("get_new_states_call_data:{}", to_hex_string(get_new_states_call_data));
        get_new_states_mc.from = tee_addr;
        get_new_states_mc.to = ct.to;
        get_new_states_mc.data = eevm::to_hex_string(get_new_states_call_data);

        // auto get_new_states_res= run_in_evm(get_new_states_mc, es).first;
        auto get_new_states_res = eevm::EVMC(get_new_states_mc, es, tx.get_view(tx_results)).run_with_result();
        CLOAK_DEBUG_FMT("get_new_states res:{}, {}, {}, {}",
                        get_new_states_res.er,
                        get_new_states_res.ex,
                        to_hex_string(get_new_states_res.output),
                        get_new_states_res.exmsg);

        // == Sync new states ==
        std::vector<std::string> new_states = abicoder::decode_uint256_array(get_new_states_res.output);
        auto encrypted = ct.encrypt_states(tx, new_states);
        CLOAK_DEBUG_FMT("encrypted:{}", fmt::join(encrypted, ", "));
        ct.sync_result(tx, encrypted);
    }
};  // class EVMHandlers

class EVM : public ccf::UserRpcFrontend {
 private:
    EVMHandlers evm_handlers;

 public:
    EVM(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context)
        : ccf::UserRpcFrontend(*network.tables, evm_handlers), evm_handlers(network, context) {}

    void open() override {
        ccf::UserRpcFrontend::open();
        evm_handlers.openapi_info.title = "CCF Homestead EVM App";
        evm_handlers.openapi_info.description = "This CCF Homestead EVM app implements a simple EVM";
    }
};  // class EVM

}  // namespace evm4ccf

namespace ccfapp {
// SNIPPET_START: rpc_handler
std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) {
    return evm4ccf::make_shared<evm4ccf::EVM>(nwt, context);
}
// SNIPPET_END: rpc_handler
}  // namespace ccfapp
