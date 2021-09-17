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

    EthereumState make_state(kv::Tx& tx) { return EthereumState(accounts.get_views(tx), tx.get_view(storage)); }

    void install_standard_rpcs() {
        auto call = [this](ccf::EndpointContext& args) {
            kv::Tx& tx = args.tx;
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto cl = body_j.get<rpcparams::Call>();

            if (!cl.call_data.to.has_value()) {
                args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto error = nlohmann::json("Missing 'to' field");
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, error).dump());
                return;
            }

            auto es = make_state(tx);

            const auto e = run_in_evm(cl.call_data, es).first;

            if (e.er == ExitReason::returned || e.er == ExitReason::halted) {
                // Call should have no effect so we don't commit it.
                // Just return the result.
                args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto result = nlohmann::json(to_hex_string(e.output));
                args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
                return;
            } else {
                args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto error = nlohmann::json(e.exmsg);
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, error).dump());
                return;
            }
        };

        auto get_chainId = [](ccf::EndpointContext& args) {
            auto result = nlohmann::json(to_hex_string(evm4ccf::current_chain_id));
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
            return;
        };

        auto get_gasPrice = [](ccf::EndpointContext& args) {
            auto result = nlohmann::json(to_hex_string(0));
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
            return;
        };
        auto get_estimateGas = [this](ccf::EndpointContext& args) {
            kv::Tx& tx = args.tx;

            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto stp = body_j.get<rpcparams::EstimateGas>();
            auto es = make_state(tx);

            auto tx_result = estimateGas(stp.call_data, es);
            auto result = nlohmann::json(to_hex_string(0));

            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
            return;
        };

        auto get_balance = [this](ccf::EndpointContext& args) {
            kv::Tx& tx = args.tx;
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto gb = body_j.get<rpcparams::AddressWithBlock>();
            if (gb.block_id != "latest") {
                args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto error = nlohmann::json("Can only request latest block");
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, error).dump());
                return;
            }

            auto es = make_state(tx);

            const auto account_state = es.get(gb.address);

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            auto result = nlohmann::json(to_hex_string(account_state.acc.get_balance()));
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
        };

        auto get_code = [this](ccf::EndpointContext& args) {
            kv::Tx& tx = args.tx;
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto gc = body_j.get<rpcparams::AddressWithBlock>();
            if (gc.block_id != "latest") {
                args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto error = nlohmann::json("Can only request latest block");
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, error).dump());
                return;
            }

            auto es = make_state(tx);

            const auto account_state = es.get(gc.address);

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            auto result = nlohmann::json(to_hex_string(account_state.acc.get_code()));
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
        };

        auto get_transaction_count = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto gtc = body_j.get<rpcparams::GetTransactionCount>();
            if (gtc.block_id != "latest") {
                args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                auto error = nlohmann::json("Can only request latest block");
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, error).dump());
                return;
            }

            auto es = make_state(args.tx);
            auto account_state = es.get(gtc.address);

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            auto result = nlohmann::json(to_hex_string(account_state.acc.get_nonce()));
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, result).dump());
            return;
        };

        auto send_raw_transaction = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto srtp = body_j.get<rpcparams::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srtp.raw_transaction);

            EthereumTransactionWithSignature eth_tx(in);

            rpcparams::MessageCall tc;
            eth_tx.to_transaction_call(tc);
            // tls::PublicKey_k1Bitcoin::recover_key

            auto tx_result = execute_transaction(args.caller_id, tc, args.tx);

            if (!tx_result.first) {
                args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, tx_result.second).dump());
                return;
            }

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, tx_result.second).dump());
            return;
        };

        auto send_transaction = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto stp = body_j.get<rpcparams::SendTransaction>();

            auto tx_result = execute_transaction(args.caller_id, stp.call_data, args.tx);

            if (!tx_result.first) {
                args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
                args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
                args.rpc_ctx->set_response_body(jsonrpc::error_response(0, tx_result.second).dump());
                return;
            }

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, tx_result.second).dump());
            return;
        };

        auto send_raw_privacy_policy_transaction = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto srpp = body_j.get<rpcparams::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srpp.raw_transaction);

            TransactionGenerator gen(txTables, args.tx);
            auto policy_digest = gen.add_privacy(in);

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, eevm::to_hex_string(policy_digest)).dump());
            return;
        };

        auto send_raw_multiPartyTransaction = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto srmp = body_j.get<rpcparams::SendRawTransaction>();
            eevm::rlp::ByteString in = eevm::to_bytes(srmp.raw_transaction);
            TransactionGenerator gen(txTables, args.tx);
            auto ct_digest = gen.add_cloakTransaction(in);

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, eevm::to_hex_string(ct_digest)).dump());
            return;
        };

        auto get_workOrderSubmit = [](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto sppp = body_j.get<rpcparams::WorkOrderSubmit>();

            rpcresults::ReceiptWorkOrderResponse response = nullopt;
            response->responseTimeoutMSecs = sppp.workOrder.responseTimeoutMSecs;
            response->workOrderId = sppp.workOrder.workOrderId;
            // response->status = 1;
            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, response).dump());
            return;
        };

        auto get_transaction_receipt = [this](ccf::EndpointContext& args) {
            kv::Tx& tx = args.tx;
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto gtrp = body_j.get<rpcparams::GetTransactionReceipt>();

            const TxHash& tx_hash = gtrp.tx_hash;

            auto results_view = tx.get_view(tx_results);
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

            // Return success HTTP response with the result json
            args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
            args.rpc_ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
            args.rpc_ctx->set_response_body(jsonrpc::result_response(0, response).dump());
            return;
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

        auto prepare = [](kv::Tx& tx, const nlohmann::json& params) {
            Address cloak_service_addr = to_uint256(params["cloak_service_addr"].get<std::string>());
            Address pki_addr = to_uint256(params["pki_addr"].get<std::string>());
            TeeManager::prepare(tx, cloak_service_addr, pki_addr);
            return true;
        };

        auto sync_old_states = [this](kv::Tx& tx, const nlohmann::json& params) {
            auto old_states = abicoder::decode_uint256_array(to_bytes(params["data"].get<std::string>()));
            h256 tx_hash = Utils::to_KeccakHash(params["tx_hash"].get<std::string>());
            auto encoder = abicoder::Encoder();
            encoder.add_inputs("oldStates", "uint[]", old_states);
            auto old_states_packed = encoder.encode();
            auto old_states_hash = eevm::keccak_256(old_states_packed);

            CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, tx, tx_hash);
            if (!ct.function.complete()) {
                CLOAK_DEBUG_FMT("function is not ready, info:{}", ct.function.info());
                LOG_AND_THROW("function is not ready");
                return false;
            }
            ct.old_states = old_states;
            ct.old_states_hash = old_states_hash;
            CLOAK_DEBUG_FMT("old_states:{}", fmt::join(ct.old_states, ", "));
            if (ct.request_public_keys(tx)) {
                ct.save(tx, txTables.cloak_policys);
                return true;
            }
            execute_mpt(ct.old_states, ct, tx);
            ct.save(tx, txTables.cloak_policys);
            return true;
        };

        auto sync_report = [this](kv::Tx& tx, const nlohmann::json& params) {
            h256 tx_hash = Utils::to_KeccakHash(params["id"].get<std::string>());
            auto result = params["result"].get<std::string>();
            CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, tx, tx_hash);
            if (result == "SYNCED") {
                ct.set_status(Status::SYNCED);
            } else {
                ct.set_status(Status::SYNC_FAILED);
            }
            ct.save(tx, txTables.cloak_policys);
            return true;
        };

        auto sync_public_keys = [this](kv::Tx& tx, const nlohmann::json& params) {
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

        auto get_mpt = [this](ccf::EndpointContext& args) {
            const auto body_j = nlohmann::json::parse(args.rpc_ctx->get_request_body());
            auto tx_hash = Utils::to_KeccakHash(body_j["id"].get<std::string>());
            try {
                CloakPolicyTransaction ct(txTables.cloak_policys, txTables.privacy_digests, args.tx, tx_hash);
                nlohmann::json j;
                j["status"] = ct.get_status_str();
                j["output"] = eevm::to_hex_string(ct.function.raw_outputs);
                args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
                args.rpc_ctx->set_response_body(jsonrpc::result_response(0, j).dump());
            } catch (std::logic_error err) {
                args.rpc_ctx->set_response_status(HTTP_STATUS_NOT_FOUND);
            }
        };

        // Because CCF OpenAPI json module do not support uint256, thus do not use
        // ccf::json_adapter(call) or add_auto_schema(...)
        make_endpoint(ethrpc::Call::name, HTTP_GET, call).install();

        make_endpoint(ethrpc::GetBalance::name, HTTP_GET, get_balance).install();

        make_endpoint(ethrpc::GetChainId::name, HTTP_GET, get_chainId).install();
        make_endpoint(ethrpc::GetGasPrice::name, HTTP_GET, get_gasPrice).install();
        make_endpoint(ethrpc::GetCode::name, HTTP_GET, get_code).install();
        make_endpoint(ethrpc::GetEstimateGas::name, HTTP_GET, get_estimateGas).install();
        make_endpoint(ethrpc::GetTransactionCount::name, HTTP_GET, get_transaction_count).install();

        make_endpoint(ethrpc::GetTransactionReceipt::name, HTTP_GET, get_transaction_receipt).install();

        make_endpoint(ethrpc::WorkOrderSubmit::name, HTTP_GET, get_workOrderSubmit).install();

        make_endpoint(ethrpc::SendRawTransaction::name, HTTP_POST, send_raw_transaction).install();

        make_endpoint(ethrpc::SendRawPrivacyTransaction::name, HTTP_POST, send_raw_privacy_policy_transaction)
            .install();

        make_endpoint(ethrpc::SendRawMultiPartyTransaction::name, HTTP_POST, send_raw_multiPartyTransaction).install();

        make_endpoint(ethrpc::SendTransaction::name, HTTP_POST, send_transaction).install();

        make_endpoint("eth_getTransactionCount_Test", HTTP_GET, ccf::json_adapter(get_transaction_count_test))
            .set_auto_schema<ethrpc::GetTransactionCountTest>()
            .install();

        make_endpoint("eth_sync_old_states", HTTP_POST, ccf::json_adapter(sync_old_states)).install();

        make_endpoint("eth_sync_public_keys", HTTP_POST, ccf::json_adapter(sync_public_keys)).install();

        make_endpoint("cloak_prepare", HTTP_POST, ccf::json_adapter(prepare)).install();

        make_endpoint("cloak_get_mpt", HTTP_GET, get_mpt).install();

        make_endpoint("cloak_sync_report", HTTP_POST, ccf::json_adapter(sync_report)).install();
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
          txTables(*nwt.tables) {
        // SNIPPET_END: initialization
        context.get_historical_state();
        install_standard_rpcs();
    }

 private:
    static std::pair<ExecResult, AccountState> run_in_evm(const rpcparams::MessageCall& call_data,
                                                          EthereumState& es,
                                                          LogHandler& log_handler) {
        Address from = call_data.from;
        Address to;

        if (call_data.to.has_value()) {
            to = call_data.to.value();
        } else {
            // If there's no to field, create a new account to deploy this to
            const auto from_state = es.get(from);
            to = eevm::generate_address(from_state.acc.get_address(), from_state.acc.get_nonce());
            es.create(to, call_data.gas, to_bytes(call_data.data));
        }

        Transaction eth_tx(from, log_handler);

        auto account_state = es.get(to);

#ifdef RECORD_TRACE
        eevm::Trace tr;
#endif

        Processor proc(es);
        const auto result = proc.run(eth_tx,
                                     from,
                                     account_state,
                                     to_bytes(call_data.data),
                                     call_data.value
#ifdef RECORD_TRACE
                                     ,
                                     &tr
#endif
        );  // NOLINT

#ifdef RECORD_TRACE
        if (result.er == ExitReason::threw) {
            LOG_INFO_FMT("--- Trace of failing evm execution ---\n{}", tr);
        }
#endif

        return std::make_pair(result, account_state);
    }

    static pair<ExecResult, AccountState> run_in_evm(const rpcparams::MessageCall& call_data, EthereumState& es) {
        NullLogHandler ignore;
        return run_in_evm(call_data, es, ignore);
    }

    // TODO(DUMMY): This and similar should take EthereumTransaction, not
    // MessageCall. EthereumTransaction should be fully parsed, then
    // MessageCall can be removed
    pair<bool, nlohmann::json> execute_transaction(CallerId caller_id,
                                                   const rpcparams::MessageCall& call_data,
                                                   kv::Tx& tx) {
        LOG_INFO_FMT("Caller_id is {}", caller_id);
        auto es = make_state(tx);

        VectorLogHandler vlh;
        const auto [exec_result, tx_hash, to_address] = execute_transaction(call_data, es, vlh);

        if (exec_result.er == ExitReason::threw) {
            return std::make_pair(false, exec_result.exmsg);
        }

        auto results_view = tx.get_view(tx_results);
        TxResult tx_result;
        if (!call_data.to.has_value()) {
            tx_result.contract_address = to_address;
        }

        tx_result.logs = vlh.logs;

        results_view->put(tx_hash, tx_result);

        return std::make_pair(true, eevm::to_hex_string_fixed(tx_hash));
    }

    static ExecResult estimateGas(const rpcparams::MessageCall& call_data, EthereumState& es) {
        const auto [exec_result, _] = run_in_evm(call_data, es);
        // if (exec_result.er == ExitReason::threw)
        // {
        return exec_result;
        // }
    }

    static std::tuple<ExecResult, TxHash, Address> execute_transaction(const rpcparams::MessageCall& call_data,
                                                                       EthereumState& es,
                                                                       LogHandler& log_handler) {
        auto [exec_result, account_state] = run_in_evm(call_data, es, log_handler);

        if (exec_result.er == ExitReason::threw) {
            return std::make_tuple(exec_result, 0, 0);
        }

        if (!call_data.to.has_value()) {
            // New contract created, result is the code that should be deployed
            account_state.acc.set_code(std::move(exec_result.output));
        }

        auto from_state = es.get(call_data.from);
        auto tx_nonce = from_state.acc.get_nonce();
        from_state.acc.increment_nonce();

        EthereumTransaction eth_tx(tx_nonce, call_data);
        const auto rlp_encoded = eth_tx.encode();

        uint8_t h[32];
        const auto raw = reinterpret_cast<unsigned char const*>(rlp_encoded.data());
        eevm::keccak_256(raw, rlp_encoded.size(), h);

        const auto tx_hash = eevm::from_big_endian(h);

        return std::make_tuple(exec_result, tx_hash, account_state.acc.get_address());
    }

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
        auto set_states_es = make_state(tx);
        auto set_states_res = run_in_evm(set_states_mc, set_states_es).first;
        if (set_states_res.er == ExitReason::threw) {
            CLOAK_DEBUG_FMT("set_states execution error: {}", set_states_res.exmsg);
            return;
        }

        // run in evm
        CLOAK_DEBUG_FMT("ct function: {}\n", ct.function.info());
        auto data = ct.function.packed_to_data();
        MessageCall mc;
        mc.from = ct.from;
        mc.to = ct.to;
        mc.data = to_hex_string(data);
        CLOAK_DEBUG_FMT("ct function data: {}", mc.data);
        auto es = make_state(tx);

        const auto res = run_in_evm(mc, es).first;
        CLOAK_DEBUG_FMT("run in evm, res: {}, msg: {}\n", res.output, res.exmsg);
        if (res.er == ExitReason::threw) {
            LOG_AND_THROW("run mpt in evm faild");
        }
        ct.function.raw_outputs = res.output;

        // == get new states ==
        MessageCall get_new_states_mc;
        auto get_new_states_call_data = ct.get_states_call_data(false);
        CLOAK_DEBUG_FMT("get_new_states_call_data:{}", to_hex_string(get_new_states_call_data));
        get_new_states_mc.from = tee_addr;
        get_new_states_mc.to = ct.to;
        get_new_states_mc.data = eevm::to_hex_string(get_new_states_call_data);
        auto get_new_states_es = make_state(tx);
        auto get_new_states_res = run_in_evm(get_new_states_mc, get_new_states_es).first;
        CLOAK_DEBUG_FMT("get_new_states res:{}, {}, {}, {}",
                        get_new_states_res.er,
                        get_new_states_res.ex,
                        to_hex_string(get_new_states_res.output),
                        get_new_states_res.exmsg);
        if (get_new_states_res.er == ExitReason::threw) {
            LOG_AND_THROW("get new states in evm faild");
        }

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
