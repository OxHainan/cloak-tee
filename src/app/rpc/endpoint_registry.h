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
#include "blit.h"
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/json_handler.h"
#include "ethereum/execute_transaction.h"
#include "ethereum/json_rpc.h"
#include "ethereum/tee_manager.h"
#include "ethereum/transaction_sync.h"
#include "ethereum/types.h"
#include "ethereum_transaction.h"
#include "jsonrpc.h"
#include "node/network_state.h"
#include "web3client/web3_operation_interface.h"

namespace cloak4ccf
{
class AbstractEndpointRegistry : public ccf::UserEndpointRegistry
{
 public:
    ccf::NetworkState& network;
    std::shared_ptr<AbstractWeb3Operation> web3;
    const ccf::AuthnPolicies auth_policies =
        {ccf::jwt_auth_policy, ccf::user_cert_auth_policy};
    explicit AbstractEndpointRegistry(
        ccfapp::AbstractNodeContext& context, ccf::NetworkState& network) :
      ccf::UserEndpointRegistry(context),
      network(network),
      web3(context.get_subsystem<AbstractWeb3Operation>())
    {
        if (web3 == nullptr) {
            throw std::logic_error(fmt::format(
                "Cannot create this strategy without access to the web3"));
        }

        openapi_info.title = "Cloak Homestead App";
        openapi_info.description =
            "This Cloak Homestead App implements a simple EVM";
        openapi_info.document_version = "0.1.0";
    }
};

class EVMHandlers : public AbstractEndpointRegistry
{
 private:
    void install_standard_rpcs()
    {
        auto get_chainId = [](ccf::endpoints::EndpointContext&,
                              const nlohmann::json&) {
            return jsonrpc::result_response(0, evm4ccf::current_chain_id);
        };

        auto get_gasPrice = [](ccf::endpoints::EndpointContext&,
                               const nlohmann::json&) { return 0; };

        auto get_balance = [this](
                               ccf::endpoints::EndpointContext& ctx,
                               const nlohmann::json& params) {
            auto gb = params.get<Ethereum::AddressWithBlock>();
            if (gb.block_id != "latest") {
                return ccf::make_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    "Can only request latest block");
            }

            auto es = make_state(ctx.tx);
            const auto account_state = es.get(gb.address);
            const auto balance = account_state.acc.get_balance();
            return ccf::make_success(
                jsonrpc::result_response(0, eevm::to_hex_string(balance)));
        };

        auto send_contract_escrow = [this](
                                        ccf::endpoints::EndpointContext& ctx,
                                        const nlohmann::json& params) {
            auto ce = params.get<Ethereum::EscrowRequest>();
            auto es = make_state(ctx.tx);
            if (auto state = es.get(ce.address); state.acc.has_code()) {
                throw ccf::make_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    jsonrpc::error_response(
                        0,
                        "Address [" + eevm::to_hex_string(ce.address) +
                            "] has alread be a contract"));
            }

            web3->contract_escrow(ce.address);
            return ccf::make_success(jsonrpc::result_response(
                0, "contract escrow alread commited, please wait..."));
        };

        auto set_contract_key = [this](
                                    ccf::endpoints::EndpointContext& ctx,
                                    const nlohmann::json& params) {
            auto ce = params.get<Ethereum::EscrowRequest>();
            auto es = make_state(ctx.tx);
            if (auto state = es.get(ce.address); !state.acc.has_code()) {
                nlohmann::json message = "Address [" +
                    eevm::to_hex_string(ce.address) + "] not a contract";
                throw ccf::make_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    jsonrpc::error_response(0, message));
            }

            if (auto ch = ctx.tx.rw(network.acc_state.encrypted); ch) {
                if (ch->get(ce.address).has_value()) {
                    nlohmann::json message = "Address [" +
                        eevm::to_hex_string(ce.address) +
                        "] has already setting contract key";

                    throw ccf::make_error(
                        HTTP_STATUS_BAD_REQUEST,
                        ccf::errors::InvalidQueryParameterValue,
                        jsonrpc::error_response(0, message));
                }

                ch->put(ce.address, crypto::create_entropy()->random(32u));
            }

            if (auto cl = ctx.tx.rw(network.acc_state.levels); cl) {
                if (auto level = cl->get(ce.address); level.has_value() &&
                    *level != Ethereum::ContractLevel::SOLIDITY) {
                    nlohmann::json message = "Address [" +
                        eevm::to_hex_string(ce.address) +
                        "] cannt match with level";

                    throw ccf::make_error(
                        HTTP_STATUS_BAD_REQUEST,
                        ccf::errors::InvalidQueryParameterValue,
                        jsonrpc::error_response(0, message));
                }

                cl->put(ce.address, Ethereum::ContractLevel::SOLIDITY_ENHANCE);
            }

            return ccf::make_success(jsonrpc::result_response(0, true));
        };

        auto get_transaction_count = [this](
                                         ccf::endpoints::EndpointContext& ctx,
                                         const nlohmann::json& params) {
            auto gtc = params.get<Ethereum::GetTransactionCount>();
            if (gtc.block_id != "latest") {
                return ccf::make_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    "Can only request latest block");
            }

            auto es = make_state(ctx.tx);
            const auto account_state = es.get(gtc.address);
            const auto nonce = account_state.acc.get_nonce();
            return ccf::make_success(
                jsonrpc::result_response(0, eevm::to_hex_string(nonce)));
        };

        auto call = [this](
                        ccf::endpoints::EndpointContext& ctx,
                        const nlohmann::json& params) {
            auto cl = params.get<Ethereum::Call>();
            if (!cl.call_data.to.has_value()) {
                return ccf::make_error(
                    HTTP_STATUS_BAD_REQUEST,
                    ccf::errors::InvalidQueryParameterValue,
                    "Missing 'to' field");
            }

            auto es = make_state(ctx.tx);
            auto exec_result =
                Ethereum::EVMC(cl.call_data, es).run_with_result();

            return ccf::make_success(jsonrpc::result_response(
                0, eevm::to_hex_string(exec_result.output)));
        };

        auto send_raw_transaction = [this](
                                        ccf::endpoints::EndpointContext& ctx,
                                        const nlohmann::json& params) {
            auto srtp = params.get<Ethereum::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srtp.raw_transaction);
            evm4ccf::EthereumTransactionWithSignature eth_tx(in);

            Ethereum::MessageCall tc;
            eth_tx.to_transaction_call(tc);
            auto hash = eth_tx.to_be_signed(true);
            auto es = make_state(ctx.tx);
            auto tx_result = Ethereum::EVMC(tc, es).run();
            if (auto it = ctx.tx.wo(network.tx_results); it) {
                it->put(eevm::to_uint256(hash.hex_str()), tx_result);
            }
            return jsonrpc::result_response(0, hash.hex_str());
        };

        auto get_transaction_receipt =
            [this](
                ccf::endpoints::ReadOnlyEndpointContext& ctx,
                const nlohmann::json& params) {
                auto gtrp = params.get<Ethereum::GetTransactionReceipt>();

                const Ethereum::TxHash& tx_hash = gtrp.tx_hash;

                auto results_view = ctx.tx.ro(network.tx_results);
                const auto r = results_view->get(tx_hash);

                // "or null when no receipt was found"
                Ethereum::ReceiptResponse response = std::nullopt;
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
                return jsonrpc::result_response(0, response);
            };

        auto set_ethereum_configuration =
            [this](
                ccf::endpoints::EndpointContext& ctx,
                const nlohmann::json& params) {
                LOG_INFO_FMT("sss {}", params.dump());
                web3->set_ethereum_configuration(params);
                return jsonrpc::result_response(0, true);
            };

        make_endpoint(
            Ethereum::ethrpc::GetChainId::name,
            HTTP_POST,
            ccf::json_adapter(get_chainId),
            auth_policies)
            .install();
        make_endpoint(
            Ethereum::ethrpc::GetGasPrice::name,
            HTTP_POST,
            ccf::json_adapter(get_gasPrice),
            auth_policies)
            .install();

        make_endpoint(
            Ethereum::ethrpc::GetBalance::name,
            HTTP_POST,
            ccf::json_adapter(get_balance),
            auth_policies)
            .install();

        make_endpoint(
            Ethereum::ethrpc::GetTransactionCount::name,
            HTTP_POST,
            ccf::json_adapter(get_transaction_count),
            auth_policies)
            .install();

        make_endpoint(
            Ethereum::ethrpc::SendRawTransaction::name,
            HTTP_POST,
            ccf::json_adapter(send_raw_transaction),
            auth_policies)
            .install();

        make_read_only_endpoint(
            Ethereum::ethrpc::GetTransactionReceipt::name,
            HTTP_POST,
            ccf::json_read_only_adapter(get_transaction_receipt),
            auth_policies)
            .install();

        make_endpoint(
            "eth_call", HTTP_POST, ccf::json_adapter(call), auth_policies)
            .install();

        make_endpoint(
            "send_contractEscrow",
            HTTP_POST,
            ccf::json_adapter(send_contract_escrow),
            auth_policies)
            .install();

        make_endpoint(
            "set_contractKey",
            HTTP_POST,
            ccf::json_adapter(set_contract_key),
            auth_policies)
            .install();

        make_endpoint(
            "set_ethereumConfiguration",
            HTTP_POST,
            ccf::json_adapter(set_ethereum_configuration),
            auth_policies)
            .install();
    }

 protected:
    Ethereum::EthereumState make_state(kv::Tx& tx)
    {
        return Ethereum::EthereumState::make_state(tx, network.acc_state);
    }

 public:
    explicit EVMHandlers(
        ccfapp::AbstractNodeContext& context, ccf::NetworkState& network) :
      AbstractEndpointRegistry(context, network)
    {
        install_standard_rpcs();
    }
};

} // namespace cloak4ccf
