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
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ccf/json_handler.h"
#include "ccf/tx.h"
#include "ethereum/block_validator.h"
#include "ethereum/execute_transaction.h"
#include "ethereum/json_rpc.h"
#include "ethereum/tables.h"
#include "ethereum/types.h"
#include "ethereum_transaction.h"
namespace cloak4ccf
{
class AbstractEndpointRegistry : public ccf::UserEndpointRegistry
{
 public:
    Ethereum::tables::AccountsState acc_state;
    Ethereum::tables::Results tx_results;
    cloak4ccf::TeeManager::tables::Table tee_table;
    const ccf::AuthnPolicies auth_policies =
        {ccf::jwt_auth_policy, ccf::user_cert_auth_policy};
    explicit AbstractEndpointRegistry(ccfapp::AbstractNodeContext& context) :
      ccf::UserEndpointRegistry(context),
      acc_state(),
      tx_results("eth.txresults"),
      tee_table()
    {
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
            return evm4ccf::current_chain_id;
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
            return ccf::make_success(eevm::to_hex_string(balance));
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
            return ccf::make_success(eevm::to_hex_string(nonce));
        };

        auto send_raw_transaction = [this](
                                        ccf::endpoints::EndpointContext& ctx,
                                        const nlohmann::json& params) {
            auto srtp = params.get<Ethereum::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srtp.raw_transaction);
            evm4ccf::EthereumTransactionWithSignature eth_tx(in);

            Ethereum::MessageCall tc;
            eth_tx.to_transaction_call(tc);
            auto es = make_state(ctx.tx);
            auto tx_result =
                Ethereum::EVMC(tc, es, ctx.tx.rw(tx_results)).run();
            return eevm::to_hex_string(tx_result);
        };

        auto get_transaction_receipt =
            [this](
                ccf::endpoints::ReadOnlyEndpointContext& ctx,
                const nlohmann::json& params) {
                auto gtrp = params.get<Ethereum::GetTransactionReceipt>();

                const Ethereum::TxHash& tx_hash = gtrp.tx_hash;

                auto results_view = ctx.tx.ro(tx_results);
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
                return response;
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
    }

 protected:
    Ethereum::EthereumState make_state(kv::Tx& tx)
    {
        return Ethereum::EthereumState::make_state(tx, acc_state);
    }

 public:
    explicit EVMHandlers(ccfapp::AbstractNodeContext& context) :
      AbstractEndpointRegistry(context)
    {
        install_standard_rpcs();
    }
};
} // namespace cloak4ccf
