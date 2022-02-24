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
#pragma once
#include "app/rpc/context.h"
#include "app/rpc/endpoint_registry.h"
#include "app/rpc/json_handler.h"
#include "ccf/app_interface.h"
#include "ccf/common_auth_policies.h"
#include "ethereum/state.h"
#include "ethereum/tee_manager.h"
#include "transaction/generator.h"

namespace cloak4ccf
{
    class CloakEndpointRegistry : public EVMHandlers
    {
      public:
        CloakEndpointRegistry(ccfapp::AbstractNodeContext& context) :
          EVMHandlers(context)
        {
            install_standard_rpcs();
        }

      private:
        void install_standard_rpcs()
        {
            auto send_raw_privacy_transaction =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  auto srt = params.get<Ethereum::SendRawTransaction>();

                  eevm::rlp::ByteString in =
                    eevm::to_bytes(srt.raw_transaction);
                  Transaction::Generator gen(ctx);
                  auto digest = gen.add_privacy(in);
                  return eevm::to_hex_string(digest);
              };

            auto send_raw_multiParty_transaction =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  auto srmp = params.get<Ethereum::SendRawTransaction>();
                  eevm::rlp::ByteString in =
                    eevm::to_bytes(srmp.raw_transaction);
                  Transaction::Generator gen(ctx);
                  auto ct_digest = gen.add_cloakTransaction(in);
                  return eevm::to_hex_string(ct_digest);
              };

            auto call_prepare =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  cloak4ccf::TeeManager::prepare(
                    ctx.tx, tables.tee_table, params);
                  return true;
              };

            auto sync_old_states =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  auto sync_states = params.get<SyncStates>();
                  Transaction::Generator gen(ctx);
                  gen.sync_states(sync_states);
                  return true;
              };

            auto sync_report =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  auto report = params.get<SyncReport>();
                  Transaction::Generator gen(ctx);
                  gen.sync_report(report);
                  return true;
              };

            auto sync_propose =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  Transaction::Generator gen(ctx);
                  gen.sync_propose(params);
                  return true;
              };

            auto sync_public_keys =
              [this](CloakContext& ctx, const nlohmann::json& params) {
                  // auto syncKeys = params.get<SyncKeys>();
                  Transaction::Generator gen(ctx);
                  gen.sync_public_keys(params);
                  return true;
              };

            auto get_mpt =
              [this](ReadOnlyCloakContext& ctx, const nlohmann::json& params) {
                  auto mpc = params.get<evm4ccf::MPT_CALL::In>();
                  auto tx_hash = Utils::to_KeccakHash(mpc.id);
                  auto cp_handler = ctx.tx.ro(tables.txTables.cloak_policys);
                  auto cpt_opt = cp_handler->get(tx_hash);
                  if (!cpt_opt.has_value())
                  {
                      throw std::logic_error(fmt::format(
                        "tx_hash:{} not found", eevm::to_hex_string(tx_hash)));
                  }

                  return evm4ccf::MPT_CALL::Out{
                    cpt_opt->get_status(),
                    eevm::to_hex_string(cpt_opt->function.raw_outputs)};
              };

            auto get_cloak = [this](CloakContext& ctx, const nlohmann::json&) {
                auto tee_acc =
                  TeeManager::State::make_account(ctx.tx, tables.tee_table);
                auto service_addr = TeeManager::get_service_addr(
                  ctx.tx.rw(tables.tee_table.service));
                return Ethereum::CloakInfo(
                  tee_acc->get_address(),
                  service_addr,
                  tee_acc->get_public_Key());
            };

            make_endpoint(
              "cloak_sendRawPrivacyTransaction",
              HTTP_POST,
              json_adapter(send_raw_privacy_transaction, tables),
              auth_policies)
              .install();

            make_endpoint(
              "cloak_sendRawMultiPartyTransaction",
              HTTP_POST,
              json_adapter(send_raw_multiParty_transaction, tables),
              auth_policies)
              .install();

            make_endpoint(
              "eth_sync_old_states",
              HTTP_POST,
              json_adapter(sync_old_states, tables),
              auth_policies)
              .install();

            make_endpoint(
              "eth_sync_public_keys",
              HTTP_POST,
              json_adapter(sync_public_keys, tables),
              auth_policies)
              .install();

            make_endpoint(
              "cloak_prepare",
              HTTP_POST,
              json_adapter(call_prepare, tables),
              auth_policies)
              .install();

            make_read_only_endpoint(
              "cloak_get_mpt",
              HTTP_POST,
              json_read_only_adapter(get_mpt, tables),
              auth_policies)
              .set_auto_schema<evm4ccf::MPT_CALL>()
              .install();

            make_endpoint(
              "cloak_sync_report",
              HTTP_POST,
              json_adapter(sync_report, tables),
              auth_policies)
              .install();

            make_endpoint(
              "cloak_sync_propose",
              HTTP_POST,
              json_adapter(sync_propose, tables),
              auth_policies)
              .install();

            make_endpoint(
              "cloak_get_cloak",
              HTTP_POST,
              json_adapter(get_cloak, tables),
              auth_policies)
              .install();
        }
    };
} // namespace cloak4ccf
