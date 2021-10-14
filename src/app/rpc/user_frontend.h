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
// ccf
#include "node/rpc/user_frontend.h"

// cloak
#include "app/rpc/context.h"
#include "app/rpc/endpoint_registry.h"
#include "app/rpc/json_handler.h"
#include "ethereum/state.h"
#include "transaction/generator.h"

namespace cloak4ccf {

class CloakEndpointRegistry : public EVMHandlers {
 public:
    CloakEndpointRegistry(ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
        EVMHandlers(nwt) {
        context.get_historical_state();
        // register rpc
        install_standard_rpcs();
    }

 private:
    void install_standard_rpcs() {
        auto send_raw_privacy_transaction = [this](CloakContext& ctx,
                                                   const nlohmann::json& params) {
            auto srt = params.get<Ethereum::SendRawTransaction>();

            eevm::rlp::ByteString in = eevm::to_bytes(srt.raw_transaction);
            Transaction::Generator gen(ctx);
            auto digest = gen.add_privacy(in);
            return eevm::to_hex_string(digest);
        };

        auto send_raw_multiParty_transaction = [this](CloakContext& ctx,
                                                      const nlohmann::json& params) {
            auto srmp = params.get<Ethereum::SendRawTransaction>();
            eevm::rlp::ByteString in = eevm::to_bytes(srmp.raw_transaction);
            Transaction::Generator gen(ctx);
            auto ct_digest = gen.add_cloakTransaction(in);
            return eevm::to_hex_string(ct_digest);
        };

        auto call_prepare = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto prepare = params.get<TeePrepare>();
            cloak4ccf::TeeManager::prepare(ctx.tx, cloakTables.tee_table, prepare);
            return true;
        };

        auto sync_old_states = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto sync_states = params.get<SyncStates>();
            Transaction::Generator gen(ctx);
            gen.sync_states(sync_states);
            return true;
        };

        auto sync_report = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto report = params.get<SyncReport>();
            Transaction::Generator gen(ctx);
            gen.sync_report(report);
            return true;
        };

        auto sync_public_keys = [this](CloakContext& ctx, const nlohmann::json& params) {
            auto syncKeys = params.get<SyncKeys>();
            Transaction::Generator gen(ctx);
            gen.sync_public_keys(syncKeys);
            return true;
        };

        auto get_mpt = [this](ReadOnlyCloakContext& ctx, const nlohmann::json& params) {
            auto mpc = params.get<evm4ccf::MPT_CALL::In>();
            auto tx_hash = Utils::to_KeccakHash(mpc.id);
            auto cp_handler = ctx.tx.get_read_only_view(cloakTables.txTables.cloak_policys);
            auto cpt_opt = cp_handler->get(tx_hash);
            if (!cpt_opt.has_value()) {
                throw std::logic_error(fmt::format("tx_hash:{} not found", tx_hash));
            }

            return evm4ccf::MPT_CALL::Out{cpt_opt->get_status(),
                                          eevm::to_hex_string(cpt_opt->function.raw_outputs)};
        };

        make_endpoint("cloak_sendRawPrivacyTransaction",
                      HTTP_POST,
                      json_adapter(send_raw_privacy_transaction, cloakTables))
            .install();

        make_endpoint("cloak_sendRawMultiPartyTransaction",
                      HTTP_POST,
                      json_adapter(send_raw_multiParty_transaction, cloakTables))
            .install();

        make_endpoint("eth_sync_old_states", HTTP_POST, json_adapter(sync_old_states, cloakTables))
            .install();

        make_endpoint(
            "eth_sync_public_keys", HTTP_POST, json_adapter(sync_public_keys, cloakTables))
            .install();

        make_endpoint("cloak_prepare", HTTP_POST, json_adapter(call_prepare, cloakTables))
            .install();

        make_read_only_endpoint(
            "cloak_get_mpt", HTTP_GET, json_read_only_adapter(get_mpt, cloakTables))
            .set_auto_schema<evm4ccf::MPT_CALL>()
            .install();

        make_endpoint("cloak_sync_report", HTTP_POST, json_adapter(sync_report, cloakTables))
            .install();
    }
};

} // namespace cloak4ccf
