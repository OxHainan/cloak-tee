// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/app_interface.h"
#include "ccf/node_context.h"
#include "ethereum/tee_manager.h"
#include "node/network_state.h"
#include "node/rpc/frontend.h"
namespace ccf
{
class UserRpcFrontend : public RpcFrontend
{
 protected:
    std::unique_ptr<ccf::endpoints::EndpointRegistry> endpoints;

 public:
    UserRpcFrontend(
        NetworkState& network,
        std::unique_ptr<ccf::endpoints::EndpointRegistry>&& endpoints_,
        ccfapp::AbstractNodeContext& context_) :
      RpcFrontend(*network.tables, *endpoints_, context_),
      endpoints(std::move(endpoints_))
    {}

    bool is_open(kv::Tx& tx) override
    {
        if (!RpcFrontend::is_open()) {
            register_tee_manager(tx);
        }

        return RpcFrontend::is_open(tx);
    }

 private:
    ccf::Pal::Mutex manager_lock;
    void register_tee_manager(kv::Tx& tx)
    {
        std::lock_guard<ccf::Pal::Mutex> mguard(manager_lock);
        // TODO: When the node is started in recovery mode
        cloak4ccf::TeeManager::tables::Table tee_table;
        cloak4ccf::TeeManager::State::make_state(tx, tee_table).create();
    }
};
}
