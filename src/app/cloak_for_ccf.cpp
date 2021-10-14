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

#include "app/formatters.h"
#include "app/rpc/user_frontend.h"
#include "node/rpc/user_frontend.h"

namespace cloak4ccf {
class CloakRpcFrontend : public ccf::UserRpcFrontend {
 private:
    CloakEndpointRegistry cloak_endpoint;

 public:
    CloakRpcFrontend(ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
        ccf::UserRpcFrontend(*nwt.tables, cloak_endpoint), cloak_endpoint(nwt, context) {}

    void open() override {
        ccf::UserRpcFrontend::open();
        cloak_endpoint.openapi_info.title = "Cloak Homestead App";
        cloak_endpoint.openapi_info.description =
            "This Cloak Homestead App implements a simple EVM";
    }
};
} // namespace cloak4ccf

namespace ccfapp {

std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(ccf::NetworkTables& nwt,
                                                      ccfapp::AbstractNodeContext& context) {
    return std::make_shared<cloak4ccf::CloakRpcFrontend>(nwt, context);
}

} // namespace ccfapp
