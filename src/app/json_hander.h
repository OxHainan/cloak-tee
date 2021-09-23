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
#include "app/tables.h"
#include "node/rpc/json_handler.h"
#include "transaction/tables.h"

namespace evm4ccf {
using SeqNo = int64_t;

struct Tables {
    TransactionTables& txTables;
    tables::Accounts& accounts;
    tables::Storage& storage;
    tables::Results& tx_results;
};

struct CloakContext {
    kv::Tx& tx;
    const Tables& table;
    SeqNo seqno;
    CloakContext(kv::Tx& _tx, const Tables& _tables) : tx(_tx), table(_tables) {}
};

struct ReadOnlyCloakContext {
    kv::ReadOnlyTx& tx;
    const Tables& table;
    SeqNo seqno;
    ReadOnlyCloakContext(kv::ReadOnlyTx& _tx, const Tables& _tables) : tx(_tx), table(_tables) {}
};

template <typename T>
static ccf::jsonhandler::JsonAdapterResponse make_error(const T&& ctx,
                                                        http_status status,
                                                        const std::string& msg = "") {
    auto error_reason = fmt::format("[CLOAK-{}]: {}", ctx.seqno, msg);

    return ccf::jsonhandler::ErrorDetails{status, error_reason};
}

static void set_response(ccf::jsonhandler::JsonAdapterResponse&& res, std::shared_ptr<enclave::RpcContext>& ctx) {
    auto error = std::get_if<ccf::jsonhandler::ErrorDetails>(&res);
    if (error != nullptr) {
        ctx->set_response_status(error->status);
        auto s = jsonrpc::error_response(0, std::move(error->msg));
        ctx->set_response_body(s.dump());
    } else {
        const auto body = std::get_if<nlohmann::json>(&res);
        ctx->set_response_status(HTTP_STATUS_OK);
        const auto s = fmt::format("{}\n", jsonrpc::result_response(0, *body).dump());
        ctx->set_response_body(std::vector<uint8_t>(s.begin(), s.end()));
        ctx->set_response_header(http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
    }
}

static std::pair<serdes::Pack, nlohmann::json> get_json_params(const std::shared_ptr<enclave::RpcContext>& ctx) {
    // Unsupport json input in client
    // const auto pack = ccf::jsonhandler::detect_json_pack(ctx);
    nlohmann::json params = nlohmann::json::parse(ctx->get_request_body());
    return std::pair(serdes::Pack::Text, params);
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

using HandlerJsonParamsAndForward =
    std::function<ccf::jsonhandler::JsonAdapterResponse(CloakContext& ctx, nlohmann::json&& params)>;

static ccf::EndpointFunction cloak_json_adapter(const HandlerJsonParamsAndForward& f, const Tables& table) {
    return [f, &table](ccf::EndpointContext& args) {
        auto [packing, params] = get_json_params(args.rpc_ctx);
        ccf::jsonhandler::JsonAdapterResponse result;
        CloakContext ctx(args.tx, table);
        try {
            result = f(ctx, std::move(params));
        } catch (const std::exception& e) {
            result = make_error(move(ctx), HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what());
        } catch (std::logic_error& e) {
            result = make_error(move(ctx), HTTP_STATUS_NOT_FOUND, e.what());
        }

        set_response(std::move(result), args.rpc_ctx);
    };
}

using HandlerTxOnly = std::function<ccf::jsonhandler::JsonAdapterResponse(CloakContext& ctx)>;

static ccf::EndpointFunction cloak_json_adapter(const HandlerTxOnly& f, const Tables& table) {
    return [f, &table](ccf::EndpointContext& args) {
        const auto [packing, params] = get_json_params(args.rpc_ctx);
        ccf::jsonhandler::JsonAdapterResponse result;
        CloakContext ctx(args.tx, table);
        try {
            result = f(ctx);
        } catch (const std::exception& e) {
            result = make_error(move(ctx), HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what());
        } catch (std::logic_error& e) {
            result = make_error(move(ctx), HTTP_STATUS_NOT_FOUND, e.what());
        }
        set_response(std::move(result), args.rpc_ctx);
    };
}

using ReadOnlyHandlerWithJson =
    std::function<ccf::jsonhandler::JsonAdapterResponse(ReadOnlyCloakContext& ctx, nlohmann::json&& params)>;

static ccf::ReadOnlyEndpointFunction cloak_json_read_only_adapter(const ReadOnlyHandlerWithJson& f,
                                                                  const Tables& table) {
    return [f, &table](ccf::ReadOnlyEndpointContext& args) {
        auto [_, params] = get_json_params(args.rpc_ctx);
        ccf::jsonhandler::JsonAdapterResponse result;
        ReadOnlyCloakContext ctx(args.tx, table);
        try {
            result = f(ctx, std::move(params));
        } catch (const std::exception& e) {
            result = make_error(move(ctx), HTTP_STATUS_INTERNAL_SERVER_ERROR, e.what());
        } catch (std::logic_error& e) {
            result = make_error(move(ctx), HTTP_STATUS_NOT_FOUND, e.what());
        }

        set_response(std::move(result), args.rpc_ctx);
    };
}

#pragma clang diagnostic pop

}  // namespace evm4ccf
