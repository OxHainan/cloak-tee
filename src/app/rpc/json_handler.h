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
#include "ccf/json_handler.h"
#include "cloak_exception.h"
#include "jsonrpc.h"
namespace cloak4ccf
{
using JsonAdapterResponse = ccf::jsonhandler::JsonAdapterResponse;

template <typename T>
static JsonAdapterResponse make_error(
    const T& ctx, http_status status, const std::string& code, const std::string& msg = "")
{
    auto error_reason = fmt::format("[CLOAK-{}]: {}", ctx.seqno, msg);
    return ccf::make_error(status, code, error_reason);
}

static void set_response(JsonAdapterResponse&& res, std::shared_ptr<ccf::RpcContext>& ctx)
{
    auto error = std::get_if<ccf::ErrorDetails>(&res);
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

static std::pair<serdes::Pack, nlohmann::json> get_json_params(const std::shared_ptr<ccf::RpcContext>& ctx)
{
    // Unsupport json input in client
    // const auto pack = ccf::jsonhandler::detect_json_pack(ctx);
    nlohmann::json params = nlohmann::json::parse(ctx->get_request_body());
    return std::pair(serdes::Pack::Text, params);
}

template <typename T>
JsonAdapterResponse func(std::function<JsonAdapterResponse()> f, T&& ctx)
{
    try {
        return f();
    }
    catch (std::logic_error& e) {
        return make_error(ctx, HTTP_STATUS_NOT_FOUND, ccf::errors::ResourceNotFound, e.what());
    }
    catch (const CloakException& e) {
        return make_error(ctx, HTTP_STATUS_NOT_FOUND, ccf::errors::ResourceNotFound, e.what());
    }
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-function"

using HandlerJsonParamsAndForward = std::function<JsonAdapterResponse(CloakContext& ctx, nlohmann::json params)>;

static ccf::endpoints::EndpointFunction json_adapter(const HandlerJsonParamsAndForward& f, CloakTables& table)
{
    return [f, &table](ccf::endpoints::EndpointContext& args) {
        auto params = get_json_params(args.rpc_ctx).second;
        CloakContext ctx(args.tx, table);
        JsonAdapterResponse result = func([&]() { return f(ctx, params); }, ctx);
        set_response(std::move(result), args.rpc_ctx);
    };
}

using ReadOnlyHandlerWithJson = std::function<JsonAdapterResponse(ReadOnlyCloakContext& ctx, nlohmann::json& params)>;

static ccf::endpoints::ReadOnlyEndpointFunction json_read_only_adapter(
    const ReadOnlyHandlerWithJson& f, CloakTables& table)
{
    return [f, &table](ccf::endpoints::ReadOnlyEndpointContext& args) {
        auto params = get_json_params(args.rpc_ctx).second;
        ReadOnlyCloakContext ctx(args.tx, table);
        JsonAdapterResponse result = func([&]() { return f(ctx, params); }, ctx);

        set_response(std::move(result), args.rpc_ctx);
    };
}

#pragma clang diagnostic pop

} // namespace cloak4ccf
