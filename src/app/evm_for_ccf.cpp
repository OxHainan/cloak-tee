// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// EVM-for-CCF
#include "../queue/workerqueue.hpp"
#include "account_proxy.h"
#include "ds/logger.h"
#include "ethereum_state.h"
#include "ethereum_transaction.h"
#include "http/http_status.h"
#include "jsonrpc.h"
#include "tables.h"
#include "tls/key_pair.h"
#include "utils.h"
// CCF
#include "ds/hash.h"
#include "enclave/app_interface.h"
#include "node/quote.h"
#include "node/rpc/user_frontend.h"
#include "rpc_types.h"

// eEVM
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/processor.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>

// STL/3rd-party
#include <iostream>
#include <msgpack/msgpack.hpp>
#include <unistd.h>

namespace evm4ccf
{
  using namespace std;
  using namespace eevm;
  using namespace ccf;
  using namespace ccfapp;

  //
  // RPC handler class
  //
  class EVMHandlers : public UserEndpointRegistry
  {
    tables::Accounts accounts;
    tables::Storage storage;
    tables::Results tx_results;
    WorkerQueue workerQueue;
    EthereumState make_state(kv::Tx& tx)
    {
      return EthereumState(accounts.get_views(tx), tx.get_view(storage));
    }

    void install_standard_rpcs()
    {
      auto call = [this](ccf::EndpointContext& args) {
        kv::Tx& tx = args.tx;
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto cl = body_j.get<rpcparams::Call>();

        if (!cl.call_data.to.has_value())
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto error = nlohmann::json("Missing 'to' field");
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, error).dump());
          return;
        }

        auto es = make_state(tx);

        const auto e = run_in_evm(cl.call_data, es).first;

        if (e.er == ExitReason::returned || e.er == ExitReason::halted)
        {
          // Call should have no effect so we don't commit it.
          // Just return the result.
          args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto result = nlohmann::json(to_hex_string(e.output));
          args.rpc_ctx->set_response_body(
            jsonrpc::result_response(0, result).dump());
          return;
        }
        else
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto error = nlohmann::json(e.exmsg);
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, error).dump());
          return;
        }
      };

      auto get_chainId = [](ccf::EndpointContext& args) {
        auto result = nlohmann::json(to_hex_string(evm4ccf::current_chain_id));
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
        return;
      };
      auto get_gasPrice = [](ccf::EndpointContext& args) {
        auto result = nlohmann::json(to_hex_string(0));
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
        return;
      };
      auto get_estimateGas = [this](ccf::EndpointContext& args) {
        kv::Tx& tx = args.tx;

        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto stp = body_j.get<rpcparams::EstimateGas>();
        auto es = make_state(tx);

        auto tx_result = estimateGas(stp.call_data, es);
        auto result = nlohmann::json(to_hex_string(0));

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
        return;
      };

      auto get_balance = [this](ccf::EndpointContext& args) {
        kv::Tx& tx = args.tx;
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto gb = body_j.get<rpcparams::AddressWithBlock>();
        if (gb.block_id != "latest")
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto error = nlohmann::json("Can only request latest block");
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, error).dump());
          return;
        }

        auto es = make_state(tx);

        const auto account_state = es.get(gb.address);

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        auto result =
          nlohmann::json(to_hex_string(account_state.acc.get_balance()));
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
      };

      auto get_code = [this](ccf::EndpointContext& args) {
        kv::Tx& tx = args.tx;
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto gc = body_j.get<rpcparams::AddressWithBlock>();
        if (gc.block_id != "latest")
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto error = nlohmann::json("Can only request latest block");
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, error).dump());
          return;
        }

        auto es = make_state(tx);

        const auto account_state = es.get(gc.address);

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        auto result =
          nlohmann::json(to_hex_string(account_state.acc.get_code()));
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
      };

      auto get_transaction_count = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto gtc = body_j.get<rpcparams::GetTransactionCount>();
        if (gtc.block_id != "latest")
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_BAD_REQUEST);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          auto error = nlohmann::json("Can only request latest block");
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, error).dump());
          return;
        }

        auto es = make_state(args.tx);
        auto account_state = es.get(gtc.address);

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        auto result =
          nlohmann::json(to_hex_string(account_state.acc.get_nonce()));
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
        return;
      };

      auto send_raw_transaction = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto srtp = body_j.get<rpcparams::SendRawTransaction>();

        eevm::rlp::ByteString in = eevm::to_bytes(srtp.raw_transaction);

        EthereumTransactionWithSignature eth_tx(in);

        rpcparams::MessageCall tc;
        eth_tx.to_transaction_call(tc);
        // tls::PublicKey_k1Bitcoin::recover_key

        auto tx_result = execute_transaction(args.caller_id, tc, args.tx);

        if (!tx_result.first)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, tx_result.second).dump());
          return;
        }

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, tx_result.second).dump());
        return;
      };

      auto send_transaction = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto stp = body_j.get<rpcparams::SendTransaction>();

        auto tx_result =
          execute_transaction(args.caller_id, stp.call_data, args.tx);

        if (!tx_result.first)
        {
          args.rpc_ctx->set_response_status(HTTP_STATUS_INTERNAL_SERVER_ERROR);
          args.rpc_ctx->set_response_header(
            http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
          args.rpc_ctx->set_response_body(
            jsonrpc::error_response(0, tx_result.second).dump());
          return;
        }

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, tx_result.second).dump());
        return;
      };

      auto send_privacy_policy = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto sppp = body_j.get<rpcparams::SendPrivacyPolicy>();
        printf( "privacy_policy tx: %p \n", (void*)&args.tx);
        // TODO: check target contract
        PrivacyPolicyTransaction ppt(sppp);
        auto hash = workerQueue.addModule(ppt);

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, eevm::to_hex_string(hash)).dump());
        return;
      };

      auto send_multiPartyTransaction = [this](ccf::EndpointContext& args) {
        CLOAK_DEBUG_FMT("request body:{}", args.rpc_ctx->get_request_body());
        printf( "send_multiPartyTransaction tx: %p \n", (void*)&args.tx);
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto smp = body_j.get<rpcparams::SendMultiPartyTransaction>();
        

        MultiPartyTransaction mpt(smp);
        mpt.checkSignature();
        auto result = workerQueue.addMultiParty(mpt);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, eevm::to_hex_string(result)).dump());

        // run in evm
        auto ct = workerQueue.GetCloakTransaction(result);
        if (ct.has_value() && ct.value()->function.complete())
        {
          CloakTransaction *ct_value = ct.value();
          CLOAK_DEBUG_FMT("ct function: {}\n", ct_value->function.info());
          ct_value->set_status(PACKAGE);
          auto data = ct_value->function.packed_to_data();
          MessageCall mc;
          mc.from = mpt.from;
          mc.to = mpt.to;
          mc.data = to_hex_string(data);
          CLOAK_DEBUG_FMT("ct function data: {}", mc.data);
          auto es = make_state(args.tx);

          const auto res = run_in_evm(mc, es).first;
          CLOAK_DEBUG_FMT("run in evm, res: {}, msg: {}\n", res.output, res.exmsg);
          if (res.er == ExitReason::threw) {
              ct_value->set_status(FAILED);
          } else {
              // TODO: add succeeded status
              // ct_value->>set_status()
          }
          // TODO: handle return result
        }

        return ccf::make_success("");
      };

      auto get_multiPartyStatus = [this](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto mps = body_j.get<rpcparams::GetMultiPartyStatus>();
        auto result = workerQueue.getMultiPartyStatus(mps.tx_hash);

        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, result).dump());
        return;
      };

      auto get_workOrderSubmit = [](ccf::EndpointContext& args) {
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto sppp = body_j.get<rpcparams::WorkOrderSubmit>();

        rpcresults::ReceiptWorkOrderResponse response = nullopt;
        response->responseTimeoutMSecs = sppp.workOrder.responseTimeoutMSecs;
        response->workOrderId = sppp.workOrder.workOrderId;
        // response->status = 1;
        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, response).dump());
        return;
      };

      auto get_transaction_receipt = [this](ccf::EndpointContext& args) {
        kv::Tx& tx = args.tx;
        const auto body_j =
          nlohmann::json::parse(args.rpc_ctx->get_request_body());
        auto gtrp = body_j.get<rpcparams::GetTransactionReceipt>();

        const TxHash& tx_hash = gtrp.tx_hash;

        auto results_view = tx.get_view(tx_results);
        const auto r = results_view->get(tx_hash);

        // "or null when no receipt was found"
        rpcresults::ReceiptResponse response = nullopt;
        if (r.has_value())
        {
          const auto& tx_result = r.value();

          response.emplace();
          response->transaction_hash = tx_hash;
          if (tx_result.contract_address.has_value())
          {
            response->contract_address = tx_result.contract_address;
          }
          else
          {
            response->to = 0x0;
          }
          response->logs = tx_result.logs;
          response->status = 1;
        }

        // Return success HTTP response with the result json
        args.rpc_ctx->set_response_status(HTTP_STATUS_OK);
        args.rpc_ctx->set_response_header(
          http::headers::CONTENT_TYPE, http::headervalues::contenttype::TEXT);
        args.rpc_ctx->set_response_body(
          jsonrpc::result_response(0, response).dump());
        return;
      };

      auto get_transaction_count_test =
        [this](kv::Tx& tx, const nlohmann::json& params) {
          auto gtcp = params.get<ethrpc::GetTransactionCountTest::In>();

          if (gtcp.block_id != "latest")
          {
            return ccf::make_error(
              HTTP_STATUS_BAD_REQUEST, "Can only request latest block");
          }

          auto es = make_state(tx);
          auto account_state = es.get(gtcp.address);

          return ccf::make_success(ethrpc::GetTransactionCountTest::Out{
            account_state.acc.get_nonce()});
        };

      // Because CCF OpenAPI json module do not support uint256, thus do not use
      // ccf::json_adapter(call) or add_auto_schema(...)
      make_endpoint(ethrpc::Call::name, HTTP_GET, call).install();

      make_endpoint(ethrpc::GetBalance::name, HTTP_GET, get_balance).install();

      make_endpoint(ethrpc::GetChainId::name, HTTP_GET, get_chainId).install();
      make_endpoint(ethrpc::GetGasPrice::name, HTTP_GET, get_gasPrice)
        .install();
      make_endpoint(ethrpc::GetCode::name, HTTP_GET, get_code).install();
      make_endpoint(ethrpc::GetEstimateGas::name, HTTP_GET, get_estimateGas)
        .install();
      make_endpoint(
        ethrpc::GetTransactionCount::name, HTTP_GET, get_transaction_count)
        .install();

      make_endpoint(
        ethrpc::GetTransactionReceipt::name, HTTP_GET, get_transaction_receipt)
        .install();

      make_endpoint(
        ethrpc::GetMultiPartyStatus::name, HTTP_GET, get_multiPartyStatus)
        .install();

      make_endpoint(
        ethrpc::WorkOrderSubmit::name, HTTP_GET, get_workOrderSubmit)
        .install();

      make_endpoint(
        ethrpc::SendRawTransaction::name, HTTP_POST, send_raw_transaction)
        .install();

      make_endpoint(ethrpc::SendTransaction::name, HTTP_POST, send_transaction)
        .install();

      make_endpoint(
        ethrpc::SendPrivacyPolicy::name, HTTP_POST, send_privacy_policy)
        .install();

      make_endpoint(
        ethrpc::SendMultiPartyTransaction::name,
        HTTP_POST,
        send_multiPartyTransaction)
        .install();

      make_endpoint(
        "eth_getTransactionCount_Test",
        HTTP_GET,
        ccf::json_adapter(get_transaction_count_test))
        .set_auto_schema<ethrpc::GetTransactionCountTest>()
        .install();
    }

  public:
    // SNIPPET_START: initialization

    EVMHandlers(ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context) :
      UserEndpointRegistry(nwt),
      accounts{
        tables::Accounts::Balances("eth.account.balance"),
        tables::Accounts::Codes("eth.account.code"),
        tables::Accounts::Nonces("eth.account.nonce"),
      },
      storage("eth.storage"),
      tx_results("eth.txresults"),
      workerQueue(*nwt.tables)
    // SNIPPET_END: initialization
    {
      context.get_historical_state();
      install_standard_rpcs();
      
    }

  private:
    static std::pair<ExecResult, AccountState> run_in_evm(
      const rpcparams::MessageCall& call_data,
      EthereumState& es,
      LogHandler& log_handler)
    {
      Address from = call_data.from;
      Address to;

      if (call_data.to.has_value())
      {
        to = call_data.to.value();
      }
      else
      {
        // If there's no to field, create a new account to deploy this to
        const auto from_state = es.get(from);
        to = eevm::generate_address(
          from_state.acc.get_address(), from_state.acc.get_nonce());
        es.create(to, call_data.gas, to_bytes(call_data.data));
      }

      Transaction eth_tx(from, log_handler);

      auto account_state = es.get(to);

#ifdef RECORD_TRACE
      eevm::Trace tr;
#endif

      Processor proc(es);
      const auto result = proc.run(
        eth_tx,
        from,
        account_state,
        to_bytes(call_data.data),
        call_data.value
#ifdef RECORD_TRACE
        ,
        &tr
#endif
      );

#ifdef RECORD_TRACE
      if (result.er == ExitReason::threw)
      {
        LOG_INFO_FMT("--- Trace of failing evm execution ---\n{}", tr);
      }
#endif

      return std::make_pair(result, account_state);
    }

    static pair<ExecResult, AccountState> run_in_evm(
      const rpcparams::MessageCall& call_data, EthereumState& es)
    {
      NullLogHandler ignore;
      return run_in_evm(call_data, es, ignore);
    }

    // TODO: This and similar should take EthereumTransaction, not
    // MessageCall. EthereumTransaction should be fully parsed, then
    // MessageCall can be removed
    pair<bool, nlohmann::json> execute_transaction(
      CallerId caller_id, const rpcparams::MessageCall& call_data, kv::Tx& tx)
    {
      LOG_INFO_FMT("Caller_id is {}", caller_id);
      auto es = make_state(tx);

      VectorLogHandler vlh;
      const auto [exec_result, tx_hash, to_address] =
        execute_transaction(call_data, es, vlh);

      if (exec_result.er == ExitReason::threw)
      {
        return std::make_pair(false, exec_result.exmsg);
      }

      auto results_view = tx.get_view(tx_results);
      TxResult tx_result;
      if (!call_data.to.has_value())
      {
        tx_result.contract_address = to_address;
      }

      tx_result.logs = vlh.logs;

      results_view->put(tx_hash, tx_result);

      return std::make_pair(true, eevm::to_hex_string_fixed(tx_hash));
    }

    static ExecResult estimateGas(
      const rpcparams::MessageCall& call_data, EthereumState& es)
    {
      const auto [exec_result, _] = run_in_evm(call_data, es);
      // if (exec_result.er == ExitReason::threw)
      // {
      return exec_result;
      // }
    }

    static std::tuple<ExecResult, TxHash, Address> execute_transaction(
      const rpcparams::MessageCall& call_data,
      EthereumState& es,
      LogHandler& log_handler)
    {
      auto [exec_result, account_state] =
        run_in_evm(call_data, es, log_handler);

      if (exec_result.er == ExitReason::threw)
      {
        return std::make_tuple(exec_result, 0, 0);
      }

      if (!call_data.to.has_value())
      {
        // New contract created, result is the code that should be deployed
        account_state.acc.set_code(std::move(exec_result.output));
      }

      auto from_state = es.get(call_data.from);
      auto tx_nonce = from_state.acc.get_nonce();
      from_state.acc.increment_nonce();

      EthereumTransaction eth_tx(tx_nonce, call_data);
      const auto rlp_encoded = eth_tx.encode();

      uint8_t h[32];
      const auto raw =
        reinterpret_cast<unsigned char const*>(rlp_encoded.data());
      eevm::keccak_256(raw, rlp_encoded.size(), h);

      const auto tx_hash = eevm::from_big_endian(h);

      return std::make_tuple(
        exec_result, tx_hash, account_state.acc.get_address());
    }

  }; // class EVMHandlers

  class EVM : public ccf::UserRpcFrontend 
  {
  private:
    EVMHandlers evm_handlers;

  public:
    EVM(ccf::NetworkTables& network, ccfapp::AbstractNodeContext& context) :
      ccf::UserRpcFrontend(*network.tables, evm_handlers),
      evm_handlers(network, context)
    {

    }
    
    void open() override
    {
      ccf::UserRpcFrontend::open();
      // LOG_INFO_FMT("primary {}", ccf::UserRpcFrontend::RpcFrontend::is_primary());
      evm_handlers.openapi_info.title = "CCF Homestead EVM App";
      evm_handlers.openapi_info.description =
        "This CCF Homestead EVM app implements a simple EVM";
    }
  }; // class EVM

} // namespace evm4ccf

namespace ccfapp
{
  // SNIPPET_START: rpc_handler
  std::shared_ptr<ccf::UserRpcFrontend> get_rpc_handler(
    ccf::NetworkTables& nwt, ccfapp::AbstractNodeContext& context)
  {
    return evm4ccf::make_shared<evm4ccf::EVM>(nwt, context);
  }
  // SNIPPET_END: rpc_handler
} // namespace ccfapp
