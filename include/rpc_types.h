// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include <cstddef>
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/transaction.h>
#include <eEVM/util.h>
#include <enclave/app_interface.h>
#include <kv/tx.h>
#include <kv/tx_view.h>
#include <kv/store.h>
#include <kv/map.h>
#include <node/rpc/serdes.h>
#include "ds/logger.h"
#include "jsonrpc.h"
#include "../src/app/utils.h"
// STL
#include <array>
#include "unordered_map"
#include <optional>
#include <vector>

#include "../src/abi/abicoder.h"
#include "../src/abi/bytecode.h"
#include "../src/abi/parsing.h"
namespace evm4ccf
{
  using Balance = uint256_t;
  using Result  = uint64_t;
  using BlockID = std::string;
  constexpr auto DefaultBlockID = "latest";

  // Pass around hex-encoded strings that we can manipulate as long as possible,
  // only convert to actual byte arrays when needed
  using ByteData = std::string;

  using EthHash = uint256_t;
  using TxHash = EthHash;
  using BlockHash = EthHash;
  using ByteString = std::vector<uint8_t>;

  using ContractParticipants = std::set<eevm::Address>;
  // TODO(eddy|#refactoring): Reconcile this with eevm::Block
  struct BlockHeader
  {
    uint64_t number = {};
    uint64_t difficulty = {};
    uint64_t gas_limit = {};
    uint64_t gas_used = {};
    uint64_t timestamp = {};
    eevm::Address miner = {};
    BlockHash block_hash = {};
  };

  struct WorkOrder 
  {
    uint64_t responseTimeoutMSecs = {};
    ByteData payloadFormat = {};
    ByteData resultUri = {};
    ByteData notifyUri = {};
    uint256_t workOrderId = {};
  };

  inline bool operator==(const BlockHeader& l, const BlockHeader& r)
  {
    return l.number == r.number && l.difficulty == r.difficulty &&
      l.gas_limit == r.gas_limit && l.gas_used == r.gas_used &&
      l.timestamp == r.timestamp && l.miner == r.miner &&
      l.block_hash == r.block_hash;
  }
  inline std::string packed_to_hex_string_fixed(
      const uint256_t& v, size_t min_hex_chars = 64)
  {
      return fmt::format("{:0>{}}", intx::hex(v), min_hex_chars);    
  }

  inline std::string packed_to_hex_string_fixed_left(
      const std::string& _v, size_t min_hex_chars = 64)
  {
      auto v = eevm::strip(_v);
      return fmt::format("{:{}}", v, v.size()) + std::string(min_hex_chars- v.size(),'0');    
  }

  namespace policy {
    
    struct MultiInput {
      ByteData name = {};
      ByteData value = {};
      MSGPACK_DEFINE(name, value);
    };

    struct MultiPartyParams {
      ByteData function = {};
      std::vector<MultiInput> inputs = {};
      MSGPACK_DEFINE(function, inputs);
      
      ByteData name() const {
        return function;
      }

    };

    struct Params {
    public:
      ByteData name = {};
      ByteData type = {};
      ByteData owner = {};
      std::optional<ByteData> value = std::nullopt;

      MSGPACK_DEFINE(name, type, owner, value);

      ByteData getValue() const {
        if(!value.has_value())
          return "";
        return value.value();
      }

      void set_value(const ByteData &_v)
      {
        value = _v;
      }

      void pack(vector<void*> &coders) const {
        abicoder::paramCoder(coders, name, type, getValue());        
      } 

      std::string info() const {
          std::string s = fmt::format("param name:{}, type:{}, owner:{}", name, type, owner);
          if (value.has_value()) {
              s.append(fmt::format(", value:{}", value.value()));
          }
          s.append("\n");
          return s;
      }
    };

    struct stateParams {
      ByteData name = {};
      std::vector<ByteData> keys = {};

      MSGPACK_DEFINE(name, keys);
    };

    enum Type  {
      ADDRESS,
      UINT,
      INT,
      BYTES,
      STRING,
      BOOL
};
static std::unordered_map<ByteData, int> contractType = {
      {"string", STRING},
      {"bytes", BYTES},
      {"bool", BOOL},
      {"address", ADDRESS},
      {"uint", UINT},
      {"int", INT},
};
    struct Function {
    public:
      ByteData type;
      ByteData name;
      std::optional<UINT8ARRAY> entry = std::nullopt;
      UINT8ARRAY signedName;
      std::vector<Params> inputs;
      std::vector<stateParams> read;
      std::vector<stateParams> mutate;
      std::vector<Params> outputs;
      std::vector<uint8_t> raw_outputs;

      MSGPACK_DEFINE(name, entry, signedName, type, inputs, read, mutate, outputs, raw_outputs);

      ByteData get_signed_name() const
      {
        auto signed_name = name + "(";
        bool first = true;
        for (auto &&p : inputs) {
            if (!first) {
                signed_name += ","+p.type;
            } else {
                signed_name += p.type;
            }
            first = false;
        }
        signed_name += ")";
        LOG_DEBUG_FMT("signed name:{}", signed_name);
        return signed_name;
      }
      void check_params()
      {
        if (!entry.has_value())
        {
          auto bc = Bytecode(name);
          for (size_t i = 0; i < inputs.size(); i++)
          {
            bc.add_inputs(inputs[i].name, inputs[i].type);
          }
          entry = bc.encode_function();
        }
        CLOAK_DEBUG_FMT("funtion select:{}", eevm::to_hex_string(entry.value()));
      }
      void sign_function_name() {
        LOG_DEBUG_FMT("original function name:{}", name);
        std::string signed_name = name + "(";
        bool first = true;
        for (auto &&p : inputs) {
            if (!first) {
                signed_name += ","+p.type;
            } else {
                signed_name += p.type;
            }
            first = false;
        }
        signed_name += ")";
        LOG_DEBUG_FMT("signed name:{}", signed_name);
        auto sha3 = eevm::keccak_256(signed_name);
        signedName = UINT8ARRAY(sha3.begin(), sha3.begin()+4);
      }

      UINT8ARRAY packed_to_data()  {
        UINT8ARRAY sha3 = signedName;
        vector<void*> coders;
        for(int i=0; i<inputs.size();i++) {
            inputs[i].pack(coders);
        }
        auto data = abicoder::pack(coders);
        // abicoder::insert(data, sha3);
        sha3.insert(sha3.end(),data.begin(), data.end());
        return sha3;
      }

      void padding(const MultiInput &p) {
          if(complete()) return false;
          
          for(int i=0; i<inputs.size(); i++) {
            if(inputs[i].name == p.name) {
              inputs[i].set_value(p.value);             
              return;
            }
          }

          throw std::logic_error(fmt::format(
              "input params doesn`t match, get {}", p.name
          ));
      }

      bool complete() const {
          for (auto && x : inputs) {
              if (!x.value.has_value()) {
                  return false;
              }
          }
          return true;
      }

      std::string info() const {
          std::string s = fmt::format("name:{}, type:{}\n", name, type);
          for (auto &&i : inputs) {
              s.append(i.info());
          }
          return s;
      }

      std::vector<std::string> get_mapping_keys(eevm::Address msg_sender, const std::string& name, bool from_read) {
          std::vector<std::string> res;
          auto&& ps = from_read ? read : mutate;
          for (auto&& x : ps) {
              if (x.name == name) {
                  for (auto&& key : x.keys) {
                      if (key == "msg.sender") {
                          res.push_back(eevm::to_checksum_address(msg_sender));
                          continue;
                      }
                      for (auto&& input : inputs) {
                          if (input.name == key) {
                              res.push_back(input.value.value());
                          }
                      }
                  }
              }
          }
          return res;
      }

      std::vector<std::string> get_mapping_keys(eevm::Address msg_sender, const std::string& name)
      {
          auto&& read_res = get_mapping_keys(msg_sender, name, true);
          auto&& mutate_res = get_mapping_keys(msg_sender, name, false);
          read_res.insert(read_res.end(), mutate_res.begin(), mutate_res.end());
          return read_res;
      }
    };
  }

  namespace rpcparams
  {
    struct MessageCall
    {
      eevm::Address from = {};
      std::optional<eevm::Address> to = std::nullopt;
      uint256_t gas = 90000;
      uint256_t gas_price = 0;
      uint256_t value = 0;
      ByteData data = {};
      std::optional<ContractParticipants> private_for = std::nullopt;
    };

    struct Policy
    {
    public:
      ByteData contract = {};
      std::vector<policy::Params> states;
      std::vector<policy::Function> functions;
      
      MSGPACK_DEFINE(contract, states, functions);

      
      policy::Function get_funtions(const ByteData &name) const {
        for(int i=0; i<functions.size(); i++) {
          if(functions[i].name == name) {
            return functions[i];
          }
        }
        throw std::logic_error(fmt::format("doesn't find this {} function in this policy modules", name));
      }

      void sign_functions_name() {
          for (auto &&f : functions) {
              f.sign_function_name();
          }
      }

      std::string info() const {
          std::string s = fmt::format("contract: {}, \n", contract);
          for (auto &&v : functions) {
              s.append(fmt::format("function: {}\n", v.info()));
          }
          return s;
      }
      
    };

    struct AddressWithBlock
    {
      eevm::Address address = {};
      BlockID block_id = DefaultBlockID;
    };

    struct Call
    {
      MessageCall call_data = {};
      BlockID block_id = DefaultBlockID;
    };

    struct GetTransactionCount
    {
      eevm::Address address = {};
      BlockID block_id = DefaultBlockID;
    };

    struct GetTransactionReceipt
    {
      TxHash tx_hash = {};
    };

    struct GetMultiPartyStatus
    {
      eevm::KeccakHash tx_hash = {};
    };

    struct SendRawTransaction
    {
      ByteData raw_transaction = {};
    };

    struct SendTransaction
    {
      MessageCall call_data = {};
    };

    struct EstimateGas
    {
      MessageCall call_data = {};
    };
    
    struct SendPrivacyPolicy
    {
      eevm::Address from = {};
      eevm::Address to = {};
      ByteData codeHash = {};
      eevm::Address verifierAddr = {};
      ByteData policy = {};
    };

    struct SendMultiPartyTransaction
    {
      ByteData params = {};
    };

    struct WorkOrderSubmit 
    {
      WorkOrder workOrder = {};
    };
  } // namespace rpcparams

  namespace rpcresults
  {
    struct TxReceipt
    {
      TxHash transaction_hash = {};
      uint256_t transaction_index = {};
      BlockHash block_hash = {};
      uint256_t block_number = {};
      eevm::Address from = {};
      std::optional<eevm::Address> to = std::nullopt;
      uint256_t cumulative_gas_used = {};
      uint256_t gas_used = {};
      std::optional<eevm::Address> contract_address = std::nullopt;
      std::vector<eevm::LogEntry> logs = {};
      // logs_bloom could be bitset for interaction, but is currently ignored
      std::array<uint8_t, 256> logs_bloom = {};
      uint256_t status = {};
    };

    struct WorkOrderReceipt
    {
      uint64_t responseTimeoutMSecs = {};
      ByteData payloadFormat = {};
      ByteData resultUri = {};
      ByteData notifyUri = {};
      eevm::Address workOrderId = {};
    };

    struct MultiPartyReceipt
    {
      bool state = {};
      ByteData progress = {};
    };

    // "A transaction receipt object, or null when no receipt was found"
    using ReceiptResponse = std::optional<TxReceipt>;
    using ReceiptWorkOrderResponse = std::optional<WorkOrderReceipt>;
    using MultiPartyReceiptResponse = std::optional<MultiPartyReceipt>;
  } // namespace rpcresults

  template <class TTag, typename TParams, typename TResult>
  struct RpcBuilder
  {
    using Tag = TTag;
    using Params = TParams;
    using Result = TResult;

    using In = jsonrpc::ProcedureCall<TParams>;
    using Out = jsonrpc::Response<TResult>;

    static constexpr auto name = TTag::name;

    static In make(ccf::SeqNo n = 0)
    {
      In in;
      in.id = n;
      in.method = TTag::name;
      return in;
    }
  };

  // Ethereum JSON-RPC
  namespace ethrpc
  {
    struct BlockNumberTag
    {
      static constexpr auto name = "eth_blockNumber";
    };
    using BlockNumber = RpcBuilder<BlockNumberTag, void, ByteData>;

    struct CallTag
    {
      static constexpr auto name = "eth_call";
    };
    using Call = RpcBuilder<CallTag, rpcparams::Call, ByteData>;

    struct GetAccountsTag
    {
      static constexpr auto name = "eth_accounts";
    };
    
    using GetAccounts =
      RpcBuilder<GetAccountsTag, void, std::vector<eevm::Address>>;
    
    struct GetChainIdTag 
    { 
      static constexpr auto name = "eth_chainId";
    };

    using GetChainId = 
      RpcBuilder<GetChainIdTag, void, size_t>;

    struct GetGasPriceTag 
    { 
      static constexpr auto name = "eth_gasPrice";
    };

    using GetGasPrice = 
      RpcBuilder<GetGasPriceTag, void, size_t>;

    struct GetEstimateGasTag
    {
      static constexpr auto name = "eth_estimateGas";     
    };
    
    using GetEstimateGas = 
      RpcBuilder<GetEstimateGasTag, rpcparams::EstimateGas, Result>;

    struct GetBalanceTag
    {
      static constexpr auto name = "eth_getBalance";
    };
    using GetBalance =
      RpcBuilder<GetBalanceTag, rpcparams::AddressWithBlock, Balance>;

    struct GetCodeTag
    {
      static constexpr auto name = "eth_getCode";
    };
    using GetCode =
      RpcBuilder<GetCodeTag, rpcparams::AddressWithBlock, ByteData>;

    struct GetTransactionCountTag
    {
      static constexpr auto name = "eth_getTransactionCount";
    };
    using GetTransactionCount = RpcBuilder<
      GetTransactionCountTag,
      rpcparams::GetTransactionCount,
      size_t>;

    struct GetTransactionCountTest 
    {
      static constexpr auto name = GetTransactionCountTag::name;
      struct In 
      {
        eevm::Address address = {};
        BlockID block_id = DefaultBlockID;   
      };
      struct Out
      {
        size_t result;
      };
    };

    DECLARE_JSON_TYPE(GetTransactionCountTest::In);
    // TODO: adding 'address' and complete add_schema_components functin
    // in eEVM/bigint.h
    DECLARE_JSON_REQUIRED_FIELDS(GetTransactionCountTest::In, block_id);
    DECLARE_JSON_TYPE(GetTransactionCountTest::Out);
    DECLARE_JSON_REQUIRED_FIELDS(GetTransactionCountTest::Out, result);

    struct GetTransactionReceiptTag
    {
      static constexpr auto name = "eth_getTransactionReceipt";
    };
    using GetTransactionReceipt = RpcBuilder<
      GetTransactionReceiptTag,
      rpcparams::GetTransactionReceipt,
      rpcresults::ReceiptResponse>;

    struct GetMultiPartyStatusTag
    {
      static constexpr auto name = "cloak_getMultiPartyStatus";
    };
    using GetMultiPartyStatus = RpcBuilder<
      GetMultiPartyStatusTag,
      rpcparams::GetMultiPartyStatus,
      rpcresults::MultiPartyReceiptResponse
    >;

    struct SendRawTransactionTag
    {
      static constexpr auto name = "eth_sendRawTransaction";
    };
    using SendRawTransaction =
      RpcBuilder<SendRawTransactionTag, rpcparams::SendRawTransaction, TxHash>;
    
    struct SendRawPrivacyTransactionTag
    {
      static constexpr auto name = "cloak_sendRawPrivacyTransaction";
    };
    using SendRawPrivacyTransaction =
      RpcBuilder<SendRawPrivacyTransactionTag, rpcparams::SendRawTransaction, TxHash>;
    
    struct SendRawMultiPartyTransactionTag
    {
      static constexpr auto name = "cloak_sendRawMultiPartyTransaction";
    };
    using SendRawMultiPartyTransaction =
      RpcBuilder<SendRawMultiPartyTransactionTag, rpcparams::SendRawTransaction, TxHash>;
    

    struct SendTransactionTag
    {
      static constexpr auto name = "eth_sendTransaction";
    };
    using SendTransaction =
      RpcBuilder<SendTransactionTag, rpcparams::SendTransaction, TxHash>;

    struct WorkOrderSubmitTag
    {
      static constexpr auto name = "cloak_workOrderSubmit";
    };
    using WorkOrderSubmit = 
      RpcBuilder<WorkOrderSubmitTag, rpcparams::WorkOrderSubmit, 
      rpcresults::ReceiptWorkOrderResponse
    >;


  } // namespace ethrpc
} // namespace evm4ccf

#include "rpc_types_serialization.inl"
