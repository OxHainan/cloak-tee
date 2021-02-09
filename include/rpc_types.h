// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

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
#include "jsonrpc.h"
#include "../src/app/utils.h"
// STL
#include <array>
#include "unordered_map"
#include <vector>

#include "../src/abi/abicoder.h"
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
    // static enum Type  {
    //   UINT256,
    //   UINT256_ARRAY,
    //   BOOL
    // };
    // static std::unordered_map<ByteData, int> contractType = {
    //   {"uint256", UINT256},
    //   {"uint256[]", UINT256_ARRAY},
    //   {"bool", BOOL}
    // };
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
    };

    struct MultiPartyParams {
      ByteData function = {};
      std::vector<MultiInput> inputs = {};

      ByteData name() const {
        return function;
      }
    };

    
    // struct MultiPartyParams
    // {
    //   ByteData name = {};
    //   ByteData value = {};

    //   eevm::KeccakHash getHash() const {
    //     return Utils::to_KeccakHash(policyHash);
    //   }
    // };

    struct Params {
    public:
      ByteData name = {};
      ByteData type = {};
      ByteData owner = {};
      std::optional<ByteData> value = std::nullopt;

      ByteData getValue() const {
        if(!value.has_value())
          return "";
        return value.value();
      }

      void pack(vector<void*> &coders) {
          abicoder::paramCoder(coders, name, type, getValue());        
      } 
    };

    struct stateParams {
      ByteData name = {};
      std::vector<ByteData> keys = {};
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
      std::vector<Params> inputs;
      std::vector<stateParams> read;
      std::vector<stateParams> mutate;
      std::vector<Params> outputs;

      UINT8ARRAY convert_funtion_name() const {
        auto sha3 = eevm::keccak_256(name);
        return UINT8ARRAY(sha3.begin(), sha3.begin()+4);
      }

      UINT8ARRAY packed_to_data()  {
        UINT8ARRAY sha3 = convert_funtion_name();
        vector<void*> coders;
        for(int i=0; i<inputs.size();i++) {
            inputs[i].pack(coders);
        }
        auto data = abicoder::pack(coders);
        abicoder::insert(data, sha3);
        return data;
      }

      bool padding(const MultiInput &p) {
          if(complete()) return false;
          
          for(int i=0; i<inputs.size(); i++) {
            if(inputs[i].name == p.name) {
              inputs[i].value = p.value;
              
              num++;
              std::cout << inputs.size() << " "<<num<< std::endl;
              return true;
            }
          }
        return false;
      }

      bool complete() const {
        return num == inputs.size();
      }
      ~Function() {
        std::cout << "functions 析构"<< std::endl;

      }
      private:
        size_t num = 0;
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
      
      policy::Function get_funtions(const ByteData &name) const {
        for(int i=0; i<functions.size(); i++) {
          if(functions[i].name == name) return functions[i];
        }
        throw std::logic_error(fmt::format("doesn`t find this {} function in this policy modules", name));
      }

      // std::tuple<bool, ByteData> paddingToPolicy(const policy::MultiPartyParams &p) {
      //   int i=0;
      //   for(; i<functions.size(); i++) {
      //     if(functions[i].name == p.name) break;
      //   }
      //     auto status = functions[i].padding(p);
      //     if(status && functions[i].complete()) {
      //       return std::make_tuple(status, functions[i].packed_to_data());
      //     }
      //     return std::make_tuple(status, "");
      // }
      
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
      eevm::Address from = {};
      eevm::Address to = {};
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

    struct SendRawTransactionTag
    {
      static constexpr auto name = "eth_sendRawTransaction";
    };
    using SendRawTransaction =
      RpcBuilder<SendRawTransactionTag, rpcparams::SendRawTransaction, TxHash>;

    struct SendTransactionTag
    {
      static constexpr auto name = "eth_sendTransaction";
    };
    using SendTransaction =
      RpcBuilder<SendTransactionTag, rpcparams::SendTransaction, TxHash>;

    struct SendPrivacyPolicyTag
    {
      static constexpr auto name = "cloak_sendPrivacyPolicy";
    };
    using SendPrivacyPolicy = 
      RpcBuilder<SendPrivacyPolicyTag, rpcparams::SendPrivacyPolicy, TxHash>;
    

    struct SendMultiPartyTransactionTag
    {
      static constexpr auto name = "cloak_sendMultiPartyTransaction";
    };
    using SendMultiPartyTransaction = 
      RpcBuilder<SendMultiPartyTransactionTag, 
        rpcparams::SendMultiPartyTransaction, 
        rpcresults::MultiPartyReceiptResponse
      >;

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
