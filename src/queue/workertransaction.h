#pragma once
#include "ds/logger.h"
#include "fmt/core.h"
#include "iostream"
#include "string"
#include "vector"
#include "../app/utils.h"
#include "map"
#include "rpc_types.h"
#include <cctype>
#include <eEVM/bigint.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include <stdexcept>
#include "ethereum_transaction.h"
#include "../transaction/bytecode.h"

namespace evm4ccf
{   
    using namespace eevm;
    using namespace rpcparams;
    using ByteData = std::string;
    using Address = eevm::Address;
    using Policy = rpcparams::Policy;
    using h256 = eevm::KeccakHash;
    using ByteString = std::vector<uint8_t>;
    using uint256 = uint256_t;

    enum Status {
        PENDING,
        PACKAGE,
        DROPPED,
        FAILED
    };

    static std::map<Status,ByteData> statusMap = {
        {PENDING, "pending"},
        {PACKAGE, "package"},
        {DROPPED, "dropped"},
        {FAILED, "failed"}
    };

    struct MultiPartyTransaction
    {
        size_t nonce;
        ByteString to;
        Address from;
        policy::MultiPartyParams params;
        MSGPACK_DEFINE(nonce, from, to, params);

        bool check_transaction_type()
        {
            if (to.size() == 20u) return false;
            if (to.size() == 32u) return true;
            throw std::logic_error(fmt::format(
                "Unsupported transaction type, to length should be {} or {}, but is {}",
                20u,
                32u,
                to.size()
            ));
        }

        ByteData name() const {
          return params.name();
        }
    };

    using MultiPartys = kv::Map<h256, MultiPartyTransaction>;

    struct PrivacyPolicyTransaction
    {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        rpcparams::Policy   policy;
        ByteString          pdata;
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, policy);
        PrivacyPolicyTransaction(){}
    };

    using Privacys = kv::Map<h256, PrivacyPolicyTransaction>;
    using PrivacyDigests = kv::Map<Address, h256>;

    struct CloakPolicyTransaction
    {
    
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        policy::Function    function;
        std::vector<policy::Params> states;
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, function, states);
        CloakPolicyTransaction() {}
        CloakPolicyTransaction(
           const PrivacyPolicyTransaction& ppt, const ByteData& name)
        {
            from = ppt.from;
            to = ppt.to;
            verifierAddr = ppt.verifierAddr;
            codeHash = ppt.codeHash;
            states = ppt.policy.states;
            function = ppt.policy.get_funtions(name);
        }

        void set_content(const std::vector<policy::MultiInput> &inputs)
        {
            if (inputs.size() != function.inputs.size()) {
                throw std::logic_error(fmt::format(
                    "input params doesn`t match, want {} but get {}",  function.inputs.size(), inputs.size()
                ));
            }

            for (size_t i = 0; i < inputs.size(); i++)
            {
                function.padding(inputs[i]);
            }
        }

        void add_multi_party()
        {

        }
    
    private:
        UINT8ARRAY packed_to_evm_data()
        {
            auto data = Bytecode(function.get_signed_name(), function.inputs);
            return data.encode();
        }
    };


    using CloakPolicys = kv::Map<h256, CloakPolicyTransaction>;
    using CloakDigests = kv::Map<Address, h256>;
} // namespace evm4ccf
