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
        Address to;
        Address from;
        policy::MultiPartyParams params;
        MSGPACK_DEFINE(nonce, from, to, params);

        ByteData name() const {
          return params.name();
        }
    };

    using MultiPartys = kv::Map<h256, MultiPartyTransaction>;
    
    struct MultiPartyTransaction1
    {
    public:
        size_t nonce;
        Address from;
        Address to;
        eevm::rlp::ByteString          data;
        uint8_t v;
        uint256_t r;
        uint256_t s;
        policy::MultiPartyParams params;

        MultiPartyTransaction1(const SendMultiPartyTransaction& s) {
            auto res = eevm::rlp::decode<
                size_t, 
                uint256_t,
                uint256_t,
                std::string,
                uint8_t,
                uint256_t,
                uint256_t>(eevm::to_bytes(s.params));
            nonce = std::get<0>(res);
            from = std::get<1>(res);
            to = std::get<2>(res);
            data = to_bytes(std::get<3>(res));
            this->v = std::get<4>(res);
            this->r = std::get<5>(res);
            this->s = std::get<6>(res);
            params = Utils::parse<policy::MultiPartyParams>(std::get<3>(res));
            CLOAK_DEBUG_FMT("nonce:{}, from:{}, to:{}, data:{} ,data hex:{}, v:{}, r:{}, s:{}", nonce, from, to, std::get<3>(res), to_hex_string(data), v, r, this->s);
        }

        void checkSignature() const {
            tls::RecoverableSignature sig;
            sig.recovery_id = from_ethereum_recovery_id(v);

            const auto s_begin = sig.raw.data() + 32;
            eevm::to_big_endian(r, sig.raw.data());
            eevm::to_big_endian(s, s_begin);
            auto hash = keccak_256(eevm::rlp::encode(nonce, from, to, to_hex_string(data)));
            auto pubk =
                tls::PublicKey_k1Bitcoin::recover_key(sig, {hash.data(), hash.size()});
            auto sf = get_address_from_public_key_asn1(public_key_asn1(pubk.get_raw_context()));
            if (sf != from) {
                CLOAK_DEBUG_FMT("sf:{}, from:{}", sf, from);
                throw std::logic_error("Signature error, please check your input");
            }
        }

        ByteData name() const {
          return params.name();
        }
        // h256 hash() const {
        //     return parmas.getHash();
        // }  
    };

    
    

    struct CloakTransaction1 {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        policy::Function    function;
        std::vector<policy::Params> states;
        Status              status = PENDING;
        std::map<Address, MultiPartyTransaction1> multiParty ;

        void insert(MultiPartyTransaction1 &mpt) {
            multiParty.insert(std::make_pair(mpt.from, mpt));
            for (size_t i = 0; i < mpt.params.inputs.size(); i++) {
                function.padding(mpt.params.inputs[i]);
            }

            // if(function.complete()){
            //     status = PACKAGE;
            //     auto data = function.packed_to_data();
            //     cout << to_hex_string(data) << endl;
            // }        
        }

        ByteData getStatus() const {
            return statusMap[status];
        }

        h256 hash() const {
            return eevm::keccak_256(eevm::to_bytes(codeHash));
        }

        void set_status(Status status) {
            this->status = status;
        }

    private:
        ByteString   data;
    };

    

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
        PrivacyPolicyTransaction(const rpcparams::SendPrivacyPolicy &p) {
            from = p.from;
            to = p.to;
            verifierAddr = p.verifierAddr;
            codeHash = p.codeHash;
            pdata =eevm::to_bytes( p.policy);
            policy = Utils::parse<Policy>(p.policy);
            policy.sign_funtions_name();
            LOG_DEBUG_FMT("PrivacyPolicyTransaction info: {}\n", info());
        }

        void to_privacyPolicyModules_call(CloakTransaction1 &tc, const ByteData &name) const {
            tc.from = from;
            tc.to = to;
            tc.verifierAddr = verifierAddr;
            tc.codeHash = codeHash;
            tc.states = policy.states;
            tc.function = policy.get_funtions(name);
        }

        void checkMptParams(const MultiPartyTransaction1& mpt) const {
            policy::Function func = policy.get_funtions(mpt.params.name());
            for (auto&& i : mpt.params.inputs) {
                bool found = false;
                for (auto&& pi : func.inputs) {
                    if (i.name == pi.name) {
                        found = true;
                        if (pi.owner != "all" && to_uint256(pi.owner) != mpt.from) {
                            throw std::logic_error(fmt::format("param:{} is not valid", i.name));
                        }
                    }
                }
                if (!found) {
                    throw std::logic_error(fmt::format("param:{} not found", i.name));
                }
            }
        }

        h256 hash() const {
            return eevm::keccak_256(pdata);
        }

        std::string to_hex_hash() const {
            return to_hex_string(hash());
        }
        
        std::string info() const {
            return fmt::format("from: {}, to: {}, codeHash: {} \n \
                    policy:{}\n", from, to, codeHash, policy.info());
        }
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

        // 添加用户的交易内容，即合约函数的入参
        void set_content(const std::vector<policy::MultiInput> &inputs)
        {
            // 检查用户的交易输入，合法性校验
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

        // 添加多方参与的交易内容，即合约定义的全局变量，未考虑
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