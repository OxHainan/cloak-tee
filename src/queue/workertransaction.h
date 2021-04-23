#pragma once
#include "ds/logger.h"
#include "fmt/core.h"
#include "iostream"
#include "string"
#include "vector"
#include "../app/utils.h"
#include "map"
#include "rpc_types.h"
#include <eEVM/bigint.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include <ethereum_transaction.h>
#include <stdexcept>

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
    public:
        size_t nonce;
        Address from;
        Address to;
        eevm::rlp::ByteString          data;
        uint8_t v;
        uint256_t r;
        uint256_t s;
        policy::MultiPartyParams parmas;

        MultiPartyTransaction(const SendMultiPartyTransaction& s) {
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
            parmas = Utils::parse<policy::MultiPartyParams>(std::get<3>(res));
            CLOAK_DEBUG_FMT("nonce:{}, from:{}, to:{}, data:{} ,data hex:{}, v:{}, r:{}, s:{}", nonce, from, to, std::get<3>(res), to_hex_string(data), v, r, this->s);
        }

        void checkSignature() {
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
            return parmas.name();
        }
        // h256 hash() const {
        //     return parmas.getHash();
        // }  
    };

    struct CloakTransaction {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        policy::Function    function;
        std::vector<policy::Params> states;
        Status              status = PENDING;
        std::map<Address, MultiPartyTransaction> multiParty ;

        void insert(MultiPartyTransaction &mpt) {
            multiParty.insert(std::make_pair(mpt.from, mpt));
            for (size_t i = 0; i < mpt.parmas.inputs.size(); i++)
            {
                function.padding(mpt.parmas.inputs[i]);
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
        rpcparams::Policy              policy;
        PrivacyPolicyTransaction(){}
        PrivacyPolicyTransaction(const rpcparams::SendPrivacyPolicy &p) {
            from = p.from;
            to = p.to;
            verifierAddr = p.verifierAddr;
            codeHash = p.codeHash;
            data = eevm::to_bytes(p.policy);
            policy = Utils::parse<Policy>(p.policy);
            policy.sign_funtions_name();
            LOG_DEBUG_FMT("PrivacyPolicyTransaction info: {}\n", info());
        }

        void to_privacyPolicyModules_call(CloakTransaction &tc, const ByteData &name) const {
            tc.from = from;
            tc.to = to;
            tc.verifierAddr = verifierAddr;
            tc.codeHash = codeHash;
            tc.states = policy.states;
            tc.function = policy.get_funtions(name);
        }

        h256 hash() const {
            return eevm::keccak_256(data);
        }

        std::string to_hex_hash() const {
            return to_hex_string(hash());
        }

        std::string info() const {
            return fmt::format("from: {}, to: {}, codeHash: {} \n \
                    policy:{}\n", from, to, codeHash, policy.info());
        }

        private:
            ByteString          data;
    };
} // namespace evm4ccf
