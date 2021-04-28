#pragma once
#include "iostream"
#include "string"
#include "vector"
#include "../app/utils.h"
#include "map"
#include "rpc_types.h"
#include "ethereum_transaction.h"
#include "../msgpack/address.h"
#include "../msgpack/policy.h"

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
        Address from;
        Address to;
        policy::MultiPartyParams parmas;

        MultiPartyTransaction(const SendMultiPartyTransaction& s) {
            from = s.from;
            to = s.to;
            data = eevm::to_bytes(s.params);
            parmas = Utils::parse<policy::MultiPartyParams>(s.params);
        }
        
        ByteData name() const {
            return parmas.name();
        }
        // h256 hash() const {
        //     return parmas.getHash();
        // }  
        private:
            ByteString          data;
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

            if(function.complete()){
                status = PACKAGE;
                auto data = function.packed_to_data();
                cout << to_hex_string(data) << endl;
            }        
        }

        ByteData getStatus() const {
            return statusMap[status];
        }

        h256 hash() const {
            return eevm::keccak_256(eevm::to_bytes(codeHash));
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
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, policy);
        PrivacyPolicyTransaction(){}
        PrivacyPolicyTransaction(const rpcparams::SendPrivacyPolicy &p) {
            from = p.from;
            to = p.to;
            verifierAddr = p.verifierAddr;
            codeHash = p.codeHash;
            pdata =eevm::to_bytes( p.policy);
            policy = Utils::parse<Policy>(p.policy);
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
            return eevm::keccak_256(pdata);
        }

        void serialized(uint8_t* &data, size_t &size) {
            serialized::write(data, size, from);
            serialized::write(data, size, to);
            serialized::write(data, size, verifierAddr);
            serialized::write(data, size, codeHash);
            serialized::write(data, size, policy);
            // serialized::write(data, size, pdata.data(), pdata.size());
        }

        static PrivacyPolicyTransaction deserialize(
            const uint8_t* &data, size_t &size ) 
        {
            PrivacyPolicyTransaction p;
            p.from =serialized::read<Address>(data,size);
            p.to = serialized::read<Address>(data,size);
            p.verifierAddr = serialized::read<Address>(data,size);
            p.codeHash = serialized::read<std::string>(data,size);
            p.policy = serialized::read<rpcparams::Policy>(data,size);
            // p.policy = Utils::parse<Policy>((char*)p.pdata.data());
            return p;
        }

        std::string to_hex_hash() const {
            return to_hex_string(hash());
        }

        // private:
            ByteString          pdata;
    };
} // namespace evm4ccf
