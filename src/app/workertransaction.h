#pragma once
#include "iostream"
#include "string"
#include "vector"
#include "utils.h"
#include "map"
#include "rpc_types.h"
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

        h256 hash() const {
            return parmas.getHash();
        }  
        private:
            ByteString          data;
    };

    struct PrivacyPolicyTransaction
    {
    public:
        Address             from;
        Address             verifierAddr;
        ByteData            codeHash;
        Policy              policy;
        Status              status;
        std::map<Address, MultiPartyTransaction> multiParty ;
        PrivacyPolicyTransaction(){}
        PrivacyPolicyTransaction(const rpcparams::SendPrivacyPolicy &p) {
            from = p.from;
            verifierAddr = p.verifierAddr;
            codeHash = p.codeHash;
            data = eevm::to_bytes(p.policy);
            policy = Utils::parse<Policy>(p.policy);
        }
        PrivacyPolicyTransaction(Address _from, Address _verifierAddr, ByteData _codeHash, Policy p){
            from = _from;
            verifierAddr = _verifierAddr;
            codeHash = _codeHash;
            policy = p;
        }

        std::tuple<bool, ByteData> insertMultiParty(MultiPartyTransaction &mpt) {
            multiParty.insert(std::make_pair(mpt.from, mpt));
            return policy.paddingToPolicy(mpt.parmas);
        }

        h256 hash() const {
            return eevm::keccak_256(data);
        }

        std::string to_hex_hash() const {
            return to_hex_string(hash());
        }
        
        uint8_t getStatus() const {
            return status;
        }

        private:
            ByteString          data;
    };

   

} // namespace evm4ccf
