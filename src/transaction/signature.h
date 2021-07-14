#pragma once

#include "../app/tables.h"
#include "kv/map.h"
#include "kv/store.h"
#include "ethereum_transaction.h"
#include "../queue/workertransaction.h"
#include "../app/utils.h"
#include "signature_abstract.h"
#include "../app/tables.h"
namespace evm4ccf
{
    struct PrivacyTransaction
    {
    protected:
        PrivacyTransaction() {}

    public:
        eevm::rlp::ByteString to;
        eevm::rlp::ByteString verifierAddr;
        eevm::rlp::ByteString codeHash;
        eevm::rlp::ByteString data;

        PrivacyTransaction(const rpcparams::SendPrivacyPolicy& tc)
        {
            to = encode_optional_address(tc.to);
            verifierAddr = encode_optional_address(tc.verifierAddr);
            codeHash = eevm::to_bytes(tc.codeHash);
            data = eevm::to_bytes(tc.policy);
        }

        PrivacyTransaction(const eevm::rlp::ByteString& encoded)
        {
            auto tup = eevm::rlp::decode<
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString>(encoded);
            to = std::get<0>(tup);
            verifierAddr = std::get<1>(tup);
            codeHash = std::get<2>(tup);
            data = std::get<3>(tup);
        }

        eevm::rlp::ByteString encode() const
        {
            return eevm::rlp::encode(to, verifierAddr, codeHash, data);
        }

        virtual eevm::KeccakHash to_be_signed() const
        {
            return eevm::keccak_256(encode());

        }

        void to_transaction(PrivacyPolicyTransaction& tc) const
        {
            tc.to = eevm::from_big_endian(to.data(), 20u);
            tc.verifierAddr = eevm::from_big_endian(verifierAddr.data(), 20u);
            tc.codeHash = eevm::to_hex_string(codeHash);
            tc.policy = Utils::parse<Policy>(eevm::to_hex_string(data));
        }
    };
    
    struct PrivacyTransactionWithSignature : public SignatureAbstract, public PrivacyTransaction
    {
        PrivacyTransactionWithSignature(const eevm::rlp::ByteString& encoded)
        {
            auto tup = eevm::rlp::decode<
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                uint8_t,
                PointCoord,
                PointCoord>(encoded);

            to = std::get<0>(tup);
            verifierAddr = std::get<1>(tup);
            codeHash = std::get<2>(tup);
            data = std::get<3>(tup);
            v = std::get<4>(tup);
            r = std::get<5>(tup);
            s = std::get<6>(tup);
        }

        PrivacyTransactionWithSignature(
            const PrivacyTransaction& tx, const tls::RecoverableSignature& sig) :           
            SignatureAbstract(sig),
            PrivacyTransaction(tx)
        {

        }

        eevm::rlp::ByteString encode() const
        {
            return eevm::rlp::encode(to, verifierAddr, codeHash, data, v, r, s);
        }

        eevm::KeccakHash to_be_signed() const override
        {
            if(is_pre_eip_155(v))
                return PrivacyTransaction::to_be_signed();
            
            return eevm::keccak_256(eevm::rlp::encode(
                to, verifierAddr, codeHash, data, current_chain_id, 0, 0
            ));
        }

        eevm::KeccakHash calc_policy_hash() const
        {
            return eevm::keccak_256(data);
        }

        eevm::KeccakHash to_transaction_call(PrivacyPolicyTransaction& tc) const
        {
            PrivacyTransaction::to_transaction(tc);
            const auto tbs = to_be_signed();
            tc.from = SignatureAbstract::signatureAndVerify(tbs);
            return calc_policy_hash();
        }
    };
    
    inline PrivacyTransactionWithSignature sign_transaction(
        tls::KeyPair_k1Bitcoin& kp, const PrivacyTransaction& tx)
    {
        const auto tbs = tx.to_be_signed();
        const auto sig = kp.sign_recoverable_hashed({tbs.data(), tbs.size()});
        return PrivacyTransactionWithSignature(tx, sig);
    }

    struct CloakTransaction
    {
    protected:
        CloakTransaction() {}
    
    public:
        size_t nonce;
        eevm::rlp::ByteString to;
        eevm::rlp::ByteString data;

        CloakTransaction(const eevm::rlp::ByteString& encoded)
        {
            auto tup = eevm::rlp::decode<
                size_t,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString>(encoded);
            nonce = std::get<0>(tup);
            to = std::get<1>(tup);
            data = std::get<2>(tup);
        }

        eevm::rlp::ByteString encode() const
        {
            return eevm::rlp::encode(nonce, to, data);
        }

        virtual eevm::KeccakHash to_be_signed() const
        {
            return eevm::keccak_256(encode());
        }

        virtual void to_transaction_call(MultiPartyTransaction& mpt) const
        {
            mpt.to = eevm::from_big_endian(to.data(), 20u);
            mpt.nonce = nonce;
            mpt.params = Utils::parse<policy::MultiPartyParams>(eevm::to_hex_string(data));
        }
    };
    
    struct CloakTransactionWithSignature : public SignatureAbstract, public CloakTransaction
    {
        CloakTransactionWithSignature(const eevm::rlp::ByteString& encoded)
        {
            auto tup = eevm::rlp::decode<
                size_t,
                eevm::rlp::ByteString,
                eevm::rlp::ByteString,
                uint8_t,
                PointCoord,
                PointCoord>(encoded);
            
            nonce = std::get<0>(tup);
            to = std::get<1>(tup);
            data = std::get<2>(tup);
            v = std::get<3>(tup);
            r = std::get<4>(tup);
            s = std::get<5>(tup);
        }

        CloakTransactionWithSignature(
            const CloakTransaction& tx, const tls::RecoverableSignature& sig) :
            SignatureAbstract(sig),
            CloakTransaction(tx)
        {}

        eevm::rlp::ByteString encode() const
        {
            return eevm::rlp::encode(nonce, to, data, v, r, s);
        }

        eevm::KeccakHash digest() const
        {
            return eevm::keccak_256(encode());
        }

        eevm::KeccakHash to_be_signed() const override
        {
            if (is_pre_eip_155(v))
            {
                return CloakTransaction::to_be_signed();
            }

            return eevm::keccak_256(eevm::rlp::encode(
                nonce, to, data, current_chain_id, 0, 0
            ));
        }

        void to_transaction_call(MultiPartyTransaction& mpt) const override
        {
            CloakTransaction::to_transaction_call(mpt);
            const auto tbs = to_be_signed();
            mpt.from = SignatureAbstract::signatureAndVerify(tbs);
        }
    };  
} // namespace evm4ccf
