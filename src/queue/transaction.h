#pragma once
#include "transaction_tables.h"

namespace evm4ccf
{
    class TransactionGenerator
    {
    private:
        TransactionTables& tables;
        kv::Tx& tx;
    public:
        TransactionGenerator(TransactionTables& _tables, kv::Tx& _tx) :
            tables(_tables),
            tx(_tx)
        {}

        ~TransactionGenerator()
        {}

        auto add_privacy(const eevm::rlp::ByteString& encoded)
        {
            const auto decoded = PrivacyTransactionWithSignature(encoded);
            PrivacyPolicyTransaction tc;
            auto hash = decoded.to_transaction_call(tc);
            auto [p, pd] = tx.get_view(tables.privacys, tables.privacy_digests);
            auto digests = pd->get(tc.to);
            if (digests.has_value()) 
            {
                throw std::logic_error(fmt::format(
                    "privacy digests already exists (digests {})", eevm::to_hex_string(digests.value())
                ));
            }

            p->put(hash, tc);
            pd->put(tc.to, hash);
            LOG_INFO_FMT("add privacy digests {}", eevm::to_hex_string(hash));
            // 返回隐私模型hash
            return hash;
        }

        auto add_cloakTransaction(const eevm::rlp::ByteString& encoded)
        {
            const auto decoded = CloakTransactionWithSignature(encoded);
            MultiPartyTransaction1 mpt;
            decoded.to_transaction_call(mpt);

            // 检查该笔交易是用户交易还是多方交易
            auto [cp, cd, mp, an] = tx.get_view(
                tables.cloak_policys, tables.cloak_digests, tables.multi_partys, tables.nonces
            );

            auto multi_digest = decoded.digest();
            // 检查交易是否已经提交
            auto check_multi = mp->get(multi_digest);
            if (check_multi.has_value())
            {
                throw std::logic_error(fmt::format(
                    "multi party transaction digests already exists (digests {})", eevm::to_hex_string(multi_digest)
                ));
            }

            
            // 检查mpt参数是否与ppt匹配


            // 检查交易是否已经存储于cloak
            auto digest = cd->get(mpt.to);
            // 如果有值，说明是多方交易，进行多方交易流程
            // 如果没有值，则是用户交易，则开辟cloak交易
            if (digest.has_value())
            {
                // 多方交易，目前多方的逻辑暂未考虑
                return add_multi_party(multi_digest);
            }
            
            // 检查对应隐私模型是否存在
            PrivacyPolicyTransaction ppt = check_privacy_modules(mpt.to);

            // 检查用户的nonces, 未考虑到用户地址初始化问题，bug
            if ( an->get(mpt.from) > mpt.nonce)
            {
                throw std::logic_error(fmt::format("nonce too low"));
            }
            // 现在说明是用户交易，存储用户交易
            CloakPolicyTransaction cpt(ppt, mpt.name());

            // 检查用户的输入是否为目标合约函数中的输入字段
            cpt.set_content(mpt.params.inputs);
            // 存入到交易中
            cp->put(multi_digest, cpt);
            // 存入到kv中  
            cd->put(mpt.to, multi_digest);
            LOG_INFO_FMT("add user transaction digests {}", eevm::to_hex_string(multi_digest));
            return multi_digest;
        }

    private:
        PrivacyPolicyTransaction check_privacy_modules(const Address& to)
        {
            // 检查对应隐私模型是否存在
            auto [p, pd] = tx.get_view(
                tables.privacys, tables.privacy_digests
            );

            auto privacy_digests = pd->get(to);
            if (!privacy_digests.has_value()) 
            {
                throw std::logic_error(fmt::format(
                    "privacy digests doesn`t exists (contract address {})", eevm::to_hex_string(to)
                ));
            }

            auto ppt = p->get(privacy_digests.value());
            if (!ppt.has_value())
            {
                throw std::logic_error(fmt::format(
                    "privacy module doesn`t exists (privacy digests {})", eevm::to_hex_string(privacy_digests.value())
                ));
            }

            return ppt.value_or(PrivacyPolicyTransaction{});
        }

        eevm::KeccakHash add_multi_party(const eevm::KeccakHash& d)
        {
            LOG_INFO_FMT("add multi party transaction digests {}", eevm::to_hex_string(d));
            return d;
        }
    };
    
} // namespace evm4ccf
