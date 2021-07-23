#pragma once
#include "tables.h"
#include "signature.h"
#include <eEVM/util.h>
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
                CLOAK_DEBUG_FMT("privacy digests already exists (digests {})", eevm::to_hex_string(digests.value()));
                throw std::logic_error(fmt::format(
                    "privacy digests already exists (digests {})", eevm::to_hex_string(digests.value())
                ));
            }

            p->put(hash, tc);
            pd->put(tc.to, hash);
            LOG_INFO_FMT("add privacy digests {}", eevm::to_hex_string(hash));
            return hash;
        }

        auto add_cloakTransaction(const eevm::rlp::ByteString& encoded)
        {
            const auto decoded = CloakTransactionWithSignature(encoded);
            MultiPartyTransaction mpt;
            decoded.to_transaction_call(mpt);

            auto [cp, cd, mp, an] = tx.get_view(
                tables.cloak_policys, tables.cloak_digests, tables.multi_partys, tables.nonces
            );

            // mpt hash
            auto multi_digest = decoded.digest();
            
            if (mpt.check_transaction_type())
            {
                eevm::KeccakHash target_digest = Utils::vec_to_KeccakHash(mpt.to);
                auto cpt = cp->get(target_digest);
                if (!cpt.has_value())
                {
                    throw std::logic_error(fmt::format(
                        "multi party transaction digests doesn't exists (digests {})", eevm::to_hex_string(target_digest)
                    ));
                }
                cpt->set_content(mpt.params.inputs);
                return multi_digest;
                // TODO: add_multi_party
            }
            
            Address to = eevm::from_big_endian(mpt.to.data(), 20u);
            CLOAK_DEBUG_FMT("to: {}", to_checksum_address(to));
            PrivacyPolicyTransaction ppt = check_privacy_modules(to);
            
            // check nonce
            auto nonce = an->get(mpt.from);
            if (!nonce.has_value())
            {
                an->put(mpt.from, 0);
            } else if (nonce.value() > mpt.nonce)
            {
                throw std::logic_error(fmt::format("nonce too low"));
            }

            CloakPolicyTransaction cpt(ppt, mpt.name(), multi_digest);

            cpt.set_content(mpt.params.inputs);
            cp->put(multi_digest, cpt);
            cd->put(to, multi_digest);
            LOG_INFO_FMT("add user transaction digests {}", eevm::to_hex_string(multi_digest));

            if (cpt.function.complete()) {
                cpt.request_old_state(tx);
            }
            return multi_digest;
        }

    private:
        PrivacyPolicyTransaction check_privacy_modules(const Address& to)
        {
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
                    "privacy module doesn`t exists (privacy digests {})",
                    eevm::to_hex_string(privacy_digests.value())));
            }

            return ppt.value_or(PrivacyPolicyTransaction{});
        }

        // eevm::KeccakHash add_multi_party(const MultiPartyTransaction& mpt)
        // {
        //     LOG_INFO_FMT("add multi party transaction digests {}", eevm::to_hex_string(d));
        //     return d;
        // }
    };
    
} // namespace evm4ccf
