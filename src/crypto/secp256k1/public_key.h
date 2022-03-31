#pragma once
#include "ccf/crypto/public_key.h"
#include "ccf/crypto/recover.h"

#include <openssl/evp.h>
namespace crypto
{
class PublicKey_k1Bitcoin : public PublicKey
{
 protected:
    EVP_PKEY* key = nullptr;
    PublicKey_k1Bitcoin();

 public:
    PublicKey_k1Bitcoin(PublicKey_k1Bitcoin&& key) = default;
    PublicKey_k1Bitcoin(EVP_PKEY* key);
    PublicKey_k1Bitcoin(const Pem& pem);
    PublicKey_k1Bitcoin(const std::vector<uint8_t>& der);
    virtual ~PublicKey_k1Bitcoin();
    using PublicKey::verify;
    using PublicKey::verify_hash;
    bool verify(
        const uint8_t* contents,
        size_t contents_size,
        const uint8_t* sig,
        size_t sig_size,
        MDType md_type,
        HashBytes& bytes) override;

    virtual bool verify_hash(
        const uint8_t* hash, size_t hash_size, const uint8_t* sig, size_t sig_size, MDType md_type) override;

    CurveID get_curve_id() const override;
    int get_secp256k1_group_id(CurveID id) const;
    int get_secp256k1_group_id() const;
    Pem public_key_pem() const override;
    std::vector<uint8_t> public_key_der() const override;
    std::vector<uint8_t> public_key_raw() const override;

    static PublicKey_k1Bitcoin recover_key(const RecoverableSignature& rs, std::span<const uint8_t> hashed);
};
}