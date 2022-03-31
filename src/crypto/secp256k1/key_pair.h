#pragma once
#include "ccf/crypto/key_pair.h"
#include "crypto/secp256k1/public_key.h"
namespace crypto
{
class KeyPair_k1Bitcoin : public PublicKey_k1Bitcoin, public KeyPair
{
 public:
    KeyPair_k1Bitcoin(CurveID curve_id);
    KeyPair_k1Bitcoin(const KeyPair_k1Bitcoin&) = delete;
    KeyPair_k1Bitcoin(const Pem& pem);
    virtual ~KeyPair_k1Bitcoin() = default;

    virtual Pem private_key_pem() const override;
    virtual std::vector<uint8_t> private_key_der() const override;
    std::vector<uint8_t> private_key_raw() const;
    virtual Pem public_key_pem() const override;
    virtual std::vector<uint8_t> public_key_der() const override;
    using PublicKey_k1Bitcoin::verify;

    virtual bool verify(const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature) override;

    virtual bool verify(
        const uint8_t* contents, size_t contents_size, const uint8_t* signature, size_t signature_size) override;

    virtual std::vector<uint8_t> public_key_raw() const override;

    virtual CurveID get_curve_id() const override;
    virtual std::vector<uint8_t> sign(std::span<const uint8_t> d, MDType md_type = {}) const override;

    int sign(std::span<const uint8_t> d, size_t* sig_size, uint8_t* sig, MDType md_type = {}) const;

    std::vector<uint8_t> sign_hash(const uint8_t* hash, size_t hash_size) const override;

    virtual int sign_hash(const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const override;
    RecoverableSignature sign_recoverable_hashed(const std::span<const uint8_t> hashed);

    virtual std::vector<uint8_t> derive_shared_secret(const PublicKey& peer_key) override;
};
}