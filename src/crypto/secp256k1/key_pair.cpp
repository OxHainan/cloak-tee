#include "crypto/openssl/key_pair.h"

#include "crypto/openssl/openssl_wrappers.h"
#include "curve.h"
#include "eEVM/util.h"
#include "key_pair.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
namespace crypto
{
KeyPair_k1Bitcoin::KeyPair_k1Bitcoin(CurveID curve_id)
{
    int curve_nid = get_secp256k1_group_id(curve_id);
    key = EVP_PKEY_new();
    OpenSSL::Unique_EVP_PKEY_CTX pkctx;
    if (EVP_PKEY_paramgen_init(pkctx) < 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pkctx, curve_nid) < 0 ||
        EVP_PKEY_CTX_set_ec_param_enc(pkctx, OPENSSL_EC_NAMED_CURVE) < 0)
        throw std::runtime_error("could not initialize PK context");
    if (EVP_PKEY_keygen_init(pkctx) < 0 || EVP_PKEY_keygen(pkctx, &key) < 0)
        throw std::runtime_error("could not generate new EC key");
}

KeyPair_k1Bitcoin::KeyPair_k1Bitcoin(const Pem& pem)
{
    OpenSSL::Unique_BIO mem(pem);
    key = PEM_read_bio_PrivateKey(mem, NULL, NULL, nullptr);
    if (!key)
        throw std::runtime_error("could not parse PEM");
}

Pem KeyPair_k1Bitcoin::private_key_pem() const
{
    OpenSSL::Unique_BIO buf;
    OpenSSL::CHECK1(
        PEM_write_bio_PrivateKey(buf, key, NULL, NULL, 0, NULL, NULL));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
}

std::vector<uint8_t> KeyPair_k1Bitcoin::private_key_der() const
{
    OpenSSL::Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PrivateKey_bio(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
}

std::vector<uint8_t> KeyPair_k1Bitcoin::private_key_raw() const
{
    OpenSSL::Unique_BIO buf;
    unsigned char* p = NULL;
    size_t n = i2d_PrivateKey(key, &p);
    std::vector<uint8_t> r;
    if (p) {
        r = {p + 7, p + 39};
    }
    free(p);
    return r;
}

Pem KeyPair_k1Bitcoin::public_key_pem() const
{
    return PublicKey_k1Bitcoin::public_key_pem();
}

std::vector<uint8_t> KeyPair_k1Bitcoin::public_key_der() const
{
    return PublicKey_k1Bitcoin::public_key_der();
}

bool KeyPair_k1Bitcoin::verify(
    const std::vector<uint8_t>& contents, const std::vector<uint8_t>& signature)
{
    // return PublicKey_k1Bitcoin::verify(contents, signature);
    return true;
}

bool KeyPair_k1Bitcoin::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* signature,
    size_t signature_size)
{
    // return PublicKey_k1Bitcoin::verify(contents, contents_size, signature,
    // signature_size);
    return true;
}

std::vector<uint8_t> KeyPair_k1Bitcoin::public_key_raw() const
{
    return PublicKey_k1Bitcoin::public_key_raw();
}

CurveID KeyPair_k1Bitcoin::get_curve_id() const
{
    return PublicKey_k1Bitcoin::get_curve_id();
}

std::vector<uint8_t> KeyPair_k1Bitcoin::sign(
    std::span<const uint8_t> d, MDType md_type) const
{
    return {};
}
int KeyPair_k1Bitcoin::sign(
    std::span<const uint8_t> d,
    size_t* sig_size,
    uint8_t* sig,
    MDType md_type) const
{
    return 0;
}

std::vector<uint8_t> KeyPair_k1Bitcoin::sign_hash(
    const uint8_t* hash, size_t hash_size) const
{
    if (hash_size != 32)
        throw std::runtime_error(
            fmt::format("Expected {} bytes in hash, got {}", 32, hash_size));

    auto bc_ctx = secp256k1::make_bc_context(
        SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_recoverable_signature ret;
    int rc = secp256k1_ecdsa_sign_recoverable(
        bc_ctx->p, &ret, hash, private_key_raw().data(), nullptr, nullptr);
    if (rc != 1) {
        throw std::runtime_error("secp256k1_ecdsa_sign_recoverable failed");
    }

    RecoverableSignature rs;
    rc = secp256k1_ecdsa_recoverable_signature_serialize_compact(
        bc_ctx->p, rs.raw.data(), &rs.recovery_id, &ret);
    if (rc != 1) {
        throw std::runtime_error(
            "secp256k1_ecdsa_recoverable_signature_serialize_compact failed");
    }

    return rs.serialise();
}

int KeyPair_k1Bitcoin::sign_hash(
    const uint8_t* hash, size_t hash_size, size_t* sig_size, uint8_t* sig) const
{
    auto bc_ctx = secp256k1::make_bc_context(
        SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN);
    secp256k1_ecdsa_recoverable_signature ret;
    int rc = secp256k1_ecdsa_sign_recoverable(
        bc_ctx->p, &ret, hash, private_key_raw().data(), nullptr, nullptr);
    if (rc != 1) {
        throw std::runtime_error("secp256k1_ecdsa_sign_recoverable failed");
    }

    std::memcpy(sig, ret.data, 65);
    return 0;
}

std::vector<uint8_t> KeyPair_k1Bitcoin::derive_shared_secret(
    const PublicKey& peer_key)
{
    auto cid = peer_key.get_curve_id();
    int nid = PublicKey_k1Bitcoin::get_secp256k1_group_id(cid);
    auto pk = key_from_raw_ec_point(peer_key.public_key_raw(), nid);

    std::vector<uint8_t> shared_secret;
    size_t shared_secret_length = 0;
    OpenSSL::Unique_EVP_PKEY_CTX ctx(key);
    OpenSSL::CHECK1(EVP_PKEY_derive_init(ctx));
    OpenSSL::CHECK1(EVP_PKEY_derive_set_peer(ctx, pk));
    OpenSSL::CHECK1(EVP_PKEY_derive(ctx, NULL, &shared_secret_length));
    shared_secret.resize(shared_secret_length);
    OpenSSL::CHECK1(
        EVP_PKEY_derive(ctx, shared_secret.data(), &shared_secret_length));

    EVP_PKEY_free(pk);
    return shared_secret;
}
PublicKey::Coordinates KeyPair_k1Bitcoin::coordinates() const
{
    return KeyPair_k1Bitcoin::coordinates();
}
}
