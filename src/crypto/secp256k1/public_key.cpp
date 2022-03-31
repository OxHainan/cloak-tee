#include "crypto/secp256k1/public_key.h"

#include "crypto/openssl/hash.h"
#include "crypto/openssl/openssl_wrappers.h"
#include "crypto/openssl/public_key.h"
#include "crypto/secp256k1/curve.h"
// #include "crypto/secp256k1/public_key.h"
#include "eEVM/keccak256.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
namespace crypto
{
PublicKey_k1Bitcoin::PublicKey_k1Bitcoin() {}

PublicKey_k1Bitcoin::PublicKey_k1Bitcoin(const Pem& pem)
{
    OpenSSL::Unique_BIO mem(pem);
    key = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL);
    if (!key)
        throw std::runtime_error("could not parse PEM");
}

PublicKey_k1Bitcoin::PublicKey_k1Bitcoin(const std::vector<uint8_t>& der)
{
    OpenSSL::Unique_BIO buf(der);
    key = d2i_PUBKEY_bio(buf, &key);
    if (!key)
        throw std::runtime_error("could not read DER");
}

PublicKey_k1Bitcoin::PublicKey_k1Bitcoin(EVP_PKEY* key) : key(key) {}

PublicKey_k1Bitcoin::~PublicKey_k1Bitcoin()
{
    if (key)
        EVP_PKEY_free(key);
}

CurveID PublicKey_k1Bitcoin::get_curve_id() const
{
    int nid = get_secp256k1_group_id();
    if (nid != NID_secp256k1)
        throw std::runtime_error(fmt::format("Unknown SECP256K1 curve, get {}", nid));
    return CurveID::SECP256K1;
}

int PublicKey_k1Bitcoin::get_secp256k1_group_id(CurveID gid) const
{
    if (gid != CurveID::SECP256K1)
        throw std::runtime_error(fmt::format("unsupported SECP256K1 CurveID {}", gid));
    return NID_secp256k1;
}

int PublicKey_k1Bitcoin::get_secp256k1_group_id() const
{
    return EC_GROUP_get_curve_name(EC_KEY_get0_group(EVP_PKEY_get0_EC_KEY(key)));
}

bool PublicKey_k1Bitcoin::verify(
    const uint8_t* contents,
    size_t contents_size,
    const uint8_t* sig,
    size_t sig_size,
    MDType md_type,
    HashBytes& bytes)
{
    if (md_type == MDType::NONE) {
        md_type = get_md_for_ec(get_curve_id());
    }

    bytes = eevm::Keccak256(contents, contents_size).HashBytes();

    return verify_hash(bytes.data(), bytes.size(), sig, sig_size, md_type);
}

bool PublicKey_k1Bitcoin::verify_hash(
    const uint8_t* hash, size_t hash_size, const uint8_t* sig, size_t sig_size, MDType md_type)
{
    if (md_type == MDType::NONE) {
        md_type = get_md_for_ec(get_curve_id());
    }

    OpenSSL::Unique_EVP_PKEY_CTX pctx(key);
    OpenSSL::CHECK1(EVP_PKEY_verify_init(pctx));
    if (md_type != MDType::NONE) {
        OpenSSL::CHECK1(EVP_PKEY_CTX_set_signature_md(pctx, OpenSSL::get_md_type(md_type)));
    }
    int rc = EVP_PKEY_verify(pctx, sig, sig_size, hash, hash_size);

    bool ok = rc == 1;
    if (!ok) {
        int ec = ERR_get_error();
        LOG_DEBUG_FMT("OpenSSL signature verification failure: {}", OpenSSL::error_string(ec));
    }

    return ok;
}

PublicKey_k1Bitcoin PublicKey_k1Bitcoin::recover_key(const RecoverableSignature& rs, std::span<const uint8_t> hashed)
{
    int rc;
    static size_t buf_len = 65;
    std::vector<uint8_t> buf(buf_len);
    if (hashed.size() != 32)
        throw std::runtime_error(fmt::format("Expected {} bytes in hash, got {}", 32, hashed.size()));

    // recover with secp256k1
    {
        auto ctx = secp256k1::make_bc_context(SECP256K1_CONTEXT_VERIFY);
        secp256k1_ecdsa_recoverable_signature sig;
        rc = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx->p, &sig, rs.raw.data(), rs.recovery_id);
        if (rc != 1)
            throw std::runtime_error("secp256k1 recoverable signature failed");

        secp256k1_pubkey pubk;
        rc = secp256k1_ecdsa_recover(ctx->p, &pubk, &sig, hashed.data());
        if (rc != 1)
            throw std::runtime_error("secp256k1 recover failed");

        rc = secp256k1_ec_pubkey_serialize(ctx->p, buf.data(), &buf_len, &pubk, SECP256K1_EC_UNCOMPRESSED);
        if (rc != 1)
            throw std::runtime_error("secp256k1 pubkey serialization failed");
    }

    // recover key into openssl context

    PublicKey_k1Bitcoin pubkey;
    pubkey.key = key_from_raw_ec_point(buf, NID_secp256k1);
    return pubkey;
}

Pem PublicKey_k1Bitcoin::public_key_pem() const
{
    OpenSSL::Unique_BIO buf;

    OpenSSL::CHECK1(PEM_write_bio_PUBKEY(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return Pem((uint8_t*)bptr->data, bptr->length);
}

std::vector<uint8_t> PublicKey_k1Bitcoin::public_key_der() const
{
    OpenSSL::Unique_BIO buf;

    OpenSSL::CHECK1(i2d_PUBKEY_bio(buf, key));

    BUF_MEM* bptr;
    BIO_get_mem_ptr(buf, &bptr);
    return {bptr->data, bptr->data + bptr->length};
}

std::vector<uint8_t> PublicKey_k1Bitcoin::public_key_raw() const
{
    OpenSSL::Unique_BIO buf;

    unsigned char* p = NULL;
    size_t n = i2d_PublicKey(key, &p);

    std::vector<uint8_t> r;
    if (p) {
        r = {p, p + n};
    }
    free(p);
    return r;
}

}