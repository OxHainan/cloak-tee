// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/logger.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
namespace crypto::secp256k1
{
inline bool verify_secp256k1_bc(
    secp256k1_context* ctx,
    const uint8_t* signature,
    size_t signature_size,
    const uint8_t* hash,
    size_t hash_size,
    const secp256k1_pubkey* pubKey)
{
    if (hash_size != 32)
        return false;
    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_der(
            ctx, &sig, signature, signature_size) != 1)
        return false;
    secp256k1_ecdsa_signature norm_sig;
    if (secp256k1_ecdsa_signature_normalize(ctx, &norm_sig, &sig) == 1) {
        LOG_TRACE_FMT("secp256k1 normalized a signature to lower-S form");
    }

    return secp256k1_ecdsa_verify(ctx, &norm_sig, hash, pubKey) == 1;
}

static void secp256k1_illegal_callback(const char* str, void*)
{
    throw std::logic_error(
        fmt::format("[libsecp256k1] illegal argument: {}", str));
}
class BCk1Context
{
 public:
    secp256k1_context* p = nullptr;

    BCk1Context(unsigned int flags)
    {
        p = secp256k1_context_create(flags);

        secp256k1_context_set_illegal_callback(
            p, secp256k1_illegal_callback, nullptr);
    }

    ~BCk1Context()
    {
        secp256k1_context_destroy(p);
    }
};

using BCk1ContextPtr = std::unique_ptr<BCk1Context>;

inline BCk1ContextPtr make_bc_context(unsigned int flags)
{
    return std::make_unique<BCk1Context>(flags);
}
} // namespace crypto
