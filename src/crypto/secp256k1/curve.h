// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#pragma once
#include "ccf/ds/logger.h"
#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#include <secp256k1/include/secp256k1.h>
#include <secp256k1/include/secp256k1_recovery.h>
namespace crypto::secp256k1
{
    enum class CurveImpl
    {
        secp256k1_mbedtls = 1,
        secp256k1_bitcoin = 2
    };
    static constexpr bool prefer_bitcoin_secp256k1 = true;

    inline mbedtls_ecp_group_id get_ec_for_curve_impl(CurveImpl curve)
    {
        switch (curve)
        {
            case CurveImpl::secp256k1_mbedtls:
            case CurveImpl::secp256k1_bitcoin:
                return MBEDTLS_ECP_DP_SECP256K1;
            default:
                throw std::logic_error(
                  "Unhandled curve type: " +
                  std::to_string(static_cast<size_t>(curve)));
        }
    }

    inline mbedtls_md_type_t get_md_for_ec(
      mbedtls_ecp_group_id ec, bool allow_nonce = false)
    {
        switch (ec)
        {
            case MBEDTLS_ECP_DP_SECP256K1:
                return MBEDTLS_MD_SHA256;

            default:
            {
                if (allow_nonce)
                {
                    return MBEDTLS_MD_NONE;
                }
                else
                {
                    const auto curve_info =
                      mbedtls_ecp_curve_info_from_grp_id(ec);
                    const auto error = fmt::format(
                      "Unhandled ecp group id: {}",
                      curve_info ? curve_info->name :
                                   fmt::format("UNKNOWN ({})", (size_t)ec));
                    throw std::logic_error(error);
                }
            }
        }
    }

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
        if (
          secp256k1_ecdsa_signature_parse_der(
            ctx, &sig, signature, signature_size) != 1)
            return false;
        secp256k1_ecdsa_signature norm_sig;
        if (secp256k1_ecdsa_signature_normalize(ctx, &norm_sig, &sig) == 1)
        {
            LOG_TRACE_FMT("secp256k1 normalized a signature to lower-S form");
        }

        return secp256k1_ecdsa_verify(ctx, &norm_sig, hash, pubKey) == 1;
    }

    static void secp256k1_illegal_callback(const char* str, void*)
    {
        throw std::logic_error(
          fmt::format("[libsecp256k1] illegal argument: {}", str));
    }

    inline mbedtls_ecp_group_id get_ec_from_context(
      const mbedtls_pk_context& ctx)
    {
        return mbedtls_pk_ec(ctx)->grp.id;
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
} // namespace crypto::secp256k1
