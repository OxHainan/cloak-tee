// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "ccf/ds/logger.h"
#include "crypto/secp256k1/entropy.h"
#include "crypto/secp256k1/error_string.h"
#include "crypto/secp256k1/key_pair.h"

#include <iostream>
#include <map>
#include <mbedtls/ecdh.h>

namespace crypto::secp256k1
{
    class KeyExchangeContext
    {
      private:
        mbedtls_ecdh_context ctx;
        std::vector<uint8_t> own_public;
        crypto::secp256k1::EntropyPtr entropy;

      public:
        static constexpr mbedtls_ecp_group_id domain_parameter =
          MBEDTLS_ECP_DP_SECP384R1;

        static constexpr size_t len_public = 1024 + 1;
        static constexpr size_t len_shared_secret = 1024;

        KeyExchangeContext() : own_public(len_public), entropy(create_entropy())
        {
            mbedtls_ecdh_init(&ctx);
            size_t len;

            int rc = mbedtls_ecp_group_load(&ctx.grp, domain_parameter);

            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }

            rc = mbedtls_ecdh_make_public(
              &ctx,
              &len,
              own_public.data(),
              own_public.size(),
              entropy->get_rng(),
              entropy->get_data());

            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }

            own_public.resize(len);
        }

        KeyExchangeContext(KeyPairPtr own_kp, PublicKeyPtr peer_pubk) :
          entropy(create_entropy())
        {
            mbedtls_ecdh_init(&ctx);

            int rc = mbedtls_ecdh_get_params(
              &ctx,
              mbedtls_pk_ec(*own_kp->get_raw_context()),
              MBEDTLS_ECDH_OURS);
            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }

            rc = mbedtls_ecdh_get_params(
              &ctx,
              mbedtls_pk_ec(*peer_pubk->get_raw_context()),
              MBEDTLS_ECDH_THEIRS);
            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }
        }

        void free_ctx()
        {
            // Should only be called when shared secret has been computed.
            mbedtls_ecdh_free(&ctx);
        }

        ~KeyExchangeContext()
        {
            free_ctx();
        }

        std::vector<uint8_t> get_own_public()
        {
            // Note that this function returns a vector of bytes
            // where the first byte represents the
            // size of the public key
            return own_public;
        }

        void load_peer_public(const uint8_t* bytes, size_t size)
        {
            int rc = mbedtls_ecdh_read_public(&ctx, bytes, size);
            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }
        }

        std::vector<uint8_t> compute_shared_secret()
        {
            // Should only be called once, when peer public has been loaded.
            std::vector<uint8_t> shared_secret(len_shared_secret);
            size_t len;
            int rc = mbedtls_ecdh_calc_secret(
              &ctx,
              &len,
              shared_secret.data(),
              shared_secret.size(),
              entropy->get_rng(),
              entropy->get_data());
            if (rc != 0)
            {
                throw std::logic_error(error_string(rc));
            }

            shared_secret.resize(len);

            return shared_secret;
        }
    };
}
