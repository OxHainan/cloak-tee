// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.

#include "ccf/crypto/key_pair.h"

#include "openssl/key_pair.h"
#include "openssl/public_key.h"
#include "secp256k1/key_pair.h"
#include "secp256k1/public_key.h"

#include <cstring>
#include <iomanip>
#include <limits>
#include <memory>
#include <string>

namespace crypto
{
using PublicKeyImpl = PublicKey_OpenSSL;
using KeyPairImpl = KeyPair_OpenSSL;

PublicKeyPtr make_public_key(const Pem& pem)
{
    return std::make_shared<PublicKeyImpl>(pem);
}

PublicKeyPtr make_public_key(const std::vector<uint8_t>& der)
{
    return std::make_shared<PublicKeyImpl>(der);
}

PublicKeyPtr make_public_key_from_raw(const std::vector<uint8_t>& raw)
{
    return std::make_shared<PublicKey_k1Bitcoin>(key_from_raw_ec_point(raw, NID_secp256k1));
}

KeyPairPtr make_key_pair(CurveID curve_id)
{
    if (curve_id == CurveID::SECP256K1)
        return std::make_shared<KeyPair_k1Bitcoin>(curve_id);
    return std::make_shared<KeyPairImpl>(curve_id);
}

KeyPairPtr make_key_pair(const Pem& pem)
{
    return std::make_shared<KeyPairImpl>(pem);
}
}
