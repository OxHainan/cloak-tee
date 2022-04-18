// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "ccf/crypto/hkdf.h"
#include "ccf/crypto/key_pair.h"
#include "ccf/crypto/symmetric_key.h"
#include "crypto/key_exchange.h"
#include "ethereum_transaction.h"
namespace State
{
class SecretKey
{
 private:
    tls::KeyExchangeContext ctx;
    static const size_t shared_key_size = 32u;

 public:
    SecretKey() = delete;
    SecretKey(const crypto::KeyPairPtr& owner, const crypto::PublicKeyPtr& user) : ctx(owner, user) {}
    SecretKey(const crypto::KeyPairPtr& owner, const std::vector<uint8_t>& user_raw_key) :
      SecretKey(owner, crypto::make_public_key_from_raw(user_raw_key))
    {}

    std::unique_ptr<crypto::KeyAesGcm> compute_shared_secret()
    {
        auto shared_key = ctx.compute_shared_secret();
        const auto bytes = crypto::hkdf(crypto::MDType::SHA256, shared_key_size, shared_key, {}, {});
        return crypto::make_key_aes_gcm(bytes);
    }

    eevm::Address compute_data_owner() const
    {
        auto pubKey = ctx.get_peer_key_share();
        auto bytes = std::vector<uint8_t>(pubKey.begin() + 1, pubKey.end());
        return evm4ccf::get_address_from_public_key(bytes);
    }
};

using SecretKeyPtr = std::shared_ptr<SecretKey>;

} // namespace State