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

#include "secret_key.h"
#include "state_cipher.h"

#include <eEVM/address.h>
#include <eEVM/state.h>
namespace State
{
template <typename T, typename S>
class EncryptorManager : public eevm::AbstractStateEncryptor
{
 public:
    EncryptorManager(const std::shared_ptr<T>& shared_ctx_) :
      shared_ctx(shared_ctx_)
    {}

    bool encrypt(
        const std::vector<uint8_t>& plain,
        std::vector<uint8_t>& serial) override
    {
        S st(plain.size());
        set_extra_data(st);
        shared_ctx->compute_shared_secret()
            ->encrypt(st.hdr.get_iv(), plain, {}, st.cipher, st.hdr.tag);
        serial = st.serialise();
        return true;
    }

    bool decrypt(
        const std::vector<uint8_t>& serial_cipher,
        std::vector<uint8_t>& plain) override
    {
        S st;
        st.deserialise(serial_cipher);
        valid_data_owner(st);
        auto ret =
            shared_ctx->compute_shared_secret()
                ->decrypt(st.hdr.get_iv(), st.hdr.tag, st.cipher, {}, plain);
        if (!ret)
            plain.resize(0);

        return ret;
    }

 private:
    void set_extra_data(S& st)
    {
        auto owner = shared_ctx->compute_data_owner();
        st.set_owner(owner);
        st.hdr.set_random_iv();
    }

    void valid_data_owner(S& st) const
    {
        if (st.owner != shared_ctx->compute_data_owner()) {
            throw std::runtime_error(fmt::format(
                "Invalid data owner, want {} but get {}",
                eevm::to_hex_string(st.owner),
                eevm::to_hex_string(shared_ctx->compute_data_owner())));
        }
    }

    std::shared_ptr<T> shared_ctx;
};

using StateEncryptor = EncryptorManager<SecretKey, StateCipher>;

SecretKeyPtr make_secret_key(
    const crypto::KeyPairPtr& owner, const std::vector<uint8_t>& raw_key)
{
    return std::make_shared<SecretKey>(owner, raw_key);
}

eevm::EncryptorPtr make_encryptor(
    const crypto::KeyPairPtr& owner, const std::vector<uint8_t>& raw_key)
{
    auto shared_ctx = make_secret_key(owner, raw_key);
    return std::make_shared<StateEncryptor>(shared_ctx);
}

} // namespace State
