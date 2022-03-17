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
#include "ccf/crypto/symmetric_key.h"
#include "crypto/secp256k1/key_exchange.h"
#include "crypto/secp256k1/key_pair.h"
#include "eEVM/address.h"
#include "eEVM/util.h"
#include "vector"

#include <mbedtls/hkdf.h>

namespace Utils
{
    inline std::string BinaryToHex(
      const std::string& strBin, bool bIsUpper = false)
    {
        std::string strHex;
        strHex.resize(strBin.size() * 2);
        for (size_t i = 0; i < strBin.size(); i++)
        {
            uint8_t cTemp = strBin[i];
            for (size_t j = 0; j < 2; j++)
            {
                uint8_t cCur = (cTemp & 0x0f);
                if (cCur < 10)
                {
                    cCur += '0';
                }
                else
                {
                    cCur += ((bIsUpper ? 'A' : 'a') - 10);
                }
                strHex[2 * i + 1 - j] = cCur;
                cTemp >>= 4;
            }
        }
        return strHex;
    }

    template <typename T>
    inline T parse(const std::vector<uint8_t>& s)
    {
        auto j = nlohmann::json::parse(s);
        return j.get<T>();
    }

    inline void cloak_agent_log(
      const std::string& tag, const nlohmann::json& msg)
    {
        std::string magic_str = "ShouokOn";
        nlohmann::json j;
        j["seq"] = 0;
        j["tag"] = tag;
        j["message"] = msg;
        LOG_INFO_FMT("{}{}{}", magic_str, j.dump(), magic_str);
    }

    inline std::string repeat_hex_string(const std::string& str, size_t n)
    {
        std::vector<uint8_t> res;
        auto tmp = eevm::to_bytes(str);
        for (size_t i = 0; i < n; i++)
        {
            res.insert(res.end(), tmp.begin(), tmp.end());
        }
        return eevm::to_hex_string(res);
    }

    template <typename T>
    inline std::vector<T> vector_filter(
      const std::vector<T>& vec, std::function<T(T&&)> f)
    {
        std::vector<T> res(vec.size());
        for (size_t i = 0; i < vec.size(); i++)
        {
            res[i] = f(vec[i]);
        }
        return res;
    }

    inline std::vector<std::string> split_string(
      const std::string& str, char delim)
    {
        std::vector<std::string> res;
        std::string tmp;
        for (auto ch : str)
        {
            if (ch == delim)
            {
                res.push_back(tmp);
                tmp.clear();
            }
            else
            {
                tmp.push_back(ch);
            }
        }

        res.push_back(tmp);
        return res;
    }
    using Bytes = std::vector<uint8_t>;

    inline std::pair<Bytes, Bytes> split_tag_and_iv(const Bytes& ti)
    {
        Bytes tag{ti.begin(), ti.begin() + crypto::GCM_SIZE_TAG};
        Bytes iv{ti.begin() + crypto::GCM_SIZE_TAG, ti.end()};
        return {tag, iv};
    }

    // generate symmetric key using ECDH and HKDF
    inline std::vector<uint8_t> generate_symmetric_key(
      crypto::secp256k1::KeyPairPtr kp, const std::vector<uint8_t>& pk_der)
    {
        auto pk = crypto::secp256k1::make_public_key(pk_der);
        auto ctx = crypto::secp256k1::KeyExchangeContext(kp, pk);
        auto ikm = ctx.compute_shared_secret();
        auto info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
        std::vector<uint8_t> key(32);
        mbedtls_hkdf(
          info,
          NULL,
          0,
          ikm.data(),
          ikm.size(),
          NULL,
          0,
          key.data(),
          key.size());
        return key;
    }
    inline std::pair<Bytes, Bytes> encrypt_data_s(
      crypto::secp256k1::KeyPairPtr kp,
      const std::vector<uint8_t>& pk_der,
      const std::vector<uint8_t>& iv,
      const std::vector<uint8_t>& data)
    {
        auto key = generate_symmetric_key(kp, pk_der);
        auto key_aes_gcm = crypto::make_key_aes_gcm(key);
        std::vector<uint8_t> res(data.size());
        std::vector<uint8_t> tag(crypto::GCM_SIZE_TAG);
        key_aes_gcm->encrypt(iv, data, {}, res, tag.data());
        return {res, tag};
    }

    inline std::vector<uint8_t> decrypt_data(
      crypto::secp256k1::KeyPairPtr kp,
      const std::vector<uint8_t>& pk_der,
      const std::vector<uint8_t>& iv,
      const std::vector<uint8_t>& data)
    {
        auto key = generate_symmetric_key(kp, pk_der);
        auto key_aes_gcm = crypto::make_key_aes_gcm(key);
        size_t c_size = data.size() - crypto::GCM_SIZE_TAG;
        std::vector<uint8_t> res(c_size);
        if (!key_aes_gcm->decrypt(
              iv, data.data() + c_size, {data.data(), c_size}, {}, res))
        {
            LOG_DEBUG_FMT("decryption failed, please check your data");
            throw std::logic_error("decryption failed, please check your data");
        }
        return res;
    }

} // namespace Utils
