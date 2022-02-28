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

    inline std::string HexToBin(const std::string& _strHex)
    {
        if (_strHex.size() % 2 != 0)
        {
            return "";
        }
        auto strHex = eevm::strip(_strHex);

        std::string strBin;
        strBin.resize(strHex.size() / 2);
        for (size_t i = 0; i < strBin.size(); i++)
        {
            uint8_t cTemp = 0;
            for (size_t j = 0; j < 2; j++)
            {
                char cCur = strHex[2 * i + j];
                if (cCur >= '0' && cCur <= '9')
                {
                    cTemp = (cTemp << 4) + (cCur - '0');
                }
                else if (cCur >= 'a' && cCur <= 'f')
                {
                    cTemp = (cTemp << 4) + (cCur - 'a' + 10);
                }
                else if (cCur >= 'A' && cCur <= 'F')
                {
                    cTemp = (cTemp << 4) + (cCur - 'A' + 10);
                }
                else
                {
                    return "";
                }
            }
            strBin[i] = cTemp;
        }

        return strBin;
    }

    template <typename T>
    inline void parse(const std::string& s, T& v)
    {
        auto j = nlohmann::json::parse(HexToBin(s));
        v = j.get<T>();
    }
    template <typename T>
    inline T parse(const std::string& s)
    {
        auto j = nlohmann::json::parse(HexToBin(s));
        return j.get<T>();
    }

    inline eevm::KeccakHash to_KeccakHash(const std::string& _s)
    {
        auto s = eevm::strip(_s);
        eevm::KeccakHash h;
        if (s.empty())
            return h;
        for (size_t i = 0, x = 0; i < 32; i++, x += 2)
        {
            h.at(i) = strtol(s.substr(x, 2).c_str(), 0, 16);
        }
        return h;
    }

    inline eevm::KeccakHash vec_to_KeccakHash(const std::vector<uint8_t>& data)
    {
        eevm::KeccakHash res;
        std::copy(data.begin(), data.end(), res.begin());
        return res;
    }

    inline uint256_t vec32_to_uint256(const std::vector<uint8_t>& v)
    {
        return eevm::from_big_endian(v.data(), v.size());
    }

    inline std::string to_lower(const std::string& str)
    {
        std::string res(str.size(), ' ');
        std::transform(str.begin(), str.end(), res.begin(), ::towlower);
        return res;
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

    inline std::vector<uint8_t> make_function_selector(const std::string& sign)
    {
        auto sha3 = eevm::keccak_256(sign);
        return {sha3.begin(), sha3.begin() + 4};
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
        // crypto::KeyAesGcm key_aes_gcm(key);
        std::vector<uint8_t> res(data.size());
        std::vector<uint8_t> tag(crypto::GCM_SIZE_TAG);
        key_aes_gcm->encrypt(iv, data, {}, res.data(), tag.data());
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
              iv, data.data() + c_size, {data.data(), c_size}, {}, res.data()))
        {
            LOG_DEBUG_FMT("decryption failed, please check your data");
            throw std::logic_error("decryption failed, please check your data");
        }
        return res;
    }

} // namespace Utils
