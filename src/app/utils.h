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
#include "crypto/symmetric_key.h"
#include "ds/logger.h"
#include "fmt/core.h"
#include "nlohmann/json.hpp"
#include "tls/key_exchange.h"
#include "tls/key_pair.h"
#include "vector"

#include <mbedtls/hkdf.h>

// eEVM
#include <eEVM/address.h>
#include <eEVM/util.h>

#ifdef CLOAK_DEBUG_LOGGING
#    define CLOAK_DEBUG_FMT(...) LOG_INFO_FMT(__VA_ARGS__)
#else
#    define CLOAK_DEBUG_FMT(...)
#endif

#ifndef LOG_AND_THROW
#    define LOG_AND_THROW(...) \
        do { \
            CLOAK_DEBUG_FMT(__VA_ARGS__); \
            throw std::logic_error(fmt::format(__VA_ARGS__)); \
        } while (false);
#endif

namespace Utils {
inline std::string BinaryToHex(const std::string& strBin, bool bIsUpper = false) {
    std::string strHex;
    strHex.resize(strBin.size() * 2);
    for (size_t i = 0; i < strBin.size(); i++) {
        uint8_t cTemp = strBin[i];
        for (size_t j = 0; j < 2; j++) {
            uint8_t cCur = (cTemp & 0x0f);
            if (cCur < 10) {
                cCur += '0';
            } else {
                cCur += ((bIsUpper ? 'A' : 'a') - 10);
            }
            strHex[2 * i + 1 - j] = cCur;
            cTemp >>= 4;
        }
    }
    return strHex;
}

inline std::string HexToBin(const std::string& _strHex) {
    if (_strHex.size() % 2 != 0) {
        return "";
    }
    auto strHex = eevm::strip(_strHex);

    std::string strBin;
    strBin.resize(strHex.size() / 2);
    for (size_t i = 0; i < strBin.size(); i++) {
        uint8_t cTemp = 0;
        for (size_t j = 0; j < 2; j++) {
            char cCur = strHex[2 * i + j];
            if (cCur >= '0' && cCur <= '9') {
                cTemp = (cTemp << 4) + (cCur - '0');
            } else if (cCur >= 'a' && cCur <= 'f') {
                cTemp = (cTemp << 4) + (cCur - 'a' + 10);
            } else if (cCur >= 'A' && cCur <= 'F') {
                cTemp = (cTemp << 4) + (cCur - 'A' + 10);
            } else {
                return "";
            }
        }
        strBin[i] = cTemp;
    }

    return strBin;
}

template <typename T>
inline void parse(const std::string& s, T& v) {
    auto j = nlohmann::json::parse(HexToBin(s));
    v = j.get<T>();
}
template <typename T>
inline T parse(const std::string& s) {
    auto j = nlohmann::json::parse(HexToBin(s));
    return j.get<T>();
}

inline eevm::KeccakHash to_KeccakHash(const std::string& _s) {
    auto s = eevm::strip(_s);
    eevm::KeccakHash h;
    if (s.empty())
        return h;
    for (size_t i = 0, x = 0; i < 32; i++, x += 2) {
        h.at(i) = strtol(s.substr(x, 2).c_str(), 0, 16);
    }
    return h;
}

inline eevm::KeccakHash vec_to_KeccakHash(const std::vector<uint8_t>& data) {
    eevm::KeccakHash res;
    std::copy(data.begin(), data.end(), res.begin());
    return res;
}

inline uint256_t vec32_to_uint256(const std::vector<uint8_t>& data) {
    return eevm::to_uint256(eevm::to_hex_string(data));
}

inline std::vector<std::string> stringToArray(const std::string& s) {
    std::vector<std::string> arr;
    for (size_t i = 1; i < s.size(); i++) {
        size_t j = i;
        for (; j < s.size(); j++) {
            if (s[j] == ',' || s[j] == ']')
                break;
        }
        arr.push_back(std::string(s.substr(i + 1, j - i - 2)));
        i = j;
    }
    return arr;
}

inline std::string to_lower(const std::string& str) {
    std::string res(str.size(), ' ');
    std::transform(str.begin(), str.end(), res.begin(), ::towlower);
    return res;
}

inline std::vector<uint8_t> get_random_id() {
    return tls::create_entropy()->random(256);
}

inline void cloak_agent_log(const std::string& tag, const nlohmann::json& msg) {
    std::string magic_str = "ShouokOn";
    nlohmann::json j;
    j["seq"] = 0;
    j["tag"] = tag;
    j["message"] = msg;
    LOG_INFO_FMT("{}{}{}", magic_str, j.dump(), magic_str);
}

inline std::vector<uint8_t> make_function_selector(const std::string& sign) {
    auto sha3 = eevm::keccak_256(sign);
    return {sha3.begin(), sha3.begin() + 4};
}

// generate symmetric key using ECDH and HKDF
inline std::vector<uint8_t> generate_symmetric_key(tls::KeyPairPtr kp, const tls::Pem& pk_pem) {
    auto pk = tls::make_public_key(pk_pem);
    auto ctx = tls::KeyExchangeContext(kp, pk);
    auto ikm = ctx.compute_shared_secret();
    auto info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    std::vector<uint8_t> key(256);
    mbedtls_hkdf(info, NULL, 0, ikm.data(), ikm.size(), NULL, 0, key.data(), key.size());
    return key;
}

using Bytes = std::vector<uint8_t>;
inline std::pair<Bytes, Bytes> encrypt_data_s(tls::KeyPairPtr kp,
                                              const tls::Pem& pk_pem,
                                              const std::vector<uint8_t>& iv,
                                              const std::vector<uint8_t>& data) {
    auto key = generate_symmetric_key(kp, pk_pem);
    crypto::KeyAesGcm key_aes_gcm(key);
    std::vector<uint8_t> res(data.size());
    std::vector<uint8_t> tag(crypto::GCM_SIZE_TAG);
    key_aes_gcm.encrypt(iv, data, {}, res.data(), tag.data());
    return {res, tag};
}

inline std::vector<uint8_t> decrypt_data(tls::KeyPairPtr kp,
                                         const tls::Pem& pk_pem,
                                         const std::vector<uint8_t>& iv,
                                         const std::vector<uint8_t>& data) {
    auto key = generate_symmetric_key(kp, pk_pem);
    crypto::KeyAesGcm key_aes_gcm(key);
    size_t c_size = data.size() - crypto::GCM_SIZE_TAG;
    std::vector<uint8_t> res(c_size);
    if (!key_aes_gcm.decrypt(iv, data.data() + c_size, {data.data(), c_size}, {}, res.data())) {
        LOG_AND_THROW("decryption failed, please check your data");
    }
    return res;
}

inline std::pair<Bytes, Bytes> split_tag_and_iv(const Bytes& ti) {
    Bytes tag{ti.begin(), ti.begin() + crypto::GCM_SIZE_TAG};
    Bytes iv{ti.begin() + crypto::GCM_SIZE_TAG,
             ti.begin() + crypto::GCM_SIZE_TAG + crypto::GCM_SIZE_IV};
    return {tag, iv};
}
} // namespace Utils
