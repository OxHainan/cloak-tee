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
#include "abi/exception.h"
#include "app/utils.h"
#include "iostream"
#include "math.h"
#include "vector"

namespace abicoder
{
std::vector<uint8_t> sub_vector(const std::vector<uint8_t>& inputs, const size_t& begin = 0, const size_t& offset = 32u)
{
    if (offset > inputs.size()) {
        throw ABIException(fmt::format("Insufficient array length, want [{}] get [{}]", offset, inputs.size()));
    }

    return std::vector<uint8_t>(inputs.begin() + begin, inputs.begin() + offset);
}

inline double alignSize(const size_t& size)
{
    return 32 * (ceil(size / 32.0));
}

void insert(std::vector<uint8_t>& coder, const std::vector<uint8_t>& input, size_t offset = 0)
{
    for (size_t i = offset, x = 0; x < input.size(); x++, i++) {
        coder.at(i) = input.at(x);
    }
}

inline void to_array(
    std::vector<uint8_t>& result, const std::vector<uint8_t>& value, size_t offset = 0, bool signal = true)
{
    if (signal) {
        for (size_t i = offset, x = 0; x < value.size(); i++, x++) {
            result.at(i) = value.at(x);
        }
        return;
    }
    for (size_t i = offset, x = value.size() - 1; i < result.size() && x >= 0; i++, x--) {
        result.at(i) = value.at(x);
    }
}

inline void to_array(std::vector<uint8_t>& result, const uint8_t& value, size_t offset)
{
    result.at(offset) = value;
}

std::vector<uint8_t> to_bytes(const std::string& _s, size_t offset = 0, bool boolean = true)
{
    auto s = eevm::strip(_s);
    if (s.size() > 64) {
        throw ABIException(fmt::format("Invalid length, want {} but get {}", 32, s.size()));
    }
    std::vector<uint8_t> h(32);
    if (!boolean)
        h.resize(ceil(s.size() / 2.0));
    if (s.empty())
        return h;
    for (size_t i = 0; i < offset; i++) {
        h.at(i) = 0;
    }

    for (size_t x = 0; x < s.size(); offset++, x += 2) {
        if (offset >= h.size()) {
            throw ABIException(
                fmt::format("Handle encoding string to uint8 array error, "
                            "offset out of maximum range 32"));
        }
        h.at(offset) = strtol(s.substr(x, 2).c_str(), 0, 16);
    }
    return h;
}

const std::vector<uint8_t> bytes_strip(const std::string& src)
{
    if (src.size() >= 2 && src[1] == 'x') {
        return eevm::to_bytes(src);
    }
    return std::vector<uint8_t>(src.begin(), src.end());
}

std::vector<uint8_t> string_to_bytes(const std::string& _s)
{
    auto s = Utils::BinaryToHex(_s);
    std::vector<uint8_t> h(ceil(s.size() / 2.0));
    if (s.empty())
        return h;
    for (size_t offset = 0, x = 0; x < s.size(); offset++, x += 2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(), 0, 16);
    }
    return h;
}

inline nlohmann::json make_array_type(const nlohmann::json& j, const std::vector<size_t>& num = {})
{
    if (!num.size())
        return array_type(j, 0);
    return array_type::make_array_type(j, num);
}

inline nlohmann::json make_number_array(
    const bool isSigned = false, const size_t& len = 256, const std::vector<size_t>& num = {})
{
    auto type = number_type(isSigned, len);
    return make_array_type(type, num);
}

inline nlohmann::json make_bytes_array(const size_t& len = 0, const std::vector<size_t>& num = {})
{
    auto type = common_type("bytes", len);
    return make_array_type(type, num);
}

inline nlohmann::json make_common_array(const std::string& t, const std::vector<size_t>& num = {})
{
    auto type = common_type(t);
    return make_array_type(type, num);
}

inline std::vector<std::string> split_abi_data(const std::vector<uint8_t>& data)
{
    std::vector<std::string> res;
    size_t count = data.size() / 32;
    for (size_t i = 0; i < count; i++) {
        res.push_back(eevm::to_hex_string({data.begin() + i * 32, data.begin() + (i + 1) * 32}));
    }
    if (data.size() % 32) {
        res.push_back(eevm::to_hex_string({data.begin() + count * 32, data.end()}));
    }
    return res;
}

inline std::string split_abi_data_to_str(const std::vector<uint8_t>& data)
{
    return fmt::format("{}", fmt::join(split_abi_data(data), "\n"));
}

inline size_t get_static_array_size(const nlohmann::json& type)
{
    if (type["type"] != "array" || !type.contains("len")) {
        return 1;
    }
    return type["len"].get<size_t>() * get_static_array_size(type["value_type"]);
}

} // namespace abicoder
