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
#include "iostream"
#include "json_utils.h"
#include "vector"
// eEVM
#include <eEVM/bigint.h>
#include <eEVM/util.h>

namespace abicoder {
using uint256 = intx::uint256;

inline constexpr auto ADDRESS = "address";
inline constexpr auto UINT = "uint";
inline constexpr auto INT = "int";
inline constexpr auto BOOL = "bool";
inline constexpr auto STRING = "string";
inline constexpr auto BYTES = "bytes";
inline constexpr auto FIXED = "fixed";
inline constexpr auto UFIXED = "ufixed";

inline constexpr auto ZERO_HEX_STR =
    "0x0000000000000000000000000000000000000000000000000000000000000000";

struct PackParams {
    bool Dynamic;
    std::vector<uint8_t> data;
};

struct abiParams {
    std::string name;
    std::string type;
};

enum class type_value { FOUNDNOT, ADDRESS, BOOL, BYTES, STRING, NUMBER, ARRAY };

NLOHMANN_JSON_SERIALIZE_ENUM(type_value,
                             {
                                 {type_value::FOUNDNOT, "null"},
                                 {type_value::ADDRESS, "address"},
                                 {type_value::BOOL, "bool"},
                                 {type_value::BYTES, "bytes"},
                                 {type_value::STRING, "string"},
                                 {type_value::NUMBER, "number"},
                                 {type_value::ARRAY, "array"},
                             })

struct base_type {
    nlohmann::json name;
    size_t length;
    bool dynamic;
    type_value type;

    base_type(const type_value& t, const nlohmann::json& j, const size_t& len, bool dynamic_) :
        type(t), name(j), length(len), dynamic(dynamic_) {}
};

using BTypePtr = std::shared_ptr<base_type>;

struct number_type {
    size_t bit_size;
    type_value type;
    bool Signed;
    number_type(const size_t& bit = 256, const bool Signed_ = false) :
        type(type_value::NUMBER), Signed(Signed_), bit_size(bit) {}

    BTypePtr get_value() const {
        return std::make_shared<base_type>(type, Signed ? "int" : "uint", bit_size, false);
    }
};

struct array_type {
    std::optional<size_t> len = std::nullopt;
    type_value type;
    nlohmann::json next;
    array_type() {}
    array_type(const nlohmann::json& j, const size_t& col) :
        type(type_value::ARRAY), next(j), len(col) {}

    BTypePtr get_value() const {
        return std::make_shared<base_type>(type, next, len.value_or(0), !len.has_value());
    }

    friend void from_json(const nlohmann::json& j, array_type& s);
    friend void to_json(nlohmann::json& j, const array_type& s);

    static nlohmann::json make_array_type(const nlohmann::json& j,
                                          const std::vector<size_t>& num,
                                          const size_t& i = 0) {
        if (i == num.size())
            return j;
        auto v = array_type(j, num[i]);
        return make_array_type(v, num, i + 1);
    }
};

struct common_type {
    type_value type;
    bool dynamic;
    std::optional<size_t> len = std::nullopt;
    common_type() = default;
    common_type(const nlohmann::json& type_, const size_t& len_ = 0) : type(type_), len(len_) {}

    BTypePtr get_value() const {
        switch (type) {
            case type_value::ADDRESS:
            case type_value::BOOL:
                return std::make_shared<base_type>(type, type, 0, false);
                break;
            case type_value::BYTES:
            case type_value::STRING:
                return std::make_shared<base_type>(type, type, len.value_or(0), true);
                break;
            default:
                break;
        }
        throw std::logic_error(fmt::format("{} can`t parsing", type));
    }
};

} // namespace abicoder

#include "nljsontypes.h"
