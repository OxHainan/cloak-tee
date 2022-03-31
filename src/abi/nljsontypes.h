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
#include "json_utils.h"
namespace abicoder
{
inline void from_json(const nlohmann::json& j, array_type& s)
{
    evm4ccf::require_object(j);
    s.type = j["type"];
    s.next = j["value_type"];
    const auto it = j.find("len");
    if (it != j.end() && !it->is_null()) {
        s.len = it->get<size_t>();
    }
}

inline void to_json(nlohmann::json& j, const array_type& s)
{
    j = nlohmann::json::object();
    j["type"] = s.type;
    j["value_type"] = s.next;
    if (s.len.has_value() && s.len.value() != 0) {
        j["len"] = s.len.value();
    }
}

inline void from_json(const nlohmann::json& j, number_type& s)
{
    evm4ccf::require_object(j);
    s.bit_size = j["bit_size"].get<size_t>();
    s.Signed = j["signed"].get<bool>();
    s.type = j["type"];
}

inline void to_json(nlohmann::json& j, const number_type& s)
{
    j = nlohmann::json::object();
    j["type"] = s.type;
    j["bit_size"] = s.bit_size;
    j["signed"] = s.Signed;
}

inline void from_json(const nlohmann::json& j, common_type& s)
{
    evm4ccf::require_object(j);
    s.type = j["type"];
    const auto it = j.find("len");
    if (it != j.end() && !it->is_null()) {
        s.len = it->get<size_t>();
        s.dynamic = true;
    }
}

inline void to_json(nlohmann::json& j, const common_type& s)
{
    j = nlohmann::json::object();
    j["type"] = s.type;
    if (s.len.has_value() && s.len.value() != 0) {
        j["len"] = s.len.value();
    }
}

} // namespace abicoder
