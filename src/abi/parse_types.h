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
#include "common.h"

namespace abicoder {
BTypePtr parse_types(const nlohmann::json& j) {
    if (j.is_null() || j.is_string()) {
        return nullptr;
    }

    type_value type = j["type"];
    switch (type) {
        case type_value::NUMBER: {
            auto v = j.get<number_type>();
            return v.get_value();
            break;
        }
        case type_value::ARRAY: {
            auto v = j.get<array_type>();
            return v.get_value();
            break;
        }
        case type_value::ADDRESS:
        case type_value::BOOL:
        case type_value::STRING:
        case type_value::BYTES: {
            auto v = j.get<common_type>();
            return v.get_value();
            break;
        }
        case type_value::FOUNDNOT:
            throw std::logic_error(fmt::format("{} can`t parsing", j["type"]));

        default:
            break;

            throw std::logic_error(fmt::format("{} can`t parsing", type));
    }
}

bool check_dynamic(const nlohmann::json& j) {
    auto v = parse_types(j);
    if (v->dynamic) {
        return v->dynamic;
    }
    if (v->name.is_string() || v->name.is_null()) {
        return false;
    }

    return check_dynamic(v->name);
}

} // namespace abicoder
