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
#include "eEVM/util.h"

namespace evm4ccf {
template <size_t N>
inline void array_from_hex_string(std::array<uint8_t, N>& a, const std::string& s) {
    const auto stripped = eevm::strip(s);

    if (stripped.size() != N * 2) {
        throw std::logic_error(
            fmt::format("Expected {} characters, got {}", N * 2, stripped.size()));
    }

    for (auto i = 0; i < N; i++) {
        a[i] = static_cast<uint8_t>(strtoul(stripped.substr(i * 2, 2).c_str(), nullptr, 16));
    }
}

template <typename T>
inline void from_to_str(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (it == j.end() || it->is_null() || (it->is_string() && it->get<std::string>().empty()))
        return;
    v = *it;
}

template <typename T>
inline void from_to_array(const nlohmann::json& j, const std::string& s, T& v) {
    std::string vs;
    from_to_str(j, s, vs);
    if (!vs.empty()) {
        v = eevm::to_bytes(vs);
    }
}

template <typename T>
inline void from_optional_hex_str(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (it == j.end() || it->is_null() || (it->is_string() && it->get<std::string>().empty())) {
        // Don't change v from default
        return;
    } else {
        v = eevm::to_uint256(*it);
    }
}

inline void require_object(const nlohmann::json& j) {
    if (!j.is_object()) {
        throw std::invalid_argument(fmt::format("Expected object, got: {}", j.dump()));
    }
}

inline void require_array(const nlohmann::json& j) {
    if (!j.is_array()) {
        throw std::invalid_argument(fmt::format("Expected array, got: {}", j.dump()));
    }
}

template <typename T>
inline void from_array_to_object(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (it != j.end() && !it->is_null()) {
        require_array(*it);
        auto tem = it->get<T>();
        for (int i = 0; i < tem.size(); i++) {
            v.push_back(tem[i]);
        }
    }
}

} // namespace evm4ccf
