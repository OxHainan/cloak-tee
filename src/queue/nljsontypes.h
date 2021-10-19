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

namespace evm4ccf {

namespace policy {

inline void from_json(const nlohmann::json& j, Function& s) {
    require_object(j);
    from_to_str(j, "name", s.name);
    from_to_str(j, "type", s.type);
    from_array_to_object(j, "inputs", s.inputs);
    from_to_array(j, "entry", s.entry);
    from_array_to_object(j, "read", s.read);
    from_array_to_object(j, "mutate", s.mutate);
    from_array_to_object(j, "outputs", s.outputs);
}

inline void to_json(nlohmann::json& j, const Function& s) {
    j = nlohmann::json::object();
    j["name"] = s.name;
    j["type"] = s.type;
    j["inputs"] = s.inputs;
    j["read"] = s.read;
    j["mutate"] = s.mutate;
    j["outputs"] = s.outputs;
}

} // namespace policy

namespace rpcparams {
//
inline void from_json(const nlohmann::json& j, Policy& s) {
    require_object(j);
    from_to_str(j, "contract", s.contract);
    from_array_to_object(j, "states", s.states);
    from_array_to_object(j, "functions", s.functions);
}

inline void to_json(nlohmann::json& j, const Policy& s) {
    j = nlohmann::json::object();
    j["contract"] = s.contract;
    j["states"] = s.states;
    j["functions"] = s.functions;
}

} // namespace rpcparams
} // namespace evm4ccf
