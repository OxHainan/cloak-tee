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

#include "abi/types/array.h"
#include "abi/types/type.h"

namespace abicoder {

class Decoder {
 public:
    Decoder() {}

    void add_params(const std::string& _name, const std::string& _type) {
        abi.push_back({_name, _type});
        auto coder = entry_identity(_type);
        coders.push_back(coder);
    }

    void decode(const std::vector<uint8_t>& inputs, size_t offset = 0u) {
        for (size_t i = 0; i < coders.size(); i++) {
            if (coders[i]->dynamicType()) {
                // calc offset
                auto jump = decode_to_uint64(inputs, offset, 32u + offset);
                CLOAK_DEBUG_FMT("jump: {}", jump);
                coders[i]->decode(std::vector<uint8_t>(inputs.begin() + jump, inputs.end()));
            } else {
                coders[i]->decode(std::vector<uint8_t>(inputs.begin() + offset, inputs.end()));
            }
            offset += coders[i]->offset();
            CLOAK_DEBUG_FMT("current offset {}", offset);
        }
    }

    ~Decoder() {
        // delete coders;
        for (size_t i = 0; i < coders.size(); i++) {
            if (coders[i] != nullptr) {
                delete coders[i];
            }
        }
    }

 private:
    std::vector<Type*> coders;
    std::vector<abiParams> abi;
};

}  // namespace abicoder
