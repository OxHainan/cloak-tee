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

class Coder {
 public:
    static std::vector<uint8_t> pack(const std::vector<TypePrt>& coders) {
        if (coders.size() < 1)
            return {};
        std::vector<PackParams> parts;
        parts.resize(coders.size());
        for (size_t i = 0; i < coders.size(); i++) {
            parts[i] = {coders[i]->dynamicType(), coders[i]->encode()};
        }
        return basic_pack(parts);
    }

 private:
    static std::vector<uint8_t> basic_pack(std::vector<PackParams>& parts) {
        size_t staticSize = 0, dynamicSize = 0;
        for (auto part : parts) {
            if (part.Dynamic) {
                staticSize += 32;
                dynamicSize += alignSize(part.data.size());
            } else {
                staticSize += alignSize(part.data.size());
            }
        }

        size_t offset = 0, dynamicOffset = staticSize;
        std::vector<uint8_t> data(staticSize + dynamicSize);

        for (auto part : parts) {
            if (part.Dynamic) {
                to_array(data, encode_to_vector(dynamicOffset), offset);
                offset += 32u;
                to_array(data, part.data, dynamicOffset);
                dynamicOffset += alignSize(part.data.size());
            } else {
                to_array(data, part.data, offset);
                offset += alignSize(part.data.size());
            }
        }
        return data;
    }
};

}  // namespace abicoder
