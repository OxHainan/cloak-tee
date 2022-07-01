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
#include "vector"

namespace Utils
{
inline std::string BinaryToHex(const std::string& strBin, bool bIsUpper = false)
{
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

} // namespace Utils
