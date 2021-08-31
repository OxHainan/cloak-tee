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

#include "../app/utils.h"
#include "abicoder.h"
#include "jsonrpc.h"

using namespace std;
using namespace eevm;
using namespace abicoder;

// 测试合约输入变量打包
int main() {
    vector<void*> coders;

    vector<ByteData> arrs;
    arrs.push_back("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");
    arrs.push_back("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");
    // arrs.push_back("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");

    abicoder::paramCoder(coders, "uint256", "uint", "0x123");
    abicoder::paramCoder(coders, "array", "address[]", arrs);
    abicoder::paramCoder(coders, "bytes", "bytes10", "1234567890");
    abicoder::paramCoder(coders, "Dbytes", "string", "Hello, world!");

    auto out1 = abicoder::pack(coders);
    cout << to_hex_string(out1) << endl;

    return 0;
}
