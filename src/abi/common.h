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
#include "vector"
// eEVM
#include <eEVM/bigint.h>
#include <eEVM/util.h>

namespace abicoder {
using uint256 = intx::uint256;

static constexpr auto ADDRESS = "address";
static constexpr auto UINT = "uint";
static constexpr auto INT = "int";
static constexpr auto BOOL = "bool";
static constexpr auto STRING = "string";
static constexpr auto BYTES = "bytes";
static constexpr auto FIXED = "fixed";
static constexpr auto UFIXED = "ufixed";

struct PackParams {
    bool Dynamic;
    std::vector<uint8_t> data;
};

struct abiParams {
    std::string name;
    std::string type;
};

}  // namespace abicoder
