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

namespace Const {
// tables name
namespace TableNames {
inline constexpr auto TEE_MANAGER = "tee.manager";
}

namespace TEE_MANAGER_KEYS {
inline constexpr auto KP_SK = "kp_sk_pem";
inline constexpr auto PKI_ADDR = "pki_addr";
inline constexpr auto NONCE = "nonce";
}  // namespace TEE_MANAGER_KEYS
}  // namespace Const
