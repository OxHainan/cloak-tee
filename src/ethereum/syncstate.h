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
#include "app/utils.h"
#include "eEVM/address.h"
#include "eEVM/keccak256.h"
#include "eEVM/util.h"
#include "json_utils.h"
#include "vector"
namespace Ethereum
{
    struct SyncStateResponse
    {
        eevm::Keccak256 tx_hash;
        std::vector<uint8_t> data;
        std::optional<eevm::Address> from = std::nullopt;
        std::optional<eevm::Address> to = std::nullopt;

        SyncStateResponse() = default;

        SyncStateResponse(
          const eevm::Keccak256& hash, const std::vector<uint8_t>& data_) :
          tx_hash(hash),
          data(data_)
        {}

        SyncStateResponse(
          const eevm::Keccak256& hash,
          const eevm::Address& from_,
          const eevm::Address& to_,
          const std::vector<uint8_t>& data_) :
          tx_hash(hash),
          data(data_),
          from(from_),
          to(to_)
        {}

        friend void to_json(nlohmann::json& j, const SyncStateResponse& s);
        friend void from_json(const nlohmann::json& j, SyncStateResponse& s);
    };

    inline void to_json(nlohmann::json& j, const SyncStateResponse& s)
    {
        j = nlohmann::json::object();
        j["tx_hash"] = s.tx_hash;

        if (s.from.has_value())
        {
            j["from"] = eevm::to_checksum_address(s.from.value());
        }

        if (s.to.has_value())
        {
            j["to"] = eevm::to_checksum_address(s.to.value());
        }

        j["data"] = eevm::to_hex_string(s.data);
    }

    inline void from_json(const nlohmann::json& j, SyncStateResponse& s)
    {
        evm4ccf::require_object(j);
        s.tx_hash = j["tx_hash"];
        evm4ccf::from_optional_hex_str(j, "from", s.from);
        evm4ccf::from_optional_hex_str(j, "to", s.to);
        s.data = eevm::to_bytes(j["data"]);
    }

} // namespace Ethereum
