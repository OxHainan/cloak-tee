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
#include "ds/json.h"
#include "ds/logger.h"

namespace Pop {

using ProposalId = uint64_t;
using Time = uint64_t;
using BlockHash = uint256_t;

struct SendSetup {
    ProposalId proposalId;
    Time timestamp;
    BlockHash blockHash;
};

DECLARE_JSON_TYPE(SendSetup)
DECLARE_JSON_REQUIRED_FIELDS(SendSetup, proposalId, timestamp, blockHash)

struct SendComplete {
    BlockHash blockHash;
    Time timestamp;
    nlohmann::json body;
};

DECLARE_JSON_TYPE(SendComplete)
DECLARE_JSON_REQUIRED_FIELDS(SendComplete, blockHash, timestamp, body)

enum class State { UNCOMMITTED, SETUP, COMPLETE, FAILED };

DECLARE_JSON_ENUM(State,
                  {
                      {State::UNCOMMITTED, "uncommitted"},
                      {State::SETUP, "setup"},
                      {State::COMPLETE, "complete"},
                      {State::FAILED, "failed"},
                  })

struct ProposalInfo {
    State state;
    Time createTime;
    Time completeTime;
    BlockHash blockHash;
    MSGPACK_DEFINE(state, createTime, completeTime, blockHash);

    bool validate() {
        if (completeTime < createTime)
            return false;

        if (completeTime - createTime > 10 * 6)
            return false;
        return true;
    }
};

DECLARE_JSON_TYPE(ProposalInfo)
DECLARE_JSON_REQUIRED_FIELDS(ProposalInfo, state, createTime, completeTime, blockHash)

struct Result {
    std::string message;
    uint256_t transactionHash;
    MSGPACK_DEFINE(message, transactionHash);
};

struct GetProposal {
    std::optional<ProposalId> proposalId = std::nullopt;
    std::optional<BlockHash> blockHash = std::nullopt;
};

inline void from_json(const nlohmann::json& j, GetProposal& s) {
    const auto it = j.find("proposalId");
    if (it != j.end() && !it->is_null()) {
        s.proposalId = *it;
    }

    const auto it2 = j.find("blockHash");
    if (it2 != j.end() && !it2->is_null()) {
        s.blockHash = eevm::to_uint256(*it2);
    }
}

} // namespace Pop

MSGPACK_ADD_ENUM(Pop::State);
