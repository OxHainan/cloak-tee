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
#include "kv/tx.h"
#include "types.h"
namespace Pop {
namespace tables {

inline constexpr auto PROPOSALS = "pop.proposals";
inline constexpr auto BLOCKEXIST = "pop.block_exist";
inline constexpr auto RESULT = "pop.result";

using Proposals = kv::Map<ProposalId, ProposalInfo>;
using Results = kv::Map<ProposalId, Result>;
using BlockExist = kv::Map<BlockHash, ProposalId>;
} // namespace tables

struct Tables {
    tables::Proposals proposals;
    tables::BlockExist blockExist;
    tables::Results results;

    Tables() :
        proposals(tables::PROPOSALS), blockExist(tables::BLOCKEXIST), results(tables::RESULT) {}
};

} // namespace Pop
