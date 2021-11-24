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
#include "queue"
#include "types.h"

namespace Ethereum {

class BlockValidator {
 public:
    explicit BlockValidator(const std::queue<std::optional<BlockHeader1>>& blocks_) :
        blocks(blocks_) {}

    bool verify() {
        if (blocks.empty())
            return false;
        if (!parent_block.has_value()) {
            parent_block = blocks.front();
            blocks.pop();
            parent_block->verify();
        }
    }

    std::queue<std::optional<BlockHeader1>> blocks;
    std::optional<BlockHeader1> parent_block = std::nullopt;
};

} // namespace Ethereum
