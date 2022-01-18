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
#include "block_header.h"
#include "transaction.h"
#include "types.h"
namespace Ethereum {
class BlocksValidator : public Transaction {
 public:
    BlocksValidator(const std::vector<std::string>& rawBlocks, const std::vector<uint8_t>& rawTx) :
        Transaction(rawTx) {
        blocks.resize(rawBlocks.size());
        for (size_t i = 0; i < rawBlocks.size(); i++) {
            blocks[i] = BlockHeader1(rawBlocks[i]);
        }
    }

    explicit BlocksValidator(const SendPop& sp) : BlocksValidator(sp.blocks, sp.tx) {}

    bool validateBody() {
        if (blocks.size() < 1)
            return false;

        BlockHash parentHash = blocks[0].hash();
        for (size_t i = 1; i < blocks.size(); i++) {
            if (!blocks[i].verifyHeader(parentHash)) {
                throw std::logic_error(fmt::format("Block validator failed, get 0x{}", parentHash));
            }

            parentHash = blocks[i].hash();
        }

        return true;
    }

    bool validateTransaction(uint256_t& blockHash, const uint256_t& timestamp) {
        if (!validate(blockHash, timestamp)) {
            throw std::runtime_error("Invalid transaction");
        }

        return true;
    }

    // auto get_transaction_hash() const {
    //     return ethTx.to_be_signed(true);
    // }

 private:
    std::vector<BlockHeader1> blocks;
};

} // namespace Ethereum
