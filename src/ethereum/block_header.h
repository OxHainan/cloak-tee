
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
#include "types.h"

namespace Ethereum
{
    struct BlockHeader1
    {
        BlockHash parentHash;
        BlockHash sha3Uncles;
        eevm::Address miner;
        EthHash stateRoot;
        EthHash transactionsRoot;
        EthHash receiptsRoot;
        std::array<uint8_t, 256> logsBloom;
        uint64_t difficulty;
        uint64_t number;
        uint64_t gasLimit;
        uint64_t gasUsed;
        uint64_t timestamp;
        std::vector<uint8_t> extraData;
        EthHash mixHash;
        std::array<uint8_t, 8> nonce;
        BlockHash blockHash;
        uint64_t baseFeePerGas;

        BlockHeader1() = default;
        friend void to_json(nlohmann::json& j, const BlockHeader1& s);
        friend void from_json(const nlohmann::json& j, BlockHeader1& s);

        explicit BlockHeader1(const std::string& raw) :
          BlockHeader1(eevm::to_bytes(raw))
        {}
        explicit BlockHeader1(const std::vector<uint8_t>& encoded)
        {
            auto tup = eevm::rlp::decode<
              BlockHash,
              BlockHash,
              eevm::Address,
              EthHash,
              EthHash,
              EthHash,
              std::array<uint8_t, 256>,
              uint64_t,
              uint64_t,
              uint64_t,
              uint64_t,
              uint64_t,
              std::vector<uint8_t>,
              EthHash,
              std::array<uint8_t, 8>,
              uint64_t>(encoded);
            parentHash = std::get<0>(tup);
            sha3Uncles = std::get<1>(tup);
            miner = std::get<2>(tup);
            stateRoot = std::get<3>(tup);
            transactionsRoot = std::get<4>(tup);
            receiptsRoot = std::get<5>(tup);
            logsBloom = std::get<6>(tup);
            difficulty = std::get<7>(tup);
            number = std::get<8>(tup);
            gasLimit = std::get<9>(tup);
            gasUsed = std::get<10>(tup);
            timestamp = std::get<11>(tup);
            extraData = std::get<12>(tup);
            mixHash = std::get<13>(tup);
            nonce = std::get<14>(tup);
            baseFeePerGas = std::get<15>(tup);
        }

        std::vector<uint8_t> encodeRLP() const
        {
            return eevm::rlp::encode(
              parentHash,
              sha3Uncles,
              miner,
              stateRoot,
              transactionsRoot,
              receiptsRoot,
              logsBloom,
              difficulty,
              number,
              gasLimit,
              gasUsed,
              timestamp,
              extraData,
              mixHash,
              nonce,
              baseFeePerGas);
        }

        BlockHash hash() const
        {
            return eevm::to_uint256(encodeRLP().data(), 32u);
        }

        bool verifyHeader(const BlockHash& parentHash_) const
        {
            if (parentHash_ == BlockHash(0) && parentHash_ != parentHash)
                return false;

            return true;
        }
    };

    DECLARE_JSON_TYPE(BlockHeader1)
    DECLARE_JSON_REQUIRED_FIELDS(
      BlockHeader1,
      parentHash,
      sha3Uncles,
      miner,
      stateRoot,
      transactionsRoot,
      receiptsRoot,
      logsBloom,
      difficulty,
      number,
      gasLimit,
      gasUsed,
      timestamp,
      extraData,
      mixHash,
      nonce,
      blockHash)

} // namespace Ethereum
