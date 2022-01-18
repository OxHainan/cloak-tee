
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
#include "abi/abicoder.h"
#include "app/utils.h"
#include "ethereum_transaction.h"
#include "types.h"

namespace Ethereum {

struct Transaction : public evm4ccf::EthereumTransactionWithSignature {
    uint64_t number;
    uint64_t transactionIndex;
    uint256_t blockHash;
    eevm::Address from;

    Transaction() = delete;
    explicit Transaction(const ByteString& rawTx) {
        auto tup = eevm::rlp::decode<size_t,
                                     uint256_t,
                                     uint256_t,
                                     ByteString,
                                     uint256_t,
                                     ByteString,
                                     size_t,
                                     uint256_t,
                                     uint256_t,
                                     uint256_t,
                                     uint256_t,
                                     uint64_t,
                                     uint64_t>(rawTx);
        nonce = std::get<0>(tup);
        gas_price = std::get<1>(tup);
        gas = std::get<2>(tup);
        to = std::get<3>(tup);
        value = std::get<4>(tup);
        data = std::get<5>(tup);
        v = std::get<6>(tup);
        r = std::get<7>(tup);
        s = std::get<8>(tup);
        blockHash = std::get<9>(tup);
        from = std::get<10>(tup);
        number = std::get<11>(tup);
        transactionIndex = std::get<12>(tup);
    }

    TxHash to_be_signed() const {
        auto hash = EthereumTransactionWithSignature::to_be_signed(true);
        return eevm::from_big_endian(hash.data());
    }

    bool validate(const uint256_t& blockHash, const uint256_t& timestamp) const {
        if (data.size() < MESSAGE_LENGTH + 4) {
            throw std::runtime_error("Invalid data in transaction");
        }

        auto m = ByteString(data.begin() + 4, data.begin() + MESSAGE_LENGTH + 4);
        return blockHash == Utils::vec32_to_uint256(ByteString(m.begin(), m.begin() + 32)) &&
            timestamp == Utils::vec32_to_uint256(ByteString(m.begin() + 32, m.end())) &&
            from == EthereumTransactionWithSignature::get_sender_address();
    }

    static constexpr size_t MESSAGE_LENGTH = 64;
};

} // namespace Ethereum
