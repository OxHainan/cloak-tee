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
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/transaction.h>
#include <eEVM/util.h>
#include <kv/tx.h>

namespace Ethereum {
using Balance = uint256_t;
using EthHash = uint256_t;
using Result = uint64_t;
using BlockID = std::string;
using ByteData = std::string;
using TxHash = EthHash;
using BlockHash = EthHash;
using ByteString = std::vector<uint8_t>;
using ContractParticipants = std::set<eevm::Address>;

constexpr auto DefaultBlockID = "latest";

struct CloakInfo {
    eevm::Address tee_addr;
    eevm::Address cloak_service;
    std::vector<uint8_t> tee_public_key;

    CloakInfo(const eevm::Address& tee_addr_,
              const eevm::Address& cloak_service_,
              const std::vector<uint8_t>& public_key) :
        tee_addr(tee_addr_),
        cloak_service(cloak_service_), tee_public_key(public_key) {}
};

struct BlockHeader {
    uint64_t number = {};
    uint64_t difficulty = {};
    uint64_t gas_limit = {};
    uint64_t gas_used = {};
    uint64_t timestamp = {};
    eevm::Address miner = {};
    BlockHash block_hash = {};
};

inline bool operator==(const BlockHeader& l, const BlockHeader& r) {
    return l.number == r.number && l.difficulty == r.difficulty && l.gas_limit == r.gas_limit &&
        l.gas_used == r.gas_used && l.timestamp == r.timestamp && l.miner == r.miner &&
        l.block_hash == r.block_hash;
}

struct TxResult {
    std::optional<eevm::Address> contract_address;
    std::vector<eevm::LogEntry> logs;
};

struct TxReceipt {
    TxHash transaction_hash = {};
    uint256_t transaction_index = {};
    BlockHash block_hash = {};
    uint256_t block_number = {};
    eevm::Address from = {};
    std::optional<eevm::Address> to = std::nullopt;
    uint256_t cumulative_gas_used = {};
    uint256_t gas_used = {};
    std::optional<eevm::Address> contract_address = std::nullopt;
    std::vector<eevm::LogEntry> logs = {};
    // logs_bloom could be bitset for interaction, but is currently ignored
    std::array<uint8_t, 256> logs_bloom = {};
    uint256_t status = {};
};

using ReceiptResponse = std::optional<TxReceipt>;

struct MessageCall {
    eevm::Address from = {};
    std::optional<eevm::Address> to = std::nullopt;
    uint256_t gas = 890000;
    uint256_t gas_price = 0;
    uint256_t value = 0;
    ByteData data = {};
    std::optional<ContractParticipants> private_for = std::nullopt;
    MessageCall() {}
    MessageCall(const eevm::Address& from_, const eevm::Address& to_, const ByteString& data_) :
        from(from_), to(to_), data(eevm::to_hex_string(data_)) {}
};

struct AddressWithBlock {
    eevm::Address address = {};
    BlockID block_id = DefaultBlockID;
};

struct GetTransactionCount {
    eevm::Address address = {};
    BlockID block_id = DefaultBlockID;
};

struct GetTransactionReceipt {
    TxHash tx_hash = {};
};

struct SendRawTransaction {
    ByteData raw_transaction = {};
};

struct EstimateGas {
    MessageCall call_data = {};
};

} // namespace Ethereum
