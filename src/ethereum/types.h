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
#include <eEVM/rlp.h>
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

struct BlockHeader1 {
    BlockHash parent_hash;
    BlockHash sha3_uncles;
    eevm::Address miner;
    EthHash state_root;
    EthHash transactions_root;
    EthHash receipts_root;
    std::array<uint8_t, 256> logs_bloom;
    uint64_t difficulty;
    uint64_t number;
    uint64_t gas_limit;
    uint64_t gas_used;
    uint64_t timestamp;
    std::vector<uint8_t> extra_data;
    EthHash mix_hash;
    std::array<uint8_t, 8> nonce;
    BlockHash block_hash;
    BlockHeader1() = default;
    explicit BlockHeader1(const std::vector<uint8_t>& encoded) {
        auto tup = eevm::rlp::decode<BlockHash,
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
                                     std::array<uint8_t, 8>>(encoded);
        parent_hash = std::get<0>(tup);
        sha3_uncles = std::get<1>(tup);
        miner = std::get<2>(tup);
        state_root = std::get<3>(tup);
        transactions_root = std::get<4>(tup);
        receipts_root = std::get<5>(tup);
        logs_bloom = std::get<6>(tup);
        difficulty = std::get<7>(tup);
        number = std::get<8>(tup);
        gas_limit = std::get<9>(tup);
        gas_used = std::get<10>(tup);
        timestamp = std::get<11>(tup);
        extra_data = std::get<12>(tup);
        mix_hash = std::get<13>(tup);
        nonce = std::get<14>(tup);
        block_hash = hash();
    }

    std::vector<uint8_t> encode() const {
        return eevm::rlp::encode(parent_hash,
                                 sha3_uncles,
                                 miner,
                                 state_root,
                                 transactions_root,
                                 receipts_root,
                                 logs_bloom,
                                 difficulty,
                                 number,
                                 gas_limit,
                                 gas_used,
                                 timestamp,
                                 extra_data,
                                 mix_hash,
                                 nonce);
    }

    BlockHash hash() const {
        return eevm::from_big_endian(eevm::keccak_256(encode()).data());
    }

    void verify() const {
        if (block_hash != hash()) {
            throw std::logic_error(fmt::format("Validator block error, want {} but get {}",
                                               eevm::to_hex_string(hash()),
                                               eevm::to_hex_string(block_hash)));
        }
    }
};

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
