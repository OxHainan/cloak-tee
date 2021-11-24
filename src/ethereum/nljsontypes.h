// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once
#include "json_utils.h"
#include "nlohmann/json.hpp"

namespace Ethereum {
using namespace evm4ccf;

inline void to_json(nlohmann::json& j, const BlockHeader& s) {
    j = nlohmann::json::object();
    j["number"] = eevm::to_hex_string(s.number);
    j["difficulty"] = eevm::to_hex_string(s.difficulty);
    j["gasLimit"] = eevm::to_hex_string(s.gas_limit);
    j["gasUsed"] = eevm::to_hex_string(s.gas_used);
    j["timestamp"] = eevm::to_hex_string(s.timestamp);
    j["miner"] = eevm::to_checksum_address(s.miner);
    j["hash"] = eevm::to_hex_string(s.block_hash);
}

inline void from_json(const nlohmann::json& j, BlockHeader& s) {
    require_object(j);

    s.number = eevm::to_uint64(j["number"]);
    s.difficulty = eevm::to_uint64(j["difficulty"]);
    s.gas_limit = eevm::to_uint64(j["gasLimit"]);
    s.gas_used = eevm::to_uint64(j["gasUsed"]);
    s.timestamp = eevm::to_uint64(j["timestamp"]);
    s.miner = eevm::to_uint256(j["miner"]);
    s.block_hash = eevm::to_uint256(j["hash"]);
}

inline void to_json(nlohmann::json& j, const BlockHeader1& s) {
    j = nlohmann::json::object();
    j["number"] = s.number;
    j["difficulty"] = s.difficulty;
    j["gasLimit"] = s.gas_limit;
    j["gasUsed"] = s.gas_used;
    j["timestamp"] = s.timestamp;
    j["miner"] = eevm::to_checksum_address(s.miner);
    j["hash"] = eevm::to_hex_string(s.block_hash);
    j["stateRoot"] = eevm::to_hex_string(s.state_root);
    j["parentHash"] = eevm::to_hex_string(s.parent_hash);
    j["sha3Uncles"] = eevm::to_hex_string(s.sha3_uncles);
    j["transactionsRoot"] = eevm::to_hex_string(s.transactions_root);
    j["mixHash"] = eevm::to_hex_string(s.mix_hash);
    j["receiptsRoot"] = eevm::to_hex_string(s.receipts_root);
    j["extraData"] = eevm::to_hex_string(s.extra_data);
    j["logsBloom"] = eevm::to_hex_string(s.logs_bloom);
    j["nonce"] = eevm::to_hex_string(s.nonce);
}

inline void from_json(const nlohmann::json& j, BlockHeader1& s) {
    require_object(j);
    s.number = evm4ccf::to_uint64(j["number"]);
    s.difficulty = evm4ccf::to_uint64(j["difficulty"]);
    s.gas_limit = evm4ccf::to_uint64(j["gasLimit"]);
    s.gas_used = evm4ccf::to_uint64(j["gasUsed"]);
    s.timestamp = evm4ccf::to_uint64(j["timestamp"]);
    s.miner = eevm::to_uint256(j["miner"]);
    s.block_hash = eevm::to_uint256(j["hash"]);
    s.parent_hash = eevm::to_uint256(j["parentHash"]);
    s.sha3_uncles = eevm::to_uint256(j["sha3Uncles"]);
    s.state_root = eevm::to_uint256(j["stateRoot"]);
    s.transactions_root = eevm::to_uint256(j["transactionsRoot"]);
    s.mix_hash = eevm::to_uint256(j["mixHash"]);
    s.receipts_root = eevm::to_uint256(j["receiptsRoot"]);
    array_from_hex_string(s.logs_bloom, j["logsBloom"]);
    array_from_hex_string(s.nonce, j["nonce"]);
    s.extra_data = eevm::to_bytes(j["extraData"]);
}

inline void from_json(const nlohmann::json& j, TxResult& txr) {
    const auto it = j.find("address");
    if (it != j.end() && !it->is_null()) {
        txr.contract_address = eevm::to_uint256(*it);
    } else {
        txr.contract_address = std::nullopt;
    }

    txr.logs = j["logs"].get<decltype(TxResult::logs)>();
}

inline void to_json(nlohmann::json& j, const TxResult& txr) {
    if (txr.contract_address.has_value()) {
        j["address"] = eevm::to_hex_string(*txr.contract_address);
    } else {
        j["address"] = nullptr;
    }
    j["logs"] = txr.logs;
}

inline void to_json(nlohmann::json& j, const ReceiptResponse& s) {
    if (!s.has_value()) {
        j = nullptr;
    } else {
        j = nlohmann::json::object();

        j["transactionHash"] = eevm::to_hex_string_fixed(s->transaction_hash);
        j["transactionIndex"] = eevm::to_hex_string(s->transaction_index);
        j["blockHash"] = eevm::to_hex_string_fixed(s->block_hash);
        j["blockNumber"] = eevm::to_hex_string(s->block_number);
        j["from"] = eevm::to_checksum_address(s->from);
        if (s->to.has_value()) {
            j["to"] = eevm::to_checksum_address(s->to.value());
        } else {
            j["to"] = nullptr;
        }
        j["cumulativeGasUsed"] = eevm::to_hex_string(s->cumulative_gas_used);
        j["gasUsed"] = eevm::to_hex_string(s->gas_used);
        if (s->contract_address.has_value()) {
            j["contractAddress"] = eevm::to_checksum_address(s->contract_address.value());
        } else {
            j["contractAddress"] = nullptr;
        }
        j["logs"] = s->logs;
        j["logsBloom"] = eevm::to_hex_string(s->logs_bloom);
        j["status"] = eevm::to_hex_string(s->status);
    }
}

inline void from_json(const nlohmann::json& j, ReceiptResponse& s) {
    if (j.is_null()) {
        s = std::nullopt;
    } else {
        require_object(j);

        s.emplace();
        s->transaction_hash = eevm::to_uint256(j["transactionHash"]);
        s->transaction_index = eevm::to_uint256(j["transactionIndex"]);
        s->block_hash = eevm::to_uint256(j["blockHash"]);
        s->block_number = eevm::to_uint256(j["blockNumber"]);
        s->from = eevm::to_uint256(j["from"]);
        from_optional_hex_str(j, "to", s->to);
        s->cumulative_gas_used = eevm::to_uint256(j["cumulativeGasUsed"]);
        s->gas_used = eevm::to_uint256(j["gasUsed"]);
        from_optional_hex_str(j, "contractAddress", s->contract_address);
        s->logs = j["logs"].get<decltype(s->logs)>();
        array_from_hex_string(s->logs_bloom, j["logsBloom"]);
        s->status = eevm::to_uint256(j["status"]);
    }
}

inline void to_json(nlohmann::json& j, const MessageCall& s) {
    j = nlohmann::json::object();

    j["from"] = eevm::to_checksum_address(s.from);

    if (s.to.has_value()) {
        j["to"] = eevm::to_checksum_address(s.to.value());
    } else {
        j["to"] = nullptr;
    }

    j["gas"] = eevm::to_hex_string(s.gas);
    j["gasPrice"] = eevm::to_hex_string(s.gas_price);
    j["value"] = eevm::to_hex_string(s.value);
    j["data"] = s.data;

    if (s.private_for.has_value()) {
        auto j_for = nlohmann::json::array();
        for (const auto& a : s.private_for.value()) {
            j_for.push_back(eevm::to_checksum_address(a));
        }
        j["privateFor"] = j_for;
    }
}

inline void from_json(const nlohmann::json& j, MessageCall& s) {
    require_object(j);

    s.from = eevm::to_uint256(j["from"]);
    from_optional_hex_str(j, "to", s.to);
    from_optional_hex_str(j, "gas", s.gas);
    from_optional_hex_str(j, "gasPrice", s.gas_price);
    from_optional_hex_str(j, "value", s.value);

    // Transactions in blocks use "input" rather than "data". To parse both
    // formats, check for either key
    const auto data_it = j.find("data");
    const auto input_it = j.find("input");
    if (data_it != j.end()) {
        s.data = *data_it;
    } else if (input_it != j.end()) {
        s.data = *input_it;
    }

    const auto private_for_it = j.find("privateFor");
    if (private_for_it != j.end()) {
        s.private_for = ContractParticipants();
        for (const auto& a : *private_for_it) {
            s.private_for->insert(eevm::to_uint256(a));
        }
    }
}

inline void to_json(nlohmann::json& j, const CloakInfo& s) {
    j = nlohmann::json::object();
    j["tee_addr"] = eevm::to_checksum_address(s.tee_addr);
    j["cloak_service"] = eevm::to_checksum_address(s.cloak_service);
    j["tee_public_key"] = eevm::to_hex_string(s.tee_public_key);
}

inline void from_json(const nlohmann::json& j, CloakInfo& s) {
    evm4ccf::require_object(j);
    s.tee_addr = eevm::to_uint256(j["tee_addr"]);
    s.cloak_service = eevm::to_uint256(j["cloak_service"]);
    s.tee_public_key = eevm::to_bytes(j["tee_public_key"]);
}

//
inline void to_json(nlohmann::json& j, const AddressWithBlock& s) {
    j = nlohmann::json::array();
    j.push_back(eevm::to_checksum_address(s.address));
    j.push_back(s.block_id);
}

inline void from_json(const nlohmann::json& j, AddressWithBlock& s) {
    require_array(j);
    s.address = eevm::to_uint256(j[0]);
    s.block_id = j[1];
}

//
inline void to_json(nlohmann::json& j, const GetTransactionCount& s) {
    j = nlohmann::json::array();
    j.push_back(eevm::to_checksum_address(s.address));
    j.push_back(s.block_id);
}

inline void from_json(const nlohmann::json& j, GetTransactionCount& s) {
    require_array(j);
    s.address = eevm::to_uint256(j[0]);
    s.block_id = j[1];
}

//
inline void to_json(nlohmann::json& j, const GetTransactionReceipt& s) {
    j = nlohmann::json::array();
    j.push_back(eevm::to_hex_string(s.tx_hash));
}

inline void from_json(const nlohmann::json& j, GetTransactionReceipt& s) {
    require_array(j);
    s.tx_hash = eevm::to_uint256(j[0]);
}

inline void to_json(nlohmann::json& j, const EstimateGas& s) {
    j = nlohmann::json::array();
    j.push_back(s.call_data);
}

inline void from_json(const nlohmann::json& j, EstimateGas& s) {
    require_array(j);
    s.call_data = j[0];
}

//
inline void to_json(nlohmann::json& j, const SendRawTransaction& s) {
    j = nlohmann::json::array();
    j.push_back(s.raw_transaction);
}

inline void from_json(const nlohmann::json& j, SendRawTransaction& s) {
    require_array(j);
    s.raw_transaction = j[0];
}

} // namespace Ethereum
