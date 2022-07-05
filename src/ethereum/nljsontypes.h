// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once
#include "json_utils.h"
#include "nlohmann/json.hpp"

namespace Ethereum
{

inline void to_json(nlohmann::json& j, const BlockHeader& s)
{
    j = nlohmann::json::object();
    j["number"] = eevm::to_hex_string(s.number);
    j["difficulty"] = eevm::to_hex_string(s.difficulty);
    j["gasLimit"] = eevm::to_hex_string(s.gas_limit);
    j["gasUsed"] = eevm::to_hex_string(s.gas_used);
    j["timestamp"] = eevm::to_hex_string(s.timestamp);
    j["miner"] = eevm::to_checksum_address(s.miner);
    j["hash"] = eevm::to_hex_string(s.block_hash);
}

inline void from_json(const nlohmann::json& j, BlockHeader& s)
{
    evm4ccf::require_object(j);

    s.number = eevm::to_uint64(j["number"]);
    s.difficulty = eevm::to_uint64(j["difficulty"]);
    s.gas_limit = eevm::to_uint64(j["gasLimit"]);
    s.gas_used = eevm::to_uint64(j["gasUsed"]);
    s.timestamp = eevm::to_uint64(j["timestamp"]);
    s.miner = eevm::to_uint256(j["miner"]);
    s.block_hash = eevm::to_uint256(j["hash"]);
}

inline void from_json(const nlohmann::json& j, TxResult& txr)
{
    const auto it = j.find("address");
    if (it != j.end() && !it->is_null()) {
        txr.contract_address = eevm::to_uint256(*it);
    } else {
        txr.contract_address = std::nullopt;
    }

    txr.logs = j["logs"].get<decltype(TxResult::logs)>();
}

inline void to_json(nlohmann::json& j, const TxResult& txr)
{
    if (txr.contract_address.has_value()) {
        j["address"] = eevm::to_hex_string(*txr.contract_address);
    } else {
        j["address"] = nullptr;
    }
    j["logs"] = txr.logs;
}

inline void to_json(nlohmann::json& j, const ReceiptResponse& s)
{
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
            j["contractAddress"] =
                eevm::to_checksum_address(s->contract_address.value());
        } else {
            j["contractAddress"] = nullptr;
        }
        j["logs"] = s->logs;
        j["logsBloom"] = eevm::to_hex_string(s->logs_bloom);
        j["status"] = eevm::to_hex_string(s->status);
    }
}

inline void from_json(const nlohmann::json& j, ReceiptResponse& s)
{
    if (j.is_null()) {
        s = std::nullopt;
    } else {
        evm4ccf::require_object(j);

        s.emplace();
        s->transaction_hash = eevm::to_uint256(j["transactionHash"]);
        s->transaction_index = eevm::to_uint256(j["transactionIndex"]);
        s->block_hash = eevm::to_uint256(j["blockHash"]);
        s->block_number = eevm::to_uint256(j["blockNumber"]);
        s->from = eevm::to_uint256(j["from"]);
        evm4ccf::from_optional_hex_str(j, "to", s->to);
        s->cumulative_gas_used = eevm::to_uint256(j["cumulativeGasUsed"]);
        s->gas_used = eevm::to_uint256(j["gasUsed"]);
        evm4ccf::
            from_optional_hex_str(j, "contractAddress", s->contract_address);
        s->logs = j["logs"].get<decltype(s->logs)>();
        evm4ccf::array_from_hex_string(s->logs_bloom, j["logsBloom"]);
        s->status = eevm::to_uint256(j["status"]);
    }
}

inline void to_json(nlohmann::json& j, const MessageCall& s)
{
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
}

inline void from_json(const nlohmann::json& j, MessageCall& s)
{
    evm4ccf::require_object(j);

    s.from = eevm::to_uint256(j["from"]);
    evm4ccf::from_optional_hex_str(j, "to", s.to);
    evm4ccf::from_optional_hex_str(j, "gas", s.gas);
    evm4ccf::from_optional_hex_str(j, "gasPrice", s.gas_price);
    evm4ccf::from_optional_hex_str(j, "value", s.value);

    // Transactions in blocks use "input" rather than "data". To parse both
    // formats, check for either key
    const auto data_it = j.find("data");
    const auto input_it = j.find("input");
    if (data_it != j.end()) {
        s.data = *data_it;
    } else if (input_it != j.end()) {
        s.data = *input_it;
    }
}

inline void to_json(nlohmann::json& j, const AddressWithBlock& s)
{
    j = nlohmann::json::array();
    j.push_back(eevm::to_checksum_address(s.address));
    j.push_back(s.block_id);
}

inline void from_json(const nlohmann::json& j, AddressWithBlock& s)
{
    evm4ccf::require_array(j);
    s.address = eevm::to_uint256(j[0]);
    s.block_id = j[1];
}

//
inline void to_json(nlohmann::json& j, const GetTransactionCount& s)
{
    j = nlohmann::json::array();
    j.push_back(eevm::to_checksum_address(s.address));
    j.push_back(s.block_id);
}

inline void from_json(const nlohmann::json& j, GetTransactionCount& s)
{
    evm4ccf::require_array(j);
    s.address = eevm::to_uint256(j[0]);
    s.block_id = j[1];
}
inline void to_json(nlohmann::json& j, const ContractEscrow& s)
{
    j = nlohmann::json::array();
    j.push_back(eevm::to_checksum_address(s.address));
}

inline void from_json(const nlohmann::json& j, ContractEscrow& s)
{
    evm4ccf::require_array(j);
    s.address = eevm::to_uint256(j[0]);
}
//
inline void to_json(nlohmann::json& j, const GetTransactionReceipt& s)
{
    j = nlohmann::json::array();
    j.push_back(eevm::to_hex_string(s.tx_hash));
}

inline void from_json(const nlohmann::json& j, GetTransactionReceipt& s)
{
    evm4ccf::require_array(j);
    s.tx_hash = eevm::to_uint256(j[0]);
}

inline void to_json(nlohmann::json& j, const EstimateGas& s)
{
    j = nlohmann::json::array();
    j.push_back(s.call_data);
}

inline void from_json(const nlohmann::json& j, EstimateGas& s)
{
    evm4ccf::require_array(j);
    s.call_data = j[0];
}

//
inline void to_json(nlohmann::json& j, const SendRawTransaction& s)
{
    j = nlohmann::json::array();
    j.push_back(s.raw_transaction);
}

inline void from_json(const nlohmann::json& j, SendRawTransaction& s)
{
    evm4ccf::require_array(j);
    s.raw_transaction = j[0];
}

} // namespace Ethereum
