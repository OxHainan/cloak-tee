// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include "../src/abi/parsing.h"
#include "../src/app/utils.h"
#include "../src/queue/workertransaction.h"

#include <eEVM/util.h>
namespace evm4ccf {
template <size_t N>
inline void array_from_hex_string(std::array<uint8_t, N>& a, const std::string& s) {
    const auto stripped = eevm::strip(s);

    if (stripped.size() != N * 2) {
        throw std::logic_error(fmt::format("Expected {} characters, got {}", N * 2, stripped.size()));
    }

    for (auto i = 0; i < N; i++) {
        a[i] = static_cast<uint8_t>(strtoul(stripped.substr(i * 2, 2).c_str(), nullptr, 16));
    }
}

template <typename T>
inline void from_to_str(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (it == j.end() || it->is_null() || (it->is_string() && it->get<std::string>().empty())) return;
    v = *it;
}

template <typename T>
inline void from_to_array(const nlohmann::json& j, const std::string& s, T& v) {
    std::string vs;
    from_to_str(j, s, vs);
    if (!vs.empty()) {
        v = eevm::to_bytes(vs);
    }
}

template <typename T>
inline void from_optional_hex_str(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (it == j.end() || it->is_null() || (it->is_string() && it->get<std::string>().empty())) {
        // Don't change v from default
        return;
    } else {
        v = eevm::to_uint256(*it);
    }
}

inline void require_object(const nlohmann::json& j) {
    if (!j.is_object()) {
        throw std::invalid_argument(fmt::format("Expected object, got: {}", j.dump()));
    }
}

inline void require_array(const nlohmann::json& j) {
    if (!j.is_array()) {
        throw std::invalid_argument(fmt::format("Expected array, got: {}", j.dump()));
    }
}

template <typename T>
inline void from_array_to_object(const nlohmann::json& j, const std::string& s, T& v) {
    const auto it = j.find(s);
    if (!it->is_null() && it != j.end()) {
        require_array(*it);
        auto tem = it->get<T>();
        for (int i = 0; i < tem.size(); i++) {
            v.push_back(tem[i]);
        }
    }
}

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

namespace policy {
inline void from_json(const nlohmann::json& j, Params& s) {
    require_object(j);
    from_to_str(j, "name", s.name);
    from_to_str(j, "owner", s.owner);
    from_to_str(j, "type", s.type);
    // Parsing().check(s.type);
}

inline void to_json(nlohmann::json& j, const Params& s) {
    j = nlohmann::json::object();
    j["name"] = s.name;
    j["owner"] = s.owner;
    j["type"] = s.type;
    if (s.value.has_value()) {
        j["value"] = s.value.value();
    }
}

inline void from_json(const nlohmann::json& j, stateParams& s) {
    require_object(j);
    from_to_str(j, "name", s.name);
    from_array_to_object(j, "keys", s.keys);
}

inline void to_json(nlohmann::json& j, const stateParams& s) {
    j = nlohmann::json::object();
    j["name"] = s.name;
    j["keys"] = s.keys;
}

inline void from_json(const nlohmann::json& j, MultiInput& s) {
    require_object(j);
    from_to_str(j, "name", s.name);
    from_to_str(j, "value", s.value);
}

inline void to_json(nlohmann::json& j, const MultiInput& s) {
    j = nlohmann::json::object();
    j["name"] = s.name;
    j["value"] = s.value;
}

inline void from_json(const nlohmann::json& j, MultiPartyParams& s) {
    require_object(j);
    from_to_str(j, "function", s.function);
    from_array_to_object(j, "inputs", s.inputs);
}

inline void to_json(nlohmann::json& j, const MultiPartyParams& s) {
    j = nlohmann::json::object();
    j["function"] = s.function;
    j["inputs"] = s.inputs;
}

inline void from_json(const nlohmann::json& j, Function& s) {
    require_object(j);
    from_to_str(j, "name", s.name);
    from_to_str(j, "type", s.type);
    from_array_to_object(j, "inputs", s.inputs);
    from_to_array(j, "entry", s.entry);
    from_array_to_object(j, "read", s.read);
    from_array_to_object(j, "mutate", s.mutate);
    from_array_to_object(j, "outputs", s.outputs);
}

inline void to_json(nlohmann::json& j, const Function& s) {
    j = nlohmann::json::object();
    j["name"] = s.name;
    j["type"] = s.type;
    j["inputs"] = s.inputs;
    j["read"] = s.read;
    j["mutate"] = s.mutate;
    j["outputs"] = s.outputs;
}

}  // namespace policy

namespace rpcparams {
//
inline void from_json(const nlohmann::json& j, Policy& s) {
    require_object(j);
    from_to_str(j, "contract", s.contract);
    from_array_to_object(j, "states", s.states);
    from_array_to_object(j, "functions", s.functions);
}

inline void to_json(nlohmann::json& j, const Policy& s) {
    j = nlohmann::json::object();
    j["contract"] = s.contract;
    j["states"] = s.states;
    j["functions"] = s.functions;
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
inline void to_json(nlohmann::json& j, const Call& s) {
    j = nlohmann::json::array();
    j.push_back(s.call_data);
    j.push_back(s.block_id);
}

inline void from_json(const nlohmann::json& j, Call& s) {
    require_array(j);
    s.call_data = j[0];
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

inline void to_json(nlohmann::json& j, const GetMultiPartyStatus& s) {
    j = nlohmann::json::array();
    j.push_back(eevm::to_hex_string(s.tx_hash));
}

inline void from_json(const nlohmann::json& j, GetMultiPartyStatus& s) {
    require_array(j);
    s.tx_hash = Utils::to_KeccakHash(j[0]);
}

inline void to_json(nlohmann::json& j, const WorkOrderSubmit& s) {
    j = nlohmann::json::object();
    j["responseTimeoutMSecs"] = eevm::to_hex_string(s.workOrder.responseTimeoutMSecs);
    j["workOrderId"] = eevm::to_checksum_address(s.workOrder.workOrderId);
}

inline void from_json(const nlohmann::json& j, WorkOrderSubmit& s) {
    require_object(j);
    s.workOrder.workOrderId = eevm::to_uint256(j["workOrderId"]);
    s.workOrder.responseTimeoutMSecs = eevm::to_uint64(j["responseTimeoutMSecs"]);
}
//
inline void to_json(nlohmann::json& j, const SendTransaction& s) {
    j = nlohmann::json::array();
    j.push_back(s.call_data);
}

inline void from_json(const nlohmann::json& j, SendTransaction& s) {
    require_array(j);
    s.call_data = j[0];
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

}  // namespace rpcparams

namespace rpcresults {
//
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

inline void to_json(nlohmann::json& j, const ReceiptWorkOrderResponse& s) {
    if (!s.has_value()) {
        j = nullptr;
    } else {
        j = nlohmann::json::object();
        j["responseTimeoutMSecs"] = eevm::to_hex_string(s->responseTimeoutMSecs);
        j["workOrderId"] = eevm::to_checksum_address(s->workOrderId);
    }
}

inline void from_json(const nlohmann::json& j, ReceiptWorkOrderResponse& s) {
    if (j.is_null()) {
        s = {};
    } else {
        require_object(j);
        s->workOrderId = eevm::to_uint256(j["workOrderId"]);
        s->responseTimeoutMSecs = eevm::to_uint64(j["responseTimeoutMSecs"]);
    }
}
inline bool to_bool(const std::string& s) {
    if (s == "true") return true;
    return false;
}
inline std::string from_bool(const bool& s) { return s == true ? "true" : "false"; }
inline void to_json(nlohmann::json& j, const MultiPartyReceiptResponse& s) {
    if (s.has_value()) {
        j = nullptr;
    } else {
        j = nlohmann::json::object();
        j["progress"] = s->progress;
        j["state"] = from_bool(s->state);
    }
}

inline void from_json(const nlohmann::json& j, MultiPartyReceiptResponse& s) {
    if (j.is_null()) {
        s = std::nullopt;
    } else {
        require_object(j);
        s->state = to_bool(j["state"]);
        from_to_str(j, "progress", s->progress);
    }
}

}  // namespace rpcresults
}  // namespace evm4ccf
