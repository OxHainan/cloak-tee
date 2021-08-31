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
#include "../abi/bytecode.h"
#include "../app/tee_manager.h"
#include "../app/utils.h"
#include "ds/logger.h"
#include "ethereum_transaction.h"
#include "fmt/core.h"
#include "fmt/format.h"
#include "iostream"
#include "kv/tx.h"
#include "map"
#include "rpc_types.h"
#include "string"
#include "tls/key_pair.h"
#include "tls/pem.h"
#include "vector"

#include <cctype>
#include <cstddef>
#include <eEVM/bigint.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include <stdexcept>
#include <stdint.h>
namespace evm4ccf {
using namespace eevm;
using namespace rpcparams;
using ByteData = std::string;
using Address = eevm::Address;
using Policy = rpcparams::Policy;
using h256 = eevm::KeccakHash;
using ByteString = std::vector<uint8_t>;
using uint256 = uint256_t;

// tables
struct PrivacyPolicyTransaction;
struct CloakPolicyTransaction;
using Privacys = kv::Map<h256, PrivacyPolicyTransaction>;
using PrivacyDigests = kv::Map<Address, h256>;
using CloakPolicys = kv::Map<h256, CloakPolicyTransaction>;
using CloakDigests = kv::Map<Address, h256>;

enum class Status : uint8_t {
    PENDING,
    REQUESTING_OLD_STATES,
    SYNCING,
    SYNCED,
    SYNC_FAILED,
    DROPPED,
};

static std::map<Status, ByteData> statusMap = {
    {Status::PENDING, "PENDING"},
    {Status::REQUESTING_OLD_STATES, "REQUESTING_OLD_STATES"},
    {Status::SYNCING, "SYNCING"},
    {Status::SYNCED, "SYNCED"},
    {Status::SYNC_FAILED, "SYNC_FAILED"},
    {Status::DROPPED, "DROPPED"},
};

struct MultiPartyTransaction {
    size_t nonce;
    ByteString to;
    Address from;
    policy::MultiPartyParams params;
    MSGPACK_DEFINE(nonce, from, to, params);

    bool check_transaction_type() {
        if (to.size() == 20u) return false;
        if (to.size() == 32u) return true;
        throw std::logic_error(
            fmt::format("Unsupported transaction type, to length should be {} or {}, but is {}", 20u, 32u, to.size()));
    }

    ByteData name() const { return params.name(); }
};

using MultiPartys = kv::Map<h256, MultiPartyTransaction>;

struct PrivacyPolicyTransaction {
 public:
    Address from;
    Address to;
    Address verifierAddr;
    ByteData codeHash;
    rpcparams::Policy policy;
    MSGPACK_DEFINE(from, to, verifierAddr, codeHash, policy);
    PrivacyPolicyTransaction() {}
};

struct CloakPolicyTransaction {
 public:
    Address from;
    Address to;
    Address verifierAddr;
    ByteData codeHash;
    policy::Function function;
    std::vector<policy::Params> states;
    h256 mpt_hash;
    h256 policy_hash;
    h256 old_states_hash;
    std::vector<std::string> old_states;
    std::vector<std::string> requested_addresses;
    std::map<std::string, std::string> public_keys;
    uint8_t status = 0;
    MSGPACK_DEFINE(
        from, to, verifierAddr, codeHash, function, states, old_states_hash, old_states, requested_addresses, status);
    CloakPolicyTransaction() {}
    CloakPolicyTransaction(const PrivacyPolicyTransaction& ppt, const ByteData& name, h256 mpt_hash) {
        from = ppt.from;
        to = ppt.to;
        verifierAddr = ppt.verifierAddr;
        codeHash = ppt.codeHash;
        states = ppt.policy.states;
        function = ppt.policy.get_funtions(name);
        this->mpt_hash = mpt_hash;
    }

    CloakPolicyTransaction(CloakPolicys& cp, PrivacyDigests& pd, kv::Tx& tx, h256 key) {
        auto [cp_handler, pd_handler] = tx.get_view(cp, pd);
        auto cpt_opt = cp_handler->get(key);
        if (!cpt_opt.has_value()) {
            LOG_AND_THROW("tx_hash:{} not found", key);
        }
        *this = cpt_opt.value();
        this->mpt_hash = key;
        auto p_hash_opt = pd_handler->get(to);
        if (!p_hash_opt.has_value()) {
            LOG_AND_THROW("policy hash:{} not found", to);
        }
        policy_hash = p_hash_opt.value();
    }

    void set_status(Status status) { this->status = uint8_t(status); }

    Status get_status() const { return Status(status); }

    std::string get_status_str() const { return statusMap[Status(status)]; }

    void save(kv::Tx& tx, CloakPolicys& cp) noexcept {
        auto handler = tx.get_view(cp);
        handler->put(mpt_hash, *this);
    }

    void set_content(const std::vector<policy::MultiInput>& inputs) {
        // if (inputs.size() != function.inputs.size()) {
        //     throw std::logic_error(fmt::format(
        //         "input params doesn`t match, want {} but get {}",  function.inputs.size(), inputs.size()
        //     ));
        // }

        for (size_t i = 0; i < inputs.size(); i++) {
            function.padding(inputs[i]);
        }
    }

    std::vector<std::string> get_states_read() {
        std::vector<std::string> read;
        for (size_t i = 0; i < states.size(); i++) {
            auto state = states[i];
            if (state.type[0] != 'm') {
                continue;
            }
            read.push_back(to_hex_string(i));
            auto keys = function.get_mapping_keys(from, state.name);
            read.push_back(to_hex_string(keys.size()));
            read.insert(read.end(), keys.begin(), keys.end());
        }
        CLOAK_DEBUG_FMT("read:{}", fmt::join(read, ", "));
        return read;
    }

    size_t get_states_return_len(bool encrypted) {
        size_t res = 0;
        for (auto&& state : states) {
            if (state.type[0] != 'm') {
                res += encrypted && state.owner != "all" ? 4 : 2;
            } else {
                auto keys = function.get_mapping_keys(from, state.name);
                res += encrypted && state.owner != "all" ? 2 + 4 * keys.size() : 2 + 2 * keys.size();
            }
        }
        CLOAK_DEBUG_FMT("return_len:{}", res);
        return res;
    }

    std::vector<uint8_t> get_states_call_data(bool encrypted) {
        std::vector<std::string> read = get_states_read();
        size_t return_len = get_states_return_len(encrypted);
        CLOAK_DEBUG_FMT("get_states_call_data, return_len:{}, read:{}", return_len, fmt::join(read, ", "));
        // function selector
        std::vector<uint8_t> data = Utils::make_function_selector("get_states(uint256[],uint256)");
        std::vector<void*> codes;
        abicoder::paramCoder(codes, "read", "uint[]", read);
        abicoder::paramCoder(codes, "return_len", "uint", to_hex_string(return_len));
        auto packed = abicoder::pack(codes);
        data.insert(data.end(), packed.begin(), packed.end());
        return data;
    }

    void request_old_state(kv::Tx& tx) {
        set_status(Status::REQUESTING_OLD_STATES);
        auto data = get_states_call_data(true);
        nlohmann::json j;
        j["from"] = to_checksum_address(TeeManager::tee_addr(tx));
        j["to"] = to_checksum_address(verifierAddr);
        j["data"] = to_hex_string(data);
        j["tx_hash"] = to_hex_string(mpt_hash);
        Utils::cloak_agent_log("request_old_state", j);
    }

    bool request_public_keys(kv::Tx& tx) {
        // state => address
        std::map<std::string, std::string> addresses;
        visit_states(old_states, true, [this, &addresses](auto id, size_t idx) {
            if (states[id].type == "address" && states[id].owner == "all") {
                addresses[states[id].name] = eevm::to_checksum_address(eevm::to_uint256(old_states[idx + 1]));
            }
        });
        for (auto [k, v] : addresses) {
            CLOAK_DEBUG_FMT("addr:{}, {}", k, v);
        }

        // get result
        std::vector<std::string> res;
        bool included_tee = false;
        visit_states(old_states, true, [this, &included_tee, &res, &addresses](size_t id, size_t) {
            auto p = states[id];
            if (p.owner == "all") {
                return;
            } else if (p.owner == "tee") {
                included_tee = true;
            } else if (p.owner[0] == 'm') {
                // mapping
                auto keys = function.get_mapping_keys(from, p.name);
                res.insert(res.end(), keys.begin(), keys.end());
            } else {
                // identifier
                res.push_back(addresses.at(p.owner));
            }
        });

        if (res.empty()) {
            if (included_tee) {
                old_states = decrypt_states(tx);
            }
            return false;
        }

        requested_addresses = res;
        CLOAK_DEBUG_FMT("requested_addresses:{}", fmt::join(requested_addresses, ", "));
        // function selector
        std::vector<uint8_t> data = Utils::make_function_selector("getPk(address[])");
        std::vector<void*> codes;
        abicoder::paramCoder(codes, "read", "address[]", res);
        auto params = abicoder::pack(codes);
        data.insert(data.end(), params.begin(), params.end());
        nlohmann::json j;
        j["tx_hash"] = to_hex_string(mpt_hash);
        j["data"] = to_hex_string(data);
        j["to"] = to_checksum_address(TeeManager::get_pki_addr(tx));
        j["from"] = to_checksum_address(TeeManager::tee_addr(tx));
        Utils::cloak_agent_log("request_public_keys", j);
        return true;
    }

    std::vector<std::string> decrypt_states(kv::Tx& tx) {
        auto tee_kp = TeeManager::get_tee_kp(tx);
        std::vector<std::string> res;
        visit_states(old_states, true, [this, &res, &tee_kp](size_t id, size_t idx) {
            res.push_back(old_states[idx]);
            auto p = states.at(id);
            // TODO(SVENFENG): better type checking
            if (p.owner == "all") {
                if (p.type[0] == 'm') {
                    auto size = size_t(to_uint256(old_states[idx + 1]));
                    res.insert(res.end(), old_states.begin() + idx + 1, old_states.begin() + idx + 2 + size * 2);
                } else {
                    res.push_back(old_states[idx + 1]);
                }
            } else if (p.owner[0] == 'm') {
                auto mapping_keys = function.get_mapping_keys(from, p.name);
                res.push_back(old_states[idx + 1]);
                for (size_t j = 0; j < mapping_keys.size(); j++) {
                    res.push_back(mapping_keys[j]);
                    size_t data_pos = idx + 3 + j * 4;
                    auto sender_addr = to_uint256(old_states[data_pos + 2]);
                    CLOAK_DEBUG_FMT("sender_addr:{}", to_checksum_address(sender_addr));
                    if (sender_addr == 0) {
                        res.push_back("0x0");
                        continue;
                    }
                    auto pk = public_keys.at(to_checksum_address(sender_addr));
                    // tag and iv
                    auto&& [tag, iv] = Utils::split_tag_and_iv(to_bytes(old_states[data_pos + 1]));
                    auto data = to_bytes(old_states[data_pos]);
                    data.insert(data.end(), tag.begin(), tag.end());
                    auto decrypted = Utils::decrypt_data(tee_kp, pk, iv, data);
                    res.push_back(to_hex_string(decrypted));
                }
            } else {
                // tee and identifier
                auto sender_addr = to_checksum_address(to_uint256(old_states[idx + 3]));
                CLOAK_DEBUG_FMT("sender_addr:{}", sender_addr);
                if (to_uint256(sender_addr) == 0) {
                    res.push_back(to_hex_string(0));
                    return;
                }
                // tag and iv
                tls::Pem pk = p.owner == "tee" ? tee_kp->public_key_pem() : tls::Pem(public_keys.at(sender_addr));
                auto&& [tag, iv] = Utils::split_tag_and_iv(to_bytes(old_states[idx + 2]));
                CLOAK_DEBUG_FMT("tag:{}, iv:{}", tag, iv);
                auto data = to_bytes(old_states[idx + 1]);
                data.insert(data.end(), tag.begin(), tag.end());
                auto decrypted = Utils::decrypt_data(tee_kp, pk, iv, data);
                res.push_back(to_hex_string(decrypted));
            }
        });
        CLOAK_DEBUG_FMT("old_states:{}, res:{}", fmt::join(old_states, ", "), fmt::join(res, ", "));
        return res;
    }

    void sync_result(kv::Tx& tx, const std::vector<std::string>& new_states) {
        auto tee_kp = TeeManager::get_tee_kp(tx);
        size_t nonce = TeeManager::get_and_incr_nonce(tx);
        // function selector
        std::vector<uint8_t> data = Utils::make_function_selector("set_states(uint256[],uint256,uint256[],uint256[])");
        size_t old_states_len = get_states_return_len(true);
        CLOAK_DEBUG_FMT("old_states_hash:{}", to_hex_string(old_states_hash));
        std::vector<void*> codes;
        abicoder::paramCoder(codes, "read", "uint[]", get_states_read());
        abicoder::paramCoder(codes, "old_states_len", "uint", to_hex_string(old_states_len));
        abicoder::paramCoder(codes, "data", "uint[]", new_states);
        abicoder::paramCoder(codes, "proof", "uint[]", get_proof());
        auto packed = abicoder::pack(codes);
        data.insert(data.end(), packed.begin(), packed.end());

        // auto bc = Bytecode("set_states");
        // bc.add_inputs("read", "uint256[]", get_states_read());
        // bc.add_inputs("old_states_len", "uint256", to_hex_string(old_states_len));
        // bc.add_inputs("data", "uint256[]", new_states);
        // bc.add_inputs("proof", "uint256[]",  get_proof());
        // auto data1 = bc.encode();

        MessageCall mc;
        mc.from = get_addr_from_kp(tee_kp);
        mc.to = verifierAddr;
        mc.data = to_hex_string(data);
        // TODO(SVENFENG): choose a better value based on concrete contract
        mc.gas = 0x34abf;
        CLOAK_DEBUG_FMT("data:{}", mc.data);
        auto signed_data = sign_eth_tx(tee_kp, mc, nonce);
        nlohmann::json j;
        j["tx_hash"] = to_hex_string(mpt_hash);
        j["data"] = to_hex_string(signed_data);
        set_status(Status::SYNCING);
        Utils::cloak_agent_log("sync_result", j);
    }

    std::vector<std::string> get_proof() {
        CLOAK_DEBUG_FMT("ch:{}, ph:{}, oh:{}", codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash));
        return {codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash)};
    }

    std::vector<std::string> encrypt_states(kv::Tx& tx, const std::vector<std::string>& new_states) {
        // identifier owner addresses
        std::map<std::string, std::string> addresses;
        visit_states(new_states, false, [this, &addresses](auto id, size_t idx) {
            if (states[id].type == "address" && states[id].owner == "all") {
                addresses[states[id].name] = eevm::to_checksum_address(eevm::to_uint256(old_states[idx + 1]));
            }
        });

        std::vector<std::string> res;
        auto tee_kp = TeeManager::get_tee_kp(tx);
        visit_states(new_states, false, [this, &res, &addresses, &tee_kp, &new_states](size_t id, size_t idx) {
            // policy state
            auto tee_addr_hex = to_hex_string(get_addr_from_kp(tee_kp));
            auto tee_pk_pem = tee_kp->public_key_pem();
            auto ps = states[id];
            res.push_back(to_hex_string(id));
            if (ps.owner == "all") {
                if (ps.type[0] == 'm') {
                    auto size = to_uint64(new_states[idx + 1]);
                    res.insert(res.end(), new_states.begin() + idx + 1, new_states.begin() + idx + 2 + 2 * size);
                } else {
                    res.push_back(new_states[idx + 1]);
                }
            } else if (ps.owner[0] == 'm') {
                auto mapping_keys = function.get_mapping_keys(from, ps.name);
                res.push_back(new_states[idx + 1]);
                for (size_t j = 0; j < mapping_keys.size(); j++) {
                    auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                    auto&& [encrypted, tag] = Utils::encrypt_data_s(
                        tee_kp, tls::Pem(public_keys.at(mapping_keys[j])), iv, to_bytes(new_states[idx + 3 + j * 2]));
                    tag.insert(tag.end(), iv.begin(), iv.end());
                    tag.resize(32, 0);
                    res.insert(res.end(),
                               {mapping_keys[j], to_hex_string(encrypted), to_hex_string(tag), mapping_keys[j]});
                }
            } else {
                // tee and identifier
                CLOAK_DEBUG_FMT("id:{}, owner:{}", id, ps.owner);
                std::string sender_addr = ps.owner == "tee" ? tee_addr_hex : addresses.at(ps.owner);
                tls::Pem pk_pem = ps.owner == "tee" ? tee_pk_pem : tls::Pem(public_keys.at(sender_addr));
                auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                auto&& [encrypted, tag] = Utils::encrypt_data_s(tee_kp, pk_pem, iv, to_bytes(new_states[idx + 1]));
                tag.insert(tag.end(), iv.begin(), iv.end());
                tag.resize(32, 0);
                res.insert(res.end(), {to_hex_string(encrypted), to_hex_string(tag), sender_addr});
            }
        });
        return res;
    }

    // f: size_t(the id of states) -> size_t(the index of states) -> void
    void visit_states(const std::vector<std::string>& v_states,
                      bool is_encryped,
                      std::function<void(size_t, size_t)> f) {
        for (size_t i = 0; i < v_states.size();) {
            size_t id = to_uint64(v_states[i]);
            f(id, i);
            auto state = states[id];
            int factor = is_encryped && state.owner != "all" ? 3 : 1;
            if (state.type[0] == 'm') {
                i += 2 + to_uint64(v_states[i + 1]) * (factor + 1);
            } else {
                i += 1 + factor;
            }
        }
    }

 private:
    // UINT8ARRAY packed_to_evm_data()
    // {
    // auto data = Bytecode(function.get_signed_name(), function.inputs);
    // return data.encode();
    // }
};

}  // namespace evm4ccf
