#pragma once
#include "ds/logger.h"
#include "fmt/core.h"
#include "iostream"
#include "kv/tx.h"
#include "string"
#include "tls/key_pair.h"
#include "vector"
#include "../app/utils.h"
#include "map"
#include "rpc_types.h"
#include <cctype>
#include <cstddef>
#include <eEVM/bigint.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include <stdexcept>
#include <stdint.h>
#include "ethereum_transaction.h"
#include "../transaction/bytecode.h"
#include "../app/tee_manager.h"

namespace evm4ccf
{   
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

    enum Status {
        PENDING,
        PACKAGE,
        DROPPED,
        FAILED
    };

    static std::map<Status,ByteData> statusMap = {
        {PENDING, "pending"},
        {PACKAGE, "package"},
        {DROPPED, "dropped"},
        {FAILED, "failed"}
    };

    struct MultiPartyTransaction
    {
        size_t nonce;
        ByteString to;
        Address from;
        policy::MultiPartyParams params;
        MSGPACK_DEFINE(nonce, from, to, params);

        bool check_transaction_type()
        {
            if (to.size() == 20u) return false;
            if (to.size() == 32u) return true;
            throw std::logic_error(fmt::format(
                "Unsupported transaction type, to length should be {} or {}, but is {}",
                20u,
                32u,
                to.size()
            ));
        }

        ByteData name() const {
          return params.name();
        }
    };

    using MultiPartys = kv::Map<h256, MultiPartyTransaction>;

    struct PrivacyPolicyTransaction
    {
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        rpcparams::Policy   policy;
        ByteString          pdata;
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, policy);
        PrivacyPolicyTransaction(){}
    };


    struct CloakPolicyTransaction
    {
    
    public:
        Address             from;
        Address             to;
        Address             verifierAddr;
        ByteData            codeHash;
        policy::Function    function;
        std::vector<policy::Params> states;
        h256 mpt_hash;
        h256 policy_hash;
        h256 old_states_hash;
        std::vector<std::string> old_states;
        MSGPACK_DEFINE(from, to, verifierAddr, codeHash, function, states, old_states_hash, old_states);
        CloakPolicyTransaction() {}
        CloakPolicyTransaction(
           const PrivacyPolicyTransaction& ppt, const ByteData& name, h256 mpt_hash)
        {
            from = ppt.from;
            to = ppt.to;
            verifierAddr = ppt.verifierAddr;
            codeHash = ppt.codeHash;
            states = ppt.policy.states;
            function = ppt.policy.get_funtions(name);
            this->mpt_hash = mpt_hash;
        }

        CloakPolicyTransaction(CloakPolicys& cp, PrivacyDigests &pd, kv::Tx& tx, h256 key)
        {
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

        void set_content(const std::vector<policy::MultiInput> &inputs)
        {
            // if (inputs.size() != function.inputs.size()) {
            //     throw std::logic_error(fmt::format(
            //         "input params doesn`t match, want {} but get {}",  function.inputs.size(), inputs.size()
            //     ));
            // }

            for (size_t i = 0; i < inputs.size(); i++)
            {
                function.padding(inputs[i]);
            }
        }

        std::vector<std::string> get_states_read()
        {
            std::vector<std::string> read;
            for (size_t i = 0; i < states.size(); i++)
            {
                auto state = states[i];
                if (state.type[0] != 'm')
                {
                    continue;
                }
                read.push_back(to_hex_string(i));
                auto keys = function.get_mapping_keys(state.name);
                read.push_back(to_hex_string(keys.size()));
                for (auto&& k : keys)
                {
                    read.push_back(k);
                }
            }
            CLOAK_DEBUG_FMT("read:{}", fmt::join(read, ", "));
            return read;
        }

        size_t get_states_return_len(bool encrypted)
        {
            size_t res = 0;
            for (auto&& state : states) {
                if (state.type[0] != 'm') {
                    res += encrypted && state.owner != "all" ? 4 : 2;
                } else {
                    auto keys = function.get_mapping_keys(state.name);
                    res += encrypted && state.owner != "all" ? 2 + 4 * keys.size() : 2 + 2 * keys.size();
                }
            }
            CLOAK_DEBUG_FMT("return_len:{}", res);
            return res;
        }

        std::vector<uint8_t> get_states_call_data(bool encrypted)
        {
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

        void request_old_state(kv::Tx& tx)
        {
            auto data = get_states_call_data(true);
            nlohmann::json j;
            j["from"] = to_checksum_address(TeeManager::tee_addr(tx));
            j["to"] = to_checksum_address(verifierAddr);
            j["data"] = to_hex_string(data);
            j["tx_hash"] = to_hex_string(mpt_hash);
            Utils::cloak_agent_log("request_old_state", j);
        }

        bool request_public_keys(kv::Tx &tx)
        {
            std::vector<std::string> res;
            bool included_tee = false;
            for (size_t i = 0; i < old_states.size();) {
                auto id = to_uint256(old_states[i]);
                auto p = states.at(size_t(id));
                int factor = 1;
                CLOAK_DEBUG_FMT("p.info{}", p.info());
                CLOAK_DEBUG_FMT("old_states[i+3]:{}", to_uint256(old_states[i + 3]));
                if (p.owner == "tee") {
                    included_tee = true;
                    factor = 3;
                }
                if (p.owner[0] == 'm') {
                    // mapping
                    auto keys = function.get_mapping_keys(p.name);
                    res.insert(res.end(), {old_states[i], to_hex_string(keys.size())});
                    res.insert(res.end(), keys.begin(), keys.end());
                    factor = 3;
                }
                if (p.type[0] == 'm') {
                    i += i + 2 + to_uint64(old_states[i + 1]) * factor;
                } else {
                    i += 1 + 1 * factor;
                }
                continue;
            }
            if (res.empty()) {
                if (included_tee) {
                    old_states = decrypt_states(tx, {});
                }
                return false;
            }
            // function selector
            std::vector<uint8_t> data = to_bytes("0xa30e2625");
            std::vector<void*> codes;
            abicoder::paramCoder(codes, "read", "uint[]", res);
            auto params = abicoder::pack(codes);
            data.insert(data.end(), params.begin(), params.end());
            nlohmann::json j;
            j["tx_hash"] = to_hex_string(mpt_hash);
            j["data"] = to_hex_string(data);
            j["to"] = to_checksum_address(TeeManager::get_pki_addr(tx));
            Utils::cloak_agent_log("request_public_keys", j);
            return true;
        }

        std::vector<std::string> decrypt_states(kv::Tx& tx, const std::map<std::string, std::string>& public_keys)
        {
            auto tee_kp = TeeManager::get_tee_kp(tx);
            std::vector<std::string> res;
            for (size_t i = 0; i < old_states.size();) {
                res.push_back(old_states[i]);
                auto p = states.at(to_uint64(old_states[i]));
                if (p.owner == "all") {
                    if (p.type[0] == 'm') {
                        auto size = size_t(to_uint256(old_states[i + 1]));
                        res.insert(res.end(), old_states.begin() + i + 1, old_states.begin() + i + 1 + size);
                        i += size + 2;
                    } else {
                        res.push_back(old_states[i + 1]);
                        i += 2;
                    }
                } else if (p.owner[0] == 'm') {
                    auto mapping_keys = function.get_mapping_keys(p.name);
                    res.push_back(old_states[i + 1]);
                    for (size_t j = 0; j < mapping_keys.size(); j++) {
                        size_t pos = i + 2 + j * 3;
                        auto pk = public_keys.at(old_states[pos + 2]);
                        // tag and iv
                        auto ti = to_bytes(old_states[pos + 1]);
                        auto data = to_bytes(old_states[pos]);
                        data.insert(data.end(), ti.begin(), ti.begin() + crypto::GCM_SIZE_TAG);
                        auto decrypted =
                            Utils::decrypt_data(tee_kp, pk, {ti.begin() + crypto::GCM_SIZE_TAG, ti.end()}, data);
                        res.insert(res.end(), {mapping_keys[i], to_hex_string(decrypted)});
                    }
                    i += i + 2 + mapping_keys.size() * 3;
                } else if (p.owner == "tee") {
                    auto sender_addr = old_states[i + 3];
                    CLOAK_DEBUG_FMT("sender_addr:{}", sender_addr);
                    if (to_uint256(sender_addr) == 0) {
                        res.push_back(to_hex_string(0));
                    } else {
                        // tag and iv
                        auto pk = tee_kp->public_key_pem();
                        auto&& [tag, iv] = Utils::split_tag_and_iv(to_bytes(old_states[i + 2]));
                        CLOAK_DEBUG_FMT("tag:{}, iv:{}", tag, iv);
                        auto data = to_bytes(old_states[i + 1]);
                        data.insert(data.end(), tag.begin(), tag.end());
                        auto decrypted = Utils::decrypt_data(tee_kp, pk, iv, data);
                        res.push_back(to_hex_string(decrypted));
                    }
                    i += 4;
                } else {
                    LOG_AND_THROW("invalid owner:{}", p.owner);
                }
            }
            CLOAK_DEBUG_FMT("old_states:{}, res:{}", fmt::join(old_states, ", "), fmt::join(res, ", "));
            return res;
        }

        void sync_result(kv::Tx &tx, const std::vector<std::string>& new_states)
        {
            auto tee_kp = TeeManager::get_tee_kp(tx);
            size_t nonce = TeeManager::get_and_incr_nonce(tx);
            // function selector
            std::vector<uint8_t> data =
                Utils::make_function_selector("set_states(uint256[],uint256,uint256[],uint256[])");
            size_t old_states_len = get_states_return_len(true);
            CLOAK_DEBUG_FMT("old_states_hash:{}", to_hex_string(old_states_hash));
            std::vector<void*> codes;
            abicoder::paramCoder(codes, "read", "uint[]", get_states_read());
            abicoder::paramCoder(codes, "old_states_len", "uint", to_hex_string(old_states_len));
            abicoder::paramCoder(codes, "data", "uint[]", new_states);
            abicoder::paramCoder(codes, "proof", "uint[]", get_proof());
            auto packed = abicoder::pack(codes);
            data.insert(data.end(), packed.begin(), packed.end());
            MessageCall mc;
            mc.from = get_addr_from_kp(tee_kp);
            mc.to = verifierAddr;
            mc.data = to_hex_string(data);
            // TODO: choose a better value based on concrete contract
            mc.gas = 0x34abf;
            CLOAK_DEBUG_FMT("data:{}", mc.data);
            auto signed_data = sign_eth_tx(tee_kp, mc, nonce);
            nlohmann::json j;
            j["tx_hash"] = to_hex_string(mpt_hash);
            j["data"] = to_hex_string(signed_data);
            Utils::cloak_agent_log("sync_result", j);
        }

        std::vector<std::string> get_proof()
        {
            CLOAK_DEBUG_FMT(
                "ch:{}, ph:{}, oh:{}", codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash));
            return {codeHash, to_hex_string(policy_hash), to_hex_string(old_states_hash)};
        }

        std::vector<std::string> encrypt_states(kv::Tx &tx, const std::vector<std::string>& new_states)
        {
            std::vector<std::string> res;
            auto tee_kp = TeeManager::get_tee_kp(tx);
            for (size_t i = 0; i < new_states.size();) {
                // policy state
                auto tee_addr_hex = to_hex_string(TeeManager::tee_addr(tx));
                auto tee_pk_pem = tee_kp->public_key_pem();
                auto ps = states[to_uint64(new_states[i])];
                if (ps.owner == "all") {
                    res.insert(res.end(), {new_states[i], new_states[i + 1]});
                    i += 2;
                } else if (ps.owner == "tee") {
                    auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                    auto&& [encrypted, tag] =
                        Utils::encrypt_data_s(tee_kp, tee_pk_pem, iv, to_bytes(new_states[i + 1]));
                    tag.insert(tag.end(), iv.begin(), iv.end());
                    tag.resize(32, 0);
                    res.insert(res.end(), {new_states[i], to_hex_string(encrypted), to_hex_string(tag), tee_addr_hex});
                    i += 2;
                } else if (ps.owner[0] == 'm') {
                    auto mapping_keys = function.get_mapping_keys(ps.name);
                    res.insert(res.end(), {new_states[i], new_states[i + 1]});
                    for (size_t j = 0; j < mapping_keys.size(); j++) {
                        size_t pos = i + 2 + j;
                        auto iv = tls::create_entropy()->random(crypto::GCM_SIZE_IV);
                        auto&& [decrypted, tag] =
                            Utils::encrypt_data_s(tee_kp, tls::Pem(mapping_keys[j]), iv, to_bytes(new_states[pos]));
                        tag.insert(tag.end(), iv.begin(), iv.end());
                        res.insert(res.end(), {to_hex_string(decrypted), to_hex_string(tag), tee_addr_hex});
                    }
                    i += 2 + mapping_keys.size();
                } else {
                    LOG_AND_THROW("invalid owner:{}", ps.owner);
                }
            }
            return res;
        }

    private:
        UINT8ARRAY packed_to_evm_data()
        {
            auto data = Bytecode(function.get_signed_name(), function.inputs);
            return data.encode();
        }
    };


} // namespace evm4ccf
