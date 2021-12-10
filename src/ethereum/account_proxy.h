// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

// utils
//#include "app/utils.h"

// EVM-for-CCF
#include "tables.h"

// eEVM
#include <eEVM/account.h>
#include <eEVM/storage.h>

namespace Ethereum {
// This implements both eevm::Account and eevm::Storage via ccf's KV
struct AccountProxy : public eevm::Account, public eevm::Storage {
    eevm::Address address;
    mutable tables::Accounts::Views accounts_views;
    tables::Storage::TxView& storage;
    tables::ReferenceKv::TxView& reference_kv;
    tables::SstoreKv::TxView& sstore_kv;

    AccountProxy(const eevm::Address& a,
                 const tables::Accounts::Views& av,
                 tables::Storage::TxView& st,
                 tables::ReferenceKv::TxView& rv,
                 tables::SstoreKv::TxView& sv) :
        address(a),
        accounts_views(av), storage(st), reference_kv(rv), sstore_kv(sv) {}

    // Implementation of eevm::Account
    eevm::Address get_address() const override {
        return address;
    }

    uint256_t get_balance() const override {
        return accounts_views.balances->get(address).value_or(0);
    }

    void set_balance(const uint256_t& b) override {
        accounts_views.balances->put(address, b);
    }

    Nonce get_nonce() const override {
        return accounts_views.nonces->get(address).value_or(0);
    }

    void increment_nonce() override {
        auto nonce = get_nonce();
        ++nonce;
        accounts_views.nonces->put(address, nonce);
    }

    eevm::Code get_code() const override {
        return accounts_views.codes->get(address).value_or(eevm::Code{});
    }

    void set_code(eevm::Code&& c) override {
        accounts_views.codes->put(address, c);
    }

    // Implementation of eevm::Storage
    std::pair<eevm::Address, uint256_t> translate(const uint256_t& key) {
        return std::make_pair(address, key);
    }

    // SNIPPET_START: store_impl
    void store(const uint256_t& key, const uint256_t& value, const std::string& mpt_id) override {
        set_reference_kv(mpt_id, key);
        set_sstore_kv(mpt_id, key, value);
        storage.put(translate(key), value);
    }
    // SNIPPET_END: store_impl

    uint256_t load(const uint256_t& key, const std::string& mpt_id) override {
        set_reference_kv(mpt_id, key);
        return storage.get(translate(key)).value_or(0);
    }

    bool remove(const uint256_t& key) override {
        return storage.remove(translate(key));
    }

    bool get_hash_state(const uint256_t& key, HashState& hash_state) {
        bool exist = false;
        uint256_t exist_key;
        for (auto& [k, v] : hash_states) {
            if (key.hi == k.hi) {
                exist = true;
                exist_key = k;
            }
        }
        if (exist) {
            hash_states[key] = hash_states[exist_key];
            hash_states[key].addr = key;
            hash_state = hash_states[key];
            return true;
        }
        return false;
    }

    void hash_state_to_var_info(const HashState& hash_state, VarInfo& var_info) {
        assert(hash_state.var_type == VarType::kMapping || hash_state.var_type == VarType::kArray ||
               hash_state.var_type == VarType::kStatic);
        var_info.var_type = hash_state.var_type;
        var_info.addr = hash_state.addr;
        if (hash_state.var_type == VarType::kMapping) {
            var_info.key = hash_state.mem_low_32;
            var_info.slot = hash_state.mem_high_32;
        } else if (hash_state.var_type == VarType::kArray) {
            var_info.slot = hash_state.mem_low_32;
        }
        return true;
    }

    void static_type_to_var_info(const uint256_t& key, VarInfo& var_info) {
        var_info.var_type = VarType::kStatic;
        var_info.slot = key;
        var_info.addr = key;
    }

    void set_reference_kv(const std::string& mpt_id, const uint256_t& key) {
        HashState hash_state;
        bool exist = get_hash_state(key, hash_state);
        VarInfo var_info;
        if (exist) {
            // dynamic type
            hash_state_to_var_info(hash_state, var_info);
        } else {
            // non-dynamic type
            static_type_to_var_info(key, var_info);
        }
        CLOAK_DEBUG_FMT("set_reference_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, slot:{}",
                        mpt_id,
                        var_info.var_type,
                        var_info.addr,
                        var_info.key,
                        var_info.slot);
        nlohmann::json j = var_info;
        reference_kv.put(std::make_pair(mpt_id, key), j.dump());
    }

    bool get_reference_kv(const std::string& mpt_id, const uint256_t& key, VarInfo& var_info) {
        std::string var_info_json = reference_kv.get(std::make_pair(mpt_id, key)).value_or("");
        if (var_info_json == "") {
            CLOAK_DEBUG_FMT("get_reference_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, slot:{}",
                            mpt_id,
                            var_info.var_type,
                            var_info.addr,
                            var_info.key,
                            var_info.slot);
            return false;
        }
        nlohmann::json j = nlohmann::json::parse(var_info_json);
        var_info = j.get<VarInfo>();
        CLOAK_DEBUG_FMT("get_reference_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, slot:{}",
                        mpt_id,
                        var_info.var_type,
                        var_info.addr,
                        var_info.key,
                        var_info.slot);
        return true;
    }

    void set_sstore_kv(const std::string& mpt_id, const uint256_t& key, const uint256_t& value) {
        HashState hash_state;
        bool exist = get_hash_state(key, hash_state);
        VarInfo var_info;
        var_info.value = value;
        if (exist) {
            // dynamic type
            hash_state_to_var_info(hash_state, var_info);
        } else {
            // non-dynamic type
            static_type_to_var_info(key, var_info);
        }
        CLOAK_DEBUG_FMT("set_sstore_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, value:{}, slot:{}",
                        mpt_id,
                        var_info.var_type,
                        var_info.addr,
                        var_info.key,
                        var_info.value,
                        var_info.slot);
        nlohmann::json j = var_info;
        sstore_kv.put(std::make_pair(mpt_id, key), j.dump());
    }

    bool get_sstore_kv(const std::string& mpt_id, const uint256_t& key, VarInfo& var_info) {
        std::string var_info_json = sstore_kv.get(std::make_pair(mpt_id, key)).value_or("");
        if (var_info_json == "") {
            CLOAK_DEBUG_FMT(
                "get_sstore_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, value:{}, slot:{}",
                mpt_id,
                var_info.var_type,
                var_info.addr,
                var_info.key,
                var_info.value,
                var_info.slot);
            return false;
        }
        nlohmann::json j = nlohmann::json::parse(var_info_json);
        var_info = j.get<VarInfo>();
        CLOAK_DEBUG_FMT("get_sstore_kv, mpt_id:{}, var_type:{}, addr:{}, key:{}, value:{}, slot:{}",
                        mpt_id,
                        var_info.var_type,
                        var_info.addr,
                        var_info.key,
                        var_info.value,
                        var_info.slot);
        return true;
    }
};
} // namespace Ethereum
