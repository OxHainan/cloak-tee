// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

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

    AccountProxy(const eevm::Address& a,
                 const tables::Accounts::Views& av,
                 tables::Storage::TxView& st) :
        address(a),
        accounts_views(av), storage(st) {}

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
        to_reference_kv(key, mpt_id);
        to_store_kv(key, value, mpt_id);
        storage.put(translate(key), value);
    }
    // SNIPPET_END: store_impl

    uint256_t load(const uint256_t& key, const std::string& mpt_id) override {
        to_reference_kv(key, mpt_id);
        return storage.get(translate(key)).value_or(0);
    }

    bool remove(const uint256_t& key) override {
        return storage.remove(translate(key));
    }

    bool get_hash_state(const uint256_t& k, HashState& hash_state) {
        bool exist = false;
        uint256_t exist_key;
        for (auto it = hash_states.begin(); it != hash_states.end(); it++) {
            if (k.hi == it->first.hi) {
                exist = true;
                exist_key = it->first;
            }
        }
        if (exist) {
            hash_states[k] = hash_states[exist_key];
            hash_states[k].addr = k;
            hash_state = hash_states[k];
            return true;
        }
        return false;
    }

    bool hash_state_to_var_info(const HashState& hash_state, VarInfo& var_info) {
        assert(hash_state.var_type != 0);
        var_info.var_type = hash_state.var_type;
        var_info.addr = hash_state.addr;
        if (hash_state.var_type == 1) {
            var_info.key = hash_state.mem_low_32;
            var_info.slot = hash_state.mem_high_32;
        } else if (hash_state.var_type == 2) {
            var_info.slot = hash_state.mem_low_32;
        }
        return true;
    }

    bool to_reference_kv(const uint256_t& key, const std::string& mpt_id) {
        HashState hash_state;
        bool exist = get_hash_state(key, hash_state);
        if (!exist) {
            return true;
        }

        VarInfo var_info;
        hash_state_to_var_info(hash_state, var_info);

        std::cout << "[to_reference_kv]"
                  << "mpt_id=" << mpt_id << ",var_type=" << var_info.var_type
                  << ",addr=" << var_info.addr << ",key=" << var_info.key
                  << ",slot=" << var_info.slot << std::endl;
        return true;
    }

    bool to_store_kv(const uint256_t& key, const uint256_t& value, const std::string& mpt_id) {
        HashState hash_state;
        bool exist = get_hash_state(key, hash_state);
        if (!exist) {
            return true;
        }

        VarInfo var_info;
        hash_state_to_var_info(hash_state, var_info);
        var_info.value = value;

        std::cout << "[to_store_kv]"
                  << "mpt_id=" << mpt_id << ",var_type=" << var_info.var_type
                  << ",addr=" << var_info.addr << ",key=" << var_info.key
                  << ",value=" << var_info.value << ",slot=" << var_info.slot << std::endl;
        return true;
    }
};
} // namespace Ethereum
