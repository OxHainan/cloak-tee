// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include "enclave/export_state.h"
#include "tables.h"
// eEVM
#include <eEVM/account.h>
#include <eEVM/storage.h>
namespace Ethereum
{
// This implements both eevm::Account and eevm::Storage via ccf's KV
struct AccountProxy : public eevm::Account, public eevm::Storage
{
    eevm::Address address;
    mutable tables::Accounts::Views accounts_views;
    tables::Storage::Handle& storage;
    tables::PendingStates::Handle& pending;

    AccountProxy(
        const eevm::Address& a,
        const tables::Accounts::Views& av,
        tables::Storage::Handle& st,
        tables::PendingStates::Handle& ut) :
      address(a),
      accounts_views(av),
      storage(st),
      pending(ut)
    {}

    // Implementation of eevm::Account
    eevm::Address get_address() const override
    {
        return address;
    }

    uint256_t get_balance() const override
    {
        return accounts_views.balances->get(address).value_or(0);
    }

    void set_balance(const uint256_t& b) override
    {
        accounts_views.balances->put(address, b);
    }

    Nonce get_nonce() const override
    {
        return accounts_views.nonces->get(address).value_or(0);
    }

    void increment_nonce() override
    {
        auto nonce = get_nonce();
        ++nonce;
        accounts_views.nonces->put(address, nonce);
    }

    eevm::Code get_code() const override
    {
        return accounts_views.codes->get(address).value_or(eevm::Code{});
    }

    void set_code(eevm::Code&& c) override
    {
        accounts_views.codes->put(address, c);
    }

    // Implementation of eevm::Storage
    std::pair<eevm::Address, uint256_t> translate(const uint256_t& key)
    {
        return std::make_pair(address, key);
    }

    // SNIPPET_START: store_impl
    void store(const uint256_t& key, const uint256_t& value) override
    {
        storage.put(translate(key), value);
        update_pending(key);
    }

    void update_pending(const uint256_t& key)
    {
        LOG_INFO_FMT("update_pending {}", key);
        pending.insert(translate(key));
    }
    // SNIPPET_END: store_impl

    uint256_t load(const uint256_t& key) override
    {
        auto val = storage.get(translate(key));
        if (val.has_value())
            return val.value();

        uint256_t value = enclave::get_export_state(address, key);
        LOG_INFO_FMT("get states {}", eevm::to_hex_string(value));
        return value;
    }

    bool remove(const uint256_t& key) override
    {
        return storage.remove(translate(key));
    }
};
} // namespace Ethereum
