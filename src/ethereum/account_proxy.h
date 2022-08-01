// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

#include "enclave/export_state.h"
#include "encryptor.h"
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
    eevm::EncryptorPtr encryptor;
    ContractLevel level;
    mutable tables::Accounts::Views accounts_views;
    tables::Storage::Handle& storage;
    tables::PendingStorage::Handle& pending_storage;
    tables::PendingStates::Handle& pending;

    AccountProxy(
        const eevm::Address& a,
        const std::optional<ContractLevel> level,
        const std::optional<std::vector<uint8_t>>& encryptKey,
        const tables::Accounts::Views& av,
        tables::Storage::Handle& st,
        tables::PendingStorage::Handle& ps,
        tables::PendingStates::Handle& ut) :
      address(a),
      level(level.value_or(ContractLevel::BASIC)),
      accounts_views(av),
      storage(st),
      pending_storage(ps),
      pending(ut)
    {
        if (encryptKey.has_value()) {
            encryptor = StateEncryptor::make_encryptor(*encryptKey);
        }
    }

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
        std::vector<uint8_t> state(32u);
        if (encryptor) {
            state.resize(64u);
            std::vector<uint8_t> plain(32u);
            eevm::to_big_endian(value, plain.data());
            encryptor->encrypt(plain, state);
        } else {
            eevm::to_big_endian(value, state.data());
        }

        LOG_DEBUG_FMT("storage {}", eevm::to_hex_string(state));
        storage.put(translate(key), state);
        if (level > ContractLevel::BASIC)
            update_pending(key);
    }

    void update_pending(const uint256_t& key)
    {
        LOG_DEBUG_FMT("update_pending {}", key);
        pending.insert(translate(key));
    }
    // SNIPPET_END: store_impl

    uint256_t load(const uint256_t& key) override
    {
        auto state = storage.get(translate(key));
        if (state.has_value()) {
            // save old state
            if (!pending_storage.get(translate(key)).has_value() &&
                level > ContractLevel::BASIC) {
                LOG_DEBUG_FMT(
                    "record old state {}", eevm::to_hex_string(*state));
                pending_storage.put(translate(key), *state);
            }

            if (level > ContractLevel::SOLIDITY && state->size() > 32) {
                std::vector<uint8_t> plain;
                if (encryptor->decrypt(*state, plain)) {
                    return eevm::from_big_endian(plain.data());
                }

                throw std::runtime_error(fmt::format(
                    "contract state decrypt failed, get key {}",
                    eevm::to_hex_string(key)));
            }

            return eevm::from_big_endian(state->data());
        }

        if (level == ContractLevel::BASIC) {
            return 0;
        }

        uint256_t value = enclave::get_export_state(address, key);
        LOG_DEBUG_FMT("record old state {}", eevm::to_hex_string(value));
        // save old state
        std::vector<uint8_t> plain(32u);
        eevm::to_big_endian(value, plain.data());
        pending_storage.put(translate(key), plain);

        if (level == ContractLevel::SOLIDITY) {
            return value;
        }

        throw std::runtime_error(fmt::format(
            "Contract privacy enhancements are not yet "
            "supported, get contract {}",
            eevm::to_hex_string(address)));
    }

    bool remove(const uint256_t& key) override
    {
        return storage.remove(translate(key));
    }
};
} // namespace Ethereum
