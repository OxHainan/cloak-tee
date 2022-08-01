#pragma once
#include "set"
#include "tables.h"

#include <eEVM/keccak256.h>
namespace Ethereum
{
class TransactionSync
{
 private:
    tables::TxSyncs::Handle& syncs;
    tables::PendingStates::Handle& pending;
    tables::Storage::Handle& storage;
    tables::PendingStorage::Handle& pending_storage;

 public:
    TransactionSync(
        tables::TxSyncs::Handle* th,
        tables::PendingStates::Handle* uh,
        tables::Storage::Handle* st,
        tables::PendingStorage::Handle* ps) :
      syncs(*th),
      pending(*uh),
      storage(*st),
      pending_storage(*ps)
    {}

    void update_sync(const uint256_t& contract_address, const uint256_t& key)
    {
        syncs.remove(std::make_pair(contract_address, key));
    }

    uint256_t load(const std::pair<uint256_t, uint256_t>& storage_key)
    {
        auto state = storage.get(storage_key);
        if (state.has_value()) {
            return eevm::from_big_endian(state->data());
        }

        return 0;
    }

    void load(uint8_t* data, const std::pair<uint256_t, uint256_t>& storage_key)
    {
        if (auto val = pending_storage.get(storage_key); val.has_value()) {
            std::memcpy(data, val->data(), 32u);
            pending_storage.remove(storage_key);
        }

        data += 32u;
    }

    std::vector<uint8_t> sync_states(
        std::multimap<uint256_t, std::pair<uint256_t, uint256_t>>& states)
    {
        size_t total = 20;
        std::set<std::pair<uint256_t, uint256_t>> update_keys;
        pending.foreach(
            [&states, &total, &update_keys, this](const auto& storageKey) {
                if (total++ < 0)
                    return false;

                update_keys.emplace(storageKey);
                states.emplace(
                    storageKey.first,
                    std::make_pair(storageKey.second, load(storageKey)));
                return true;
            });

        if (update_keys.size() < 1) {
            return {};
        }

        std::vector<uint8_t> old_states(update_keys.size() * 32u);
        auto _data = old_states.data();
        // remove key from pending
        for (auto& key : update_keys) {
            load(_data, key);
            syncs.insert(key);
            pending.remove(key);
        }

        auto hash = eevm::Keccak256(old_states);
        return hash.HashBytes();
    }
};

};