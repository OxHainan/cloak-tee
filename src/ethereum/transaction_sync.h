#pragma once
#include "set"
#include "tables.h"
namespace Ethereum
{
class TransactionSync
{
 private:
    tables::TxSyncs::Handle& syncs;
    tables::PendingStates::Handle& pending;
    tables::Storage::Handle& storage;

 public:
    TransactionSync(
        tables::TxSyncs::Handle* th,
        tables::PendingStates::Handle* uh,
        tables::Storage::Handle* st) :
      syncs(*th),
      pending(*uh),
      storage(*st)
    {}

    void update_sync(const uint256_t& contract_address, const uint256_t& key)
    {
        syncs.remove(std::make_pair(contract_address, key));
    }

    void sync_states(
        std::multimap<uint256_t, std::pair<uint256_t, uint256_t>>& states)
    {
        size_t total = 20;
        std::set<std::pair<uint256_t, uint256_t>> update_keys;
        pending.foreach([&states, &total, &update_keys, this](
                            const auto& storageKey) {
            if (total++ < 0)
                return false;

            update_keys.emplace(storageKey);
            states.emplace(
                storageKey.first,
                std::make_pair(
                    storageKey.second, storage.get(storageKey).value_or(0)));
            return true;
        });

        // remove key from pending
        for (auto& key : update_keys) {
            syncs.insert(key);
            pending.remove(key);
        }
    }
};

};