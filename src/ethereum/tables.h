// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

// EVM-for-CCF
#include "types.h"

#include <ccf/kv/map.h>
#include <ccf/kv/set.h>
// eEVM
#include "nljsontypes.h"

#include <eEVM/account.h>

namespace Ethereum
{
inline bool operator==(const TxResult& l, const TxResult& r)
{
    return l.contract_address == r.contract_address && l.logs == r.logs;
}

namespace tables
{
    inline constexpr auto BALANCES = "eth.account.balance";
    inline constexpr auto CODES = "eth.account.code";
    inline constexpr auto NONCES = "eth.account.nonce";
    inline constexpr auto STORAGE = "eth.storage";
    inline constexpr auto TXRESULT = "eth.txresults";
    inline constexpr auto TXSYNC = "eth.txsync";
    inline constexpr auto PENDING_STATES = "eth.pending_states";
    inline constexpr auto PENDING_STORAGE = "eth.pending_storage";
    inline constexpr auto CONTRACT_ENCRYPTED_KEY = "eth.contract_encrypted_key";
    inline constexpr auto LEVELS = "eth.contract_levels";
    inline constexpr auto PROOF = "eth.contract_proof";

    struct Accounts
    {
        using Balances = kv::Map<eevm::Address, uint256_t>;
        Balances balances;

        using Codes = kv::Map<eevm::Address, eevm::Code>;
        Codes codes;

        using Nonces = kv::Map<eevm::Address, eevm::Account::Nonce>;
        Nonces nonces;

        struct Views
        {
            Balances::Handle* balances;
            Codes::Handle* codes;
            Nonces::Handle* nonces;
        };

        Views get_views(kv::Tx& tx)
        {
            return {tx.rw(balances), tx.rw(codes), tx.rw(nonces)};
        }
    };

    using StorageKey = std::pair<eevm::Address, uint256_t>;
    using Storage = kv::Map<StorageKey, std::vector<uint8_t>>;
    using PendingStorage = kv::Map<StorageKey, std::vector<uint8_t>>;
    using Results = kv::Map<TxHash, TxResult>;
    using TxSyncs = kv::Set<StorageKey>;
    using PendingStates = kv::Set<StorageKey>;
    using ContractEncryptedKey = kv::Map<eevm::Address, std::vector<uint8_t>>;
    using ContractLevels = kv::Map<eevm::Address, ContractLevel>;
    using Proof = kv::Map<eevm::Address, uint256_t>;

    struct AccountsState
    {
        Accounts accounts;
        Storage storage;
        TxSyncs syncs;
        PendingStates pending_states;
        PendingStorage pending_storage;
        ContractEncryptedKey encrypted;
        ContractLevels levels;
        Proof proof;
        AccountsState() :
          accounts{
              Accounts::Balances(BALANCES),
              Accounts::Codes(CODES),
              Accounts::Nonces(NONCES)},
          storage(STORAGE),
          syncs(TXSYNC),
          pending_states(PENDING_STATES),
          pending_storage(PENDING_STORAGE),
          encrypted(CONTRACT_ENCRYPTED_KEY),
          levels(LEVELS),
          proof(PROOF)
        {}
    };

} // namespace tables
} // namespace Ethereum
