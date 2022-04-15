// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

// EVM-for-CCF
#include "types.h"

#include <ccf/kv/map.h>
// eEVM
#include "nljsontypes.h"

#include <eEVM/account.h>
#include <eEVM/address.h>

// Implement std::hash for uint256, so it can be used as key in kv
// namespace std
// {
// template <unsigned N>
// struct hash<intx::uint<N>>
// {
//     size_t operator()(const intx::uint<N>& n) const
//     {
//         const auto words = intx::to_words<size_t>(n);
//         return hash_container(words);
//     }
// };
// } // namespace std

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
    using Storage = kv::Map<StorageKey, uint256_t>;

    using Results = kv::Map<TxHash, TxResult>;

    struct AccountsState
    {
        Accounts accounts;
        Storage storage;

        AccountsState() :
          accounts{Accounts::Balances(BALANCES), Accounts::Codes(CODES), Accounts::Nonces(NONCES)},
          storage(STORAGE)
        {}
    };

} // namespace tables
} // namespace Ethereum
