// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#pragma once

// EVM-for-CCF
#include "types.h"
// CCF
#include "ds/hash.h"
#include "ds/logger.h"
#include "enclave/app_interface.h"

#include <kv/map.h>
#include <kv/store.h>
#include <kv/tx.h>
#include <kv/tx_view.h>
#include <node/rpc/serdes.h>
// eEVM
#include <eEVM/account.h>
#include <eEVM/address.h>
#include <eEVM/storage.h>

// STL/3rd-party
#include "msgpack/address.h"
#include "msgpack/types.h"
#include "nljsontypes.h"

#include <vector>

// Implement std::hash for uint256, so it can be used as key in kv
namespace std {
template <unsigned N>
struct hash<intx::uint<N>> {
    size_t operator()(const intx::uint<N>& n) const {
        const auto words = intx::to_words<size_t>(n);
        return hash_container(words);
    }
};
} // namespace std

namespace Ethereum {

inline bool operator==(const TxResult& l, const TxResult& r) {
    return l.contract_address == r.contract_address && l.logs == r.logs;
}

namespace tables {

inline constexpr auto BALANCES = "eth.account.balance";
inline constexpr auto CODES = "eth.account.code";
inline constexpr auto NONCES = "eth.account.nonce";
inline constexpr auto STORAGE = "eth.storage";
inline constexpr auto TXRESULT = "eth.txresults";
inline constexpr auto REFERENCE_KV = "eth.reference_kv";
inline constexpr auto SSTORE_KV = "eth.sstore_kv";

struct Accounts {
    using Balances = kv::Map<eevm::Address, uint256_t>;
    Balances balances;

    using Codes = kv::Map<eevm::Address, eevm::Code>;
    Codes codes;

    using Nonces = kv::Map<eevm::Address, eevm::Account::Nonce>;
    Nonces nonces;

    struct Views {
        Balances::TxView* balances;
        Codes::TxView* codes;
        Nonces::TxView* nonces;
    };

    Views get_views(kv::Tx& tx) {
        return {tx.get_view(balances), tx.get_view(codes), tx.get_view(nonces)};
    }
};

using StorageKey = std::pair<eevm::Address, uint256_t>;
using Storage = kv::Map<StorageKey, uint256_t>;

using StateKey = std::pair<std::string, uint256_t>; // mpt_id + addr
using ReferenceKv = kv::Map<StateKey, std::string>;
using SstoreKv = kv::Map<StateKey, std::string>;

using Results = kv::Map<TxHash, TxResult>;

struct AccountsState {
    Accounts accounts;
    Storage storage;
    ReferenceKv reference_kv;
    SstoreKv sstore_kv;

    AccountsState() :
        accounts{Accounts::Balances(BALANCES), Accounts::Codes(CODES), Accounts::Nonces(NONCES)},
        storage(STORAGE), reference_kv(REFERENCE_KV), sstore_kv(SSTORE_KV) {}
};

} // namespace tables
} // namespace Ethereum
