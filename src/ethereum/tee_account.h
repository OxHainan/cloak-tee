// Copyright (c) 2020 Oxford-Hainan Blockchain Research Institute
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once
#include "kv/tx.h"
#include "tls/key_pair.h"
#include "tls/pem.h"

#include <eEVM/account.h>
#include <eEVM/address.h>

namespace cloak4ccf {

namespace TeeManager {
namespace tables {
inline constexpr auto PRIVATEKEY = "tee.account.privateKey";
inline constexpr auto PUBLICADDR = "tee.account.publicAddr";
inline constexpr auto BALANCES = "tee.account.balance";
inline constexpr auto NONCES = "tee.account.nonce";
inline constexpr auto SERVICE = "tee.account.service";

struct KeyPair {
    using PrivateKey = kv::Map<eevm::Address, tls::Pem>;
    PrivateKey privateKey;

    using PublicAddr = kv::Map<std::string, eevm::Address>;
    PublicAddr publicAddr;

    struct Views {
        PrivateKey::TxView* privateKey;
        PublicAddr::TxView* publicAddr;
    };

    Views get_views(kv::Tx& tx) {
        return {tx.get_view(privateKey), tx.get_view(publicAddr)};
    }

    KeyPair() : privateKey(PRIVATEKEY), publicAddr(PUBLICADDR) {}
};

struct Accounts {
    using Balances = kv::Map<eevm::Address, uint256_t>;
    Balances balances;
    using Nonces = kv::Map<eevm::Address, eevm::Account::Nonce>;
    Nonces nonces;

    struct Views {
        Balances::TxView* balances;
        Nonces::TxView* nonces;
    };

    Views get_views(kv::Tx& tx) {
        return {tx.get_view(balances), tx.get_view(nonces)};
    }

    Accounts() : balances(BALANCES), nonces(NONCES) {}
};
using CloakService = kv::Map<std::string, eevm::Address>;

struct Table {
    tables::Accounts acc;
    tables::KeyPair key_pair;
    tables::CloakService service;

    Table() : acc(), key_pair(), service(tables::SERVICE) {}
};

} // namespace tables
} // namespace TeeManager
} // namespace cloak4ccf
