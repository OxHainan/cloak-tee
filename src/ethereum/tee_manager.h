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

#include "app/utils.h"
#include "ethereum/types.h"
#include "kv/tx.h"
#include "tee_account.h"
#include "tls/key_pair.h"
#include "tls/pem.h"
#include "transaction/types.h"

#include <eEVM/account.h>
#include <eEVM/address.h>
#include <eEVM/util.h>
#include <ethereum_transaction.h>
#include <string>
namespace cloak4ccf {

using Address = eevm::Address;

namespace TeeManager {

struct Account : public eevm::Account {
    mutable tables::Accounts::Views acc_views;
    tables::KeyPair::Views key_views;
    Address address;

    Account(const tables::Accounts::Views& acc_, const tables::KeyPair::Views& key_pair_) :
        acc_views(acc_), key_views(key_pair_), address(check_tee_addr()) {}

    Address check_tee_addr() {
        auto addr_it = key_views.publicAddr->get("TEE_PUBLICADDR");
        if (!addr_it.has_value()) {
            throw std::logic_error("TEE is not prepare");
        }

        return addr_it.value();
    }

    Address get_address() const override {
        return address;
    }

    eevm::Account::Nonce get_nonce() const override {
        return acc_views.nonces->get(address).value_or(0);
    }

    uint256_t get_balance() const override {
        return acc_views.balances->get(address).value_or(0);
    }

    void increment_nonce() override {
        auto nonce = get_nonce();
        ++nonce;
        acc_views.nonces->put(address, nonce);
    }

    void set_balance(const uint256_t& b) override {
        acc_views.balances->put(address, b);
    }

    eevm::Code get_code() const override {
        return {};
    }

    void set_code(eevm::Code&& c) override {}

    tls::KeyPairPtr get_tee_kp() const {
        auto kp_it = key_views.privateKey->get(address);
        if (!kp_it.has_value()) {
            throw std::logic_error("kp_sk not found");
        }
        return tls::make_key_pair(kp_it.value());
    }
};

using AccountPtr = std::shared_ptr<Account>;

Address get_pki_addr(tables::Pki::TxView* view) {
    auto pki_it = view->get("TEE_PKI");
    if (!pki_it.has_value()) {
        throw std::logic_error("TEE is not prepare");
    }
    return pki_it.value();
}

class State {
 public:
    tables::Accounts::Views accounts;
    tables::KeyPair::Views key_pair;

    template <typename... Ts>
    State(const tables::Accounts::Views& acc_, const tables::KeyPair::Views& key_pair_) :
        accounts(acc_), key_pair(key_pair_) {}

    AccountPtr get() {
        if (!key_pair.publicAddr->get("TEE_PUBLICADDR").has_value()) {
            LOG_AND_THROW("tee not prepared");
        }

        return std::make_shared<Account>(accounts, key_pair);
    }

    AccountPtr create() {
        if (key_pair.publicAddr->get("TEE_PUBLICADDR").has_value()) {
            LOG_AND_THROW("tee has been prepared");
        }

        auto kp = tls::make_key_pair(tls::CurveImpl::secp256k1_bitcoin);
        auto addr = evm4ccf::get_addr_from_kp(kp);

        key_pair.privateKey->put(addr, kp->private_key_pem());
        key_pair.publicAddr->put("TEE_PUBLICADDR", addr);

        eevm::Account::Nonce initial_nonce = 0;

        // Write initial balance
        const auto balance_it = accounts.balances->get(addr);
        if (balance_it.has_value()) {
            throw std::logic_error(
                fmt::format("Trying to create account at {}, but it already has a balance",
                            eevm::to_checksum_address(addr)));
        } else {
            accounts.balances->put(addr, 0);
        }

        // Write initial nonce
        const auto nonce_it = accounts.nonces->get(addr);
        if (nonce_it.has_value()) {
            throw std::logic_error(
                fmt::format("Trying to create account at {}, but it already has a nonce",
                            eevm::to_checksum_address(addr)));
        } else {
            accounts.nonces->put(addr, initial_nonce);
        }

        return std::make_shared<Account>(accounts, key_pair);
    }

    static State make_state(kv::Tx& tx, tables::Table& table) {
        return State(table.acc.get_views(tx), table.key_pair.get_views(tx));
    }

    static AccountPtr make_account(kv::Tx& tx, tables::Table& table) {
        return make_state(tx, table).get();
    }
};

void prepare(kv::Tx& tx, tables::Table& tee_table, TeePrepare& tee_prepare) {
    auto tee_acc = State::make_state(tx, tee_table).create();
    // register tee address on chain
    std::vector<uint8_t> data = Utils::make_function_selector("setTEEAddress()");
    Ethereum::MessageCall mc(tee_acc->get_address(), tee_prepare.cloak_service_addr, data);
    auto signed_data = evm4ccf::sign_eth_tx(tee_acc->get_tee_kp(), mc, tee_acc->get_nonce());
    Utils::cloak_agent_log("register_tee_addr", eevm::to_hex_string(signed_data));

    tee_acc->increment_nonce();

    auto pki_view = tx.get_view(tee_table.pki);
    pki_view->put("TEE_PKI", tee_prepare.pki_addr);
}

} // namespace TeeManager
} // namespace cloak4ccf
