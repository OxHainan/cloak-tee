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

#include "abi/abicoder.h"
#include "crypto/secp256k1/key_pair.h"
#include "ethereum/types.h"
#include "tee_account.h"
#include "transaction/types.h"

#include <ccf/crypto/key_pair.h>
#include <ccf/tx.h>
#include <eEVM/account.h>
#include <eEVM/address.h>
#include <eEVM/util.h>
#include <ethereum_transaction.h>
#include <string>
namespace cloak4ccf::TeeManager
{
struct Account : public eevm::Account
{
    mutable tables::Accounts::Views acc_views;
    tables::KeyPair::Views key_views;
    eevm::Address address;

    Account(
        const tables::Accounts::Views& acc_,
        const tables::KeyPair::Views& key_pair_) :
      acc_views(acc_),
      key_views(key_pair_),
      address(check_tee_addr())
    {}

    eevm::Address check_tee_addr()
    {
        auto addr_it = key_views.publicAddr->get();
        if (!addr_it.has_value()) {
            throw std::logic_error("TEE is not prepare");
        }

        return addr_it.value();
    }

    eevm::Address get_address() const override
    {
        return address;
    }

    eevm::Account::Nonce get_nonce() const override
    {
        return acc_views.nonces->get(address).value_or(0);
    }

    uint256_t get_balance() const override
    {
        return acc_views.balances->get(address).value_or(0);
    }

    void increment_nonce() override
    {
        auto nonce = get_nonce();
        ++nonce;
        acc_views.nonces->put(address, nonce);
    }

    void set_balance(const uint256_t& b) override
    {
        acc_views.balances->put(address, b);
    }

    eevm::Code get_code() const override
    {
        return {};
    }

    void set_code(eevm::Code&& c) override {}

    crypto::KeyPairPtr get_tee_kp() const
    {
        auto kp_it = key_views.privateKey->get(address);
        if (!kp_it.has_value()) {
            throw std::logic_error("kp_sk not found");
        }
        return std::make_shared<crypto::KeyPair_k1Bitcoin>(kp_it.value());
    }

    std::vector<uint8_t> get_public_Key() const
    {
        auto kp = get_tee_kp();
        return kp->public_key_raw();
    }
};

using AccountPtr = std::shared_ptr<Account>;

class State
{
 public:
    tables::Accounts::Views accounts;
    tables::KeyPair::Views key_pair;

    State(
        const tables::Accounts::Views& acc_,
        const tables::KeyPair::Views& key_pair_) :
      accounts(acc_),
      key_pair(key_pair_)
    {}

    AccountPtr get()
    {
        if (!key_pair.publicAddr->get().has_value()) {
            LOG_DEBUG_FMT("tee not prepared");
            throw std::logic_error("tee not prepared");
        }

        return std::make_shared<Account>(accounts, key_pair);
    }

    AccountPtr create()
    {
        if (key_pair.publicAddr->get().has_value()) {
            LOG_DEBUG_FMT("tee has been prepared");
            throw std::logic_error("tee has been prepared");
        }

        auto kp = crypto::make_key_pair(crypto::CurveID::SECP256K1);
        auto addr = evm4ccf::get_address_from_public_key(kp);

        key_pair.privateKey->put(addr, kp->private_key_pem());
        key_pair.publicAddr->put(addr);

        eevm::Account::Nonce initial_nonce = 0;

        // Write initial balance
        const auto balance_it = accounts.balances->get(addr);
        if (balance_it.has_value()) {
            throw std::logic_error(fmt::format(
                "Trying to create account at {}, but it already has a "
                "balance",
                eevm::to_checksum_address(addr)));
        } else {
            accounts.balances->put(addr, 0);
        }

        // Write initial nonce
        const auto nonce_it = accounts.nonces->get(addr);
        if (nonce_it.has_value()) {
            throw std::logic_error(fmt::format(
                "Trying to create account at {}, but it already has a "
                "nonce",
                eevm::to_checksum_address(addr)));
        } else {
            accounts.nonces->put(addr, initial_nonce);
        }

        return std::make_shared<Account>(accounts, key_pair);
    }

    static State make_state(kv::Tx& tx, tables::Table& table)
    {
        return State(table.acc.get_views(tx), table.key_pair.get_views(tx));
    }

    static AccountPtr make_account(kv::Tx& tx, tables::Table& table)
    {
        return make_state(tx, table).get();
    }
};

// void append_argument(std::vector<uint8_t>& code, const std::vector<uint8_t>&
// arg)
// {
//     code.insert(code.end(), arg.begin(), arg.end());
// }

// void prepare(kv::Tx& tx, tables::Table& tee_table, const TeePrepare&
// tee_prepare)
// {
//     auto tee_acc = State::make_state(tx, tee_table).create();
//     // register tee address on chain
//     auto encoder = abicoder::Encoder();

//     encoder.add_inputs("manager", "address", tee_prepare.manager,
//     abicoder::common_type("address"));

//     encoder
//         .add_inputs("pubKey", "bytes",
//         eevm::to_hex_string(tee_acc->get_public_Key()),
//         abicoder::common_type("bytes"));
//     LOG_INFO_FMT("cloak public key {}",
//     eevm::to_hex_string(tee_acc->get_public_Key()));

//     auto contractCode = eevm::to_bytes(tee_prepare.cloakServiceContract);
//     append_argument(contractCode, encoder.encode());
//     const auto contractAddress =
//     eevm::generate_address(tee_acc->get_address(), tee_acc->get_nonce());
//     LOG_INFO_FMT("Cloak service address {}",
//     eevm::to_hex_string(contractAddress)); Ethereum::MessageCall
//     mc(tee_acc->get_address(), contractCode); auto signed_data =
//     evm4ccf::sign_eth_tx(tee_acc->get_tee_kp(), mc, tee_acc->get_nonce());
//     Utils::cloak_agent_log("register_tee_addr",
//     eevm::to_hex_string(signed_data)); tee_acc->increment_nonce();

//     auto service_view = tx.rw(tee_table.service);
//     service_view->put(contractAddress);
// }
} // namespace cloak4ccf::TeeManager
