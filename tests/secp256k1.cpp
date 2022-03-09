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

#include "app/blit.h"
#include "ccf/crypto/pem.h"
#include "crypto/secp256k1/key_pair.h"
#include "eEVM/address.h"
#include "eEVM/keccak256.h"
#include "eEVM/util.h"
#include "ethereum/tee_account.h"
#include "kv/store.h"
#include "kv/test/null_encryptor.h"
#include "service/blit.h"

#include <chrono>
#include <doctest/doctest.h>
#include <ethereum_transaction.h>

namespace crypto::secp256k1
{
    using namespace std;
    static const string contents_ =
      "Lorem ipsum dolor sit amet, consectetur adipiscing "
      "elit, sed do eiusmod tempor incididunt ut labore et"
      " dolore magna aliqua. Ut enim ad minim veniam, quis"
      " nostrud exercitation ullamco laboris nisi ut "
      "aliquip ex ea commodo consequat. Duis aute irure "
      "dolor in reprehenderit in voluptate velit esse "
      "cillum dolore eu fugiat nulla pariatur. Excepteur "
      "sint occaecat cupidatat non proident, sunt in culpa "
      "qui officia deserunt mollit anim id est laborum.";

    vector<uint8_t> contents(contents_.begin(), contents_.end());

    template <typename T>
    void corrupt(T& buf)
    {
        buf[1]++;
        buf[buf.size() / 2]++;
        buf[buf.size() - 2]++;
    }

    TEST_CASE("Sign, verify, with KeyPair")
    {
        auto kp = make_key_pair();
        const vector<uint8_t> sig = kp->sign(contents);
        CHECK(kp->verify(contents, sig));

        auto kp2 = crypto::secp256k1::make_key_pair(kp->private_key_pem());
        CHECK(kp2->verify(contents, sig));

        for (auto i = 0; i < 10; ++i)
        {
            const auto new_sig = kp2->sign(contents);
            CHECK(kp->verify(contents, new_sig));
            CHECK(kp2->verify(contents, new_sig));
        }
    }

    TEST_CASE("Sign, verify, with PublicKey")
    {
        auto kp = make_key_pair();
        const vector<uint8_t> sig = kp->sign(contents);

        const auto pubKey = kp->public_key_pem();
        auto pubk = secp256k1::make_public_key(pubKey);
        CHECK(pubk->verify(contents, sig));
    }

    TEST_CASE("Sign, fail to verify with bad signature")
    {
        auto kp = make_key_pair();
        vector<uint8_t> sig = kp->sign(contents);
        const auto public_key = kp->public_key_pem();
        auto pubk = secp256k1::make_public_key(public_key);
        corrupt(sig);
        CHECK_FALSE(pubk->verify(contents, sig));
    }

    TEST_CASE("secp256k1 store in kv")
    {
        using PrivateKeyPem =
          kv::RawCopySerialisedMap<eevm::Address, crypto::Pem>;
        PrivateKeyPem privatePem("public:private");
        kv::Store store;

        auto encryptor = std::make_shared<kv::NullTxEncryptor>();
        store.set_encryptor(encryptor);
        auto tx = store.create_tx();
        auto privateTx = tx.rw(privatePem);

        INFO("generate secp256k1 keypair");
        {
            auto kp = make_key_pair();
            auto addr = evm4ccf::get_address_from_public_key(kp);
            privateTx->put(addr, kp->private_key_pem());
            REQUIRE(tx.commit() == kv::CommitResult::SUCCESS);
        }
    }
} // namespace crypto::secp256k1
