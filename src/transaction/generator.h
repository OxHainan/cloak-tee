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
#include "app/rpc/context.h"
#include "ethereum/execute_transaction.h"
#include "ethereum/state.h"
#include "signature.h"
#include "tables.h"
#include "transaction/exception.h"

#include <eEVM/util.h>

namespace cloak4ccf {
namespace Transaction {

using Status = evm4ccf::Status;
using PrivacyPolicyTransaction = evm4ccf::PrivacyPolicyTransaction;
using Address = eevm::Address;
using CloakPolicyTransaction = evm4ccf::CloakPolicyTransaction;

class Generator {
 private:
    CloakContext& ctx;
    TransactionTables& tables;

 public:
    explicit Generator(CloakContext& ctx_) : ctx(ctx_), tables(ctx.cloakTables.txTables) {}

    auto add_privacy(const eevm::rlp::ByteString& encoded) {
        const auto decoded = evm4ccf::PrivacyTransactionWithSignature(encoded);
        PrivacyPolicyTransaction tc;
        auto hash = decoded.to_transaction_call(tc);
        auto [p, pd] = ctx.tx.get_view(tables.privacys, tables.privacy_digests);
        auto digests = pd->get(tc.to);
        if (digests.has_value()) {
            CLOAK_DEBUG_FMT("privacy digests already exists (digests {})",
                            eevm::to_hex_string(digests.value()));
            throw TransactionException(fmt::format("privacy digests already exists (digests {})",
                                                   eevm::to_hex_string(digests.value())));
        }

        p->put(hash, tc);
        pd->put(tc.to, hash);
        LOG_INFO_FMT("add privacy digests {}, address {}", hash, tc.to);
        return hash;
    }

    auto add_cloakTransaction(const eevm::rlp::ByteString& encoded) {
        const auto decoded = evm4ccf::CloakTransactionWithSignature(encoded);
        evm4ccf::MultiPartyTransaction mpt;
        decoded.to_transaction_call(mpt);

        auto [cp, cd, mp] =
            ctx.tx.get_view(tables.cloak_policys, tables.cloak_digests, tables.multi_partys);

        // mpt hash
        auto multi_digest = decoded.digest();

        if (mpt.check_transaction_type()) {
            eevm::KeccakHash target_digest = Utils::vec_to_KeccakHash(mpt.to);
            auto cpt_opt = cp->get(target_digest);
            if (!cpt_opt.has_value()) {
                throw TransactionException(
                    fmt::format("multi party transaction digests doesn't exists (digests {})",
                                eevm::to_hex_string(target_digest)));
            }

            cpt_opt->mpt_hash = target_digest;
            if (cpt_opt->get_status() != Status::PENDING) {
                LOG_AND_THROW("mpt is not PENDING");
            }
            cpt_opt->set_content(mpt.params.inputs);
            cp->put(target_digest, cpt_opt.value());
            if (cpt_opt->function.complete()) {
                cpt_opt->request_old_state(ctx.tx);
            }
            return target_digest;
        }

        Address to = eevm::from_big_endian(mpt.to.data(), 20u);
        CLOAK_DEBUG_FMT("to: {}", to_checksum_address(to));
        auto [pHash, ppt] = check_privacy_modules(to);

        // check nonce
        auto es = Ethereum::EthereumState::make_state(ctx.tx, ctx.cloakTables.acc_state);
        auto account_state = es.get(mpt.from);
        if (account_state.acc.get_nonce() > mpt.nonce) {
            throw TransactionException(fmt::format("nonce too low"));
        }

        CloakPolicyTransaction cpt(ppt, mpt.name(), multi_digest);

        cpt.set_content(mpt.params.inputs);
        cpt.policy_hash = pHash;
        CLOAK_DEBUG_FMT("cpt {}", eevm::to_hex_string(cpt.policy_hash));
        cp->put(multi_digest, cpt);
        cd->put(to, multi_digest);
        LOG_INFO_FMT("add user transaction digests {}", eevm::to_hex_string(multi_digest));

        if (cpt.function.complete()) {
            cpt.request_old_state(ctx.tx);
        }
        return multi_digest;
    }

    void sync_report(const evm4ccf::SyncReport& report) {
        auto cp_handler = ctx.tx.get_view(tables.cloak_policys);
        auto target_digest = Utils::to_KeccakHash(report.id);
        auto cp_opt = cp_handler->get(target_digest);
        if (!cp_opt.has_value()) {
            throw TransactionException(
                fmt::format("multi party transaction digests doesn't exists (digests {})",
                            eevm::to_hex_string(target_digest)));
        }

        if (report.result == "SYNCED") {
            cp_opt->set_status(Status::SYNCED);
        } else {
            cp_opt->set_status(Status::SYNC_FAILED);
        }
        cp_opt->mpt_hash = target_digest;
        cp_handler->put(target_digest, cp_opt.value());
    }

    void sync_public_keys(const evm4ccf::SyncKeys& syncKeys) {
        auto target_digest = Utils::to_KeccakHash(syncKeys.tx_hash);
        auto cp_handler = ctx.tx.get_view(tables.cloak_policys);
        auto cp_opt = cp_handler->get(target_digest);
        if (!cp_opt.has_value()) {
            throw TransactionException(
                fmt::format("multi party transaction digests doesn't exists (digests {})",
                            eevm::to_hex_string(target_digest)));
        }

        std::map<std::string, std::string> public_keys;
        auto public_keys_vec = eevm::to_bytes(syncKeys.data);
        auto public_key_list =
            abicoder::decode_string_array({public_keys_vec.begin() + 32, public_keys_vec.end()});
        for (size_t i = 0; i < cp_opt->requested_addresses.size(); i++) {
            public_keys[cp_opt->requested_addresses[i]] = public_key_list[i];
        }

        cp_opt->mpt_hash = target_digest;
        cp_opt->public_keys = public_keys;
        auto decrypted = cp_opt->decrypt_states(ctx.tx);
        Ethereum::execute_mpt(ctx, cp_opt.value(), decrypted);
        cp_handler->put(target_digest, cp_opt.value());
    }

    void sync_states(const evm4ccf::SyncStates& syncStates) {
        auto target_digest = Utils::to_KeccakHash(syncStates.tx_hash);
        auto cp_handler = ctx.tx.get_view(tables.cloak_policys);
        auto cp_opt = cp_handler->get(target_digest);
        if (!cp_opt.has_value()) {
            throw TransactionException(
                fmt::format("multi party transaction digests doesn't exists (digests {})",
                            eevm::to_hex_string(target_digest)));
        }

        auto old_states = abicoder::decode_uint256_array(eevm::to_bytes(syncStates.data));
        auto encoder = abicoder::Encoder();
        encoder.add_inputs("oldStates", "uint[]", old_states);
        auto old_states_packed = encoder.encode();
        auto old_states_hash = eevm::keccak_256(old_states_packed);

        if (!cp_opt->function.complete()) {
            throw TransactionException(
                fmt::format("function is not ready, get {}", eevm::to_hex_string(target_digest)));
        }

        cp_opt->old_states = old_states;
        cp_opt->old_states_hash = old_states_hash;
        cp_opt->mpt_hash = target_digest;
        if (!cp_opt->request_public_keys(ctx.tx)) {
            Ethereum::execute_mpt(ctx, cp_opt.value(), old_states);
        }

        cp_handler->put(target_digest, cp_opt.value());
    }

 private:
    std::tuple<eevm::KeccakHash, PrivacyPolicyTransaction> check_privacy_modules(
        const eevm::Address& to) {
        auto [p, pd] = ctx.tx.get_view(tables.privacys, tables.privacy_digests);

        auto privacy_digests = pd->get(to);
        if (!privacy_digests.has_value()) {
            throw TransactionException(fmt::format(
                "privacy digests doesn`t exists (contract address {})", eevm::to_hex_string(to)));
        }

        auto ppt = p->get(privacy_digests.value());
        if (!ppt.has_value()) {
            throw TransactionException(
                fmt::format("privacy module doesn`t exists (privacy digests {})",
                            eevm::to_hex_string(privacy_digests.value())));
        }

        return std::make_tuple(privacy_digests.value(), ppt.value());
    }
};

} // namespace Transaction
} // namespace cloak4ccf
