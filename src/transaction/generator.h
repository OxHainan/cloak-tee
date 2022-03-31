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
#include "ccf/tx.h"
#include "eEVM/keccak256.h"
#include "ethereum/execute_transaction.h"
#include "ethereum/state.h"
#include "ethereum/syncstate.h"
#include "ethereum/tee_manager.h"
#include "signature.h"
#include "tables.h"
#include "transaction/exception.h"
#include "types.h"

#include <app/utils.h>
#include <eEVM/util.h>
namespace cloak4ccf::Transaction
{
using Status = evm4ccf::Status;
using PrivacyPolicyTransaction = evm4ccf::PrivacyPolicyTransaction;
using Address = eevm::Address;
using CloakPolicyTransaction = evm4ccf::CloakPolicyTransaction;

class Generator
{
 private:
    CloakContext& ctx;
    TransactionTables& tables;

 public:
    explicit Generator(CloakContext& ctx_) : ctx(ctx_), tables(ctx.cloakTables.txTables) {}

    auto add_privacy(const eevm::rlp::ByteString& encoded)
    {
        const auto decoded = evm4ccf::PrivacyTransactionWithSignature(encoded);
        PrivacyPolicyTransaction tc;
        auto hash = decoded.to_transaction_call(tc);
        auto p = ctx.tx.rw(tables.privacys);
        auto pd = ctx.tx.rw(tables.privacy_digests);
        auto digests = pd->get(tc.to);

        if (digests.has_value()) {
            LOG_DEBUG_FMT("privacy digests already exists (digests {})", digests.value());
            throw TransactionException(fmt::format("privacy digests already exists (digests {})", digests.value()));
        }

        p->put(hash, tc);
        pd->put(tc.to, hash);
        LOG_INFO_FMT("add privacy digests {}, address {}", hash, eevm::to_hex_string(tc.to));
        return hash;
    }

    auto add_cloakTransaction(const eevm::rlp::ByteString& encoded)
    {
        const auto decoded = evm4ccf::CloakTransactionWithSignature(encoded);
        evm4ccf::MultiPartyTransaction mpt;
        decoded.to_transaction_call(mpt);

        auto cp = ctx.tx.rw(tables.cloak_policys);
        auto cd = ctx.tx.rw(tables.cloak_digests);
        auto mp = ctx.tx.rw(tables.multi_partys);
        // mpt hash
        auto multi_digest = decoded.digest();
        if (mpt.check_transaction_type()) {
            auto target_digest = eevm::Keccak256::from_hex(mpt.to);
            auto cpt_opt = cp->get(target_digest);
            if (!cpt_opt.has_value()) {
                throw TransactionException(fmt::format(
                    "multi party transaction digests doesn't exists "
                    "(digests {})",
                    target_digest));
            }

            if (cpt_opt->get_status() != Status::PENDING) {
                LOG_DEBUG_FMT("mpt is not PENDING");
                throw TransactionException("mpt is not PENDING");
            }

            cpt_opt->set_content(mpt);
            cp->put(target_digest, cpt_opt.value());

            if (cpt_opt->function.complete()) {
                // commit propose
                auto acc = TeeManager::State::make_account(ctx.tx, ctx.cloakTables.tee_table);
                propose(target_digest, cpt_opt.value(), acc);
            }

            return target_digest;
        }

        Address to = eevm::from_big_endian(mpt.to.data(), 20u);
        LOG_DEBUG_FMT("to: {}", eevm::to_checksum_address(to));
        auto [pHash, ppt] = check_privacy_modules(to);

        // check nonce
        auto es = Ethereum::EthereumState::make_state(ctx.tx, ctx.cloakTables.acc_state);
        auto account_state = es.get(mpt.from);
        if (account_state.acc.get_nonce() > mpt.nonce) {
            throw TransactionException(fmt::format("nonce too low"));
        }

        CloakPolicyTransaction cpt(ppt, mpt.name());
        cpt.from = mpt.from;
        cpt.set_content(mpt);
        cp->put(multi_digest, cpt);
        cd->put(to, multi_digest);
        LOG_INFO_FMT("add user transaction digests {}", multi_digest);

        if (cpt.function.complete()) {
            auto acc = TeeManager::State::make_account(ctx.tx, ctx.cloakTables.tee_table);
            propose(multi_digest, cpt, acc);
        }

        return multi_digest;
    }

    void sync_report(const SyncReport& report)
    {
        auto cp_handler = ctx.tx.rw(tables.cloak_policys);
        // auto target_digest = Utils::to_KeccakHash(report.id);
        auto cp_opt = cp_handler->get(report.id);
        if (!cp_opt.has_value()) {
            throw TransactionException(fmt::format(
                "multi party transaction digests doesn't exists (digests "
                "{})",
                report.id));
        }

        if (report.result == "SYNCED") {
            cp_opt->set_status(Status::SYNCED);
        } else {
            cp_opt->set_status(Status::SYNC_FAILED);
        }

        cp_handler->put(report.id, cp_opt.value());
    }

    void sync_propose(const SyncPropose& report)
    {
        auto cp_handler = ctx.tx.rw(tables.cloak_policys);
        // auto target_digest = Utils::to_KeccakHash(report.id);
        auto cp_opt = cp_handler->get(report.id);
        if (!cp_opt.has_value()) {
            throw TransactionException(fmt::format(
                "multi party transaction digests doesn't exists (digests "
                "{})",
                report.id));
        }

        if (report.success) {
            auto acc = TeeManager::State::make_account(ctx.tx, ctx.cloakTables.tee_table);
            request_old_state(report.id, cp_opt.value(), acc);
        } else {
            cp_opt->set_status(Status::DROPPED);
        }

        cp_handler->put(report.id, cp_opt.value());
    }

    void sync_public_keys(const SyncKeys& syncKeys)
    {
        auto cp_handler = ctx.tx.rw(tables.cloak_policys);
        auto cp_opt = cp_handler->get(syncKeys.tx_hash);
        if (!cp_opt.has_value()) {
            throw TransactionException(fmt::format(
                "multi party transaction digests doesn't exists (digests "
                "{})",
                syncKeys.tx_hash));
        }

        std::map<std::string, std::string> public_keys;
        auto public_keys_data = eevm::to_bytes(syncKeys.data);
        auto public_key_list = abicoder::Decoder::decode_bytes_array(public_keys_data);

        for (size_t i = 0; i < cp_opt->requested_addresses.size(); i++) {
            public_keys[cp_opt->requested_addresses[i]] = public_key_list[i];
        }

        cp_opt->public_keys = public_keys;
        auto acc = TeeManager::State::make_account(ctx.tx, ctx.cloakTables.tee_table);
        auto decrypted = cp_opt->decrypt_states(acc->get_tee_kp());
        auto new_states = Ethereum::execute_mpt(ctx, cp_opt.value(), acc->get_address(), decrypted);
        sync_result(syncKeys.tx_hash, cp_opt.value(), acc, new_states);
        cp_handler->put(syncKeys.tx_hash, cp_opt.value());
    }

    void sync_states(const SyncStates& syncStates)
    {
        auto cp_handler = ctx.tx.rw(tables.cloak_policys);
        auto states_handler = ctx.tx.rw(tables.states_digests);
        auto cp_opt = cp_handler->get(syncStates.tx_hash);
        if (!cp_opt.has_value()) {
            throw TransactionException(fmt::format(
                "multi party transaction digests doesn't exists (digests "
                "{})",
                syncStates.tx_hash));
        }
        auto data = eevm::to_bytes(syncStates.data);
        auto old_states = abicoder::Decoder::decode_bytes_array(data);
        states_handler->put(syncStates.tx_hash, eevm::Keccak256(data));

        if (!cp_opt->function.complete()) {
            throw TransactionException(fmt::format("function is not ready, get {}", syncStates.tx_hash));
        }

        cp_opt->old_states = old_states;

        auto acc = TeeManager::State::make_account(ctx.tx, ctx.cloakTables.tee_table);
        auto service_addr = TeeManager::get_service_addr(ctx.tx.rw(ctx.cloakTables.tee_table.service));
        if (!cp_opt->request_public_keys(syncStates.tx_hash, acc, service_addr)) {
            auto new_states = Ethereum::execute_mpt(ctx, cp_opt.value(), acc->get_address(), old_states);
            sync_result(syncStates.tx_hash, cp_opt.value(), acc, new_states);
        }

        cp_handler->put(syncStates.tx_hash, cp_opt.value());
    }

 private:
    std::tuple<eevm::Keccak256, PrivacyPolicyTransaction> check_privacy_modules(const eevm::Address& to)
    {
        auto pd = ctx.tx.rw(tables.privacy_digests);
        auto p = ctx.tx.rw(tables.privacys);
        auto privacy_digests = pd->get(to);
        if (!privacy_digests.has_value()) {
            throw TransactionException(
                fmt::format("privacy digests doesn`t exists (contract address {})", eevm::to_hex_string(to)));
        }

        auto ppt = p->get(privacy_digests.value());
        if (!ppt.has_value()) {
            throw TransactionException(
                fmt::format("privacy module doesn`t exists (privacy digests {})", privacy_digests.value()));
        }

        return std::make_tuple(privacy_digests.value(), ppt.value());
    }

    void request_old_state(
        const eevm::Keccak256& target_digest, CloakPolicyTransaction& cpt, TeeManager::AccountPtr acc)
    {
        cpt.set_status(Status::REQUESTING_OLD_STATES);
        auto data = cpt.get_states_call_data(true);

        auto response = Ethereum::SyncStateResponse(target_digest, acc->get_address(), cpt.verifierAddr, data);
        Utils::cloak_agent_log("request_old_state", response);
    }

    void propose(const eevm::Keccak256& target_digest, const CloakPolicyTransaction& cpt, TeeManager::AccountPtr acc)
    {
        auto packed = cpt.packedPropose(target_digest);
        LOG_INFO_FMT("propose: {}", eevm::to_hex_string(packed));
        auto service_addr = TeeManager::get_service_addr(ctx.tx.rw(ctx.cloakTables.tee_table.service));
        Ethereum::MessageCall mc(acc->get_address(), service_addr, packed);
        auto signed_data = evm4ccf::sign_eth_tx(acc->get_tee_kp(), mc, acc->get_nonce());
        auto response = Ethereum::SyncStateResponse(target_digest, signed_data);
        Utils::cloak_agent_log("propose", response);
        acc->increment_nonce();
    }

    // == Sync new states ==
    void sync_result(
        const eevm::Keccak256& target_digest,
        CloakPolicyTransaction& cpt,
        TeeManager::AccountPtr acc,
        const std::vector<uint8_t>& new_states_)
    {
        auto new_states = abicoder::Decoder::decode_bytes_array(new_states_);
        LOG_DEBUG_FMT("splited new_states:{}\n", fmt::join(new_states, "\n"));

        auto encrypted_states = cpt.encrypt_states(acc->get_tee_kp(), new_states);
        LOG_DEBUG_FMT("encrypted:{}", fmt::join(encrypted_states, ", "));

        auto old_states_len = cpt.get_states_return_len(true);
        auto encoder = abicoder::Encoder("set_states");

        encoder.add_inputs("read", "bytes[]", cpt.get_states_read(), abicoder::make_bytes_array());
        encoder.add_inputs("old_states_len", "uint256", eevm::to_hex_string(old_states_len), abicoder::number_type());
        encoder.add_inputs("data", "bytes[]", encrypted_states, abicoder::make_bytes_array());
        encoder.add_inputs("proof", "uint256[]", get_proof(cpt, target_digest), abicoder::make_number_array());
        auto packed = encoder.encodeWithSignatrue();
        LOG_DEBUG_FMT("encoded data:{}", abicoder::split_abi_data_to_str(packed));

        // packed complete tx;
        auto encoderCom = abicoder::Encoder("complete");
        encoderCom.add_inputs("txid", "uint256", target_digest.hex_str(), abicoder::number_type());
        encoderCom.add_inputs("data", "bytes", eevm::to_hex_string(packed), abicoder::common_type("bytes"));
        encoderCom.add_inputs(
            "returnCommit", "bytes", eevm::to_hex_string(cpt.function.raw_outputs), abicoder::common_type("bytes"));

        auto service_addr = TeeManager::get_service_addr(ctx.tx.rw(ctx.cloakTables.tee_table.service));

        Ethereum::MessageCall mc(acc->get_address(), service_addr, encoderCom.encodeWithSignatrue());

        // TODO(DUMMY): choose a better value based on concrete contract
        LOG_DEBUG_FMT("data:{}", mc.data);
        auto signed_data = evm4ccf::sign_eth_tx(acc->get_tee_kp(), mc, acc->get_nonce());
        auto response = Ethereum::SyncStateResponse(target_digest, signed_data);

        Utils::cloak_agent_log("sync_result", response);
        cpt.set_status(evm4ccf::Status::SYNCING);
        acc->increment_nonce();
    }

    std::vector<std::string> get_proof(CloakPolicyTransaction& cpt, const eevm::Keccak256& target_digest)
    {
        auto pd = ctx.tx.rw(tables.privacy_digests);
        auto sd = ctx.tx.rw(tables.states_digests);

        auto privacy_digest = pd->get(cpt.to);
        if (!privacy_digest.has_value()) {
            throw TransactionException(
                fmt::format("privacy digests doesn`t exists (contract address {})", eevm::to_hex_string(cpt.to)));
        }

        auto old_states_digest = sd->get(target_digest);
        if (!old_states_digest.has_value()) {
            throw TransactionException(fmt::format(
                "old states digests doesn`t exists (cloak transaction "
                "{})",
                target_digest));
        }

        return {cpt.codeHash, privacy_digest.value().hex_str(), old_states_digest.value().hex_str()};
    }
};

} // namespace cloak4ccf::Transaction
