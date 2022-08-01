#pragma once
#include "abi/abicoder.h"
#include "abi/utils.h"
#include "blit.h"
#include "ds/messaging.h"
#include "eEVM/rlp.h"
#include "eEVM/util.h"
#include "ethereum/state.h"
#include "ethereum/tee_account.h"
#include "ethereum/tee_manager.h"
#include "ethereum/transaction_sync.h"
#include "kv/store.h"
#include "web3_operation_interface.h"
#include "web3_ringbuffer_types.h"
namespace cloak4ccf
{
class Web3Operation : public AbstractWeb3Operation
{
 protected:
    ringbuffer::WriterPtr to_host;
    std::shared_ptr<kv::Store> store = nullptr;
    Ethereum::tables::AccountsState& acc_state;
    TeeManager::tables::Table& tee_table;
    std::map<uint256_t, uint256_t> escrows;
    std::map<uint256_t, std::vector<uint8_t>> contract_codes;
    EthereumConfiguration config;

 public:
    Web3Operation(
        const ringbuffer::WriterPtr& writer,
        std::shared_ptr<kv::Store> _store,
        Ethereum::tables::AccountsState& _acc_state,
        TeeManager::tables::Table& _tee_table) :
      to_host(writer),
      store(_store),
      acc_state(_acc_state),
      tee_table(_tee_table)
    {}

    void register_message_handlers(
        messaging::Dispatcher<ringbuffer::Message>& dispatcher)
    {
        DISPATCHER_SET_MESSAGE_HANDLER(
            dispatcher,
            Web3Msg::success,
            [this](const uint8_t* data, size_t size) {
                auto [_target_contract, _keys] =
                    ringbuffer::read_message<Web3Msg::success>(data, size);

                auto tx = store->create_tx();
                auto sync = Ethereum::TransactionSync(
                    tx.rw(acc_state.syncs),
                    tx.rw(acc_state.pending_states),
                    tx.rw(acc_state.storage),
                    tx.rw(acc_state.pending_storage));

                auto target_contract = eevm::to_uint256(_target_contract);
                auto keys =
                    nlohmann::json::parse(_keys).get<std::vector<uint256_t>>();

                for (auto key : keys) {
                    sync.update_sync(target_contract, key);
                }

                tx.commit();
            });

        DISPATCHER_SET_MESSAGE_HANDLER(
            dispatcher,
            Web3Msg::heartbeat,
            [this](const uint8_t* data, size_t size) { on_heart_beat(); });

        DISPATCHER_SET_MESSAGE_HANDLER(
            dispatcher,
            Web3Msg::call_response,
            [this](const uint8_t* data, size_t size) {
                auto [methods, request, code] = ringbuffer::read_message<
                    Web3Msg::call_response>(data, size);
                auto tx = store->create_tx();
                switch (methods) {
                    case Methods::GetCode:
                    {
                        auto logic = eevm::
                            to_uint256(request.data(), request.size(), false);

                        auto contract_address = escrows[logic];
                        if (code.empty()) {
                            LOG_INFO_FMT(
                                "Address [{}] doesn't a "
                                "contract on chain",
                                eevm::to_hex_string(contract_address));
                            return;
                        }

                        contract_codes[contract_address] = code;
                        auto proof_slot = eevm::to_uint256(
                            "0x2c3b1d89f196b8b08364560cca554b8f81cb28533bd8b87a"
                            "acb02775960713c2");

                        RINGBUFFER_WRITE_MESSAGE(
                            Web3Msg::escrow,
                            to_host,
                            EscrowStatus::GETPROOF,
                            eevm::rlp::encode_details::to_byte_string(
                                contract_address),
                            eevm::rlp::encode_details::to_byte_string(
                                proof_slot));
                        break;
                    }

                    default:
                        break;
                }
                tx.commit();
            });
        DISPATCHER_SET_MESSAGE_HANDLER(
            dispatcher,
            Web3Msg::escrow,
            [this](const uint8_t* data, size_t size) {
                auto [status, contract_address, params] =
                    ringbuffer::read_message<Web3Msg::escrow>(data, size);
                auto addr = eevm::from_big_endian(contract_address.data(), 20u);
                switch (status) {
                    case EscrowStatus::GETCODE:
                    {
                        auto logic_addr =
                            eevm::from_big_endian(params.data(), 20u);
                        LOG_INFO_FMT(
                            "logic: {} ", eevm::to_hex_string(logic_addr));

                        if (logic_addr == 0) {
                            LOG_INFO_FMT(
                                "contract {} is not a valid cloak contract",
                                eevm::to_hex_string(contract_address));
                            return;
                        }

                        escrows[logic_addr] = addr;
                        RINGBUFFER_WRITE_MESSAGE(
                            Web3Msg::call, to_host, Methods::GetCode, params);
                        break;
                    }

                    case EscrowStatus::GETPROOF:
                    {
                        auto proof = eevm::from_big_endian(params.data(), 0x20);
                        for (auto it = escrows.begin(); it != escrows.end();
                             it++) {
                            if (it->second == addr) {
                                escrows.erase(it);
                                break;
                            }
                        }

                        auto codeHash = eevm::Keccak256(contract_codes[addr]);
                        auto state_vec =
                            eevm::rlp::encode_details::to_byte_string(
                                config.state);

                        auto hashBytes = codeHash.HashBytes();

                        hashBytes.insert(
                            hashBytes.end(),
                            state_vec.begin(),
                            state_vec.end());

                        auto proof_ = eevm::Keccak256(hashBytes);
                        if (proof !=
                            eevm::from_big_endian(
                                proof_.HashBytes().data(), 32u)) {
                            LOG_INFO_FMT(
                                "contract {} escrow verify proof failed",
                                eevm::to_hex_string(addr));
                            return;
                        }

                        auto tx = store->create_tx();
                        auto es =
                            Ethereum::EthereumState::make_state(tx, acc_state);

                        auto account_state = es.get(addr);
                        if (account_state.acc.has_code()) {
                            LOG_INFO_FMT(
                                "Address [{}] is a contract address",
                                eevm::to_hex_string(addr));
                            return;
                        }

                        LOG_INFO_FMT(
                            "sync contract escrow, contract {}",
                            eevm::to_hex_string(addr));

                        if (auto cl = tx.wo(acc_state.levels); cl) {
                            cl->put(addr, Ethereum::ContractLevel::SOLIDITY);
                        }

                        if (auto pr = tx.wo(acc_state.proof); pr) {
                            pr->put(addr, proof);
                        }

                        account_state.acc.set_code(
                            std::move(contract_codes[addr]));
                        contract_codes.erase(addr);
                        tx.commit();
                        break;
                    }
                }
            });
    }

    void send(
        const RequestData& data,
        const uint256_t& addr,
        const std::vector<uint8_t>& keys)
    {
        RINGBUFFER_WRITE_MESSAGE(
            Web3Msg::send, to_host, data, eevm::to_hex_string(addr), keys);
    }

    void contract_escrow(const uint256_t& contract_address) override
    {
        auto logic_slot = eevm::to_uint256(
            "0x2a7ee7a990a244bda6b8218d6cc50c824030ffcca1203a6c59bdca9cb30f9e5"
            "8");

        RINGBUFFER_WRITE_MESSAGE(
            Web3Msg::escrow,
            to_host,
            EscrowStatus::GETCODE,
            eevm::rlp::encode_details::to_byte_string(contract_address),
            eevm::rlp::encode_details::to_byte_string(logic_slot));
    }

    void get(const Methods method, const RequestData& data)
    {
        RINGBUFFER_WRITE_MESSAGE(Web3Msg::call, to_host, method, data);
    }

    void set_ethereum_configuration(
        const EthereumConfiguration _config) override
    {
        config = _config;
    }

 private:
    void on_heart_beat()
    {
        auto tx = store->create_tx();
        auto sync = Ethereum::TransactionSync(
            tx.rw(acc_state.syncs),
            tx.rw(acc_state.pending_states),
            tx.rw(acc_state.storage),
            tx.rw(acc_state.pending_storage));

        std::multimap<uint256_t, std::pair<uint256_t, uint256_t>> states;

        auto old_states = sync.sync_states(states);
        if (states.size() == 0)
            return;

        TeeManager::AccountPtr acc;
        try {
            acc = TeeManager::State::make_account(tx, tee_table);
        }
        catch (const std::exception& e) {
            std::cerr << e.what() << '\n';
        }

        std::vector<std::string> keys;
        std::vector<std::string> vals;
        std::optional<uint256_t> contract_address = std::nullopt;
        for (auto& [contract, state] : states) {
            if (!contract_address.has_value()) {
                contract_address = contract;
            }

            keys.emplace_back(eevm::to_hex_string(state.first));
            vals.emplace_back(eevm::to_hex_string(state.second));
            LOG_DEBUG_FMT(
                "on_heart_beat, key {}, value {}",
                eevm::to_hex_string(state.first),
                eevm::to_hex_string(state.second));
        }

        auto encoder = abicoder::Encoder("updateState");

        std::vector<uint8_t> proof(64);
        if (auto pr = tx.ro(acc_state.proof); pr) {
            eevm::to_big_endian(
                pr->get(*contract_address).value_or(0), proof.data());
        }

        std::memcpy(proof.data() + 32, old_states.data(), 32);
        encoder.add_inputs(
            "proof",
            "bytes32",
            eevm::Keccak256(proof).hex_str(),
            abicoder::common_type("bytes", 32));
        encoder.add_inputs(
            "keys", "bytes32[]", keys, abicoder::make_number_array());
        encoder.add_inputs(
            "values", "bytes32[]", vals, abicoder::make_number_array());

        auto encoder1 = abicoder::Encoder("updateState");

        encoder1.add_inputs(
            "proxy",
            "address[]",
            {eevm::to_hex_string(contract_address.value())},
            abicoder::make_common_array("address"));

        std::vector<std::string> sigVec;
        sigVec.push_back(eevm::to_hex_string(encoder.encodeWithSignatrue()));

        encoder1.add_inputs(
            "data", "bytes[]", sigVec, abicoder::make_bytes_array());

        Ethereum::MessageCall mc;
        mc.to = config.service;
        mc.data = eevm::to_hex_string(encoder1.encodeWithSignatrue());
        auto sig =
            evm4ccf::sign_eth_tx(acc->get_tee_kp(), mc, acc->get_nonce());
        acc->increment_nonce();
        auto key_j = nlohmann::json(keys).dump();
        tx.commit();
        send(
            sig,
            contract_address.value(),
            std::vector<uint8_t>(key_j.begin(), key_j.end()));
    }
};
} // namespace cloak4ccf