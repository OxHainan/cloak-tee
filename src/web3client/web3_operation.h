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
                    tx.rw(acc_state.storage));

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
                        auto contract_address = eevm::
                            to_uint256(request.data(), request.size(), false);

                        if (code.empty()) {
                            LOG_INFO_FMT(
                                "Address [{}] doesn't a "
                                "contract on chain",
                                eevm::to_hex_string(contract_address));
                            return;
                        }

                        auto es =
                            Ethereum::EthereumState::make_state(tx, acc_state);

                        auto account_state = es.get(contract_address);
                        if (account_state.acc.has_code()) {
                            LOG_INFO_FMT(
                                "Address [{}] is a contract address",
                                eevm::to_hex_string(contract_address));
                            return;
                        }

                        LOG_INFO_FMT(
                            "sync contract escrow, contract {}",
                            eevm::to_hex_string(contract_address));

                        if (auto cl = tx.wo(acc_state.levels); cl) {
                            cl->put(
                                contract_address,
                                Ethereum::ContractLevel::SOLIDITY);
                        }

                        account_state.acc.set_code(std::move(code));
                        break;
                    }

                    default:
                        break;
                }
                tx.commit();
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
        RINGBUFFER_WRITE_MESSAGE(
            Web3Msg::call,
            to_host,
            Methods::GetCode,
            eevm::rlp::encode_details::to_byte_string(contract_address));
    }

    void get(const Methods method, const RequestData& data)
    {
        RINGBUFFER_WRITE_MESSAGE(Web3Msg::call, to_host, method, data);
    }

 private:
    void on_heart_beat()
    {
        auto tx = store->create_tx();
        auto sync = Ethereum::TransactionSync(
            tx.rw(acc_state.syncs),
            tx.rw(acc_state.pending_states),
            tx.rw(acc_state.storage));

        std::multimap<uint256_t, std::pair<uint256_t, uint256_t>> states;
        sync.sync_states(states);
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
            LOG_INFO_FMT(
                "on_heart_beat, key {}, value {}",
                eevm::to_hex_string(state.first),
                eevm::to_hex_string(state.second));
        }

        auto encoder = abicoder::Encoder("set_states");
        encoder.add_inputs(
            "keys", "uint256[]", keys, abicoder::make_number_array());
        encoder.add_inputs(
            "values", "uint256[]", vals, abicoder::make_number_array());
        LOG_INFO_FMT(
            "signature address {}", eevm::to_hex_string(acc->get_address()));
        Ethereum::MessageCall mc;
        mc.to = contract_address.value();
        mc.data = eevm::to_hex_string(encoder.encodeWithSignatrue());
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