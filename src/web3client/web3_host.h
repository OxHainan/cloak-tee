#pragma once
#include "ds/messaging.h"
#include "eEVM/keccak256.h"
#include "eEVM/rlp.h"
#include "eEVM/util.h"
#include "host/timer.h"
#include "types.h"
#include "web3_operation_interface.h"
#include "web3_ringbuffer_types.h"
#include "web3client/client.h"
namespace cloak4ccf
{
class Web3HostImpl
{
    messaging::BufferProcessor& bp;
    ringbuffer::WriterPtr to_enclave;
    std::shared_ptr<jsonrpc::ws::Client> client;
    std::unordered_map<std::string, std::string> pending;
    std::unordered_map<std::string, std::vector<uint8_t>> pendingKeys;

 public:
    Web3HostImpl(
        messaging::BufferProcessor& bp, const ringbuffer::WriterPtr& writer) :
      bp(bp),
      to_enclave(writer),
      client(jsonrpc::ws::Client::get_instance())
    {
        register_message_handlers();
    }

    void register_message_handlers()
    {
        DISPATCHER_SET_MESSAGE_HANDLER(
            bp, Web3Msg::send, [&](const uint8_t* data, size_t size) {
                auto [request, target_contract, keys] =
                    ringbuffer::read_message<Web3Msg::send>(data, size);

                auto tx_hash = eevm::Keccak256(request).hex_str();

                pending.emplace(tx_hash, target_contract);
                pendingKeys.emplace(tx_hash, keys);

                try {
                    client->jsonrpc()->send<jsonrpc::ws::SendRawTransaction>(
                        {request},
                        [&](jsonrpc::ws::Error::Ptr err,
                            std::shared_ptr<std::vector<uint8_t>> _result) {
                            if (err && err->errorCode() != 0) {
                                LOG_INFO_FMT("Error: {}", err->errorMessage());
                                return;
                            }

                            auto tx_hash = jsonrpc::ws::SendRawTransaction::
                                ResultSerialiser::from_serialised(*_result);

                            LOG_INFO_FMT("send: {}", tx_hash);
                            auto target_contract = pending[tx_hash];
                            auto keys = pendingKeys[tx_hash];

                            pending.erase(tx_hash);
                            pendingKeys.erase(tx_hash);
                            RINGBUFFER_WRITE_MESSAGE(
                                Web3Msg::success,
                                to_enclave,
                                target_contract,
                                keys);
                        });
                }
                catch (const std::exception& e) {
                    std::cerr << e.what() << '\n';
                }
            });

        DISPATCHER_SET_MESSAGE_HANDLER(
            bp, Web3Msg::call, [&](const uint8_t* data, size_t size) {
                auto [method, request] =
                    ringbuffer::read_message<Web3Msg::call>(data, size);

                switch (method) {
                    case Methods::ETH_CALL:
                        client->jsonrpc()->send<jsonrpc::ws::EthSyncing>(
                            [](jsonrpc::ws::Error::Ptr err,
                               std::shared_ptr<std::vector<uint8_t>> _result) {
                                if (err && err->errorCode() != 0) {
                                    return;
                                }
                                LOG_INFO_FMT(
                                    "result: {}",
                                    std::string(
                                        _result->begin(), _result->end()));
                            });
                        break;
                    case Methods::GetCode:
                    {
                        auto contract_address = request;
                        client->jsonrpc()->send<jsonrpc::ws::GetCode>(
                            {contract_address},
                            [&, contract_address](
                                jsonrpc::ws::Error::Ptr err,
                                std::shared_ptr<std::vector<uint8_t>> _result) {
                                if (err && err->errorCode() != 0) {
                                    return;
                                }

                                auto result = jsonrpc::ws::GetCode::
                                    ResultSerialiser::from_serialised(*_result);

                                RINGBUFFER_WRITE_MESSAGE(
                                    Web3Msg::call_response,
                                    to_enclave,
                                    Methods::GetCode,
                                    contract_address,
                                    eevm::to_bytes(result));
                            });
                        break;
                    }
                    default:
                        throw std::runtime_error(
                            fmt::format("Unexpected method {}", method));
                }
            });

        DISPATCHER_SET_MESSAGE_HANDLER(
            bp, Web3Msg::escrow, [&](const uint8_t* data, size_t size) {
                auto [status_, contract_address_, params_] =
                    ringbuffer::read_message<Web3Msg::escrow>(data, size);
                auto contract_address = contract_address_;
                auto addr = eevm::from_big_endian(contract_address.data(), 20u);
                auto params = eevm::from_big_endian(params_.data(), 0x20);
                auto status = status_;
                client->jsonrpc()->send<jsonrpc::ws::EthGetStorageAt>(
                    {addr, params},
                    [&, status, contract_address](
                        jsonrpc::ws::Error::Ptr err,
                        std::shared_ptr<std::vector<uint8_t>> _result) {
                        if (err && err->errorCode() != 0) {
                            return;
                        }

                        auto result = jsonrpc::ws::EthGetStorageAt::
                            ResultSerialiser::from_serialised(*_result);

                        RINGBUFFER_WRITE_MESSAGE(
                            Web3Msg::escrow,
                            to_enclave,
                            status,
                            contract_address,
                            eevm::rlp::encode_details::to_byte_string(result));
                    });
            });
    }

    void on_heart_beat()
    {
        RINGBUFFER_WRITE_MESSAGE(Web3Msg::heartbeat, to_enclave, true);
    }

    void on_timer()
    {
        on_heart_beat();
    }
};
using Web3Host = asynchost::proxy_ptr<asynchost::Timer<Web3HostImpl>>;
}