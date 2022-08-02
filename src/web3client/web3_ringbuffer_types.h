#pragma once
#include "ds/ring_buffer_types.h"
#include "web3_operation_interface.h"

namespace cloak4ccf
{
enum Web3Msg : ringbuffer::Message
{
    DEFINE_RINGBUFFER_MSG_TYPE(send),
    DEFINE_RINGBUFFER_MSG_TYPE(heartbeat),
    DEFINE_RINGBUFFER_MSG_TYPE(call),
    DEFINE_RINGBUFFER_MSG_TYPE(call_response),
    DEFINE_RINGBUFFER_MSG_TYPE(escrow),
    DEFINE_RINGBUFFER_MSG_TYPE(failed),
    DEFINE_RINGBUFFER_MSG_TYPE(success),
};
} // namespace cloak4ccf

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
    cloak4ccf::Web3Msg::send,
    cloak4ccf::RequestData,
    std::string,
    std::vector<uint8_t>);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(cloak4ccf::Web3Msg::heartbeat, bool);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
    cloak4ccf::Web3Msg::call, cloak4ccf::Methods, cloak4ccf::RequestData);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
    cloak4ccf::Web3Msg::call_response,
    cloak4ccf::Methods,
    cloak4ccf::RequestData,
    cloak4ccf::ResponseData);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
    cloak4ccf::Web3Msg::escrow,
    cloak4ccf::EscrowStatus,
    std::vector<uint8_t>,
    std::vector<uint8_t>);

DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(cloak4ccf::Web3Msg::failed, std::string);
DECLARE_RINGBUFFER_MESSAGE_PAYLOAD(
    cloak4ccf::Web3Msg::success, std::string, std::vector<uint8_t>);