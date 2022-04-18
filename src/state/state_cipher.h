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
#include "ccf/crypto/symmetric_key.h"

#include <ds/serialized.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
namespace State
{
struct StateCipher : public crypto::GcmCipher
{
    eevm::Address owner;
    StateCipher() = default;
    StateCipher(size_t size) : crypto::GcmCipher(size) {}
    std::vector<uint8_t> serialise()
    {
        auto owner_ = eevm::rlp::encode_details::to_byte_string(owner);
        auto space = hdr.serialised_size() + cipher.size() + owner_.size();
        std::vector<uint8_t> serial(space);

        auto data_ = serial.data();
        serialized::write(data_, space, owner_.data(), owner_.size());
        serialized::write(data_, space, hdr.tag, sizeof(hdr.tag));
        serialized::write(data_, space, hdr.iv.data(), hdr.iv.size());
        serialized::write(data_, space, cipher.data(), cipher.size());
        return serial;
    }

    void set_owner(const eevm::Address& owner_)
    {
        owner = owner_;
    }

    void deserialise(const std::vector<uint8_t>& serial)
    {
        auto data = serial.data();
        auto size = serial.size();
        auto owner_ = serialized::read(data, size, 20u);
        owner = eevm::from_big_endian(owner_.data(), owner_.size());
        hdr.deserialise(data, size);
        cipher = serialized::read(data, size, size);
    }
};
} // namespace State