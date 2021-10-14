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

#include "abi/common.h"
#include "abi/exception.h"
#include "abi/utils.h"
#include "fmt/format.h"
#include "nlohmann/json.hpp"
#include "string"

#include <algorithm>
#include <app/utils.h>
#include <iostream>
#include <sys/types.h>
#include <vector>

namespace abicoder {

class Type {
 public:
    static constexpr size_t MAX_BIT_LENGTH = 256;
    static constexpr size_t MAX_BYTE_LENGTH = MAX_BIT_LENGTH / 8;
    virtual std::vector<uint8_t> encode() = 0;
    virtual void decode(const std::vector<uint8_t>&) = 0;
    virtual std::string getTypeAsString() = 0;
    virtual void set_value(const std::string&) {}
    virtual std::vector<uint8_t> get_value() = 0;
    virtual bool dynamicType() {
        return false;
    }
    virtual size_t offset() = 0;
    virtual ~Type() {}
};

using TypePrt = std::shared_ptr<Type>;
using TypePtrLst = std::vector<TypePrt>;

class Address : public Type {
 public:
    Address() {}
    explicit Address(const std::string& _value) : value(to_bytes(_value, LENGTH)) {}

    std::vector<uint8_t> encode() override {
        return value;
    }

    void set_value(const std::string& src) override {
        value = to_bytes(src, LENGTH);
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        if (inputs.size() < MAX_BYTE_LENGTH) {
            throw ABIException("Input value length has no enough space");
        }

        value.resize(MAX_BYTE_LENGTH);
        std::copy(inputs.begin(), inputs.begin() + MAX_BYTE_LENGTH, value.begin());
    }

    std::vector<uint8_t> get_value() override {
        return value;
    }

    bool dynamicType() override {
        return false;
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

    std::string getTypeAsString() override {
        return ADDRESS;
    }

 private:
    size_t LENGTH = 12u;
    std::vector<uint8_t> value;
};

class NumericType : public Type {
 public:
    NumericType() {}
    explicit NumericType(const std::vector<uint8_t>& val) {
        value = eevm::from_big_endian(val.data(), val.size());
    }

    NumericType(const std::string& _type, const intx::uint256& _value) :
        value(_value), type(_type) {}

    NumericType(const std::string& _type, const std::string& _value) :
        value(eevm::to_uint256(_value)), type(_type) {}

    explicit NumericType(const size_t& length) : value(eevm::to_uint256(std::to_string(length))) {}

    uint64_t to_uint64() {
        const auto val = value;
        if (val > std::numeric_limits<uint64_t>::max()) {
            throw ABIException(fmt::format("Value on NumbericType {} is larger than 2^64",
                                           eevm::to_hex_string(val)));
        }
        return static_cast<uint64_t>(val);
    }

    std::vector<uint8_t> encode() override {
        std::vector<uint8_t> result(MAX_BYTE_LENGTH);
        std::vector<uint8_t> desh_hash(MAX_BYTE_LENGTH);
        std::memcpy(&desh_hash[0], &value, MAX_BYTE_LENGTH);
        to_array(result, desh_hash, 0, false);
        return result;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        if (inputs.size() < MAX_BYTE_LENGTH) {
            throw ABIException("Input value length has no enough space");
        }
        auto val = sub_vector(inputs, 0, MAX_BYTE_LENGTH);
        value = eevm::from_big_endian(val.data(), val.size());
    }

    std::vector<uint8_t> get_value() override {
        auto val = std::vector<uint8_t>(MAX_BYTE_LENGTH);
        eevm::to_big_endian(value, val.data());
        return val;
    }

    std::string getTypeAsString() override {
        return type;
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

 private:
    std::string type;
    intx::uint256 value;
};

class IntType : public NumericType {
 public:
    IntType() {}

    explicit IntType(const size_t& bitSize,
                     const uint256& value = 0u,
                     const std::string& typePrefix = "") :
        NumericType(parse(typePrefix, bitSize), value) {}

 private:
    bool isValidBitSize(const size_t& bitSize) {
        return bitSize % 8 == 0 && bitSize > 0 && bitSize <= MAX_BIT_LENGTH;
    }

    std::string parse(const std::string& typePrefix, const size_t& _bitSize) {
        auto bitSize = calc_bitSize(_bitSize);
        if (!isValidBitSize(bitSize)) {
            throw ABIException(
                "Bitsize must be 8 bit aligned, and in range 0 < bitSize <= 256, and in valid "
                "range.");
        }

        if (typePrefix.empty())
            return typePrefix;
        return typePrefix + std::to_string(bitSize);
    }

    size_t calc_bitSize(const size_t& size) {
        return size == 0 ? MAX_BIT_LENGTH : size;
    }
};

class Int : public IntType {
 public:
    explicit Int(const size_t& bitSize = MAX_BIT_LENGTH) : Int(uint256(0u), bitSize) {}

    explicit Int(const std::string& value, const size_t& bitSize = MAX_BIT_LENGTH) :
        Int(eevm::to_uint256(value), bitSize) {}

    explicit Int(const uint256& _value, const size_t& bitSize = MAX_BIT_LENGTH) :
        IntType(bitSize, _value, INT) {}

    bool dynamicType() override {
        return false;
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

 private:
    Int() = delete;
};

class Uint : public IntType {
 public:
    explicit Uint(const size_t& bitSize = MAX_BIT_LENGTH) : Uint(uint256(0u), bitSize) {}
    explicit Uint(const std::string& value, const size_t& bitSize = MAX_BIT_LENGTH) :
        Uint(eevm::to_uint256(value), bitSize) {}

    explicit Uint(const uint256& _value, const size_t& bitSize = MAX_BIT_LENGTH) :
        IntType(bitSize, _value, UINT) {}

    explicit Uint(const std::vector<uint8_t>& inputs, const size_t& bitSize = MAX_BIT_LENGTH) :
        Uint(eevm::from_big_endian(inputs.data(), inputs.size()), bitSize) {}

    bool dynamicType() override {
        return false;
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

 private:
    Uint() = delete;
};

class Boolean : public Type {
 public:
    Boolean() {}
    explicit Boolean(const bool& _value) {
        value = _value;
    }

    explicit Boolean(const std::string& _value) {
        auto v = eevm::to_bytes(_value);
        if (v.size() > 1) {
            throw ABIException("Input value length is greater than 1");
        }

        auto c = static_cast<size_t>(v[0]);
        if (c > 1 || c < 0) {
            throw ABIException("The input value exceeds the maximum range of the bool type");
        }

        value = c == 1;
    }

    std::vector<uint8_t> encode() override {
        std::vector<uint8_t> result(MAX_BYTE_LENGTH);
        to_array(result, (uint8_t)value, MAX_BYTE_LENGTH - 1u);
        return result;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        if (inputs.size() < MAX_BYTE_LENGTH) {
            throw ABIException("Input value length has no enough space");
        }

        auto val_inputs = sub_vector(inputs, 0, MAX_BYTE_LENGTH);
        auto val = eevm::from_big_endian(val_inputs.data(), val_inputs.size());
        auto match = val & (uint256(0) - 1);

        if (match == uint256(1)) {
            value = true;
        } else if (match == uint256(0)) {
            value = false;
        } else {
            throw ABIException("decode bool failed");
        }
    }

    bool get_value() const {
        return value;
    }

    std::vector<uint8_t> get_value() override {
        return encode();
    }

    bool dynamicType() override {
        return false;
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

    std::string getTypeAsString() override {
        return BOOL;
    }

 private:
    bool value;
};

inline uint64_t decode_to_uint64(const std::vector<uint8_t>& inputs) {
    if (inputs.size() != 32u) {
        throw ABIException(
            fmt::format("Cant't convert to uint64, want {} but get {}", 32u, inputs.size()));
    }
    return NumericType(inputs).to_uint64();
}

inline uint64_t decode_to_uint64(const std::vector<uint8_t>& inputs,
                                 const size_t& begin,
                                 const size_t& offset = 32u) {
    auto val = sub_vector(inputs, begin, offset);
    return decode_to_uint64(val);
}

inline std::vector<uint8_t> encode_to_vector(const size_t& value) {
    return NumericType(value).encode();
}

class BytesType : public Type {
 public:
    explicit BytesType(const std::string& _type) : type(_type) {}
    BytesType(const std::string& _type, const std::vector<uint8_t>& src) :
        type(_type), value(src) {}

    std::vector<uint8_t> encode() override {
        std::vector<uint8_t> result(MAX_BYTE_LENGTH + alignSize(value.size()));
        auto header = NumericType(value.size()).encode();
        to_array(result, header);
        to_array(result, value, MAX_BYTE_LENGTH);
        return result;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        if (inputs.size() < MAX_BYTE_LENGTH) {
            throw ABIException("Input value length has no enough space");
        }

        auto header = decode_to_uint64(inputs, 0, MAX_BYTE_LENGTH);
        value = sub_vector(inputs, MAX_BYTE_LENGTH, MAX_BYTE_LENGTH + header);
    }

    std::vector<uint8_t> get_value() const {
        return value;
    }

    size_t offset() override {
        return alignSize(value.size());
    }

    std::string getTypeAsString() override {
        return type;
    }

    std::vector<uint8_t> get_value() override {
        return value;
    }

 protected:
    std::vector<uint8_t> value;

 private:
    std::string type;
    bool isDynamic;
};

// static bytes, likes bytes8, bytes32
class Bytes : public BytesType {
 public:
    explicit Bytes(const size_t& byteSize = 32) : Bytes(byteSize, std::vector<uint8_t>(byteSize)) {}

    Bytes(const size_t& byteSize, const std::vector<uint8_t>& _value) :
        BytesType(BYTES + std::to_string(_value.size()), _value), length(byteSize) {
        if (!isValid(byteSize, value)) {
            throw ABIException(
                "Input byte array must be in range 0 < M <= 32 and length must match type");
        }
    }

    Bytes(const size_t& byteSize, const std::string& src) :
        Bytes(byteSize, std::vector<uint8_t>(src.begin(), src.end())) {}

    std::vector<uint8_t> encode() override {
        size_t mod = value.size() % MAX_BYTE_LENGTH;
        if (mod != 0) {
            size_t padding = MAX_BYTE_LENGTH - mod;
            auto pad = std::vector<uint8_t>(padding);
            value.insert(value.end(), pad.begin(), pad.end());
        }
        return value;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        if (inputs.size() < MAX_BYTE_LENGTH && inputs.size() > length) {
            throw ABIException("Input value length has no enough space");
        }

        std::copy(inputs.begin(), inputs.begin() + length, value.begin());
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
    }

    bool dynamicType() override {
        return false;
    }

 private:
    bool isValid(const size_t& byteSize, const std::vector<uint8_t>& _value) {
        size_t length = _value.size();
        return length > 0 && length <= MAX_BYTE_LENGTH && length == byteSize;
    }

    size_t length;
};

class DynamicBytes : public BytesType {
 public:
    DynamicBytes() : BytesType(BYTES) {}
    explicit DynamicBytes(const std::vector<uint8_t>& _value) : BytesType(BYTES, _value) {}

    explicit DynamicBytes(const std::string& src) : DynamicBytes(bytes_strip(src)) {}

    bool dynamicType() override {
        return true;
    }
};

class Utf8String : public BytesType {
 public:
    explicit Utf8String(const std::string& src = "") : BytesType(STRING, string_to_bytes(src)) {}

    std::string getTypeAsString() override {
        return STRING;
    }

    bool dynamicType() override {
        return true;
    }

    void set_value(const std::string& src) override {
        value = string_to_bytes(src);
    }
};

} // namespace abicoder
