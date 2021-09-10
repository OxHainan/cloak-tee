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
#include "abi/coder.h"
#include "abi/common.h"
#include "abi/parsing.h"
#include "abi/utils.h"
#include "type.h"

#include <cstddef>
#include <stdint.h>
#include <string>

namespace abicoder {

Type* entry_identity(const std::string& rawType);
Type* generate_coders(const std::string& rawType, const std::string& value);
class ArrayType : public Type {
 protected:
    ArrayType() {}

    ArrayType(const std::string& _type, const std::vector<std::string> _value, bool _dynamicType)
        : type(_type), isDynamicType(_dynamicType), value(_value) {
        if (!valid(_type, _value)) {
            throw std::logic_error("If empty vector is provided, use empty array instance");
        }
    }

    ArrayType(const std::string& _type, bool _dynamicType) : type(_type), isDynamicType(_dynamicType) {}

    ArrayType(const std::string& _type, const std::string& _value, bool _isDynamicType)
        : type(_type), isDynamicType(_isDynamicType), value(Utils::stringToArray(_value)) {
        if (!valid(_type, _value)) {
            throw std::logic_error("If empty string value is provided, use empty array instance");
        }
    }

    std::string getTypeAsString() override { return type; }

    std::vector<uint8_t> encode() override {
        for (size_t i = 0; i < value.size(); i++) {
            auto parameter = generate_coders(type, value[i]);
            parameters.push_back(parameter);
        }

        std::vector<uint8_t> data = Coder::pack(parameters);

        if (isDynamicType) {
            auto result = NumericType(value.size()).encode();
            result.insert(result.end(), data.begin(), data.end());
            return result;
        }

        return data;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        CLOAK_DEBUG_FMT("dynamic decode: {}", eevm::to_hex_string(inputs));
        auto length = inputs.size() / MAX_BYTE_LENGTH;

        if (length < 2) {
            throw std::logic_error(
                fmt::format("The minimum length of the dynamic array type is 1, get {}", length - 1));
        }

        auto header = decode_to_uint64(inputs, 0u, MAX_BYTE_LENGTH);
        if (header > length - 1) {
            throw std::logic_error(fmt::format(
                "The parsed dynamic type length does not match the actual array length, want {}, but get {}",
                length - 1,
                header));
        }

        size_t offset = MAX_BYTE_LENGTH, end = MAX_BYTE_LENGTH + header * MAX_BYTE_LENGTH;
        while (offset < end) {
            basic_decode(inputs, offset);
        }
    }

    size_t offset() override { return MAX_BYTE_LENGTH; }

    virtual ~ArrayType() {
        for (auto parameter : parameters) {
            if (parameter != nullptr) {
                delete parameter;
                parameter = nullptr;
            }
        }
    }

    std::vector<uint8_t> get_value() override {
        std::vector<uint8_t> data;
        for (auto parameter : parameters) {
            if (parameter != nullptr) {
                auto val = parameter->get_value();
                data.insert(data.end(), val.begin(), val.end());
            }
        }
        return data;
    }

 protected:
    void basic_decode(const std::vector<uint8_t>& inputs, size_t& offset) {
        auto parameter = entry_identity(type);
        parameter->decode(sub_vector(inputs, offset, offset + MAX_BYTE_LENGTH));
        parameters.push_back(parameter);
        offset += MAX_BYTE_LENGTH;
    }

    std::vector<std::string> value;
    std::vector<Type*> parameters;

 private:
    bool valid(const std::string& _type, const std::vector<std::string>& _value) {
        return !_type.empty() && _value.size() != 0;
    }

    bool valid(const std::string& _type, const std::string& _value) { return !_type.empty(); }

    bool isDynamicType;
    std::string type;
};

class DynamicArray : public ArrayType {
 public:
    explicit DynamicArray(const std::string& _type) : DynamicArray(_type, "") {}

    DynamicArray(const std::string& _type, const std::string& _value) : ArrayType(_type, _value, dynamicType()) {}

    DynamicArray(const std::string& _type, const std::vector<std::string>& _value)
        : ArrayType(_type, _value, dynamicType()) {}

    bool dynamicType() override { return true; }
};

class StaticArray : public ArrayType {
 public:
    StaticArray(const std::string& _type, const size_t& _expectedSize, const std::string& _value = "")
        : ArrayType(_type, _value, dynamicType()), expectedSize(_expectedSize) {}

    StaticArray(const std::string& _type, const std::vector<std::string>& _value)
        : ArrayType(_type, _value, dynamicType()), expectedSize(_value.size()) {
        isValid();
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        CLOAK_DEBUG_FMT("static decode:  {}", eevm::to_hex_string(inputs));
        auto length = inputs.size() / MAX_BYTE_LENGTH;
        if (length < 1) {
            throw std::logic_error(fmt::format("The minimum length of the static array type is 1, get {}", 0));
        }
        size_t offset = 0;
        for (size_t i = 0; i < expectedSize; i++) {
            basic_decode(inputs, offset);
        }
    }

    bool dynamicType() override { return false; }

    size_t offset() override { return expectedSize * MAX_BYTE_LENGTH; }

    std::string getTypeAsString() override {
        return ArrayType::getTypeAsString() + "[" + to_string(expectedSize) + "]";
    }

 private:
    void isValid() {
        if (expectedSize == 0 && value.size() > MAX_SIZE_OF_STATIC_ARRAY) {
            throw std::logic_error("Static arrays with a length greater than 1024 are not supported");
        } else if (expectedSize != 0 && value.size() != expectedSize) {
            throw std::logic_error(fmt::format("Expected array of type {} to have [{}] elements, but get {}",
                                               getTypeAsString(),
                                               expectedSize,
                                               value.size()));
        }
    }

    static constexpr size_t MAX_SIZE_OF_STATIC_ARRAY = 1024 * MAX_BYTE_LENGTH;
    size_t expectedSize;
};

Type* check_paramter(const std::string& rawType, const size_t& length) {
    if (!rawType.find(UINT)) {
        return new Uint(length);
    } else if (!rawType.find(INT)) {
        return new Int(length);
    } else if (!rawType.find(ADDRESS)) {
        return new Address();
    } else if (!rawType.find(STRING)) {
        return new Utf8String();
    } else if (!rawType.find(BOOL)) {
        return new Boolean();
    } else if (!rawType.find(BYTES)) {
        if (std::strcmp(rawType.c_str(), BYTES) == 0) return new DynamicBytes();
        return new Bytes(length);
    } else if (!rawType.find(FIXED) || !rawType.find(UFIXED)) {
        throw std::logic_error(fmt::format("Unsupported type: {}", rawType));
    }
    throw std::logic_error(fmt::format("Unrecognized type: {}", rawType));
}

Type* generate_coders(const std::string& rawType, const size_t& length, const std::string& value) {
    if (!rawType.find(UINT)) {
        return new Uint(value, length);
    } else if (!rawType.find(INT)) {
        return new Int(value, length);
    } else if (!rawType.find(ADDRESS)) {
        return new Address(value);
    } else if (!rawType.find(STRING)) {
        return new Utf8String(value);
    } else if (!rawType.find(BOOL)) {
        return new Boolean(value);
    } else if (!rawType.find(BYTES)) {
        if (std::strcmp(rawType.c_str(), BYTES) == 0 && length == 0) return new DynamicBytes(value);
        return new Bytes(length, value);
    } else if (!rawType.find(FIXED) || !rawType.find(UFIXED)) {
        throw std::logic_error(fmt::format("Unsupported type: {}", rawType));
    }
    throw std::logic_error(fmt::format("Unrecognized type: {}", rawType));
}

Type* entry_identity(const std::string& rawType) {
    auto [type, expectedSize, boolean] = Parsing(rawType).result();
    if (boolean) {
        if (expectedSize > 0) {
            // dynamic type
            return new StaticArray(type, expectedSize);
        }
        return new DynamicArray(type);
    }
    return check_paramter(type, expectedSize);
}

Type* generate_coders(const std::string& rawType, const std::string& value) {
    auto [type, expectedSize, boolean] = Parsing(rawType).result();
    if (boolean) {
        if (expectedSize > 0) {
            return new StaticArray(type, expectedSize, value);
        }

        return new DynamicArray(type, value);
    }

    return generate_coders(type, expectedSize, value);
}

}  // namespace abicoder
