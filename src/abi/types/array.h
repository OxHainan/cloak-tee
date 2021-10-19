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
#include "abi/exception.h"
#include "abi/parsing.h"
#include "abi/utils.h"
#include "type.h"

#include <cstddef>
#include <stdint.h>
#include <string>

namespace abicoder {
class Encoder;

TypePrt entry_identity(const std::string& rawType);
TypePrt generate_coders(const std::string& rawType, const nlohmann::json& value);

class ArrayType : public Type {
 public:
    std::string getTypeAsString() override {
        return type;
    }

    std::vector<uint8_t> encode() override {
        if (value.size() == 0) {
            return std::vector<uint8_t>(32);
        }

        bool isArray = value[0].is_array();
        for (size_t i = 0; i < value.size(); i++) {
            if (isArray) {
                auto parameter = generate_coders(type, value[i]);
                parameters.push_back(parameter);
                continue;
            }

            auto parameter = generate_coders(type, value[i]);
            parameters.push_back(parameter);
        }

        auto data = Coder::pack(parameters);

        if (isDynamicType) {
            auto result = NumericType(value.size()).encode();
            result.insert(result.end(), data.begin(), data.end());
            return result;
        }

        return data;
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        auto length = inputs.size() / MAX_BYTE_LENGTH;

        if (length < 2) {
            throw ABIException(fmt::format(
                "The minimum length of the dynamic array type is 1, get {}", length - 1));
        }

        auto header = decode_to_uint64(inputs, 0u, MAX_BYTE_LENGTH);
        if (header > length - 1) {
            throw ABIException(
                fmt::format("The parsed dynamic type length does not match the actual array "
                            "length, want {}, but get {}",
                            length - 1,
                            header));
        }
        size_t offset = MAX_BYTE_LENGTH, end = MAX_BYTE_LENGTH + header * MAX_BYTE_LENGTH;
        while (offset < end) {
            basic_decode(inputs, offset);
        }
    }

    size_t offset() override {
        return MAX_BYTE_LENGTH;
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
    ArrayType(const std::string& _type, bool _dynamicType) :
        isDynamicType(_dynamicType), type(_type) {}

    ArrayType(const std::string& _type, const nlohmann::json& _value, bool _isDynamicType) :
        value(_value.get<std::vector<nlohmann::json>>()), isDynamicType(_isDynamicType),
        type(_type) {
        if (!valid(_type)) {
            throw std::logic_error("If empty string value is provided, use empty array instance");
        }
    }

    void basic_decode(const std::vector<uint8_t>& inputs, size_t& offset) {
        auto parameter = entry_identity(type);

        if (parameter->dynamicType()) {
            auto offDst = decode_to_uint64(inputs, offset, offset + MAX_BYTE_LENGTH);
            parameter->decode(
                std::vector<uint8_t>(inputs.begin() + offDst + MAX_BYTE_LENGTH, inputs.end()));
        } else {
            parameter->decode(sub_vector(inputs, offset, offset + MAX_BYTE_LENGTH));
        }

        parameters.push_back(parameter);
        offset += MAX_BYTE_LENGTH;
    }

    std::vector<nlohmann::json> value;
    std::vector<TypePrt> parameters;

 private:
    ArrayType() = delete;

    bool valid(const std::string& _type) {
        return !_type.empty();
    }

    bool isDynamicType;
    std::string type;
};

class DynamicArray : public ArrayType {
 public:
    explicit DynamicArray(const std::string& _type,
                          const nlohmann::json& _value = vector<string>()) :
        ArrayType(_type, _value, dynamicType()) {}

    bool dynamicType() override {
        return true;
    }

    TypePtrLst get_parameters() {
        return parameters;
    }
};

class StaticArray : public ArrayType {
 public:
    StaticArray(const std::string& _type,
                const size_t& _expectedSize,
                const nlohmann::json& _value = vector<string>()) :
        ArrayType(_type, _value, false),
        dynamic(check_dynamic(_type)), expectedSize(_expectedSize) {}

    StaticArray(const std::string& _type, const nlohmann::json& _value) :
        ArrayType(_type, _value, false), dynamic(check_dynamic(_type)), expectedSize(value.size()) {
    }

    void decode(const std::vector<uint8_t>& inputs) override {
        auto length = inputs.size() / MAX_BYTE_LENGTH;
        if (length < 1) {
            throw ABIException(
                fmt::format("The minimum length of the static array type is 1, get {}", 0));
        }

        size_t offset = 0;
        for (size_t i = 0; i < expectedSize; i++) {
            basic_decode(inputs, offset);
        }
    }

    bool dynamicType() override {
        return dynamic;
    }

    size_t offset() override {
        return expectedSize * MAX_BYTE_LENGTH;
    }

    std::string getTypeAsString() override {
        return ArrayType::getTypeAsString() + "[" + to_string(expectedSize) + "]";
    }

 private:
    void isValid() {
        if (!expectedSize && value.size() > MAX_SIZE_OF_STATIC_ARRAY) {
            throw ABIException("Static arrays with a length greater than 1024 are not supported");
        } else if (expectedSize != 0 && value.size() != expectedSize) {
            throw ABIException(
                fmt::format("Expected array of type {} to have [{}] elements, but get {}",
                            getTypeAsString(),
                            expectedSize,
                            value.size()));
        }
    }

    static constexpr size_t MAX_SIZE_OF_STATIC_ARRAY = 1024 * MAX_BYTE_LENGTH;
    size_t expectedSize;
    bool dynamic;
};

inline TypePrt generate_coders(const std::string& rawType,
                               const size_t& length,
                               const std::string& value = "") {
    if (!rawType.find(UINT)) {
        return std::make_shared<Uint>(value, length);
    } else if (!rawType.find(INT)) {
        return std::make_shared<Int>(value, length);
    } else if (!rawType.find(ADDRESS)) {
        return std::make_shared<Address>(value);
    } else if (!rawType.find(STRING)) {
        return std::make_shared<Utf8String>(value);
    } else if (!rawType.find(BOOL)) {
        return std::make_shared<Boolean>(value);
    } else if (!rawType.find(BYTES)) {
        if (std::strcmp(rawType.c_str(), BYTES) == 0 && length == 0)
            return std::make_shared<DynamicBytes>(value);
        return std::make_shared<Bytes>(length, value);
    } else if (!rawType.find(FIXED) || !rawType.find(UFIXED)) {
        throw ABIException(fmt::format("Unsupported type: {}", rawType));
    }
    throw ABIException(fmt::format("Unrecognized type: {}", rawType));
}

inline TypePrt entry_identity(const std::string& rawType) {
    auto [type, expectedSize, boolean] = Parsing(rawType).result();
    if (boolean) {
        if (expectedSize > 0) {
            return std::make_shared<StaticArray>(type, expectedSize);
        }
        return std::make_shared<DynamicArray>(type);
    }
    return generate_coders(type, expectedSize);
}

inline TypePrt generate_coders(const std::string& rawType, const nlohmann::json& value) {
    auto [type, expectedSize, boolean] = Parsing(rawType).result();
    if (boolean) {
        if (expectedSize > 0) {
            return std::make_shared<StaticArray>(type, expectedSize, value);
        }
        return std::make_shared<DynamicArray>(type, value);
    }

    return generate_coders(type, expectedSize, value);
}

} // namespace abicoder
