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

#include "abi/parse_types.h"
#include "abi/types/array.h"
#include "abi/types/type.h"

namespace abicoder
{
    class Encoder
    {
      public:
        Encoder() {}
        explicit Encoder(const std::string& _entry) : entry(_entry) {}

        void add_inputs(const std::string& _name, const std::string& _type)
        {
            add_params(_name, _type);
        }

        void add_inputs(
          const std::string& _name,
          const std::string& _type,
          const nlohmann::json& _value,
          const nlohmann::json& _type_value)
        {
            add_params(_name, _type);
            paramsCoder(_type_value, _value);
        }

        std::vector<uint8_t> encode()
        {
            return Coder::pack(coders);
        }

        static std::vector<uint8_t> encode(
          const std::string& type,
          const nlohmann::json& value,
          const nlohmann::json& j_type)
        {
            Encoder encoder;
            encoder.add_inputs("", type, value, j_type);
            return encoder.encode();
        }

        std::vector<uint8_t> encode(
          const std::vector<uint8_t>& _signature_function)
        {
            auto sha3 = std::vector<uint8_t>(
              _signature_function.begin(), _signature_function.begin() + 4);
            auto data = encode();
            sha3.insert(sha3.end(), data.begin(), data.end());
            return sha3;
        }

        std::vector<uint8_t> encodeWithSignatrue()
        {
            auto data = encode();
            auto sha3 = build_method_signature();
            sha3.insert(sha3.end(), data.begin(), data.end());
            return sha3;
        }

        std::vector<uint8_t> build_method_signature()
        {
            std::string params;
            for (size_t i = 0; i < abi.size(); i++)
            {
                params += abi[i].type;
                if (i != abi.size() - 1)
                {
                    params += ",";
                }
            }

            auto sha3 = eevm::Keccak256(entry + "(" + params + ")").hash;
            return std::vector<uint8_t>(sha3.begin(), sha3.begin() + 4);
        }

      private:
        void paramsCoder(
          const nlohmann::json& _type_value, const nlohmann::json& _value)
        {
            auto coder = generate_coders(_type_value, _value);
            coders.push_back(coder);
        }

        void add_params(const std::string& name, const std::string& _type)
        {
#ifdef FUNCTION_SELECT
            auto [type, length, isArray] = Parsing(_type).result();
            if (!type.compare("uint") || !type.compare("int"))
            {
                type.append("256");
            }
            else if (!type.compare("fixed") || !type.compare("ufixed"))
            {
                type.append("128x18");
            }
            if (isArray)
            {
                type.append("[" + (length > 0 ? to_string(length) : "") + "]");
            }
            abi.push({name, _type});
            return;
#endif
            abi.push_back({name, _type});
        }

        std::vector<TypePrt> coders;
        std::vector<abiParams> abi;
        std::string entry;
    };

} // namespace abicoder
