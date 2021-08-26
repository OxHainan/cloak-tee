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
#include "abicoder.h"
#include "parsing.h"
#include "vector"
#include <string>
struct abiParams
{
    string name;
    string type;
};
class Bytecode
{
private:
    std::vector<void*> coders;
    std::string entry;
    std::vector<abiParams> inputs;
public:
    Bytecode(const std::string& _entry) :
        entry(_entry)
    {}
    
    void add_inputs(const std::string& _name, const std::string& _type, const std::string& _value)
    {
        add_params(_name, _type);
        abicoder::paramCoder(coders, _name, _type, _value);
    }

    void add_inputs(const std::string& _name, const std::string& _type, const std::vector<std::string>& _value)
    {
        add_params(_name, _type);
        abicoder::paramCoder(coders, _name, _type, _value);
    }

    void add_inputs(const std::string& _name, const std::string& _type)
    {
        add_params(_name, _type);
    }

    std::vector<uint8_t> encode()
    {
        auto sha3 = encode_function();
        std::vector<uint8_t> data = abicoder::pack(coders);
        sha3.insert(sha3.end(), data.begin(), data.end());
        return sha3;
    }

    std::vector<uint8_t> encode(const std::vector<uint8_t>& _entry)
    {
        auto sha3 = vector<uint8_t>(_entry.begin(), _entry.begin() + 4);
        std::vector<uint8_t> data = abicoder::pack(coders);
        sha3.insert(sha3.end(), data.begin(), data.end());
        return sha3;
    }

    std::vector<uint8_t> encode_function() const
    {
        std::string params;
        for (size_t i = 0; i < inputs.size(); i++)
        {
            params += inputs[i].type;
            if ( i != inputs.size() - 1) {
                params += ",";
            }          
        }

        auto sha3 = eevm::keccak_256(entry + "(" + params + ")");
        return vector<uint8_t>(sha3.begin(), sha3.begin() + 4);
    }
private:
    void add_params(const std::string& name, const std::string& _type)
    {
    #ifdef FUNCTION_SELECT
        auto [type, length, isArray] = Parsing(_type).result();
        if (!type.compare("uint") || !type.compare("int"))
        {
            type.append("256");
        } else if (!type.compare("fixed") || !type.compare("ufixed")) {
            type.append("128x18");
        }
        if (isArray) {
            type.append("[" + (length > 0 ? to_string(length) : "") + "]");
        }
        inputs.push({name, _type});
        return;
    #endif

        inputs.push_back({name, _type});
    }   
};
