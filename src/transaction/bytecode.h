#pragma once

#include "../abi/abicoder.h"
#include "vector"
class Bytecode
{
private:
    vector<void*> coders;
    UINT8ARRAY sha3;
    
public:
    Bytecode(const ByteData& name, const std::vector<evm4ccf::policy::Params>& inputs)
    {
        auto sha3_name = eevm::keccak_256(name);
        sha3 = UINT8ARRAY(sha3_name.begin(), sha3_name.begin() + 4);

        for (size_t i = 0; i < inputs.size(); i++)
        {
            inputs[i].pack(coders);
        }
    }

    UINT8ARRAY encode()
    {
        UINT8ARRAY data = abicoder::pack(coders);
        sha3.insert(sha3.end(), data.begin(), data.end());
        return sha3;
    }
};

