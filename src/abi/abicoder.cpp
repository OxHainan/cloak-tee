#include "abicoder.h"
#include "ds/logger.h"
#include "vector"
#include <cstddef>
#include <eEVM/util.h>

void abicoder::insert(UINT8ARRAY &coder,const UINT8ARRAY &input, size_t offset) {
    for(size_t i= offset, x = 0; x< input.size(); x++, i++ ) {
        coder.at(i) = input.at(x);
    }
}


UINT8ARRAY abicoder::to_bytes(const std::string& _s, size_t offset, bool boolean) {
    auto s = eevm::strip(_s);
    UINT8ARRAY h(32);
    if(!boolean)
        h.resize(ceil(s.size() / 2.0));
    if(s.empty()) return h;
    for(size_t i=0; i<offset; i++) {
        h.at(i ) = 0;
    }
        
    for(size_t  x = 0; x < s.size(); offset++, x+=2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(),0,16);          
    }
    return h;
}

UINT8ARRAY abicoder::uint256Coder(size_t size) {
    return UintNumber().encode(to_string(size));
}

UINT8ARRAY abicoder::fixed_to_bytes(const std::string &_s) {
    UINT8ARRAY h(32);
    auto s = Utils::BinaryToHex(_s);
    for(size_t  x = 0,offset=0; x < s.size(); offset++, x+=2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(),0,16);          
    }
    return h;
}

UINT8ARRAY abicoder::string_to_bytes(const std::string& _s) {
    auto s = Utils::BinaryToHex(_s);
    UINT8ARRAY h(ceil(s.size() / 2.0));
    if(s.empty()) return h;
    for(size_t offset=0, x = 0; x < s.size(); offset++, x+=2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(),0,16);    
    }
    return h;
}

UINT8ARRAY abicoder::encodeDynamicBytes(const UINT8ARRAY& value) {
    UINT8ARRAY result(32 + alignSize(value.size()));
    auto header = UintNumber().encode(to_string(value.size()));
    to_array(result, header);
    to_array(result, value, 32);
    return result;
}

UINT8ARRAY abicoder::basic_pack(const vector<PackParams>& parts) {
    size_t staticSize = 0, dynamicSize = 0;
    for(auto part : parts) {
        if(part.Dynamic) {
            staticSize +=32;
            dynamicSize += alignSize(part.data.size());
        } else {
            staticSize += alignSize(part.data.size());
        }
    }

    size_t offset = 0, dynamicOffset = staticSize;
    UINT8ARRAY data(staticSize + dynamicSize);

    for(auto part : parts) {
        if(part.Dynamic) {
            to_array(data, uint256Coder(dynamicOffset), offset);
            offset +=32;
            to_array(data, part.data, dynamicOffset);
            dynamicOffset += alignSize(part.data.size());
        } else {
            to_array(data, part.data, offset);
            offset += alignSize(part.data.size());
        }
    }
    return data;
}

UINT8ARRAY abicoder::pack(const std::vector<void*>& coders) {
    vector<abicoder::PackParams> parts;
    Coder* coder;
    for(size_t i=0; i<coders.size(); i++) {
        coder = (Coder*)coders[i];
        parts.push_back({coder->getDynamic(), coder->encode()});
        delete coder;
    }
    return basic_pack(parts);
}

UINT8ARRAY abicoder::pack(const std::vector<void*>& coders, const vector<ByteData> &value) {
    vector<PackParams> parts;
    Coder* coder;
    for(size_t i=0; i<coders.size(); i++) {
        coder = (Coder*)coders[i];
        coder->setValue(value[i]);
        parts.push_back({coder->getDynamic(), coder->encode()});
        delete coder;
    }
    return basic_pack(parts);
}

UINT8ARRAY abicoder::CoderArray::encode() {  
    vector<void*> coders;
    for (size_t i=0; i<value.size(); i++) {
        abicoder::paramCoder(coders, name, type, value[i], length);
    }
    auto data = pack(coders);
    if (Dynamic)
    {
        auto result = UintNumber().encode(to_string(value.size()));
        result.insert(result.end(),data.begin(), data.end());
        return result;
    }
    return data;
}

void abicoder::paramCoder(vector<void*> &coders, const ByteData &name, const ByteData &_type,const ByteData & value) {

    auto [type, length, boolean] = Parsing(_type).result();
    if(boolean) {
        // size_t len = length > 1 ? length : value.size();
        CoderArray* array = new CoderArray(name, type, length, length == 0);
        array->setValue(value);
        coders.push_back(array);
        return;
    }
    paramCoder(coders, name, type, value, length);  
}

// handle Array type
void abicoder::paramCoder(vector<void*> &coders, const ByteData &name, const ByteData &_type,const vector<ByteData> & value) {
    auto [type, length, boolean] = Parsing(_type).result();
    if(boolean) {
        // array
        size_t len = length > 1 ? length : value.size();
        CoderArray* array = new CoderArray(name, type, len, length == 0);
        array->setValue(value);
        coders.push_back(array);
        return;
    }
}

void abicoder::paramCoder(vector<void*> &coders, const ByteData &name, const ByteData &type,const ByteData & value, int length) {
    switch (contractType[type]){
    case ADDRESS: {
        CoderAddress* code = new CoderAddress(name);
        code->setValue(value);
        coders.push_back(code);
        return;
    }
    case BOOL: {
        CoderBoolean* code =new  CoderBoolean(name);
        code->setValue(value);
        coders.push_back(code);
        break;
    }
    case STRING: {
        CoderString* code = new CoderString(name);
        code->setValue(value);
        coders.push_back(code);
        break;
    }
    case BYTES: {
        if(length == 0) {
            CoderDynamicBytes* code = new CoderDynamicBytes(name);
            code->setValue(value);
            coders.push_back(code);
        } else {
            CoderFixedBytes* code= new CoderFixedBytes(length);
            code->setValue(value);
            coders.push_back(code);
        }       
        break;
    }
    case UINT: {
        CoderNumber* code =new  CoderNumber(length, false);
        code->setValue(value);
        coders.push_back(code);
        break;
    }
    case INT: {
        CoderNumber* code = new CoderNumber(length, true);
        code->setValue(value);
        coders.push_back(code);
        break;
    }
    default:
        break;
    }

}

std::vector<std::string> abicoder::decode_uint256_array(const std::vector<uint8_t>& states)
{
    CLOAK_DEBUG_FMT("raw data:{}", states);
    if (states.size() < 64) {
        LOG_AND_THROW("decode_uint256_array error, states length:{} is to short", states.size());
    }
    std::vector<uint8_t> count_vec(states.begin() + 32, states.begin() + 64);
    size_t count = size_t(eevm::to_uint256(eevm::to_hex_string(count_vec)));
    CLOAK_DEBUG_FMT("count:{}", count);
    std::vector<std::string> res;
    for (size_t i = 0; i < count; i++) {
        auto it = states.begin() + 64 + i * 32;
        std::vector<uint8_t> state(it, it + 32);
        res.push_back(eevm::to_hex_string(state));
    }
    CLOAK_DEBUG_FMT("res:{}", fmt::join(res, ", "));
    return res;
}

std::string abicoder::decode_string(const std::vector<uint8_t>& data) {
    CLOAK_DEBUG_FMT("decode_string, raw:{}", data);
    if (data.size() < 32) {
        LOG_DEBUG_FMT("decode_string error, data length:{} is to short", data.size());
    }
    std::vector<uint8_t> len_vec(data.begin(), data.begin() + 32);
    // NOTICE: string length can't greater than 2**64
    size_t len = size_t(eevm::to_uint256(eevm::to_hex_string(len_vec)));
    std::string res;
    if (len == 0) {
        return res;
    }
    size_t block_count = len / 32 + 1;
    size_t last_block_size = len % 32;
    for (size_t i = 0; i < block_count - 1; i++) {
        res.append(data.begin() + 32 * (i + 1), data.begin() + 32 * (i + 2));
    }
    res.append(data.begin() + 32 * block_count, data.begin() + 32 * block_count + last_block_size);
    CLOAK_DEBUG_FMT("decode_string, res:{}", res);
    return res;
}

std::vector<std::string> abicoder::decode_string_array(const std::vector<uint8_t> &data) {
    if (data.size() < 32) {
        LOG_DEBUG_FMT("decode_string error, data length:{} is to short", data.size());
    }
    size_t count = size_t(Utils::vec32_to_uint256({data.begin(), data.begin() + 32}));
    CLOAK_DEBUG_FMT("count:{}", count);
    std::vector<std::string> res;
    for (size_t i = 0; i < count; i++) {
        size_t offset = size_t(Utils::vec32_to_uint256({data.begin() + 32 * (i + 1), data.begin() + 32 * (i + 2)}));
        // TODO: better end
        res.push_back(decode_string({data.begin()+32+offset, data.end()}));
    }
    return res;
}

