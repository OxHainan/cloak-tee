#pragma once
#include "iostream"
#include "vector"
#include <stdio.h>
#include <stdlib.h>
#include "string"
#include <array>
#include "utils.h"
#include <sstream>
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/processor.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
#include "math.h"
#include "optional"
using namespace std;

using ByteData = std::string;
using uint256 = intx::uint256;
// using UINT8ARRAY = array<uint8_t,32u>;
using UINT8ARRAY = vector<uint8_t>;
void printChar(const unsigned char c) {
    for(int j = 7; j >= 0; j--) {
        std::cout << ((c >> j) & 1);
    }
    std::cout << std::endl;
}

inline double alignSize(size_t size) {
    return 32 * (ceil(size / 32.0));
}

// template <size_t N>
void insert(UINT8ARRAY &coder,const UINT8ARRAY &input, size_t offset = 0) {
    for(size_t i= offset, x = 0; x< input.size(); x++, i++ ) {
        coder.at(i) = input.at(x);
    }
}

// template <size_t N>
inline void to_array(UINT8ARRAY& result, const UINT8ARRAY &value, size_t offset = 0, bool signal = true) {
    if(signal) {
        for(size_t i=offset, x=0; x<value.size()  ; i++, x++) {
            result.at(i) = value.at(x);
        }
        return;
    } 
    for(size_t i=offset, x = value.size()-1; i<result.size() && x >=0 ; i++, x--) {
        result.at(i) = value.at(x);
    }
    
}

// template <size_t N>
inline void to_array(UINT8ARRAY& result, const uint8_t &value, size_t offset = 0) {
    result.at(offset) = value;
}

UINT8ARRAY to_bytes(const std::string& _s, size_t offset = 0, bool boolean = true) {
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

UINT8ARRAY fixed_to_bytes(const std::string &s) {
    UINT8ARRAY h(32);
    for(size_t  x = 0,offset=0; x < s.size(); offset++, x+=2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(),0,16);          
    }
    return h;
}

UINT8ARRAY string_to_bytes(const std::string& _s) {
    auto s = Utils::BinaryToHex(_s);
    UINT8ARRAY h(ceil(s.size() / 2.0));
    if(s.empty()) return h;
    for(size_t offset=0, x = 0; x < s.size(); offset++, x+=2) {
        h.at(offset) = strtol(s.substr(x, 2).c_str(),0,16);    
    }
    return h;
}

class Coder {
public:
    virtual UINT8ARRAY encode() = 0;
    virtual void setValue(const ByteData &_value) {}
    virtual bool getDynamic() const = 0;
};

class CoderNumber {
public:
    CoderNumber() {}
    CoderNumber(size_t _size, bool _signal) :
        size(_size),
        signal(_signal)
    {
        name = (signal ? "int" : "uint") + to_string(size * 8);
    }

    UINT8ARRAY encode(ByteData value) {
        return encode(eevm::to_uint256(value));
    }

    UINT8ARRAY encode(uint256 value) {
        UINT8ARRAY result(32);
        vector<uint8_t> dest_hash(32);
        std::memcpy(&dest_hash[0], &value, 32);
        to_array(result, dest_hash, 0, false);
        return result;
    }

    UINT8ARRAY encode(bool boolean) {
        UINT8ARRAY result(32);
        // result.fill(0);
        to_array(result, (uint8_t)boolean, 31);
        return result;
    }


private:
    ByteData name;
    size_t size;
    bool signal;
};

class CoderAddress : public Coder {
public:
    CoderAddress(ByteData _name) :name(_name) {}
    void setValue(const ByteData &_value) {
        value = _value;
    }
    UINT8ARRAY encode() {
        UINT8ARRAY result = to_bytes(value, 12u);
        return result;       
    }
    bool getDynamic() const {
        return Dynamic;
    }

private:
    ByteData name;
    ByteData coderType = "address";
    ByteData value;
    bool     Dynamic = false;

};

class CoderBoolean : public Coder {
public:
    CoderBoolean(ByteData _name) :name(_name) {
        uint256Coder =  CoderNumber(32, true);
    }
    void setValue(const ByteData &_value) {
        value = _value;
    }
    UINT8ARRAY encode() {
        return uint256Coder.encode(value == "1" ? true : false);
    }

    bool getDynamic() const {
        return Dynamic;
    }

    ~CoderBoolean() {
        cout << "释放CoderBoolean" << endl;
    }

private:
    ByteData name;
    ByteData coderType = "bool";
    ByteData value;
    bool     Dynamic = false;
    CoderNumber uint256Coder;
};


auto encodeDynamicBytes(const UINT8ARRAY& value) {
    UINT8ARRAY result(32 + alignSize(value.size()));
    auto header = CoderNumber().encode(to_string(value.size()));
    to_array(result, header);
    to_array(result, value, 32);
    return result;
}


class CoderString : public Coder {
public:
    CoderString(ByteData _name, bool _dynamic = true) :name(_name), Dynamic(_dynamic) {}
    void setValue(const ByteData &_value) {
        value = _value;
    }
    UINT8ARRAY encode() {
        UINT8ARRAY result = string_to_bytes(value);
        return encodeDynamicBytes(result);
    }

    bool getDynamic() const {
        return Dynamic;
    }

private:
    ByteData name;
    ByteData coderType = "string";
    ByteData value;
    bool     Dynamic = false;

};

class CoderDynamicBytes : public Coder {
public:
    CoderDynamicBytes() {}
    CoderDynamicBytes(ByteData _name, bool _dynamic = true) :name(_name), Dynamic(_dynamic) {}
    void setValue(const ByteData &_value) {
        value = _value;
    }

    UINT8ARRAY encode() {
        UINT8ARRAY result = to_bytes(value, 0, false);
        return encodeDynamicBytes(result);
    }

    bool getDynamic() const {
        return Dynamic;
    }

private:
    ByteData name;
    ByteData coderType = "bytes";
    ByteData value;
    bool     Dynamic = false;

};

// 处理静态bytes类型，如bytes2 bytes10等
class CoderFixedBytes : public Coder {
public:
    CoderFixedBytes() {}
    CoderFixedBytes(size_t _length) : length(_length) {
        name = "bytes" + to_string(length);
    }
    void setValue(const ByteData &_value) {
        value = _value;
    }

    UINT8ARRAY encode() {
        auto s = eevm::strip(value);
        auto len = ceil(s.size() / 2.0);
        if(len != length) throw -1;

        UINT8ARRAY result = fixed_to_bytes(s); 
        return result;           
    }

    bool getDynamic() const {
        return Dynamic;
    }

private:
    ByteData name;
    bool     Dynamic = false;
    ByteData value;
    size_t      length;
};

struct PackParams
{
    bool Dynamic;
    UINT8ARRAY data;
};

UINT8ARRAY uint256Coder(size_t size) {
    return CoderNumber().encode(to_string(size));
}

UINT8ARRAY basic_pack(const vector<PackParams>& parts) {
    size_t staticSize = 0, dynamicSize = 0;
    for(auto part : parts) {
        if(part.Dynamic) {
            staticSize +=32;
            dynamicSize += alignSize(part.data.size());
        } else {
            staticSize += alignSize(part.data.size());
        }
    }
    cout << "dynamicSize:" << dynamicSize << " staticSize:" << staticSize << endl;
    size_t offset = 0, dynamicOffset = staticSize;
    UINT8ARRAY data(staticSize + dynamicSize);
    cout << "data size" << data.size()<< endl;
    for(auto part : parts) {
        if(part.Dynamic) {
            cout << "dynamic" << part.Dynamic << endl;
            // cout << "data:" << part.data
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

UINT8ARRAY pack(std::vector<void*>& coders) {
    vector<PackParams> parts;
    Coder* coder;
    for(int i=0; i<coders.size(); i++) {
        coder = (Coder*)coders[i];
        parts.push_back({coder->getDynamic(), coder->encode()});
    }
    return basic_pack(parts);
}

UINT8ARRAY pack(std::vector<void*>& coders, vector<ByteData> &value) {
    vector<PackParams> parts;
    Coder* coder;
    for(int i=0; i<coders.size(); i++) {
        coder = (Coder*)coders[i];
        coder->setValue(value[i]);
        parts.push_back({coder->getDynamic(), coder->encode()});
    }
    return basic_pack(parts);
}

class CoderArray : Coder{
public:
    CoderArray(void* _coder, ByteData _type, int _length, bool dynamic = true) : length(_length) {
        // 此长度并非数组的长度，而是type中括号标识的程度
        type = _type + "[" + (length >=0 ? to_string(length) : "") + "]";
        Dynamic = (length == -1 || dynamic);
        coder = _coder;
    }

    void setValue(const vector<ByteData> &_value){
        value = _value;
    }
    UINT8ARRAY encode() {
        UINT8ARRAY result;
        // if(length == -1) {
        result = CoderNumber().encode(to_string(value.size()));
        // }

        vector<void*> coders(value.size(), coder);
        
        auto data = pack(coders, value);
        result.insert(result.end(),data.begin(), data.end());
        return result;
    }

    bool getDynamic() const {
        return Dynamic;
    }

private:
    size_t length;
    bool   Dynamic = false;
    ByteData type;
    void* coder;
    vector<ByteData> value;
};

