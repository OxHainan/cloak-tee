#pragma once
#include "iostream"
#include <string>
// eEVM
#include <eEVM/address.h>
#include <eEVM/bigint.h>
#include <eEVM/processor.h>
#include <eEVM/rlp.h>
#include <eEVM/util.h>
namespace Utils 
{
    inline std::string BinaryToHex(
        const std::string &strBin,
        bool bIsUpper = false
    ) {
        std::string strHex;
        strHex.resize(strBin.size() * 2);
        for (size_t i = 0; i < strBin.size(); i++)
        {
            uint8_t cTemp = strBin[i];
            for (size_t j = 0; j < 2; j++)
            {
                uint8_t cCur = (cTemp & 0x0f);
                if (cCur < 10) {
                    cCur += '0';
                } else {
                    cCur += ((bIsUpper ? 'A' : 'a') - 10);
                }
                strHex[2 * i + 1 - j] = cCur;
                cTemp >>= 4;
            }
        }
        return strHex;
    }

    inline std::string HexToBin(const std::string &_strHex)
    {
        if (_strHex.size() % 2 != 0)
        {
            return "";
        }
        auto strHex = eevm::strip(_strHex);

        std::string strBin;
        strBin.resize(strHex.size() / 2);
        for (size_t i = 0; i < strBin.size(); i++)
        {
            uint8_t cTemp = 0;
            for (size_t j = 0; j < 2; j++)
            {
                char cCur = strHex[2 * i + j];
                if (cCur >= '0' && cCur <= '9')
                {
                    cTemp = (cTemp << 4) + (cCur - '0');
                } else if (cCur >= 'a' && cCur <= 'f')
                {
                    cTemp = (cTemp << 4) + (cCur - 'a' + 10);
                } else if (cCur >= 'A' && cCur <= 'F')
                {
                    cTemp = (cTemp << 4) + (cCur - 'A' + 10);
                } else
                {
                    return "";
                }
            }
            strBin[i] = cTemp;
        }

        return strBin;
    }

    template<typename T>
    inline void parse(const std::string &s, T &v) {
        auto j = nlohmann::json::parse(HexToBin(s));
        v = j.get<T>();
    } 
    template<typename T>
    inline T parse(const std::string &s) {
        auto j = nlohmann::json::parse(HexToBin(s));
        return j.get<T>();
    } 

    inline eevm::KeccakHash to_KeccakHash(const std::string& _s) {
        auto s = eevm::strip(_s);
        eevm::KeccakHash h;
        if(s.empty()) return h;
        for(size_t i = 0, x = 0; i<32; i++, x+=2) {
            h.at(i) = strtol(s.substr(x, 2).c_str(),0,16);
        }
        return h;
    }
}