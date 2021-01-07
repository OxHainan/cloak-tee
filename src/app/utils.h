#include "iostream"
#include <string>

namespace Utils 
{
    std::string strip(const std::string& s)
    {
        return (s.size() >= 2 && s[1] == 'x') ? s.substr(2) : s;
    }
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
        auto strHex = strip(_strHex);

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
}