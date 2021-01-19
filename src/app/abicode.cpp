#include "abicoder.h"

int main() {
    CoderAddress address = CoderAddress("owner");
    Coder* coder = &address;
    auto addr1 = coder->encode("de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");
    auto addr2 = coder->encode("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697Baa");
    array<uint8_t, 64u> res;
    insert(res, addr1);
    insert(res, addr2,32);
    // for (size_t i = 0; i < res.size(); i++)
    // {
    //     printChar(res.at(i));
    // }
    CoderNumber number(2,1);
    auto boolean = number.encode(true);
    // cout << to_hex_string1(boolean);
    for (size_t i = 0; i < boolean.size(); i++)
    {
        printChar(boolean.at(i));
    }
    // res.insert(addr1.begin(), addr1.end());
    return 0;
}