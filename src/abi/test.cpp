
#include "jsonrpc.h"
#include "../app/utils.h"
#include "abicoder.h"

using namespace std;
using namespace eevm;
using namespace abicoder;

// 测试合约输入变量打包
int main() {

    vector<void*> coders;

    vector<ByteData> arrs;
    arrs.push_back("0x456");
    arrs.push_back("0x789");

    abicoder::paramCoder(coders, "uint256", "uint", "0x123");
    abicoder::paramCoder(coders, "array", "uint[]", arrs);
    abicoder::paramCoder(coders, "bytes", "bytes10","1234567890");
    abicoder::paramCoder(coders, "Dbytes", "string", "Hello, world!");
   
    auto out1 = abicoder::pack(coders);
    cout << to_hex_string(out1) << endl;
   
    return 0;
}