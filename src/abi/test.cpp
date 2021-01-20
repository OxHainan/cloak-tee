
#include "jsonrpc.h"
#include "../app/utils.h"
#include "abicoder.h"

using namespace std;
using namespace eevm;
using namespace abicoder;


int main() {

    CoderNumber uint256S(2,1);
    CoderNumber uint256S1(2,1);

    CoderArray array1(&uint256S1, "uint", 2);
    CoderFixedBytes bytes(5);
    CoderString Dbytes("bytes");
    vector<void*> coders;
    coders.push_back(&uint256S);
    coders.push_back(&array1);
    coders.push_back(&bytes);
    coders.push_back(&Dbytes);

    uint256S.setValue("0x123");
    bytes.setValue("1234567890");
    Dbytes.setValue("Hello, world!");
    vector<ByteData> arrs;
    arrs.push_back("0x456");
    arrs.push_back("0x789");
    array1.setValue(arrs);
    auto out1 = abicoder::pack(coders);
    cout << to_hex_string(out1) << endl;
   
    return 0;
}