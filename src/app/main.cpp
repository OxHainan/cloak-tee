


#include "tables.h"
#include "jsonrpc.h"
#include "utils.h"
#include "workerqueue.h"
#include "abicoder.h"
using namespace ccf;
using namespace evm4ccf;
using namespace std;
using namespace eevm;

template <typename T>
nlohmann::json json_with(
  const nlohmann::json& j, const std::string& field, T&& v)
{
  nlohmann::json result = j;
  result[field] = v;
  return result;
}

nlohmann::json json_without(const nlohmann::json& j, const std::string& field)
{
  nlohmann::json result = j;
  result.erase(field);
  return result;
}

const nlohmann::json basic_request = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"codeHash": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"verifierAddr": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe", 
		"policy": "0x7b2266756e6374696f6e73223a5b7b2274797065223a2266756e6374696f6e222c226e616d65223a22736574746c6552656365697661626c65222c22696e70757473223a5b7b226e616d65223a226f776e6572222c2274797065223a2275696e74323536222c226f776e6572223a22616c6c227d2c7b226e616d65223a22616d6f756e74222c2274797065223a2275696e74323536222c226f776e6572223a22746565227d5d2c2272656164223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226f776e6572225d7d5d2c226d7574617465223a5b7b226e616d65223a2262616c616e636573222c226b657973223a5b226d73672e73656e646572225d7d2c7b226e616d65223a2272656365697661626c6573222c226b657973223a5b226f776e65723a6d73672e73656e646572225d7d5d2c226f757470757473223a5b7b226e616d65223a22222c2274797065223a2275696e74323536222c226f776e6572223a22616c6c227d5d7d5d2c22636f6e7472616374223a2253756270707070222c22737461746573223a5b7b226e616d65223a2262616c616e636573222c2274797065223a226d617070696e6728616464726573733d3e75696e7432353629222c226f776e6572223a226d617070696e67286164647265737321783d3e75696e74323536407829227d2c7b226e616d65223a2272656365697661626c6573222c2274797065223a226d617070696e6728616464726573733d3e6d617070696e6728616464726573733d3e75696e743235362929222c226f776e6572223a226d617070696e67286164647265737321783d3e6d617070696e6728616464726573733d3e75696e7432353640782929227d5d7d"
    }
  )xxx"_json
};
const nlohmann::json multiParty = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"params": "0x7b22706f6c69637948617368223a22307862653839666238383864376131333432333664383765303530616532343930303931343439613461343262396636333863346264383331666534306563393137222c226e616d65223a22736574746c6552656365697661626c65222c22696e707574223a226f776e6572222c2276616c7565223a22313233343536227d"
    }
  )xxx"_json
};
const nlohmann::json multiParty1 = {
R"xxx(
    {
		"from": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"to": "0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe",
		"params": "0x7b22706f6c69637948617368223a22307862653839666238383864376131333432333664383765303530616532343930303931343439613461343262396636333863346264383331666534306563393137222c226e616d65223a22736574746c6552656365697661626c65222c22696e707574223a22616d6f756e74222c2276616c7565223a22313830303030303030303030303030303030227d"
    }
  )xxx"_json
};

int main() {
    auto wq = std::make_unique<WorkerQueue>();
    const auto tc = basic_request.get<rpcparams::SendPrivacyPolicy>();
    
    auto p = nlohmann::json::parse(Utils::HexToBin(tc.policy));
    auto s = p.get<rpcparams::Policy>();
    PrivacyPolicyTransaction ppt(tc);
    std::cout << to_checksum_address(tc.from) << std::endl;
    wq->add(ppt);
    auto hash = ppt.hash();
    auto ppp = wq->getPrivacyPolicyTransactionByHash(hash);
    const auto mp = multiParty.get<rpcparams::SendMultiPartyTransaction>();
    MultiPartyTransaction mpt(mp);
    auto [result, status] = wq->addMultiParty(mpt);
    cout << result << " " << status << endl;

    auto pp = wq->getPrivacyPolicyTransactionByHash(ppt.hash());
    const auto mp1 = multiParty1.get<rpcparams::SendMultiPartyTransaction>();
    MultiPartyTransaction mpt1(mp1);
    auto [result1, status1] = wq->addMultiParty(mpt1);
    cout << result1 << " " << status1 << endl;

       CoderAddress address = CoderAddress("owner");
    Coder* coder = &address;
    // auto addr1 = coder->encode("de0B295669a9FD93d5F28D9Ec85E40f4cb697BAe");
    // auto addr2 = coder->encode("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697Baa");
    // // array<uint8_t, 64u> res;
    // UINT8ARRAY res(64);
    // insert(res, addr1);
    // insert(res, addr2,32);
    // cout << to_hex_string(res) << endl;

    // for (size_t i = 0; i < res.size(); i++)
    // {
    //     printChar(res.at(i));
    // }
    CoderNumber number(2,1);
    auto boolean = number.encode(true);
    cout << to_hex_string(boolean) << endl;
    // for (size_t i = 0; i < boolean.size(); i++)
    // {
    //     printChar(boolean.at(i));
    // }
    CoderBoolean coderbool("bool");
    coder = &coderbool;
    coderbool.setValue("1");
    cout << to_hex_string(coder->encode()) << endl;
    // auto encode = encodeDynamicBytes("0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BkJHDKJSAHDKJAHSDKLAHDKASLDHFKSDHFKSALaasadllkasdjlaksj");
    // cout << encode.size() << endl;
    CoderString stringcoder("string");
    stringcoder.setValue("Hello, world!");
    coder = &stringcoder;
    cout << to_hex_string(coder->encode()) << endl;
    

    CoderFixedBytes bytes1(1);
    bytes1.setValue("0xabcdef3545612aabb");
    coder = &bytes1;
    try
    {
      cout << to_hex_string(coder->encode()) << endl;
    }
    catch(const int e)
    {
      cout << e << endl;
    }
    
    CoderDynamicBytes bytes("bytes1");
    bytes.setValue("69");
    coder = &bytes;
    cout << to_hex_string(coder->encode()) << endl;

    CoderArray array1(&bytes1,"uint256", 2, true);

    vector<void*> coders;
    // coders.push_back(&bytes1);
    coders.push_back(&stringcoder);
    // coders.push_back(&coderbool);
    
    // coders.push_back(&address);
    
    vector<ByteData> value;
    // value.push_back("69");
    
    // value.push_back("Hello, world!");
    // value.push_back("1");
    // value.push_back("0xabcdef3545612aabb");
    auto pc = pack(coders);
    // array.encode();
      cout << to_hex_string(pc) << endl;
    vector<ByteData> value2;
    value2.push_back("69");
    value2.push_back("6");
    array1.setValue(value2);
    auto arr = array1.encode();

    cout << to_hex_string(arr) << endl;

    return 0;
}